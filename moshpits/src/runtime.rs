// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

use std::{ffi::OsString, net::SocketAddr, sync::Arc};

use anyhow::{Context as _, Result};
use aws_lc_rs::{
    aead::{AES_256_GCM_SIV, Aad, Nonce, RandomizedNonceKey},
    agreement::{EphemeralPrivateKey, UnparsedPublicKey, X25519, agree_ephemeral},
    cipher::AES_256_KEY_LEN,
    error::Unspecified,
    hkdf::{HKDF_SHA256, Salt},
    rand::{SystemRandom, fill},
};
use clap::Parser as _;
use libmoshpit::{Connection, Frame, MoshpitError, UdpState, UuidWrapper, init_tracing, load};
use tokio::{
    net::{TcpListener, UdpSocket},
    spawn,
    sync::mpsc::{UnboundedSender, unbounded_channel},
};
use tracing::{error, info, trace};
use uuid::Uuid;

use crate::{
    cli::Cli,
    config::Config,
    udp::{reader::UdpReader, sender::UdpSender},
};

pub(crate) async fn run<I, T>(args: Option<I>) -> Result<()>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    // Parse the command line
    let cli = if let Some(args) = args {
        Cli::try_parse_from(args)?
    } else {
        Cli::try_parse()?
    };

    // Load the configuration
    let config = load::<Cli, Config, Cli>(&cli, &cli).with_context(|| MoshpitError::ConfigLoad)?;

    // Initialize tracing
    init_tracing(&config, config.tracing().file(), &cli, None)
        .with_context(|| MoshpitError::TracingInit)?;

    trace!("Configuration loaded");
    trace!("Tracing initialized");

    let socket_addr = SocketAddr::new(
        config
            .mps()
            .ip()
            .parse()
            .with_context(|| MoshpitError::InvalidIpAddress)?,
        config.mps().port(),
    );
    let listener = TcpListener::bind(socket_addr).await?;
    let udp_listener = UdpSocket::bind(socket_addr).await?;
    let udp_arc = Arc::new(udp_listener);

    loop {
        match listener.accept().await {
            Ok((socket, addr)) => {
                info!("Accepted connection from {addr}");
                let mut handler = Handler {
                    connection: Connection::new(socket),
                    rnk: None,
                };
                let udp_recv = udp_arc.clone();
                let udp_send = udp_arc.clone();
                let _handle = spawn(async move {
                    match handler.handle_connection().await {
                        Ok((key_bytes, uuid)) => {
                            info!("connection can be promoted");

                            let (_tx, rx) = unbounded_channel::<Vec<u8>>();

                            let mut udp_reader = UdpReader::builder()
                                .socket(udp_recv)
                                .id(uuid)
                                .rnk(key_bytes)
                                .unwrap()
                                .build();
                            let mut udp_sender = UdpSender::builder()
                                .socket(udp_send)
                                .rx(rx)
                                .id(uuid)
                                .rnk(key_bytes)
                                .unwrap()
                                .build();

                            let _udp_reader_handle = spawn(async move {
                                if let Err(e) = udp_reader.handle_read().await {
                                    error!("udp reader error {e}");
                                }
                            });

                            let _udp_handle = spawn(async move {
                                if let Err(e) = udp_sender.handle_send().await {
                                    error!("udp sender error {e}");
                                }
                            });
                        }
                        Err(e) => error!("connection error: {e} from {addr}"),
                    }
                });
            }
            Err(e) => error!("couldn't get client: {e:?}"),
        }
    }
}

struct Handler {
    connection: Connection,
    rnk: Option<RandomizedNonceKey>,
}

impl Handler {
    async fn handle_connection(&mut self) -> Result<([u8; 32], Uuid)> {
        let (tx_udp_state, mut rx_udp_state) = unbounded_channel::<UdpState>();
        if let Some(frame) = self.connection.read_frame().await? {
            if let Frame::Initialize(pk) = frame {
                self.handle_initialize(pk, tx_udp_state.clone()).await?;
            } else {
                error!("Expected initialize frame");
                return Err(MoshpitError::InvalidFrame.into());
            }
        }

        if let Some(frame) = self.connection.read_frame().await? {
            if let Frame::Check(nonce, enc) = frame {
                self.handle_check(nonce, enc, tx_udp_state).await?;
            } else {
                error!("Expected check frame");
                return Err(MoshpitError::InvalidFrame.into());
            }
        }

        // Wait for UDP state updates with the key and UUID
        // once we have both, we can set up the UDP socket
        let mut key_bytes = [0u8; 32];
        let mut uuid = Uuid::nil();
        while let Some(udp_state) = rx_udp_state.recv().await {
            match udp_state {
                UdpState::Key(key_b) => {
                    trace!("Received UDP key");
                    key_bytes = key_b;
                }
                UdpState::Uuid(set_uuid) => {
                    trace!("Received UDP UUID: {}", set_uuid);
                    uuid = set_uuid;
                    break;
                }
            }
        }
        Ok((key_bytes, uuid))
    }

    async fn handle_initialize(
        &mut self,
        pk: Vec<u8>,
        tx_udp_state: UnboundedSender<UdpState>,
    ) -> Result<()> {
        info!("Received initialize frame with public key");
        let rng = SystemRandom::new();

        // Generate our ephemeral key pair
        let ephemeral_priv_key = EphemeralPrivateKey::generate(&X25519, &rng)?;
        let public_key = ephemeral_priv_key.compute_public_key()?;
        let unparsed_public_key = UnparsedPublicKey::new(&X25519, &pk);

        // Generate a (non-secret) salt value
        let mut salt_bytes = [0u8; 32];
        fill(&mut salt_bytes)?;

        // Send the public key and salt back to the peer
        let peer_initialize =
            Frame::PeerInitialize(public_key.as_ref().to_vec(), salt_bytes.to_vec());
        self.connection.write_frame(&peer_initialize).await?;
        info!("Sent peer initialize frame with public key and salt");

        // Extract pseudo-random key from secret keying materials
        let salt = Salt::new(HKDF_SHA256, &salt_bytes);

        // Setup the rnk and wait for a check frame
        agree_ephemeral(
            ephemeral_priv_key,
            unparsed_public_key,
            Unspecified,
            |key_material| {
                let pseudo_random_key = salt.extract(key_material);
                let okm = pseudo_random_key.expand(&[b"aead key"], &AES_256_GCM_SIV)?;
                let mut key_bytes = [0u8; AES_256_KEY_LEN];
                okm.fill(&mut key_bytes)?;
                tx_udp_state
                    .send(UdpState::Key(key_bytes))
                    .map_err(|_| Unspecified)?;
                let rnk = RandomizedNonceKey::new(&AES_256_GCM_SIV, &key_bytes)?;
                self.rnk = Some(rnk);
                Ok(())
            },
        )?;
        Ok(())
    }

    async fn handle_check(
        &mut self,
        nonce_bytes: [u8; 12],
        mut check_bytes: Vec<u8>,
        tx_udp_state: UnboundedSender<UdpState>,
    ) -> Result<()> {
        info!("Received check frame with encrypted check message");
        if let Some(rnk) = &mut self.rnk {
            let nonce = Nonce::from(&nonce_bytes);
            let decrypted_data = rnk
                .open_in_place(nonce, Aad::empty(), &mut check_bytes)
                .map_err(|_| MoshpitError::DecryptionFailed)?;
            if decrypted_data == b"Yoda" {
                info!("Check frame verified successfully");
                let id = Uuid::new_v4();
                tx_udp_state
                    .send(UdpState::Uuid(id))
                    .map_err(|_| Unspecified)?;
                self.connection
                    .write_frame(&Frame::KeyAgreement(UuidWrapper::new(id)))
                    .await?;
            } else {
                error!("Check frame verification failed");
                return Err(MoshpitError::DecryptionFailed.into());
            }
        } else {
            error!("Opening key not established");
            return Err(MoshpitError::KeyNotEstablished.into());
        }
        Ok(())
    }
}
