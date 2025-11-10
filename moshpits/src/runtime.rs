// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

use std::{
    ffi::OsString,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU16, Ordering},
    },
};

use anyhow::{Context as _, Result};
use aws_lc_rs::{
    aead::{AES_256_GCM_SIV, Aad, Nonce, RandomizedNonceKey},
    agreement::{EphemeralPrivateKey, UnparsedPublicKey, X25519, agree_ephemeral},
    cipher::AES_256_KEY_LEN,
    digest::SHA512_OUTPUT_LEN,
    error::Unspecified,
    hkdf::{HKDF_SHA256, HKDF_SHA512, Salt},
    rand::{SystemRandom, fill},
};
use clap::Parser as _;
use libmoshpit::{
    Connection, EncryptedFrame, Frame, Kex, KexEvent, KexStateMachine, MoshpitError, UuidWrapper,
    init_tracing, load,
};
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

static CURRENT_UDP_PORT: AtomicU16 = AtomicU16::new(50000);

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

    loop {
        match listener.accept().await {
            Ok((socket, addr)) => {
                error!("Accepted connection from {addr}");
                let mut handler = Handler {
                    connection: Connection::new(socket),
                    rnk: None,
                };

                let config_clone = config.clone();
                let _handle = spawn(async move {
                    match handler.handle_connection(&config_clone).await {
                        Ok((kex, udp_socket)) => {
                            info!("connection can be promoted");
                            let (_tx, rx) = unbounded_channel::<Vec<u8>>();
                            let udp_recv = udp_socket.clone();
                            let udp_send = udp_socket.clone();

                            let mut udp_reader = UdpReader::builder()
                                .socket(udp_recv)
                                .id(kex.uuid())
                                .hmac(kex.hmac_key())
                                .rnk(kex.key())
                                .unwrap()
                                .build();
                            let mut udp_sender = UdpSender::builder()
                                .socket(udp_send)
                                .rx(rx)
                                .id(kex.uuid())
                                .hmac(kex.hmac_key())
                                .rnk(kex.key())
                                .unwrap()
                                .build();

                            let _udp_reader_handle = spawn(async move {
                                while let Ok(frame_opt) = udp_reader.read_encrypted_frame().await {
                                    if let Some(frame) = frame_opt {
                                        match frame {
                                            EncryptedFrame::Bytes((id, _message)) => {
                                                info!("Received UDP packet for id {}", id);
                                            }
                                        }
                                    }
                                }
                            });

                            let _udp_handle = spawn(async move {
                                if let Err(e) = udp_sender.handle_send().await {
                                    error!("udp sender error {e}");
                                }
                            });
                            info!("UDP sender and reader tasks spawned");
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
    async fn handle_connection(&mut self, config: &Config) -> Result<(Kex, Arc<UdpSocket>)> {
        let (tx_event, rx_event) = unbounded_channel::<KexEvent>();
        let mut kex_sm = KexStateMachine::builder().rx_event(rx_event).build();
        let kex_handle = spawn(async move { kex_sm.handle_events(false).await });
        if let Some(frame) = self.connection.read_frame().await? {
            if let Frame::Initialize(pk) = frame {
                self.handle_initialize(pk, tx_event.clone()).await?;
            } else {
                error!("Expected initialize frame");
                return Err(MoshpitError::InvalidFrame.into());
            }
        }

        if let Some(frame) = self.connection.read_frame().await? {
            if let Frame::Check(nonce, enc) = frame {
                self.handle_check(nonce, enc, tx_event).await?;
            } else {
                error!("Expected check frame");
                return Err(MoshpitError::InvalidFrame.into());
            }
        }

        let udp_arc = self.handle_udp_setup(config).await?;

        if let Some(frame) = self.connection.read_frame().await? {
            if let Frame::MoshpitAddr(moshpit_addr) = frame {
                info!("Received address from moshpit: {}", moshpit_addr);
                udp_arc.connect(moshpit_addr).await?;
            } else {
                error!("Expected moshpit address frame");
                return Err(MoshpitError::InvalidFrame.into());
            }
        }

        Ok((kex_handle.await??, udp_arc))
    }

    async fn handle_initialize(
        &mut self,
        pk: Vec<u8>,
        tx_event: UnboundedSender<KexEvent>,
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
                // Derive the HMAC key and send it over UDP
                let okm_hmac =
                    pseudo_random_key.expand(&[b"hmac key"], HKDF_SHA512.hmac_algorithm())?;
                let mut hmac_key_bytes = [0u8; SHA512_OUTPUT_LEN];
                okm_hmac.fill(&mut hmac_key_bytes)?;

                tx_event
                    .send(KexEvent::KeyMaterial(key_bytes))
                    .map_err(|_| Unspecified)?;
                tx_event
                    .send(KexEvent::HMACKeyMaterial(hmac_key_bytes))
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
        tx_event: UnboundedSender<KexEvent>,
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
                tx_event.send(KexEvent::Uuid(id)).map_err(|_| Unspecified)?;
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

    async fn handle_udp_setup(&mut self, config: &Config) -> Result<Arc<UdpSocket>> {
        let next_port = CURRENT_UDP_PORT.fetch_add(1, Ordering::SeqCst);
        let socket_addr = SocketAddr::new(
            config
                .mps()
                .ip()
                .parse()
                .with_context(|| MoshpitError::InvalidIpAddress)?,
            next_port,
        );
        self.connection
            .write_frame(&Frame::MoshpitsAddr(socket_addr))
            .await?;

        let udp_listener = UdpSocket::bind(socket_addr).await?;
        trace!("Bound UDP socket to {}", udp_listener.local_addr()?);
        Ok(Arc::new(udp_listener))
    }
}
