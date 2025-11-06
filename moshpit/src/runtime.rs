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
    aead::{AES_256_GCM_SIV, Aad, RandomizedNonceKey},
    agreement::{EphemeralPrivateKey, UnparsedPublicKey, X25519, agree_ephemeral},
    error::Unspecified,
    hkdf::{HKDF_SHA256, Salt},
    rand::SystemRandom,
};
use clap::Parser as _;
use libmoshpit::{ConnectionReader, ConnectionWriter, Frame, MoshpitError, init_tracing, load};
use tokio::{
    net::{TcpStream, UdpSocket},
    spawn,
    sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel},
};
use tracing::{error, info, trace};
use uuid::Uuid;

use crate::{cli::Cli, config::Config};

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

    // The `addr` argument is passed directly to `TcpStream::connect`. This
    // performs any asynchronous DNS lookup and attempts to establish the TCP
    // connection. An error at either step returns an error, which is then
    // bubbled up to the caller of `mini_redis` connect.
    let socket_addr = SocketAddr::new(
        config
            .mps()
            .ip()
            .parse()
            .with_context(|| MoshpitError::InvalidIpAddress)?,
        config.mps().port(),
    );
    let socket = TcpStream::connect(socket_addr).await?;
    let (sock_read, sock_write) = socket.into_split();
    let reader = ConnectionReader::builder().reader(sock_read).build();
    let writer = ConnectionWriter::builder().writer(sock_write).build();
    let (tx, rx) = unbounded_channel();
    let (tx_udp_state, mut rx_udp_state) = unbounded_channel::<UdpState>();
    info!("Connected to the server!");

    let rng = SystemRandom::new();
    let pk = EphemeralPrivateKey::generate(&X25519, &rng)?;
    let my_public_key = pk.compute_public_key()?;

    let tx_c = tx.clone();
    let tx_udp_state_c = tx_udp_state.clone();
    let _read_handle = spawn(async move {
        let mut handler = MpsFrameHandler {
            reader,
            tx: tx_c,
            tx_udp: tx_udp_state_c,
        };
        if let Err(e) = handler.handle_connection(pk).await {
            error!("mp handler error {e}");
        }
    });

    let _write_handle = spawn(async move {
        let mut sender = MpsFrameSender { writer, rx };
        if let Err(e) = sender.handle_tx().await {
            error!("mp sender error {e}");
        }
    });
    info!("Sending initialize frame...");
    let frame = Frame::Initialize(my_public_key.as_ref().to_vec());
    tx.send(frame.clone())?;

    while let Some(udp_state) = rx_udp_state.recv().await {
        match udp_state {
            UdpState::Key(_key_bytes) => {
                info!("Received UDP key");
                // Here you would typically set up your UDP socket with the received key
            }
            UdpState::Uuid(uuid) => {
                info!("Received UDP UUID: {}", uuid);
                // Handle UUID as needed
                break;
            }
        }
    }

    let udp_listener = UdpSocket::bind("127.0.0.1:0").await?;
    let remote_addr = "127.0.0.1:40404".parse::<SocketAddr>().unwrap();
    udp_listener.connect(remote_addr).await?;
    let udp_recv = Arc::new(udp_listener);
    let udp_send = udp_recv.clone();
    let (tx, mut rx) = unbounded_channel::<(Vec<u8>, SocketAddr)>();

    let _udp_handle = spawn(async move {
        while let Some((bytes, addr)) = rx.recv().await {
            let len = udp_send.send_to(&bytes, &addr).await.unwrap();
            println!("{len:?} bytes sent");
        }
    });

    tx.send((b"Hello, world!".to_vec(), remote_addr))?;

    let mut buf = [0; 1024];
    loop {
        let (len, addr) = udp_recv.recv_from(&mut buf).await?;
        println!("{len:?} bytes received from {addr:?}");
    }
}

struct MpsFrameHandler {
    reader: ConnectionReader,
    tx: UnboundedSender<Frame>,
    tx_udp: UnboundedSender<UdpState>,
}

impl MpsFrameHandler {
    async fn handle_connection(&mut self, epk: EphemeralPrivateKey) -> Result<()> {
        if let Some(frame) = self.reader.read_frame().await?
            && let Frame::PeerInitialize(pk, salt_bytes) = frame
        {
            info!("Received peer initialize frame");
            let peer_public_key = UnparsedPublicKey::new(&X25519, &pk);
            let salt = Salt::new(HKDF_SHA256, &salt_bytes);

            agree_ephemeral(epk, peer_public_key, Unspecified, |key_material| {
                let pseudo_random_key = salt.extract(key_material);
                let mut check = b"Yoda".to_vec();

                // Derive UnboundKey for AES-256-GCM-SIV
                let okm = pseudo_random_key.expand(&[b"aead key"], &AES_256_GCM_SIV)?;
                let mut key_bytes = [0u8; 32];
                self.tx_udp
                    .send(UdpState::Key(key_bytes))
                    .map_err(|_| Unspecified)?;
                okm.fill(&mut key_bytes)?;
                let rnk = RandomizedNonceKey::new(&AES_256_GCM_SIV, &key_bytes)?;
                let nonce = rnk.seal_in_place_append_tag(Aad::empty(), &mut check)?;

                self.tx
                    .send(Frame::Check(*nonce.as_ref(), check))
                    .map_err(|_| Unspecified)?;
                info!("Sent check frame with encrypted check message");
                Ok(())
            })?;
        }
        if let Some(frame) = self.reader.read_frame().await?
            && let Frame::KeyAgreement(uuid) = frame
        {
            info!("Received key agreement frame with UUID: {}", uuid);
            self.tx_udp
                .send(UdpState::Uuid(*uuid.as_ref()))
                .map_err(|_| Unspecified)?;
        }
        Ok(())
    }
}

struct MpsFrameSender {
    writer: ConnectionWriter,
    rx: UnboundedReceiver<Frame>,
}

impl MpsFrameSender {
    async fn handle_tx(&mut self) -> Result<()> {
        while let Some(frame) = self.rx.recv().await {
            self.writer.write_frame(&frame).await?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
enum UdpState {
    Key([u8; 32]),
    Uuid(Uuid),
}
