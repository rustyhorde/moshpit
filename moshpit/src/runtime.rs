// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

use std::{ffi::OsString, io::stdin, net::SocketAddr, sync::Arc};

use anyhow::{Context as _, Result};
use aws_lc_rs::{
    agreement::{EphemeralPrivateKey, X25519},
    rand::SystemRandom,
};
use clap::Parser as _;
use libmoshpit::{
    ConnectionReader, ConnectionWriter, Frame, MoshpitError, UdpState, init_tracing, load,
};
use tokio::{
    net::{TcpStream, UdpSocket},
    spawn,
    sync::mpsc::unbounded_channel,
};
use tracing::{error, info, trace};
use uuid::Uuid;

use crate::{
    cli::Cli,
    config::Config,
    tcp::{reader::FrameReader, sender::FrameSender},
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

    // Setup the TCP connection to the server for key exchange
    let socket_addr = config
        .server_ip()
        .parse::<SocketAddr>()
        .with_context(|| MoshpitError::InvalidServerAddress)?;

    let (key_bytes, uuid) = run_key_exchange(&socket_addr).await?;

    let udp_listener = UdpSocket::bind("127.0.0.1:0").await?;
    udp_listener.connect(socket_addr).await?;
    let udp_recv = Arc::new(udp_listener);
    let udp_send = udp_recv.clone();
    let (tx, rx) = unbounded_channel::<Vec<u8>>();
    let mut udp_reader = UdpReader::builder().socket(udp_recv).build();
    let mut udp_sender = UdpSender::builder()
        .socket(udp_send)
        .rx(rx)
        .id(uuid)
        .rnk(key_bytes)?
        .build();

    let _udp_handle = spawn(async move {
        if let Err(e) = udp_sender.handle_send().await {
            error!("udp sender error {e}");
        }
    });

    let _udp_reader_handle = spawn(async move {
        if let Err(e) = udp_reader.handle_read().await {
            error!("udp reader error {e}");
        }
    });

    tx.send(b"Hello, world!".to_vec())?;

    loop {
        let mut input = String::new();
        match stdin().read_line(&mut input) {
            Ok(_n) => {
                tx.send(input.into_bytes())?;
            }
            Err(error) => {
                println!("error: {error}");
                break;
            }
        }
    }

    Ok(())
}

async fn run_key_exchange(socket_addr: &SocketAddr) -> Result<([u8; 32], Uuid)> {
    // Setup the TCP connection to the server for key exchange
    let socket = TcpStream::connect(socket_addr).await?;
    let (sock_read, sock_write) = socket.into_split();
    let reader = ConnectionReader::builder().reader(sock_read).build();
    let writer = ConnectionWriter::builder().writer(sock_write).build();
    let (tx, rx) = unbounded_channel();
    let (tx_udp_state, mut rx_udp_state) = unbounded_channel::<UdpState>();
    info!("Connected to the server!");

    // Generate ephemeral X25519 key pair
    let rng = SystemRandom::new();
    let pk = EphemeralPrivateKey::generate(&X25519, &rng)?;
    let my_public_key = pk.compute_public_key()?;
    trace!("Generated ephemeral X25519 key pair");

    // Setup the TCP frame reader
    let tx_c = tx.clone();
    let tx_udp_state_c = tx_udp_state.clone();
    let _read_handle = spawn(async move {
        let mut frame_reader = FrameReader::builder()
            .reader(reader)
            .tx(tx_c)
            .tx_udp(tx_udp_state_c)
            .build();
        if let Err(e) = frame_reader.handle_connection(pk).await {
            error!("mps frame reader: {e}");
        }
    });
    trace!("Spawned TCP frame reader task");

    // Setup the TCP frame sender
    let _write_handle = spawn(async move {
        let mut sender = FrameSender::builder().writer(writer).rx(rx).build();
        if let Err(e) = sender.handle_tx().await {
            error!("mp sender error {e}");
        }
    });
    trace!("Spawned TCP frame sender task");

    // Send the initialize frame with our public key
    trace!("Sending initialize frame...");
    let frame = Frame::Initialize(my_public_key.as_ref().to_vec());
    tx.send(frame.clone())?;

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
