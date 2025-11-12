// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

use std::{ffi::OsString, net::SocketAddr};

use anyhow::{Context as _, Result};
use clap::Parser as _;
use libmoshpit::{
    EncryptedFrame, KexMode, MoshpitError, UdpReader, UdpSender, init_tracing, load,
    run_key_exchange,
};
use tokio::{net::TcpListener, spawn, sync::mpsc::unbounded_channel};
use tracing::{error, info, trace};

use crate::{cli::Cli, config::Config};

// static CURRENT_UDP_PORT: AtomicU16 = AtomicU16::new(50000);

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
                let (sock_read, sock_write) = socket.into_split();
                let (kex, udp_arc) =
                    run_key_exchange(KexMode::Server(socket_addr), sock_read, sock_write).await?;
                info!("Key exchange completed with client at {addr}");
                info!("connection can be promoted");
                let (_tx, rx) = unbounded_channel::<Vec<u8>>();
                let udp_recv = udp_arc.clone();
                let udp_send = udp_arc.clone();

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
            Err(e) => error!("couldn't get client: {e:?}"),
        }
    }
}
