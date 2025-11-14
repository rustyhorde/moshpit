// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

use std::{
    ffi::OsString,
    io::{Read as _, Write as _},
    net::SocketAddr,
    process::Command,
    thread,
};

use anyhow::{Context as _, Result};
use bytes::{Buf as _, BytesMut};
use clap::Parser as _;
use libmoshpit::{
    EncryptedFrame, KexMode, MoshpitError, UdpReader, UdpSender, init_tracing, load,
    run_key_exchange,
};
use pseudoterminal::CommandExt as _;
use tokio::{net::TcpListener, spawn, sync::mpsc::unbounded_channel};
use tracing::{error, info, trace};

use crate::{cli::Cli, config::Config};

#[allow(clippy::too_many_lines)]
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
            Ok((socket, _addr)) => {
                let (sock_read, sock_write) = socket.into_split();
                let (kex, udp_arc) =
                    run_key_exchange(KexMode::Server(socket_addr), sock_read, sock_write).await?;
                info!("Key exchange completed with moshpit");
                let (tx, rx) = unbounded_channel::<Vec<u8>>();
                let udp_recv = udp_arc.clone();
                let udp_send = udp_arc.clone();
                let (term_tx, mut term_rx) = unbounded_channel::<Vec<u8>>();
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
                                EncryptedFrame::Bytes((id, message)) => {
                                    trace!("Received UDP packet for id {}", id);
                                    term_tx.send(message).unwrap();
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

                let _term_handle = thread::spawn(move || {
                    info!("Starting terminal handler");
                    let mut cmd = Command::new("/usr/bin/fish");
                    let _ = cmd.arg("-li");
                    let mut terminal = cmd.spawn_terminal().unwrap();
                    if let Some((mut term_in, mut term_out)) = terminal.split() {
                        let _in_handle = thread::spawn(move || {
                            info!("Starting terminal input handler");
                            while let Some(packet) = term_rx.blocking_recv() {
                                trace!("Writing packet to terminal");
                                if let Err(e) = term_in.write_all(&packet) {
                                    error!("error writing to terminal: {e}");
                                    break;
                                }
                            }
                            info!("Terminal input handler exiting");
                        });

                        loop {
                            let mut buffer = BytesMut::zeroed(4096);
                            match term_out.read(&mut buffer) {
                                Ok(0) => {
                                    trace!("read 0 bytes from terminal, exiting");
                                    break;
                                }
                                Ok(n) => {
                                    trace!("Read {n} bytes from terminal");
                                    if let Err(e) = tx.send(buffer[..n].to_vec()) {
                                        error!("error sending udp packet: {e}");
                                        break;
                                    }
                                    buffer.advance(n);
                                }
                                Err(e) => {
                                    error!("error reading from terminal: {e}");
                                    break;
                                }
                            }
                        }
                        info!("Terminal output handler exiting");
                    }
                });
            }
            Err(e) => error!("couldn't get client: {e:?}"),
        }
    }
}
