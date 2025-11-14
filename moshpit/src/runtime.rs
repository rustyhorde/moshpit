// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

use std::{
    ffi::OsString,
    io::{Read as _, Write as _, stdin, stdout},
    net::SocketAddr,
    thread,
};

use anyhow::{Context as _, Result};
use bytes::{Buf as _, BytesMut};
use clap::Parser as _;
use libmoshpit::{
    EncryptedFrame, KexMode, MoshpitError, UdpReader, UdpSender, init_tracing, load,
    run_key_exchange,
};
use termion::raw::IntoRawMode as _;
use tokio::{net::TcpStream, spawn, sync::mpsc::unbounded_channel};
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

    // Setup the TCP connection to the server for key exchange
    let socket_addr = config
        .server_ip()
        .parse::<SocketAddr>()
        .with_context(|| MoshpitError::InvalidServerAddress)?;
    let socket = TcpStream::connect(socket_addr).await?;
    let (sock_read, sock_write) = socket.into_split();

    // Run the key exchange
    let (kex, udp_arc) = run_key_exchange(KexMode::Client, sock_read, sock_write).await?;
    info!("Key exchange completed with moshpits");

    let udp_recv = udp_arc.clone();
    let udp_send = udp_arc.clone();
    let (tx, rx) = unbounded_channel::<Vec<u8>>();
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
        .rnk(kex.key())?
        .build();

    let _udp_handle = spawn(async move {
        if let Err(e) = udp_sender.handle_send().await {
            error!("udp sender error {e}");
        }
    });

    let (stdout_tx, mut stdout_rx) = unbounded_channel::<Vec<u8>>();

    let stdout_tx_c = stdout_tx.clone();
    let _udp_reader_handle = spawn(async move {
        let mut prev_bytes = BytesMut::with_capacity(1024);
        while let Ok(frame_opt) = udp_reader.read_encrypted_frame().await {
            if let Some(frame) = frame_opt {
                match frame {
                    EncryptedFrame::Bytes((_id, message)) => {
                        let message = if prev_bytes.is_empty() {
                            message
                        } else {
                            let mut combined =
                                BytesMut::with_capacity(prev_bytes.len() + message.len());
                            combined.extend_from_slice(&prev_bytes);
                            combined.extend_from_slice(&message);
                            prev_bytes.clear();
                            combined.freeze().to_vec()
                        };
                        prev_bytes.clear();
                        let mut valid_utf8 = String::new();
                        for chunk in message.utf8_chunks() {
                            valid_utf8.push_str(chunk.valid());

                            if !chunk.invalid().is_empty() {
                                info!("Received invalid UTF-8 chunk");
                                prev_bytes.extend_from_slice(chunk.invalid());
                            }
                        }
                        let _unused = stdout_tx_c.send(valid_utf8.into_bytes());
                    }
                }
            } else {
                trace!("UDP reader received None frame, exiting");
            }
        }
        info!("UDP reader exiting");
    });

    let stdout_handle = thread::spawn(move || {
        let stdout = stdout();
        let mut stdout = stdout.lock().into_raw_mode().unwrap();

        while let Some(msg) = stdout_rx.blocking_recv() {
            if msg.len() == 1 && msg[0] == b'q' {
                info!("Exiting stdout thread on 'q' input");
                break;
            }
            if let Err(e) = stdout.write_all(&msg) {
                error!("Error writing to stdout: {e}");
            }
            if let Err(e) = stdout.flush() {
                error!("Error flushing stdout: {e}");
            }
        }
    });

    let mut stdin = stdin();
    let mut total_bytes = 0;

    loop {
        let mut buf = BytesMut::zeroed(8192);

        let len = stdin.read(&mut buf)?;
        if len > 0 {
            total_bytes += len;
            trace!("Read {len} bytes from stdin, total bytes: {total_bytes}");
            if len == 1 && buf[0] == b'q' {
                info!("Exiting on 'q' input");
                stdout_tx.send(b"q".to_vec()).unwrap();
                break;
            }
            let msg = &buf[..len];
            tx.send(msg.to_vec()).unwrap();
            buf.advance(len);
        }
    }

    stdout_handle.join().unwrap();
    Ok(())
}
