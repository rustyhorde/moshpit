// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

use std::{
    collections::BTreeSet,
    ffi::OsString,
    io::{Read as _, Write as _},
    net::SocketAddr,
    sync::Arc,
    thread::{self, sleep},
    time::Duration,
};

use anyhow::{Context as _, Result};
use bytes::{Buf as _, BytesMut};
use clap::Parser as _;
use libmoshpit::{
    EncryptedFrame, KexMode, MoshpitError, TerminalMessage, UdpReader, UdpSender, init_tracing,
    is_exit_title, load, run_key_exchange,
};
use portable_pty::{CommandBuilder, PtySize, native_pty_system};
use tokio::{
    net::{TcpListener, TcpStream},
    select, spawn,
    sync::{Mutex, mpsc::unbounded_channel},
};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, trace};

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
    let mut config =
        load::<Cli, Config, Cli>(&cli, &cli).with_context(|| MoshpitError::ConfigLoad)?;

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
    let _ = config.set_mode(KexMode::Server(socket_addr));
    let listener = TcpListener::bind(socket_addr).await?;

    let mut port_pool = BTreeSet::new();
    for i in 50000..60000 {
        let _ = port_pool.insert(i);
    }
    let port_pool_arc = Arc::new(Mutex::new(port_pool));
    let _ = config.set_port_pool(port_pool_arc);

    let server_token = CancellationToken::new();
    loop {
        let config_c = config.clone();
        let st = server_token.clone();
        select! {
            _ = tokio::signal::ctrl_c() => {
                info!("Received Ctrl-C, shutting down server");
                server_token.cancel();
                // Allow active connections time to send Shutdown frames to clients
                tokio::time::sleep(Duration::from_millis(300)).await;
                break;
            }
            accept_res = listener.accept() => {
                match accept_res {
                    Ok((socket, _addr)) => {
                        let _conn = spawn(async move {
                            if let Err(e) = handle_connection(config_c, socket, st).await {
                                trace!("{e}");
                            }
                        });
                    }
                    Err(e) => error!("{e}"),
                }
            }
        }
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
async fn handle_connection(
    config: Config,
    socket: TcpStream,
    server_token: CancellationToken,
) -> Result<()> {
    let (sock_read, sock_write) = socket.into_split();
    let port_pool = config.port_pool().clone();
    let (kex, udp_arc, _skex_opt) =
        run_key_exchange(config, sock_read, sock_write, || Ok(None)).await?;
    info!("Key exchange completed with moshpit");

    let (tx, rx) = unbounded_channel::<EncryptedFrame>();
    let (retransmit_tx, retransmit_rx) = unbounded_channel::<Vec<u64>>();
    let udp_recv = udp_arc.clone();
    let udp_send = udp_arc.clone();
    let (term_tx, mut term_rx) = unbounded_channel::<TerminalMessage>();
    let mut udp_reader = UdpReader::builder()
        .socket(udp_recv)
        .id(kex.uuid())
        .hmac(kex.hmac_key())
        .rnk(kex.key())?
        .nak_out_tx(tx.clone())
        .retransmit_tx(retransmit_tx)
        .build();
    let mut udp_sender = UdpSender::builder()
        .socket(udp_send)
        .rx(rx)
        .retransmit_rx(retransmit_rx)
        .id(kex.uuid())
        .hmac(kex.hmac_key())
        .rnk(kex.key())?
        .build();

    let token = CancellationToken::new();
    let reader_token = token.clone();
    let term_tx_c = term_tx.clone();
    let _udp_reader_handle = spawn(async move {
        if let Err(e) = udp_reader.server_frame_loop(reader_token, term_tx_c).await {
            error!("{e}");
        }
    });

    let sender_token = token.clone();
    let _udp_handle = spawn(async move { udp_sender.frame_loop(sender_token).await });

    let (tx_pool, mut rx_pool) = unbounded_channel();
    let _port_handler = spawn(async move {
        if let Some(port) = rx_pool.recv().await {
            let mut pool = port_pool.lock().await;
            let _ = pool.insert(port);
        }
    });

    // When the server shuts down, notify the connected client then cancel the local token
    let watcher_tx = tx.clone();
    let watcher_conn_token = token.clone();
    let _shutdown_watcher = spawn(async move {
        server_token.cancelled().await;
        drop(watcher_tx.send(EncryptedFrame::Shutdown));
        tokio::time::sleep(Duration::from_millis(100)).await;
        watcher_conn_token.cancel();
    });

    let _term_handle = thread::spawn(move || {
        #[cfg(unix)]
        let cmd = {
            let mut c = CommandBuilder::new("/usr/bin/fish");
            c.arg("-li");
            c
        };
        #[cfg(windows)]
        let cmd = CommandBuilder::new("cmd.exe");

        let pty_system = native_pty_system();
        let pair = pty_system
            .openpty(PtySize {
                rows: 24,
                cols: 80,
                pixel_width: 0,
                pixel_height: 0,
            })
            .unwrap();
        let _child = pair.slave.spawn_command(cmd).unwrap();
        let master = pair.master;

        let mut term_out = master.try_clone_reader().unwrap();
        let mut term_in = master.take_writer().unwrap();

        let _read_handle = thread::spawn(move || {
            loop {
                let mut buffer = BytesMut::zeroed(4096);
                match term_out.read(&mut buffer) {
                    Ok(0) => {
                        trace!("read 0 bytes from terminal, exiting");
                        break;
                    }
                    Ok(n) => {
                        let buf = buffer[..n].to_vec();
                        let utf8_buf = String::from_utf8_lossy(&buf);
                        let frame = EncryptedFrame::Bytes((kex.uuid_wrapper(), buf.clone()));
                        if let Err(e) = tx.send(frame) {
                            error!("error sending udp packet: {e}");
                            break;
                        }
                        if is_exit_title(&utf8_buf, true) {
                            sleep(Duration::from_millis(500));
                            token.cancel();
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
            if let Ok(local_addr) = udp_arc.local_addr() {
                let _ = tx_pool.send(local_addr.port());
            }
        });

        while let Some(terminal_message) = term_rx.blocking_recv() {
            match terminal_message {
                TerminalMessage::Resize { columns, rows } => {
                    if let Err(e) = master.resize(PtySize {
                        rows,
                        cols: columns,
                        pixel_width: 0,
                        pixel_height: 0,
                    }) {
                        error!("error resizing terminal: {e}");
                    }
                }
                TerminalMessage::Input(data) => {
                    if let Err(e) = term_in.write_all(&data) {
                        error!("error writing to terminal: {e}");
                        break;
                    }
                }
            }
        }
    });
    Ok(())
}
