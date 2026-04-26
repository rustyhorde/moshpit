// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

use std::{
    collections::{BTreeSet, VecDeque},
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
    EncryptedFrame, KexMode, MAX_UDP_PAYLOAD, MoshpitError, SessionRegistry, TerminalMessage,
    UdpReader, UdpSender, UuidWrapper, init_tracing, is_exit_title, load, new_session_registry,
    run_key_exchange,
};
use portable_pty::{CommandBuilder, PtySize, native_pty_system};
use tokio::{
    net::{TcpListener, TcpStream},
    select, spawn,
    sync::{
        Mutex,
        mpsc::{Receiver, Sender, channel},
    },
};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, trace};
use uuid::Uuid;

use crate::{
    cli::Cli,
    config::Config,
    session::{
        FullSessionRegistry, SCROLLBACK_CAPACITY, SessionOutputHandle, SessionRecord,
        new_full_registry,
    },
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

    let session_registry = new_session_registry();
    let _ = config.set_session_registry(session_registry);
    let full_registry = new_full_registry();

    let server_token = CancellationToken::new();
    loop {
        let config_c = config.clone();
        let st = server_token.clone();
        let fr_c = full_registry.clone();
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
                            if let Err(e) = handle_connection(config_c, socket, st, fr_c).await {
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
    full_registry: FullSessionRegistry,
) -> Result<()> {
    let (sock_read, sock_write) = socket.into_split();
    let port_pool = config.port_pool();
    let session_registry = config.session_registry();
    let (kex, udp_arc, skex_opt) =
        run_key_exchange(config, sock_read, sock_write, || Ok(None)).await?;
    info!("Key exchange completed with moshpit");

    let skex = skex_opt.ok_or_else(|| anyhow::anyhow!("missing server kex info"))?;
    let session_uuid = skex.session_uuid();
    let is_resume = skex.is_resume();
    let udp_port = udp_arc.local_addr()?.port();

    let (tx, rx) = channel::<EncryptedFrame>(256);
    let (retransmit_tx, retransmit_rx) = channel::<Vec<u64>>(64);
    let udp_recv = udp_arc.clone();
    let udp_send = udp_arc.clone();

    let conn_token = CancellationToken::new();

    // Resolve channels and decide whether to spawn a new PTY.
    let (term_tx, maybe_term_rx, output_handle, scrollback) = if is_resume {
        let reg = full_registry.lock().await;
        if let Some(record) = reg.get(&session_uuid) {
            let term_tx = record.term_tx.clone();
            let output_handle = record.output_handle.clone();
            let scrollback = record.scrollback.clone();
            drop(reg);

            // Replace the output handle with the new connection's channels.
            {
                let mut h = output_handle.lock().await;
                // Shut down the stale reader/sender for the previous connection.
                if let Some(old_token) = h.conn_token.take() {
                    old_token.cancel();
                }
                h.kex_uuid = kex.uuid();
                h.tx = Some(tx.clone());
                h.conn_token = Some(conn_token.clone());
                h.udp_port = Some(udp_port);
            }

            // Replay scrollback so the client terminal catches up.
            let sb_data: Vec<u8> = scrollback.lock().await.iter().copied().collect();
            for chunk in sb_data.chunks(MAX_UDP_PAYLOAD) {
                tx.send(EncryptedFrame::Bytes((kex.uuid_wrapper(), chunk.to_vec())))
                    .await?;
            }
            info!("Resumed session {session_uuid}");

            (
                term_tx,
                None::<Receiver<TerminalMessage>>,
                output_handle,
                scrollback,
            )
        } else {
            // Session expired; start fresh.
            drop(reg);
            info!("Session {session_uuid} not found (expired?); starting new session");
            new_session(
                &kex,
                &conn_token,
                udp_port,
                session_uuid,
                tx.clone(),
                &full_registry,
            )
            .await?
        }
    } else {
        new_session(
            &kex,
            &conn_token,
            udp_port,
            session_uuid,
            tx.clone(),
            &full_registry,
        )
        .await?
    };

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

    let reader_token = conn_token.clone();
    let term_tx_c = term_tx.clone();
    let _udp_reader_handle = spawn(async move {
        if let Err(e) = udp_reader.server_frame_loop(reader_token, term_tx_c).await {
            error!("{e}");
        }
    });

    let sender_token = conn_token.clone();
    let _udp_handle = spawn(async move { udp_sender.frame_loop(sender_token).await });

    // Notify client on server shutdown, then cancel the connection token.
    let watcher_tx = tx.clone();
    let watcher_conn_token = conn_token.clone();
    let _shutdown_watcher = spawn(async move {
        server_token.cancelled().await;
        drop(watcher_tx.send(EncryptedFrame::Shutdown).await);
        tokio::time::sleep(Duration::from_millis(100)).await;
        watcher_conn_token.cancel();
    });

    // For new sessions, spawn the long-lived PTY thread.
    if let Some(term_rx) = maybe_term_rx {
        spawn_pty(
            session_uuid,
            term_rx,
            output_handle,
            scrollback,
            port_pool,
            session_registry,
            full_registry,
        );
    }

    Ok(())
}

/// Create a new session record, register it in both registries, and return the live
/// channels needed to wire up the UDP reader/sender.
async fn new_session(
    kex: &libmoshpit::Kex,
    conn_token: &CancellationToken,
    udp_port: u16,
    session_uuid: Uuid,
    tx: Sender<EncryptedFrame>,
    full_registry: &FullSessionRegistry,
) -> Result<(
    Sender<TerminalMessage>,
    Option<Receiver<TerminalMessage>>,
    Arc<Mutex<SessionOutputHandle>>,
    Arc<Mutex<VecDeque<u8>>>,
)> {
    let (term_tx, term_rx) = channel::<TerminalMessage>(256);
    let output_handle = Arc::new(Mutex::new(SessionOutputHandle {
        kex_uuid: kex.uuid(),
        tx: Some(tx),
        conn_token: Some(conn_token.clone()),
        udp_port: Some(udp_port),
    }));
    let scrollback = Arc::new(Mutex::new(VecDeque::with_capacity(SCROLLBACK_CAPACITY)));

    {
        let mut fr = full_registry.lock().await;
        drop(fr.insert(
            session_uuid,
            SessionRecord {
                term_tx: term_tx.clone(),
                output_handle: output_handle.clone(),
                scrollback: scrollback.clone(),
            },
        ));
    }

    Ok((term_tx, Some(term_rx), output_handle, scrollback))
}

/// Spawn the background thread that reads PTY output, writes scrollback, and forwards
/// frames to the currently connected client.  Cleans up session state when the shell exits.
fn spawn_pty_reader(
    session_uuid: Uuid,
    mut term_out: Box<dyn std::io::Read + Send>,
    output_handle: Arc<Mutex<SessionOutputHandle>>,
    scrollback: Arc<Mutex<VecDeque<u8>>>,
    port_pool: Arc<Mutex<BTreeSet<u16>>>,
    session_registry: SessionRegistry,
    full_registry: FullSessionRegistry,
) {
    let _read_handle = thread::spawn(move || {
        loop {
            let mut buffer = BytesMut::zeroed(4096);
            match term_out.read(&mut buffer) {
                Ok(0) => {
                    trace!("read 0 bytes from terminal, exiting");
                    break;
                }
                Ok(n) => {
                    let buf = &buffer[..n];
                    let utf8_buf = String::from_utf8_lossy(buf);

                    // Fragment into MTU-safe chunks.
                    for chunk in buf.chunks(MAX_UDP_PAYLOAD) {
                        // Write to scrollback ring buffer.
                        {
                            let mut sb = scrollback.blocking_lock();
                            let available = SCROLLBACK_CAPACITY.saturating_sub(sb.len());
                            if chunk.len() > available {
                                for _ in 0..(chunk.len() - available) {
                                    let _ = sb.pop_front();
                                }
                            }
                            sb.extend(chunk.iter().copied());
                        }

                        // Send to the currently connected client (if any).
                        let send_ok = {
                            let h = output_handle.blocking_lock();
                            if let Some(ref sender) = h.tx {
                                let uuid_wrapper = UuidWrapper::new(h.kex_uuid);
                                let sender_clone = sender.clone();
                                drop(h);
                                let frame = EncryptedFrame::Bytes((uuid_wrapper, chunk.to_vec()));
                                sender_clone.blocking_send(frame).is_ok()
                            } else {
                                drop(h);
                                true // headless: just buffer
                            }
                        };
                        if !send_ok {
                            // Client dropped; clear tx but keep the PTY running.
                            output_handle.blocking_lock().tx = None;
                        }
                    }

                    if is_exit_title(&utf8_buf, true) {
                        sleep(Duration::from_millis(500));
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

        // PTY process has exited — clean up the session.
        {
            let mut h = output_handle.blocking_lock();
            if let Some(token) = h.conn_token.take() {
                token.cancel();
            }
            if let Some(port) = h.udp_port.take() {
                let mut pool = port_pool.blocking_lock();
                let _ = pool.insert(port);
            }
            h.tx = None;
        }
        {
            let mut sr = session_registry.blocking_lock();
            drop(sr.remove(&session_uuid));
        }
        {
            let mut fr = full_registry.blocking_lock();
            drop(fr.remove(&session_uuid));
        }
    });
}

/// Spawn the long-lived PTY OS thread for a new session.
///
/// The thread owns the PTY master and keeps running until the shell exits, regardless of
/// how many clients connect and disconnect.
fn spawn_pty(
    session_uuid: Uuid,
    mut term_rx: Receiver<TerminalMessage>,
    output_handle: Arc<Mutex<SessionOutputHandle>>,
    scrollback: Arc<Mutex<VecDeque<u8>>>,
    port_pool: Arc<Mutex<BTreeSet<u16>>>,
    session_registry: SessionRegistry,
    full_registry: FullSessionRegistry,
) {
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

        let term_out = master.try_clone_reader().unwrap();
        let mut term_in = master.take_writer().unwrap();

        spawn_pty_reader(
            session_uuid,
            term_out,
            output_handle,
            scrollback,
            port_pool,
            session_registry,
            full_registry,
        );

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
}
