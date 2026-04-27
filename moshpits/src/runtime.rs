// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

use std::{
    collections::{BTreeSet, HashMap, VecDeque},
    ffi::OsString,
    io::{IsTerminal as _, Read as _, Write as _},
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

/// Info about a currently-connected moshpit client.
struct ClientInfo {
    peer_addr: SocketAddr,
    user: String,
    session_uuid: Uuid,
}

/// Shared mutable state for the server status banner.
#[derive(Clone)]
struct BannerState {
    inner: Arc<Mutex<BannerInner>>,
    /// `false` when stderr is not a TTY; banner operations become no-ops.
    enabled: bool,
}

struct BannerInner {
    clients: HashMap<Uuid, ClientInfo>,
    /// Number of banner lines written on the last render, used to clear stale lines.
    prev_lines: usize,
}

impl BannerState {
    fn new(enabled: bool) -> Self {
        Self {
            inner: Arc::new(Mutex::new(BannerInner {
                clients: HashMap::new(),
                prev_lines: 0,
            })),
            enabled,
        }
    }

    async fn insert(&self, kex_uuid: Uuid, info: ClientInfo) {
        let mut inner = self.inner.lock().await;
        drop(inner.clients.insert(kex_uuid, info));
        if self.enabled {
            Self::render_and_write(&mut inner);
        }
    }

    /// Remove the entry for this connection.  Each connection has a unique kex UUID as
    /// its key, so there is no risk of evicting a different connection's entry.
    async fn remove(&self, kex_uuid: Uuid) {
        let mut inner = self.inner.lock().await;
        if inner.clients.remove(&kex_uuid).is_some() && self.enabled {
            Self::render_and_write(&mut inner);
        }
    }

    /// Redraw the banner without changing the client list.
    ///
    /// Called periodically to repair any damage caused by log output that
    /// momentarily overwrote the banner rows.
    async fn refresh(&self) {
        if !self.enabled {
            return;
        }
        let mut inner = self.inner.lock().await;
        if !inner.clients.is_empty() {
            Self::render_and_write(&mut inner);
        }
    }

    fn render_and_write(inner: &mut BannerInner) {
        let clients: Vec<&ClientInfo> = inner.clients.values().collect();
        let bytes = render_banner(&clients, inner.prev_lines);
        inner.prev_lines = if clients.is_empty() {
            0
        } else {
            clients.len() + 1
        };
        drop(std::io::stderr().write_all(&bytes));
        drop(std::io::stderr().flush());
    }
}

/// Render the server status banner as a byte sequence of raw ANSI escape codes.
///
/// The banner is anchored to the **top** of the terminal, occupying rows 1 through
/// `banner_lines` (header + one row per client).  Normal log output scrolls below
/// and may temporarily overwrite the banner; the 5-second periodic refresh task in
/// [`run`] repaints it.
///
/// Layout (2 clients):
/// ```text
/// row 1 : [moshpits] 2 client(s) connected
/// row 2 : client 1 info
/// row 3 : client 2 info
/// row 4+: scrolling tracing output
/// ```
fn render_banner(clients: &[&ClientInfo], prev_lines: usize) -> Vec<u8> {
    let mut out = Vec::<u8>::new();
    out.extend_from_slice(b"\x1b[s"); // save cursor

    if clients.is_empty() {
        // Erase every line that was part of the previous banner.
        for row in 1..=prev_lines {
            out.extend_from_slice(format!("\x1b[{row};1H\x1b[0m\x1b[K").as_bytes());
        }
        out.extend_from_slice(b"\x1b[u"); // restore cursor
    } else {
        let n = clients.len();
        let banner_lines = n + 1; // header + one row per client

        // Header row (row 1).
        out.extend_from_slice(
            format!("\x1b[1;1H\x1b[44;97;1m [moshpits] {n} client(s) connected \x1b[K\x1b[0m")
                .as_bytes(),
        );
        // One row per client.
        for (i, c) in clients.iter().enumerate() {
            let row = 2 + i;
            let peer = c.peer_addr;
            let user = &c.user;
            let sid = c.session_uuid;
            out.extend_from_slice(
                format!("\x1b[{row};1H\x1b[44;97;1m  {peer:<25}  {user:<15}  {sid} \x1b[K\x1b[0m")
                    .as_bytes(),
            );
        }

        // When the banner shrank (fewer clients than last render), clear the rows
        // that are no longer part of the banner.
        for row in (banner_lines + 1)..=prev_lines {
            out.extend_from_slice(format!("\x1b[{row};1H\x1b[0m\x1b[K").as_bytes());
        }

        out.extend_from_slice(b"\x1b[u"); // restore cursor
    }

    out
}

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
    let banner = BannerState::new(std::io::stderr().is_terminal());

    let server_token = CancellationToken::new();

    // Periodically redraw the banner to repair any transient overwrite from log output.
    let banner_refresh = banner.clone();
    let refresh_token = server_token.clone();
    let _banner_refresh = spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(5));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            select! {
                () = refresh_token.cancelled() => break,
                _ = ticker.tick() => banner_refresh.refresh().await,
            }
        }
    });

    loop {
        let config_c = config.clone();
        let st = server_token.clone();
        let fr_c = full_registry.clone();
        let banner_c = banner.clone();
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
                            if let Err(e) = handle_connection(config_c, socket, st, fr_c, banner_c).await {
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

/// Resolve which session to use for this connection.
///
/// On resume, reconnects to the existing session and replays scrollback.
/// On new or expired sessions, creates a fresh session via [`new_session`].
async fn resolve_session(
    kex: &libmoshpit::Kex,
    skex: &libmoshpit::ServerKex,
    conn_token: &CancellationToken,
    udp_port: u16,
    tx: Sender<EncryptedFrame>,
    full_registry: &FullSessionRegistry,
) -> Result<(
    Sender<TerminalMessage>,
    Option<Receiver<TerminalMessage>>,
    Arc<Mutex<SessionOutputHandle>>,
    Arc<Mutex<VecDeque<u8>>>,
)> {
    let session_uuid = skex.session_uuid();
    if skex.is_resume() {
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
            let scrollback_bytes = sb_data.len();
            for chunk in sb_data.chunks(MAX_UDP_PAYLOAD) {
                tx.send(EncryptedFrame::Bytes((kex.uuid_wrapper(), chunk.to_vec())))
                    .await?;
            }
            info!(
                user = skex.user(),
                session = %session_uuid,
                scrollback_bytes,
                "session resumed"
            );

            Ok((
                term_tx,
                None::<Receiver<TerminalMessage>>,
                output_handle,
                scrollback,
            ))
        } else {
            // Session expired; start fresh.
            drop(reg);
            info!(
                user = skex.user(),
                session = %session_uuid,
                "previous session expired, starting new session"
            );
            new_session(kex, conn_token, udp_port, session_uuid, tx, full_registry).await
        }
    } else {
        let result =
            new_session(kex, conn_token, udp_port, session_uuid, tx, full_registry).await?;
        info!(
            user = skex.user(),
            session = %session_uuid,
            "new session started"
        );
        Ok(result)
    }
}

async fn handle_connection(
    config: Config,
    socket: TcpStream,
    server_token: CancellationToken,
    full_registry: FullSessionRegistry,
    banner: BannerState,
) -> Result<()> {
    let peer_addr = socket.peer_addr()?;
    let (sock_read, sock_write) = socket.into_split();
    let port_pool = config.port_pool();
    let session_registry = config.session_registry();
    let (kex, udp_arc, skex_opt) =
        run_key_exchange(config, sock_read, sock_write, || Ok(None)).await?;
    info!("Key exchange completed with moshpit");

    let skex = skex_opt.ok_or_else(|| anyhow::anyhow!("missing server kex info"))?;
    let session_uuid = skex.session_uuid();

    let udp_port = udp_arc.local_addr()?.port();

    let (tx, rx) = channel::<EncryptedFrame>(256);
    let (retransmit_tx, retransmit_rx) = channel::<Vec<u64>>(512);
    let udp_recv = udp_arc.clone();
    let udp_send = udp_arc.clone();

    let conn_token = CancellationToken::new();

    // Resolve channels and decide whether to spawn a new PTY.
    let (term_tx, maybe_term_rx, output_handle, scrollback) = resolve_session(
        &kex,
        &skex,
        &conn_token,
        udp_port,
        tx.clone(),
        &full_registry,
    )
    .await?;

    // Register this connection in the banner; schedule removal when the connection drops.
    banner
        .insert(
            kex.uuid(),
            ClientInfo {
                peer_addr,
                user: skex.user().to_owned(),
                session_uuid,
            },
        )
        .await;
    let banner_dc = banner.clone();
    let dc_kex_uuid = kex.uuid();
    let dc_conn_token = conn_token.clone();
    let _banner_watcher = spawn(async move {
        dc_conn_token.cancelled().await;
        banner_dc.remove(dc_kex_uuid).await;
    });

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

    spawn_connection_watchdogs(tx.clone(), conn_token.clone(), server_token);

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

/// Spawn the shutdown-watcher and keepalive tasks for one client connection.
///
/// - Shutdown watcher: on server cancellation, sends `Shutdown` to the client and
///   cancels the per-connection token after a short drain delay.
/// - Keepalive: sends `Keepalive` every 10 s so the client's 15 s silence timeout
///   never fires during idle sessions.
fn spawn_connection_watchdogs(
    tx: Sender<EncryptedFrame>,
    conn_token: CancellationToken,
    server_token: CancellationToken,
) {
    let watcher_tx = tx.clone();
    let watcher_conn_token = conn_token.clone();
    let _shutdown_watcher = spawn(async move {
        server_token.cancelled().await;
        drop(watcher_tx.send(EncryptedFrame::Shutdown).await);
        tokio::time::sleep(Duration::from_millis(100)).await;
        watcher_conn_token.cancel();
    });

    let _keepalive = spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(10));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            select! {
                () = conn_token.cancelled() => break,
                _ = ticker.tick() => {
                    if tx.send(EncryptedFrame::Keepalive).await.is_err() {
                        break;
                    }
                }
            }
        }
    });
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
        info!(session = %session_uuid, "session ended, client exited cleanly");
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
