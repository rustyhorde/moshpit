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
    io::Read as _,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread::{self, sleep},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[cfg(unix)]
use std::{
    ffi::{CStr, CString},
    os::unix::{fs::OpenOptionsExt as _, process::CommandExt},
    process::Stdio,
};

use anyhow::{Context as _, Result};
use bytes::{Buf as _, BytesMut};
use clap::Parser as _;
use libmoshpit::{
    EncryptedFrame, KexMode, MAX_UDP_PAYLOAD, MoshpitError, SessionRegistry, TerminalMessage,
    UdpReader, UdpSender, UuidWrapper, init_tracing, is_exit_title, load, new_session_registry,
    run_key_exchange,
};
#[cfg(windows)]
use portable_pty::CommandBuilder;
use portable_pty::{PtySize, native_pty_system};

use tokio::{
    net::{TcpListener, TcpStream},
    select, spawn,
    sync::{
        Mutex,
        mpsc::{Receiver, Sender, channel},
        oneshot,
    },
};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, trace};
use uuid::Uuid;
use zstd::encode_all;

use crate::{
    cli::Cli,
    config::Config,
    session::{
        FullSessionRegistry, SCROLLBACK_CAPACITY, SessionOutputHandle, SessionRecord,
        new_full_registry,
    },
};

/// Default minimum inter-packet delay between consecutive diff chunks sent to the client.
const DEFAULT_PACING_DELAY_US: u64 = 1000;
/// Number of client NAK frames received within the 200 ms poll window that triggers a
/// proactive `ScreenStateCompressed` push without waiting for a `RepaintRequest`.
/// At the adaptive NAK check interval floor of 5 ms, 10 NAKs ≈ one per 20 ms, which
/// reliably signals a high-loss condition where the `RepaintRequest` itself may be lost.
const PROACTIVE_REPAINT_NAK_THRESHOLD: u64 = 10;

/// Normal screen-sync interval when the terminal is idle.
const SCREEN_SYNC_IDLE_INTERVAL: Duration = Duration::from_millis(50);
/// Reduced screen-sync interval during rapid terminal output bursts (Option H).
const SCREEN_SYNC_BURST_INTERVAL: Duration = Duration::from_millis(10);
/// Dirty-counter delta threshold above which a tick is classified as a burst.
const SCREEN_SYNC_BURST_DIRTY_THRESHOLD: u64 = 5;

#[allow(unsafe_code)]
#[cfg_attr(coverage_nightly, coverage(off))]
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

    #[cfg(unix)]
    if unsafe { libc::getuid() } == 0 {
        info!("Running as root (multi-user mode enabled)");
    }

    // Load the configuration
    let mut config =
        load::<Cli, Config, Cli>(&cli, &cli).with_context(|| MoshpitError::ConfigLoad)?;

    // Initialize tracing
    let mut file_tracing = config.tracing().file().clone();
    let _ = file_tracing.set_verbose(cli.verbose());
    let _ = file_tracing.set_quiet(cli.quiet());

    init_tracing(&config, &file_tracing, &cli, None).with_context(|| MoshpitError::TracingInit)?;

    info!("Configuration loaded");
    info!("Tracing initialized");

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
                        // Use the TCP connection's actual local address (the interface the
                        // client connected to) so that the UDP advertisement in
                        // handle_udp_setup sends an IP the client can actually reach,
                        // rather than the bind address (0.0.0.0) or whatever local_ip()
                        // happens to return.
                        let tcp_local_addr = match socket.local_addr() {
                            Ok(a) => a,
                            Err(e) => { error!("local_addr: {e}"); continue; }
                        };
                        let mut config_conn = config_c;
                        let _ = config_conn.set_mode(KexMode::Server(tcp_local_addr));
                        let _conn = spawn(async move {
                            if let Err(e) = handle_connection(config_conn, socket, st, fr_c).await {
                                error!("{e}");
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
/// On resume, reconnects to the existing session and sends a `ScreenState` frame
/// for an instant clean repaint.  On new or expired sessions, creates a fresh
/// session via [`new_session`].
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
    Arc<Mutex<vt100::Parser>>,
    Arc<AtomicU64>,
    Arc<AtomicBool>,
)> {
    let session_uuid = skex.session_uuid();
    if skex.is_resume() {
        let reg = full_registry.lock().await;
        if let Some(record) = reg.get(&session_uuid) {
            let term_tx = record.term_tx.clone();
            let output_handle = record.output_handle.clone();
            let scrollback = record.scrollback.clone();
            let server_emulator = record.server_emulator.clone();
            let dirty_counter = record.dirty_counter.clone();
            let diff_in_flight = record.diff_in_flight.clone();
            drop(reg);
            // Give the new connection's screen-sync task a clean slate so the
            // first tick correctly senses whether diffs are flowing.
            diff_in_flight.store(false, Ordering::Relaxed);

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

            // Send current screen state for an instant clean repaint on reconnect.
            let screen_state = {
                let emu = server_emulator.lock().await;
                emu.screen().contents_formatted()
            };
            let screen_state_bytes = screen_state.len();
            let compressed =
                encode_all(screen_state.as_slice(), 3).unwrap_or_else(|_| screen_state.clone());
            tx.send(EncryptedFrame::ScreenStateCompressed(compressed))
                .await?;
            info!(
                user = skex.user(),
                session = %session_uuid,
                screen_state_bytes,
                "session resumed"
            );

            Ok((
                term_tx,
                None::<Receiver<TerminalMessage>>,
                output_handle,
                scrollback,
                server_emulator,
                dirty_counter,
                diff_in_flight,
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

#[cfg_attr(nightly, allow(clippy::too_many_lines))]
#[cfg_attr(coverage_nightly, coverage(off))]
async fn handle_connection(
    config: Config,
    socket: TcpStream,
    server_token: CancellationToken,
    full_registry: FullSessionRegistry,
) -> Result<()> {
    let (sock_read, sock_write) = socket.into_split();
    let port_pool = config.port_pool();
    let session_registry = config.session_registry();
    let warmup_delay = config.warmup_delay_ms().map(Duration::from_millis);
    let pacing_delay =
        Duration::from_micros(config.pacing_delay_us().unwrap_or(DEFAULT_PACING_DELAY_US));
    let term_type = config.term_type().clone();
    let (kex, udp_arc, skex_opt) =
        run_key_exchange(config, sock_read, sock_write, || Ok(None), None, None).await?;
    info!("Key exchange completed with moshpit");

    let skex = skex_opt.ok_or_else(|| anyhow::anyhow!("missing server kex info"))?;
    let session_uuid = skex.session_uuid();

    let udp_port = udp_arc.local_addr()?.port();

    let (tx, rx) = channel::<EncryptedFrame>(256);
    let (retransmit_tx, retransmit_rx) = channel::<Vec<u64>>(512);
    let udp_recv = udp_arc.clone();
    let udp_send = udp_arc.clone();

    let conn_token = CancellationToken::new();

    // Oneshot channel that lets UdpSender wait until UdpReader has discovered
    // the client's real post-NAT address and connected the shared UDP socket.
    let (peer_discovered_tx, peer_discovered_rx) = oneshot::channel::<()>();

    // Resolve channels and decide whether to spawn a new PTY.
    let (
        term_tx,
        maybe_term_rx,
        output_handle,
        scrollback,
        server_emulator,
        dirty_counter,
        diff_in_flight,
    ) = resolve_session(
        &kex,
        &skex,
        &conn_token,
        udp_port,
        tx.clone(),
        &full_registry,
    )
    .await?;

    let (repaint_tx, mut repaint_rx) = channel::<()>(1);
    let nak_received_count = Arc::new(AtomicU64::new(0));
    let mut udp_reader = UdpReader::builder()
        .socket(udp_recv)
        .id(kex.uuid())
        .hmac(kex.hmac_key())
        .rnk(kex.key())?
        .nak_out_tx(tx.clone())
        .retransmit_tx(retransmit_tx)
        .peer_discovered_tx(peer_discovered_tx)
        .repaint_tx(repaint_tx)
        .nak_received_count(nak_received_count.clone())
        .build();
    let mut udp_sender = UdpSender::builder()
        .socket(udp_send)
        .rx(rx)
        .retransmit_rx(retransmit_rx)
        .id(kex.uuid())
        .hmac(kex.hmac_key())
        .rnk(kex.key())?
        .peer_discovered_rx(peer_discovered_rx)
        .maybe_warmup_delay(warmup_delay)
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

    // Periodic screen-state sync: normally every 50 ms, but drops to 10 ms during rapid
    // bursts (Option H — adaptive tick rate).  The dirty_counter is incremented by
    // spawn_pty_reader on every PTY output chunk and by spawn_pty on every Resize event,
    // so the load is a pure atomic read — essentially free — when the terminal is idle.
    //
    // When the counter advances by SCREEN_SYNC_BURST_DIRTY_THRESHOLD or more in a single tick
    // period, the screen is changing quickly: switch to SCREEN_SYNC_BURST_INTERVAL so the
    // client receives a fresh full-screen snapshot faster than the normal 50 ms cadence.
    // Return to SCREEN_SYNC_IDLE_INTERVAL once the delta drops below the threshold.
    //
    // Option C: when diff chunks are actively flowing to the client, skip the snapshot
    // entirely to avoid competing with the diff stream on the same UDP path.  The
    // diff_in_flight flag is set by spawn_pty_reader on each chunk send and cleared here
    // each tick.  Explicit client repaint requests are handled by _repaint_on_request.
    let sync_emu = server_emulator.clone();
    let sync_tx = tx.clone();
    let sync_token = conn_token.clone();
    let sync_dirty = dirty_counter.clone();
    let sync_diff = diff_in_flight.clone();
    let _screen_sync = spawn(async move {
        let mut last_dirty: u64 = 0;
        let mut interval = SCREEN_SYNC_IDLE_INTERVAL;
        loop {
            select! {
                () = sync_token.cancelled() => break,
                () = tokio::time::sleep(interval) => {
                    let current = sync_dirty.load(Ordering::Relaxed);
                    let delta = current.wrapping_sub(last_dirty);
                    // Adapt tick rate based on how active the screen has been.
                    interval = if delta >= SCREEN_SYNC_BURST_DIRTY_THRESHOLD {
                        SCREEN_SYNC_BURST_INTERVAL
                    } else {
                        SCREEN_SYNC_IDLE_INTERVAL
                    };
                    if delta == 0 {
                        // Screen has not changed since last tick — skip expensive formatting.
                        continue;
                    }
                    // Diffs are actively flowing — skip snapshot to avoid contending with
                    // the diff stream.  Advance last_dirty so we detect when diffs stop.
                    if sync_diff.swap(false, Ordering::Relaxed) {
                        last_dirty = current;
                        continue;
                    }
                    last_dirty = current;
                    let contents = {
                        let emu = sync_emu.lock().await;
                        emu.screen().contents_formatted()
                    };
                    let compressed = encode_all(contents.as_slice(), 3)
                        .unwrap_or_else(|_| contents.clone());
                    if sync_tx.send(EncryptedFrame::ScreenStateCompressed(compressed)).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    // Respond to RepaintRequest frames from the client with an immediate ScreenState.
    // The repaint_rx channel has capacity 1; bursts of requests are coalesced naturally
    // since the channel is drained before each response is sent.
    let repaint_emu = server_emulator.clone();
    let repaint_tx_out = tx.clone();
    let repaint_token = conn_token.clone();
    let _repaint_on_request = spawn(async move {
        loop {
            select! {
                () = repaint_token.cancelled() => break,
                msg = repaint_rx.recv() => {
                    if msg.is_none() {
                        break;
                    }
                    // Drain any additional queued requests — one ScreenState covers them all.
                    while repaint_rx.try_recv().is_ok() {}
                    let contents = {
                        let emu = repaint_emu.lock().await;
                        emu.screen().contents_formatted()
                    };
                    let compressed = encode_all(contents.as_slice(), 3)
                        .unwrap_or_else(|_| contents.clone());
                    if repaint_tx_out.send(EncryptedFrame::ScreenStateCompressed(compressed)).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    spawn_proactive_repaint_watchdog(
        tx.clone(),
        conn_token.clone(),
        nak_received_count,
        server_emulator.clone(),
    );

    // For new sessions, spawn the long-lived PTY thread.
    if let Some(term_rx) = maybe_term_rx {
        spawn_pty(
            session_uuid,
            skex.user().to_owned(),
            skex.shell().to_owned(),
            term_rx,
            output_handle,
            scrollback,
            server_emulator,
            dirty_counter,
            diff_in_flight,
            pacing_delay,
            term_type,
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
        // 3 s interval: with a client silence timeout of max(nak_timeout × 30, 9 s),
        // three keepalives fit within the minimum 9 s window, tolerating one lost
        // keepalive before a false disconnect would occur.
        let mut ticker = tokio::time::interval(Duration::from_secs(3));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            select! {
                () = conn_token.cancelled() => break,
                _ = ticker.tick() => {
                    let ts = u64::try_from(
                        SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_micros(),
                    )
                    .unwrap_or(0);
                    if tx.send(EncryptedFrame::Keepalive(ts)).await.is_err() {
                        break;
                    }
                }
            }
        }
    });
}

/// Spawn a watchdog task that proactively pushes a `ScreenStateCompressed` frame when the
/// server receives an elevated rate of NAK frames from the client.
///
/// When NAK delta over a 200 ms window reaches [`PROACTIVE_REPAINT_NAK_THRESHOLD`], a
/// `RepaintRequest` may itself be lost (the same loss condition that prompted the NAKs can
/// affect control frames too).  This watchdog breaks the dependency by pushing the screen
/// state unconditionally, without waiting for the client to ask.
fn spawn_proactive_repaint_watchdog(
    tx: Sender<EncryptedFrame>,
    token: CancellationToken,
    nak_received_count: Arc<AtomicU64>,
    server_emulator: Arc<Mutex<vt100::Parser>>,
) {
    let _watchdog = spawn(async move {
        let mut last_count: u64 = 0;
        let mut ticker = tokio::time::interval(Duration::from_millis(200));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            select! {
                () = token.cancelled() => break,
                _ = ticker.tick() => {
                    let current = nak_received_count.load(Ordering::Relaxed);
                    let delta = current.wrapping_sub(last_count);
                    last_count = current;
                    if delta >= PROACTIVE_REPAINT_NAK_THRESHOLD {
                        let contents = {
                            let emu = server_emulator.lock().await;
                            emu.screen().contents_formatted()
                        };
                        let compressed = encode_all(contents.as_slice(), 3)
                            .unwrap_or_else(|_| contents.clone());
                        if tx
                            .send(EncryptedFrame::ScreenStateCompressed(compressed))
                            .await
                            .is_err()
                        {
                            break;
                        }
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
    Arc<Mutex<vt100::Parser>>,
    Arc<AtomicU64>,
    Arc<AtomicBool>,
)> {
    let (term_tx, term_rx) = channel::<TerminalMessage>(256);
    let output_handle = Arc::new(Mutex::new(SessionOutputHandle {
        kex_uuid: kex.uuid(),
        tx: Some(tx),
        conn_token: Some(conn_token.clone()),
        udp_port: Some(udp_port),
    }));
    let scrollback = Arc::new(Mutex::new(VecDeque::with_capacity(SCROLLBACK_CAPACITY)));
    let server_emulator = Arc::new(Mutex::new(vt100::Parser::new(24, 80, 0)));
    // Start at 1 so the first sync tick always sends an initial screen state.
    let dirty_counter = Arc::new(AtomicU64::new(1));
    let diff_in_flight = Arc::new(AtomicBool::new(false));

    {
        let mut fr = full_registry.lock().await;
        drop(fr.insert(
            session_uuid,
            SessionRecord {
                term_tx: term_tx.clone(),
                output_handle: output_handle.clone(),
                scrollback: scrollback.clone(),
                server_emulator: server_emulator.clone(),
                dirty_counter: dirty_counter.clone(),
                diff_in_flight: diff_in_flight.clone(),
            },
        ));
    }

    Ok((
        term_tx,
        Some(term_rx),
        output_handle,
        scrollback,
        server_emulator,
        dirty_counter,
        diff_in_flight,
    ))
}

/// Spawn the background thread that reads PTY output, writes scrollback, and forwards
/// frames to the currently connected client.  Cleans up session state when the shell exits.
#[cfg_attr(nightly, allow(clippy::too_many_arguments))]
#[cfg_attr(coverage_nightly, coverage(off))]
fn spawn_pty_reader(
    session_uuid: Uuid,
    mut term_out: Box<dyn std::io::Read + Send>,
    output_handle: Arc<Mutex<SessionOutputHandle>>,
    scrollback: Arc<Mutex<VecDeque<u8>>>,
    server_emulator: Arc<Mutex<vt100::Parser>>,
    dirty_counter: Arc<AtomicU64>,
    diff_in_flight: Arc<AtomicBool>,
    pacing_delay: Duration,
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
                    let buf_slice = &buffer[..n];
                    let utf8_buf = String::from_utf8_lossy(buf_slice);

                    // Write to scrollback ring buffer.
                    {
                        let mut sb = scrollback.blocking_lock();
                        let available = SCROLLBACK_CAPACITY.saturating_sub(sb.len());
                        if buf_slice.len() > available {
                            for _ in 0..(buf_slice.len() - available) {
                                let _ = sb.pop_front();
                            }
                        }
                        sb.extend(buf_slice.iter().copied());
                    }

                    // Feed into the server-side emulator for screen-state tracking.
                    server_emulator.blocking_lock().process(buf_slice);

                    // Signal to the screen-sync task that new content is available.
                    let _ = dirty_counter.fetch_add(1, Ordering::Relaxed);

                    // Send to the currently connected client (if any).
                    let send_ok = {
                        let h = output_handle.blocking_lock();
                        if let Some(ref sender) = h.tx {
                            let uuid_wrapper = UuidWrapper::new(h.kex_uuid);
                            let sender_clone = sender.clone();
                            drop(h);
                            // Signal the screen-sync task that diffs are flowing.
                            diff_in_flight.store(true, Ordering::Relaxed);
                            // Try zstd level-1 compression.  When it reduces payload size,
                            // the entire PTY read fits in a single datagram — eliminating
                            // multi-packet bursts and their NAK exposure.  Fall back to
                            // paced MTU chunks for incompressible binary data.
                            if let Ok(compressed) = encode_all(buf_slice, 1)
                                && compressed.len() < buf_slice.len()
                            {
                                let frame =
                                    EncryptedFrame::CompressedBytes((uuid_wrapper, compressed));
                                sender_clone.blocking_send(frame).is_ok()
                            } else {
                                let mut ok = true;
                                let mut chunks = buf_slice.chunks(MAX_UDP_PAYLOAD).peekable();
                                while let Some(chunk) = chunks.next() {
                                    let more = chunks.peek().is_some();
                                    let frame =
                                        EncryptedFrame::Bytes((uuid_wrapper, chunk.to_vec()));
                                    ok = sender_clone.blocking_send(frame).is_ok();
                                    if !ok {
                                        break;
                                    }
                                    // Space out consecutive chunks to prevent burst loss
                                    // on stateful NAT devices.
                                    if more && !pacing_delay.is_zero() {
                                        sleep(pacing_delay);
                                    }
                                }
                                ok
                            }
                        } else {
                            drop(h);
                            true // headless: just buffer
                        }
                    };
                    if !send_ok {
                        // Client dropped; clear tx but keep the PTY running.
                        output_handle.blocking_lock().tx = None;
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
#[allow(unsafe_code)]
#[cfg_attr(
    nightly,
    allow(
        clippy::too_many_arguments,
        clippy::needless_pass_by_value,
        clippy::too_many_lines
    )
)]
#[cfg_attr(not(nightly), allow(clippy::needless_pass_by_value))]
#[cfg_attr(coverage_nightly, coverage(off))]
fn spawn_pty(
    session_uuid: Uuid,
    #[cfg_attr(not(unix), allow(unused_variables))] user: String,
    shell: String,
    mut term_rx: Receiver<TerminalMessage>,
    output_handle: Arc<Mutex<SessionOutputHandle>>,
    scrollback: Arc<Mutex<VecDeque<u8>>>,
    server_emulator: Arc<Mutex<vt100::Parser>>,
    dirty_counter: Arc<AtomicU64>,
    diff_in_flight: Arc<AtomicBool>,
    pacing_delay: Duration,
    #[cfg_attr(not(unix), allow(unused_variables))] term_type: String,
    port_pool: Arc<Mutex<BTreeSet<u16>>>,
    session_registry: SessionRegistry,
    full_registry: FullSessionRegistry,
) {
    let _term_handle = thread::spawn(move || {
        let pty_system = native_pty_system();
        let pair = pty_system
            .openpty(PtySize {
                rows: 24,
                cols: 80,
                pixel_width: 0,
                pixel_height: 0,
            })
            .unwrap();

        #[cfg(unix)]
        {
            let daemon_uid = unsafe { libc::getuid() };
            if daemon_uid != 0 {
                let daemon_user = current_daemon_user();
                if daemon_user.as_deref() != Some(user.as_str()) {
                    error!(
                        "Daemon user {} cannot spawn shell for user {}",
                        daemon_user.unwrap_or_else(|| String::from("<unknown>")),
                        user
                    );
                    return;
                }
            }

            let Some(tty_path) = pair.master.tty_name() else {
                error!("Unable to determine PTY slave tty path");
                return;
            };
            // O_NOCTTY: prevent the server process (a daemon/session leader with
            // no controlling terminal) from acquiring the PTY slave as its own
            // controlling terminal.  Without this flag, the kernel would silently
            // assign the slave to the server's session, causing the subsequent
            // ioctl(TIOCSCTTY) in the child to fail with EPERM.
            let slave = match std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(libc::O_NOCTTY)
                .open(&tty_path)
            {
                Ok(file) => file,
                Err(e) => {
                    error!("Failed to open PTY slave {}: {e}", tty_path.display());
                    return;
                }
            };

            let stdin_file = match slave.try_clone() {
                Ok(file) => file,
                Err(e) => {
                    error!("Failed to clone PTY slave for stdin: {e}");
                    return;
                }
            };
            let stdout_file = match slave.try_clone() {
                Ok(file) => file,
                Err(e) => {
                    error!("Failed to clone PTY slave for stdout: {e}");
                    return;
                }
            };
            let stderr_file = match slave.try_clone() {
                Ok(file) => file,
                Err(e) => {
                    error!("Failed to clone PTY slave for stderr: {e}");
                    return;
                }
            };

            let mut cmd = std::process::Command::new(&shell);
            let _ = cmd.arg("-li");

            let mut drop_creds: Option<(CString, libc::uid_t, libc::gid_t)> = None;

            if daemon_uid == 0 {
                let account = match resolve_user_account(&user, &shell) {
                    Ok(account) => account,
                    Err(e) => {
                        error!("Failed to resolve target account for {user}: {e}");
                        return;
                    }
                };

                let Ok(username_c) = CString::new(account.username.clone()) else {
                    error!("Target username contains invalid NUL byte");
                    return;
                };
                let login_uid = account.uid;
                let primary_group_id = account.gid;

                let _ = cmd.current_dir(&account.home);
                let _ = cmd.env("HOME", &account.home);
                let _ = cmd.env("USER", &account.username);
                let _ = cmd.env("LOGNAME", &account.username);
                let _ = cmd.env("SHELL", &account.shell);
                let _ = cmd.env("TERM", &term_type);

                drop_creds = Some((username_c, login_uid, primary_group_id));
            }

            let _ = unsafe {
                cmd.pre_exec(move || {
                    let tiocsctty_request = tiocsctty_ioctl_request();

                    if libc::setsid() < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    if libc::ioctl(0, tiocsctty_request, 0) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }

                    if let Some((username_c, login_uid, primary_group_id)) = drop_creds.as_ref() {
                        #[cfg(target_os = "linux")]
                        let initgroups_basegroup = initgroups_base_group(*primary_group_id);

                        #[cfg(target_os = "macos")]
                        let initgroups_basegroup = initgroups_base_group(*primary_group_id)?;

                        if libc::initgroups(username_c.as_ptr(), initgroups_basegroup) < 0 {
                            return Err(std::io::Error::last_os_error());
                        }
                        if libc::setgid(*primary_group_id) < 0 {
                            return Err(std::io::Error::last_os_error());
                        }
                        if libc::setuid(*login_uid) < 0 {
                            return Err(std::io::Error::last_os_error());
                        }
                    }

                    Ok(())
                })
            };

            let _ = cmd
                .stdin(Stdio::from(stdin_file))
                .stdout(Stdio::from(stdout_file))
                .stderr(Stdio::from(stderr_file));

            if let Err(e) = cmd.spawn() {
                error!("Failed to spawn shell for user {user}: {e}");
                return;
            }

            drop(pair.slave);
            drop(slave);
        }

        #[cfg(windows)]
        {
            let cmd = CommandBuilder::new(shell);
            if let Err(e) = pair.slave.spawn_command(cmd) {
                error!("Failed to spawn shell: {e}");
                return;
            }
        }

        let master = pair.master;

        let term_out = master.try_clone_reader().unwrap();
        let mut term_in = master.take_writer().unwrap();

        spawn_pty_reader(
            session_uuid,
            term_out,
            output_handle,
            scrollback,
            server_emulator.clone(),
            dirty_counter.clone(),
            diff_in_flight,
            pacing_delay,
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
                    // Keep the server-side emulator in sync with the PTY dimensions.
                    server_emulator
                        .blocking_lock()
                        .screen_mut()
                        .set_size(rows, columns);
                    // Resize changes the rendered screen layout — mark dirty.
                    let _ = dirty_counter.fetch_add(1, Ordering::Relaxed);
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

#[cfg(unix)]
#[allow(unsafe_code)]
fn current_daemon_user() -> Option<String> {
    let daemon_uid = unsafe { libc::getuid() };
    let pwd = unsafe { libc::getpwuid(daemon_uid) };
    if pwd.is_null() {
        return None;
    }
    Some(
        unsafe { CStr::from_ptr((*pwd).pw_name) }
            .to_string_lossy()
            .into_owned(),
    )
}

#[cfg(all(unix, target_os = "linux"))]
fn tiocsctty_ioctl_request() -> libc::Ioctl {
    libc::TIOCSCTTY
}

#[cfg(all(unix, target_os = "macos"))]
fn tiocsctty_ioctl_request() -> libc::c_ulong {
    libc::c_ulong::from(libc::TIOCSCTTY)
}

#[cfg(all(unix, target_os = "linux"))]
fn initgroups_base_group(group_id: libc::gid_t) -> libc::gid_t {
    group_id
}

#[cfg(all(unix, target_os = "macos"))]
fn initgroups_base_group(group_id: libc::gid_t) -> std::io::Result<libc::c_int> {
    group_id.try_into().map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "gid does not fit into c_int for initgroups",
        )
    })
}

#[cfg(unix)]
struct ResolvedUserAccount {
    username: String,
    uid: libc::uid_t,
    gid: libc::gid_t,
    home: String,
    shell: String,
}

#[cfg(unix)]
#[allow(unsafe_code)]
fn resolve_user_account(username: &str, fallback_shell: &str) -> Result<ResolvedUserAccount> {
    let username_c = CString::new(username)?;
    let pwd = unsafe { libc::getpwnam(username_c.as_ptr()) };
    if pwd.is_null() {
        return Err(anyhow::anyhow!("user '{username}' not found"));
    }
    let pw = unsafe { *pwd };

    let home = unsafe { CStr::from_ptr(pw.pw_dir) }
        .to_string_lossy()
        .to_string();
    let shell_from_db = unsafe { CStr::from_ptr(pw.pw_shell) }
        .to_string_lossy()
        .to_string();

    Ok(ResolvedUserAccount {
        username: username.to_string(),
        uid: pw.pw_uid,
        gid: pw.pw_gid,
        home,
        shell: if shell_from_db.is_empty() {
            fallback_shell.to_string()
        } else {
            shell_from_db
        },
    })
}

#[cfg(test)]
#[allow(dead_code, clippy::all)]
mod test {
    use libmoshpit::{EncryptedFrame, Kex, ServerKex};
    use tokio::sync::mpsc::channel;
    use tokio_util::sync::CancellationToken;
    use uuid::Uuid;

    #[cfg(unix)]
    use super::{current_daemon_user, resolve_user_account};
    use std::sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    };

    use super::{
        PROACTIVE_REPAINT_NAK_THRESHOLD, new_full_registry, new_session, resolve_session,
        spawn_connection_watchdogs, spawn_proactive_repaint_watchdog,
    };

    #[cfg(unix)]
    #[test]
    fn current_daemon_user_returns_some() {
        let user = current_daemon_user();
        assert!(user.is_some());
    }

    #[cfg(unix)]
    #[test]
    fn resolve_user_account_unknown_user_errors() {
        let result = resolve_user_account("__moshpit_no_such_user__", "/bin/sh");
        assert!(result.is_err());
    }

    #[cfg(unix)]
    #[test]
    fn resolve_user_account_current_user_roundtrip() {
        let Some(username) = current_daemon_user() else {
            panic!("expected current daemon user on unix")
        };

        let account =
            resolve_user_account(&username, "/bin/sh").expect("current daemon user should resolve");

        assert_eq!(account.username, username);
        assert!(!account.home.is_empty());
        assert!(!account.shell.is_empty());
    }

    // ── Phase 5: new_session ──────────────────────────────────────────────────

    #[tokio::test]
    async fn new_session_registers_in_full_registry() {
        let kex = Kex::default();
        let conn_token = CancellationToken::new();
        let (tx, _rx) = channel::<EncryptedFrame>(4);
        let session_uuid = Uuid::new_v4();
        let registry = new_full_registry();

        let _reg_result = new_session(&kex, &conn_token, 50_000, session_uuid, tx, &registry)
            .await
            .unwrap();

        assert!(registry.lock().await.contains_key(&session_uuid));
    }

    #[tokio::test]
    async fn new_session_returns_some_term_rx() {
        let kex = Kex::default();
        let conn_token = CancellationToken::new();
        let (tx, _rx) = channel::<EncryptedFrame>(4);
        let session_uuid = Uuid::new_v4();
        let registry = new_full_registry();

        let (_, maybe_rx, _, _, _, _, _) =
            new_session(&kex, &conn_token, 50_000, session_uuid, tx, &registry)
                .await
                .unwrap();
        assert!(maybe_rx.is_some());
    }

    #[tokio::test]
    async fn new_session_output_handle_has_correct_kex_uuid() {
        let kex = Kex::default();
        let conn_token = CancellationToken::new();
        let (tx, _rx) = channel::<EncryptedFrame>(4);
        let session_uuid = Uuid::new_v4();
        let registry = new_full_registry();

        let (_, _, output_handle, _, _, _, _) =
            new_session(&kex, &conn_token, 50_000, session_uuid, tx, &registry)
                .await
                .unwrap();
        assert_eq!(output_handle.lock().await.kex_uuid, kex.uuid());
    }

    #[tokio::test]
    async fn new_session_scrollback_initially_empty() {
        let kex = Kex::default();
        let conn_token = CancellationToken::new();
        let (tx, _rx) = channel::<EncryptedFrame>(4);
        let session_uuid = Uuid::new_v4();
        let registry = new_full_registry();

        let (_, _, _, scrollback, _, _, _) =
            new_session(&kex, &conn_token, 50_000, session_uuid, tx, &registry)
                .await
                .unwrap();
        assert!(scrollback.lock().await.is_empty());
    }

    #[tokio::test]
    async fn new_session_emulator_default_size() {
        let kex = Kex::default();
        let conn_token = CancellationToken::new();
        let (tx, _rx) = channel::<EncryptedFrame>(4);
        let session_uuid = Uuid::new_v4();
        let registry = new_full_registry();

        let (_, _, _, _, emulator, _, _) =
            new_session(&kex, &conn_token, 50_000, session_uuid, tx, &registry)
                .await
                .unwrap();
        let emu = emulator.lock().await;
        let screen = emu.screen();
        assert_eq!(screen.size(), (24, 80));
    }

    // ── Phase 9: spawn_connection_watchdogs ────────────────────────────────────

    #[tokio::test]
    async fn watchdogs_keepalive_sends_frame() {
        let (tx, mut rx) = channel::<EncryptedFrame>(4);
        let conn_token = CancellationToken::new();
        let server_token = CancellationToken::new();
        spawn_connection_watchdogs(tx, conn_token.clone(), server_token);

        // The keepalive fires every 10 s — wait for the first tick (immediate on start)
        // or drain until we see a Keepalive within a short timeout.
        let frame = tokio::time::timeout(std::time::Duration::from_millis(200), rx.recv()).await;
        // Either we got a frame or the channel is still open; cancel to clean up
        conn_token.cancel();
        // We just verify the channel was not closed (tasks are alive)
        // A Keepalive arrives on the first tick; the tick interval starts with an
        // immediate first tick so we expect it promptly.
        let frame = frame
            .expect("timeout waiting for keepalive")
            .expect("channel closed");
        assert!(matches!(frame, EncryptedFrame::Keepalive(_)));
    }

    #[tokio::test]
    async fn watchdogs_server_cancel_sends_shutdown_then_cancels_conn() {
        let (tx, mut rx) = channel::<EncryptedFrame>(4);
        let conn_token = CancellationToken::new();
        let server_token = CancellationToken::new();
        spawn_connection_watchdogs(tx, conn_token.clone(), server_token.clone());

        server_token.cancel();

        // Allow the watcher task to run
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Drain frames looking for Shutdown
        let mut saw_shutdown = false;
        while let Ok(frame) = rx.try_recv() {
            if matches!(frame, EncryptedFrame::Shutdown) {
                saw_shutdown = true;
                break;
            }
        }
        assert!(
            saw_shutdown,
            "expected Shutdown frame after server_token cancel"
        );
        // After another short wait, conn_token should be cancelled
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert!(conn_token.is_cancelled());
    }

    #[tokio::test]
    async fn watchdogs_conn_cancel_stops_keepalive() {
        let (tx, mut rx) = channel::<EncryptedFrame>(4);
        let conn_token = CancellationToken::new();
        let server_token = CancellationToken::new();
        spawn_connection_watchdogs(tx, conn_token.clone(), server_token);

        // Cancel immediately — keepalive loop should stop
        conn_token.cancel();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Drain any already-queued frames
        while rx.try_recv().is_ok() {}
        // No further Keepalive frames should arrive
        let result = tokio::time::timeout(std::time::Duration::from_millis(100), rx.recv()).await;
        // Either timeout (no frame) or channel closed — both are acceptable
        assert!(result.is_err() || result.unwrap().is_none());
    }

    // ── Phase 10: resolve_session ─────────────────────────────────────────────

    #[tokio::test]
    async fn resolve_session_new_session_path() {
        let kex = Kex::default();
        let session_uuid = Uuid::new_v4();
        let skex = ServerKex::builder()
            .user("alice".to_string())
            .shell("/usr/bin/fish".to_string())
            .session_uuid(session_uuid)
            .build();
        let conn_token = CancellationToken::new();
        let (tx, _rx) = channel::<EncryptedFrame>(4);
        let registry = new_full_registry();

        let (_, maybe_rx, _, _, _, _, _) =
            resolve_session(&kex, &skex, &conn_token, 50_000, tx, &registry)
                .await
                .unwrap();
        // New session → PTY needs to be spawned → Some(term_rx)
        assert!(maybe_rx.is_some());
    }

    #[tokio::test]
    async fn resolve_session_resume_existing() {
        let kex = Kex::default();
        let session_uuid = Uuid::new_v4();
        let conn_token = CancellationToken::new();
        let (tx, _rx) = channel::<EncryptedFrame>(16);
        let registry = new_full_registry();

        // First connection: create a session
        let _first_session = new_session(
            &kex,
            &conn_token,
            50_000,
            session_uuid,
            tx.clone(),
            &registry,
        )
        .await
        .unwrap();

        // Second connection: resume
        let new_kex = Kex::default();
        let skex_resume = ServerKex::builder()
            .user("alice".to_string())
            .shell("/usr/bin/fish".to_string())
            .session_uuid(session_uuid)
            .is_resume(true)
            .build();
        let new_conn_token = CancellationToken::new();
        let (tx2, mut rx2) = channel::<EncryptedFrame>(16);

        let (_, maybe_rx, output_handle, _, _, _, _) = resolve_session(
            &new_kex,
            &skex_resume,
            &new_conn_token,
            50_001,
            tx2,
            &registry,
        )
        .await
        .unwrap();

        // Resume → no new PTY → None
        assert!(maybe_rx.is_none());
        // Output handle should be updated with the new kex uuid
        assert_eq!(output_handle.lock().await.kex_uuid, new_kex.uuid());
        // A ScreenState frame should have been sent on the *new* connection's tx
        let mut saw_screen_state = false;
        while let Ok(frame) = rx2.try_recv() {
            if matches!(
                frame,
                EncryptedFrame::ScreenState(_) | EncryptedFrame::ScreenStateCompressed(_)
            ) {
                saw_screen_state = true;
                break;
            }
        }
        assert!(saw_screen_state, "expected ScreenState frame on resume");
    }

    #[tokio::test]
    async fn resolve_session_resume_expired() {
        let kex = Kex::default();
        let session_uuid = Uuid::new_v4();
        // Registry is empty — no existing session with this UUID
        let skex = ServerKex::builder()
            .user("alice".to_string())
            .shell("/usr/bin/fish".to_string())
            .session_uuid(session_uuid)
            .is_resume(true)
            .build();
        let conn_token = CancellationToken::new();
        let (tx, _rx) = channel::<EncryptedFrame>(4);
        let registry = new_full_registry();

        let (_, maybe_rx, _, _, _, _, _) =
            resolve_session(&kex, &skex, &conn_token, 50_000, tx, &registry)
                .await
                .unwrap();
        // Falls back to new session → Some(term_rx)
        assert!(maybe_rx.is_some());
    }

    // ── Phase 5: platform helper functions ────────────────────────────────────

    #[cfg(all(unix, target_os = "linux"))]
    use super::{initgroups_base_group, tiocsctty_ioctl_request};

    #[cfg(all(unix, target_os = "linux"))]
    #[test]
    fn tiocsctty_ioctl_request_is_nonzero() {
        // libc::TIOCSCTTY is 0x540E on Linux — must never be zero
        assert_ne!(tiocsctty_ioctl_request(), 0);
    }

    #[cfg(all(unix, target_os = "linux"))]
    #[test]
    fn initgroups_base_group_roundtrip() {
        // On Linux this is a trivial pass-through of gid_t
        assert_eq!(initgroups_base_group(42), 42);
        assert_eq!(initgroups_base_group(0), 0);
        assert_eq!(initgroups_base_group(u32::MAX), u32::MAX);
    }

    // ── Phase 8: spawn_proactive_repaint_watchdog ──────────────────────────────

    #[tokio::test]
    async fn proactive_repaint_fires_on_nak_saturation() {
        let (tx, mut rx) = channel::<EncryptedFrame>(4);
        let token = CancellationToken::new();
        let nak_count = Arc::new(AtomicU64::new(0));
        let emulator = Arc::new(tokio::sync::Mutex::new(vt100::Parser::new(24, 80, 0)));

        spawn_proactive_repaint_watchdog(tx, token.clone(), nak_count.clone(), emulator);

        // Bump the counter above the threshold so the first watchdog tick triggers a push.
        nak_count.store(PROACTIVE_REPAINT_NAK_THRESHOLD, Ordering::Relaxed);

        // The watchdog polls every 200 ms — give it up to 500 ms to fire.
        let frame = tokio::time::timeout(std::time::Duration::from_millis(500), rx.recv()).await;
        token.cancel();

        let frame = frame
            .expect("timeout: proactive repaint did not fire within 500 ms")
            .expect("channel closed before proactive repaint");
        assert!(matches!(frame, EncryptedFrame::ScreenStateCompressed(_)));
    }

    #[tokio::test]
    async fn proactive_repaint_does_not_fire_below_threshold() {
        let (tx, mut rx) = channel::<EncryptedFrame>(4);
        let token = CancellationToken::new();
        let nak_count = Arc::new(AtomicU64::new(0));
        let emulator = Arc::new(tokio::sync::Mutex::new(vt100::Parser::new(24, 80, 0)));

        spawn_proactive_repaint_watchdog(tx, token.clone(), nak_count.clone(), emulator);

        // Set count one below the threshold.
        nak_count.store(PROACTIVE_REPAINT_NAK_THRESHOLD - 1, Ordering::Relaxed);

        // Wait for at least one poll cycle — no frame should arrive.
        let result = tokio::time::timeout(std::time::Duration::from_millis(300), rx.recv()).await;
        token.cancel();

        assert!(
            result.is_err(),
            "expected no proactive repaint below threshold, but got a frame"
        );
    }

    #[tokio::test]
    async fn proactive_repaint_stops_on_cancel() {
        let (tx, mut rx) = channel::<EncryptedFrame>(4);
        let token = CancellationToken::new();
        let nak_count = Arc::new(AtomicU64::new(PROACTIVE_REPAINT_NAK_THRESHOLD));
        let emulator = Arc::new(tokio::sync::Mutex::new(vt100::Parser::new(24, 80, 0)));

        spawn_proactive_repaint_watchdog(tx, token.clone(), nak_count, emulator);

        // Cancel immediately before any tick fires.
        token.cancel();
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;

        // Channel should be drained and no further frames arrive.
        while rx.try_recv().is_ok() {}
        let result = tokio::time::timeout(std::time::Duration::from_millis(100), rx.recv()).await;
        assert!(
            result.is_err() || result.unwrap().is_none(),
            "watchdog kept sending after cancellation"
        );
    }
}
