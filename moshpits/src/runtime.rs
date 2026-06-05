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
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
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
    DiffMode, EncryptedFrame, KexMode, MAX_UDP_PAYLOAD, MoshpitError, SessionRegistry,
    TerminalMessage, UdpReader, UdpSender, UuidWrapper, env_var_matches, init_tracing,
    is_exit_title, load, new_session_registry, run_key_exchange,
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
    time::{Instant as TokioInstant, sleep_until},
};
use tokio_util::sync::CancellationToken;
#[cfg(target_os = "linux")]
use tracing::warn;
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

/// MTU tier sizes — maximum PTY-chunk payload bytes tried in ascending order.
/// Wire size ≈ payload + 124 bytes overhead (nonce + seq + HMAC + length + UUID + AEAD tag).
/// Tier 2 (1348 B payload) produces a ≈ 1472-byte wire frame — the IPv4 maximum
/// (1500 Ethernet MTU − 20 IP − 8 UDP).  Tier 1 (1300 B) is a safe intermediate.
const MTU_TIERS: &[usize] = &[1_200, 1_300, 1_348];
/// 200 ms polling interval shared by the MTU probe task and the proactive-repaint watchdog.
const MTU_POLL_INTERVAL: Duration = Duration::from_millis(200);
/// Consecutive 200 ms ticks with zero NAK delta required before probing the next tier (60 s).
const MTU_PROBE_QUIET_TICKS: u32 = 300;
/// Consecutive 200 ms probe ticks with low NAK delta required to confirm the upgrade (30 s).
const MTU_PROBE_SUCCESS_TICKS: u32 = 150;
/// NAK delta in a single 200 ms window that signals the larger MTU caused a black hole.
const MTU_PROBE_FAIL_THRESHOLD: u64 = 3;
/// Consecutive zero-NAK-delta ticks before the connection-health task starts backing off
/// its poll interval (5 ticks × 200 ms = 1 s of idle before first slowdown).
const HEALTH_BACKOFF_TICKS: u32 = 5;
/// Maximum poll interval for the connection-health task during prolonged idle.  The interval
/// doubles every quiet tick (200 ms → 400 → 800 → 1600 → 2000 ms), reducing the combined
/// MTU probe + proactive-repaint wakeup rate from 5 Hz to 0.5 Hz after ~2 s of silence.
/// Any NAK activity snaps it back to [`MTU_POLL_INTERVAL`] immediately.
const HEALTH_MAX_INTERVAL: Duration = Duration::from_secs(2);

/// Normal screen-sync interval when the terminal is idle.
const SCREEN_SYNC_IDLE_INTERVAL: Duration = Duration::from_millis(50);
/// Reduced screen-sync interval during rapid terminal output bursts (Option H).
const SCREEN_SYNC_BURST_INTERVAL: Duration = Duration::from_millis(10);
/// Dirty-counter delta threshold above which a tick is classified as a burst.
const SCREEN_SYNC_BURST_DIRTY_THRESHOLD: u64 = 5;
/// Maximum screen-sync sleep when the terminal has been quiet for several consecutive
/// ticks.  The interval doubles on each zero-delta tick (50 ms → 100 → 200 → … → 2 s),
/// reducing wakeups from 20 Hz to 0.5 Hz after ~3 s of inactivity.  The next non-zero
/// delta resets it to [`SCREEN_SYNC_IDLE_INTERVAL`] immediately.
const MAX_SCREEN_SYNC_IDLE_INTERVAL: Duration = Duration::from_secs(2);
/// Interval between periodic full `ScreenStateCompressed` pushes in datagram mode.
/// Since the client never sends NAKs, this push is the only recovery mechanism for
/// lost diff packets.  150 ms gives a good balance between recovery latency and
/// bandwidth: at a 40 KB/s average compressed screen size of ~3 KB, the overhead
/// is ~20 KB/s — negligible on any modern link.
const DATAGRAM_REPAINT_INTERVAL: Duration = Duration::from_millis(150);
/// Tick interval for the state-sync task in `StateSync` mode.  Each tick computes
/// `contents_diff(ack_state, current)` and sends the result if non-empty.
const STATESYNC_INTERVAL: Duration = Duration::from_millis(50);
/// Maximum number of `(diff_id, contents_formatted)` entries kept in the server's
/// sent-states ring buffer.  When `ClientAck(diff_id)` arrives, the server looks up
/// this entry to advance its ack baseline.
const STATESYNC_HISTORY_LEN: usize = 32;
/// Maximum compressed byte count for a `StateSyncDiff` payload that fits in a single UDP
/// datagram.  `MAX_UDP_PAYLOAD` (1200) minus ~149 bytes of wire/crypto/bincode overhead.
/// Diffs exceeding this are replaced with a `ScreenStateCompressed` full-state push so
/// fragmented (and NAT-dropped) packets cannot stall the ack pipeline.
const MAX_STATESYNC_DIFF_BYTES: usize = 900;
/// Maximum payload bytes per `StateChunk` frame.  Each chunk plus ~149 bytes of
/// wire/crypto/bincode overhead produces a datagram well within `MAX_UDP_PAYLOAD` (1200 B).
const STATE_CHUNK_SIZE: usize = 800;
/// How long with no UDP frame received from the client before the server cancels the connection.
const CLIENT_SILENCE_TIMEOUT_US: u64 = 30_000_000;

/// Current time as microseconds since the UNIX epoch.
fn now_micros() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros(),
    )
    .unwrap_or(0)
}

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
    data_tx: Sender<EncryptedFrame>,
    control_tx: Sender<EncryptedFrame>,
    full_registry: &FullSessionRegistry,
) -> Result<(
    Sender<TerminalMessage>,
    Option<Receiver<TerminalMessage>>,
    Arc<Mutex<SessionOutputHandle>>,
    Arc<Mutex<VecDeque<u8>>>,
    Arc<Mutex<vt100::Parser>>,
    Arc<AtomicU64>,
    Arc<AtomicBool>,
    Arc<AtomicUsize>,
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
            let effective_mtu = record.effective_mtu.clone();
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
                h.data_tx = Some(data_tx.clone());
                h.control_tx = Some(control_tx.clone());
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
            data_tx
                .send(EncryptedFrame::ScreenStateCompressed(compressed))
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
                effective_mtu,
            ))
        } else {
            // Session expired; start fresh.
            drop(reg);
            info!(
                user = skex.user(),
                session = %session_uuid,
                "previous session expired, starting new session"
            );
            new_session(
                kex,
                conn_token,
                udp_port,
                session_uuid,
                data_tx,
                control_tx,
                full_registry,
            )
            .await
        }
    } else {
        let result = new_session(
            kex,
            conn_token,
            udp_port,
            session_uuid,
            data_tx,
            control_tx,
            full_registry,
        )
        .await?;
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
    // Client IP for the logind session's remote-host marker (best-effort).
    let remote_host = socket.peer_addr().ok().map(|addr| addr.ip().to_string());
    let (sock_read, sock_write) = socket.into_split();
    let port_pool = config.port_pool();
    let session_registry = config.session_registry();
    let warmup_delay = config.warmup_delay_ms().map(Duration::from_millis);
    let pacing_delay =
        Duration::from_micros(config.pacing_delay_us().unwrap_or(DEFAULT_PACING_DELAY_US));
    let term_type = config.term_type().clone();
    let accept_env = config.accept_env().clone();
    let server_path = config.server_path().clone();
    let path_locked = config.path_locked();
    let namespace_escape = config.namespace_escape();
    let use_logind = config.use_logind();
    let (kex, udp_arc, skex_opt) =
        run_key_exchange(config, sock_read, sock_write, || Ok(None), None, None).await?;
    info!("Key exchange completed with moshpit");

    let skex = skex_opt.ok_or_else(|| anyhow::anyhow!("missing server kex info"))?;
    let session_uuid = skex.session_uuid();
    let diff_mode = skex.diff_mode();

    let accepted_client_env: Vec<(String, String)> = skex
        .client_env()
        .iter()
        .filter(|(k, _)| env_var_matches(k, &accept_env))
        .cloned()
        .collect();
    let server_base = server_path.join(":");
    let pty_path = if path_locked || skex.client_extra_path().is_empty() {
        server_base
    } else {
        format!("{}:{server_base}", skex.client_extra_path().join(":"))
    };

    let udp_port = udp_arc.local_addr()?.port();

    let (data_tx, data_rx) = channel::<EncryptedFrame>(256);
    let (control_tx, control_rx) = channel::<EncryptedFrame>(16);
    let (retransmit_tx, retransmit_rx) = channel::<Vec<u64>>(512);
    let udp_recv = udp_arc.clone();
    let udp_send = udp_arc.clone();

    let conn_token = CancellationToken::new();

    // Oneshot carries the initial peer SocketAddr from UdpReader to UdpSender.
    let (peer_discovered_tx, peer_discovered_rx) = oneshot::channel::<SocketAddr>();
    // mpsc carries mid-session NAT roam updates from UdpReader to UdpSender.
    let (peer_addr_tx, peer_addr_rx) = channel::<SocketAddr>(4);

    // Resolve channels and decide whether to spawn a new PTY.
    let (
        term_tx,
        maybe_term_rx,
        output_handle,
        scrollback,
        server_emulator,
        dirty_counter,
        diff_in_flight,
        effective_mtu,
    ) = resolve_session(
        &kex,
        &skex,
        &conn_token,
        udp_port,
        data_tx.clone(),
        control_tx.clone(),
        &full_registry,
    )
    .await?;

    let (repaint_tx, mut repaint_rx) = channel::<()>(1);
    let (client_ack_tx, mut client_ack_rx) = channel::<u64>(16);
    let nak_received_count = Arc::new(AtomicU64::new(0));
    let last_rx_us = Arc::new(AtomicU64::new(now_micros()));
    let mac_tag_len = kex.mac_tag_len();
    let mut udp_reader = UdpReader::builder()
        .socket(udp_recv)
        .id(kex.uuid())
        .hmac(kex.build_hmac())
        .rnk(kex.build_aead_key()?)
        .mac_tag_len(mac_tag_len)
        .nak_out_tx(data_tx.clone())
        .retransmit_tx(retransmit_tx)
        .peer_discovered_tx(peer_discovered_tx)
        .peer_addr_tx(peer_addr_tx)
        .repaint_tx(repaint_tx)
        .nak_received_count(nak_received_count.clone())
        .diff_mode(diff_mode)
        .client_ack_tx(client_ack_tx)
        .last_rx_us(last_rx_us.clone())
        .build();
    let mut udp_sender = UdpSender::builder()
        .socket(udp_send)
        .control_rx(control_rx)
        .rx(data_rx)
        .retransmit_rx(retransmit_rx)
        .id(kex.uuid())
        .hmac(kex.build_hmac())
        .rnk(kex.build_aead_key()?)
        .peer_discovered_rx(peer_discovered_rx)
        .peer_addr_rx(peer_addr_rx)
        .maybe_warmup_delay(warmup_delay)
        .diff_mode(diff_mode)
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

    spawn_connection_watchdogs(control_tx.clone(), conn_token.clone(), server_token);
    spawn_silence_watchdog(conn_token.clone(), last_rx_us);

    if diff_mode == DiffMode::StateSync {
        // Mosh-style ack-based diff delivery.  Each tick computes
        // contents_diff(ack_state → current) and sends it if non-empty.
        // Repaint requests (desync recovery) are handled here instead of by
        // _repaint_on_request.  ClientAck frames advance the ack baseline.
        let ss_emu = server_emulator.clone();
        let ss_tx = data_tx.clone();
        let ss_token = conn_token.clone();
        let _state_sync = spawn(async move {
            let mut ticker = tokio::time::interval(STATESYNC_INTERVAL);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let mut sent_states: VecDeque<(u64, Vec<u8>)> = VecDeque::new();
            let mut ack_diff_id: u64 = 0;
            let mut ack_state: Vec<u8> = Vec::new();
            let mut diff_counter: u64 = 0;
            // CPU optimisation: skip parser creation when neither the screen content
            // nor the ack baseline has changed since the last tick.
            let mut last_current: Vec<u8> = Vec::new();
            let mut ack_dirty = true;
            loop {
                select! {
                    () = ss_token.cancelled() => break,
                    msg = repaint_rx.recv() => {
                        if msg.is_none() {
                            break;
                        }
                        while repaint_rx.try_recv().is_ok() {}
                        let (contents, is_alt) = {
                            let emu = ss_emu.lock().await;
                            let screen = emu.screen();
                            (screen.contents_formatted(), screen.alternate_screen())
                        };
                        let compressed = encode_all(contents.as_slice(), 3)
                            .unwrap_or_else(|_| contents.clone());
                        if !send_state_chunked(&ss_tx, compressed).await {
                            break;
                        }
                        // Reset ack baseline to match client's reset after ScreenStateCompressed.
                        // Store alt-screen-aware: prefix \033[?1049h so a fresh parser reconstructs
                        // the correct screen mode when computing future diffs.
                        let mut ack = contents;
                        if is_alt {
                            let mut prefixed = b"\x1b[?1049h".to_vec();
                            prefixed.extend_from_slice(&ack);
                            ack = prefixed;
                        }
                        ack_state = ack;
                        ack_diff_id = 0;
                        sent_states.clear();
                        ack_dirty = true;
                    }
                    diff_id = client_ack_rx.recv() => {
                        let Some(diff_id) = diff_id else { break; };
                        if let Some(pos) = sent_states.iter().position(|(id, _)| *id == diff_id) {
                            let snapshot = sent_states[pos].1.clone();
                            ack_state = snapshot;
                            ack_diff_id = diff_id;
                            drop(sent_states.drain(..=pos));
                            ack_dirty = true;
                        }
                    }
                    _ = ticker.tick() => {
                        let (current, rows, cols, is_alt) = {
                            let emu = ss_emu.lock().await;
                            let screen = emu.screen();
                            let formatted = screen.contents_formatted();
                            let (r, c) = screen.size();
                            let alt = screen.alternate_screen();
                            (formatted, r, c, alt)
                        };
                        // Skip expensive parser work when client is fully caught up and
                        // the screen hasn't changed since the last tick.
                        if current == last_current && !ack_dirty && ack_diff_id == diff_counter {
                            continue;
                        }
                        // Clone for cache update; used after `current` may be moved below.
                        let current_for_cache = current.clone();
                        let mut ack_parser = vt100::Parser::new(rows, cols, 0);
                        if !ack_state.is_empty() {
                            // ack_state may be prefixed with \033[?1049h — process as-is so the
                            // parser reconstructs the correct screen mode before diffing.
                            ack_parser.process(&ack_state);
                        }
                        let ack_is_alt = ack_parser.screen().alternate_screen();
                        let mut cur_parser = vt100::Parser::new(rows, cols, 0);
                        cur_parser.process(&current);
                        let mut diff = Vec::new();
                        if is_alt && !ack_is_alt {
                            diff.extend_from_slice(b"\x1b[?1049h");
                        } else if !is_alt && ack_is_alt {
                            diff.extend_from_slice(b"\x1b[?1049l");
                        }
                        let content_diff = cur_parser.screen().contents_diff(ack_parser.screen());
                        if content_diff.is_empty() && diff.is_empty() {
                            last_current = current_for_cache;
                            ack_dirty = false;
                            continue;
                        }
                        diff.extend_from_slice(&content_diff);
                        let compressed = encode_all(diff.as_slice(), 1)
                            .unwrap_or_else(|_| diff.clone());
                        if compressed.len() > MAX_STATESYNC_DIFF_BYTES {
                            // Diff too large for a single UDP datagram (e.g., full alt-screen
                            // repaint from htop over NAT).  Fall back to a chunked full-state push
                            // so fragmented/dropped packets cannot stall the ack pipeline.
                            let full_compressed = encode_all(current.as_slice(), 3)
                                .unwrap_or_else(|_| current.clone());
                            if !send_state_chunked(&ss_tx, full_compressed).await {
                                break;
                            }
                            let mut ack = current;
                            if is_alt {
                                let mut prefixed = b"\x1b[?1049h".to_vec();
                                prefixed.extend_from_slice(&ack);
                                ack = prefixed;
                            }
                            ack_state = ack;
                            ack_diff_id = 0;
                            sent_states.clear();
                        } else {
                            diff_counter += 1;
                            if ss_tx
                                .send(EncryptedFrame::StateSyncDiff((ack_diff_id, diff_counter, compressed)))
                                .await
                                .is_err()
                            {
                                break;
                            }
                            // Store alt-screen-aware snapshot so ack-state reconstruction is correct.
                            let mut snapshot = current;
                            if is_alt {
                                let mut prefixed = b"\x1b[?1049h".to_vec();
                                prefixed.extend_from_slice(&snapshot);
                                snapshot = prefixed;
                            }
                            sent_states.push_back((diff_counter, snapshot));
                            if sent_states.len() > STATESYNC_HISTORY_LEN {
                                drop(sent_states.pop_front());
                            }
                        }
                        last_current = current_for_cache;
                        ack_dirty = false;
                    }
                }
            }
        });
    } else {
        // Reliable and Datagram modes: periodic screen-state sync.
        //
        // Normally every 50 ms, but drops to 10 ms during rapid bursts (Option H).
        // Option C: skip the snapshot when diff chunks are actively flowing to avoid
        // competing with the diff stream; the diff_in_flight flag handles detection.
        let sync_emu = server_emulator.clone();
        let sync_tx = data_tx.clone();
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
                        if delta == 0 {
                            // No PTY output since last tick — double the sleep up to the
                            // maximum, reducing wakeups from 20 Hz toward 0.5 Hz.
                            interval = (interval * 2).min(MAX_SCREEN_SYNC_IDLE_INTERVAL);
                            continue;
                        }
                        // PTY output detected — snap back to the appropriate interval.
                        interval = if delta >= SCREEN_SYNC_BURST_DIRTY_THRESHOLD {
                            SCREEN_SYNC_BURST_INTERVAL
                        } else {
                            SCREEN_SYNC_IDLE_INTERVAL
                        };
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

        // Respond to RepaintRequest frames with an immediate ScreenStateCompressed.
        // Channel capacity 1 coalesces bursts naturally.
        let repaint_emu = server_emulator.clone();
        let repaint_tx_out = data_tx.clone();
        let repaint_token = conn_token.clone();
        let _repaint_on_request = spawn(async move {
            loop {
                select! {
                    () = repaint_token.cancelled() => break,
                    msg = repaint_rx.recv() => {
                        if msg.is_none() {
                            break;
                        }
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

        // Datagram mode: fixed-interval full-screen push as the sole loss-recovery mechanism.
        if diff_mode == DiffMode::Datagram {
            let datagram_emu = server_emulator.clone();
            let datagram_tx = data_tx.clone();
            let datagram_token = conn_token.clone();
            let _datagram_repaint = spawn(async move {
                loop {
                    select! {
                        () = datagram_token.cancelled() => break,
                        () = tokio::time::sleep(DATAGRAM_REPAINT_INTERVAL) => {
                            let contents = {
                                let emu = datagram_emu.lock().await;
                                emu.screen().contents_formatted()
                            };
                            let compressed = encode_all(contents.as_slice(), 3)
                                .unwrap_or_else(|_| contents.clone());
                            if datagram_tx.send(EncryptedFrame::ScreenStateCompressed(compressed)).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    }

    spawn_connection_health_task(
        data_tx.clone(),
        conn_token.clone(),
        nak_received_count,
        effective_mtu.clone(),
        server_emulator.clone(),
    );

    // For new sessions, spawn the long-lived PTY thread.
    if let Some(term_rx) = maybe_term_rx {
        spawn_pty(
            session_uuid,
            skex.user().to_owned(),
            skex.shell().to_owned(),
            term_rx,
            term_tx.clone(),
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
            effective_mtu,
            diff_mode,
            accepted_client_env,
            pty_path,
            namespace_escape,
            use_logind,
            remote_host,
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
    control_tx: Sender<EncryptedFrame>,
    conn_token: CancellationToken,
    server_token: CancellationToken,
) {
    let watcher_tx = control_tx.clone();
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
                    if control_tx.send(EncryptedFrame::Keepalive(ts)).await.is_err() {
                        break;
                    }
                }
            }
        }
    });
}

/// Cancel the connection token if no UDP frame has been received from the client within
/// Send `compressed` as [`EncryptedFrame::ScreenStateCompressed`] if it fits within
/// [`MAX_STATESYNC_DIFF_BYTES`], otherwise split it into [`EncryptedFrame::StateChunk`]
/// frames of at most [`STATE_CHUNK_SIZE`] bytes so every datagram fits within the UDP MTU
/// even over NAT connections that drop IP fragments.
///
/// Returns `false` if the sender channel has closed.
async fn send_state_chunked(ss_tx: &Sender<EncryptedFrame>, compressed: Vec<u8>) -> bool {
    if compressed.len() <= MAX_STATESYNC_DIFF_BYTES {
        ss_tx
            .send(EncryptedFrame::ScreenStateCompressed(compressed))
            .await
            .is_ok()
    } else {
        let chunks: Vec<Vec<u8>> = compressed
            .chunks(STATE_CHUNK_SIZE)
            .map(<[u8]>::to_vec)
            .collect();
        // Max compressed size is MAX_ENCFRAME_LENGTH (64 KiB) / STATE_CHUNK_SIZE (800 B) = 82
        // chunks, well within u16 range.
        let total = u16::try_from(chunks.len()).unwrap_or(u16::MAX);
        for (seq, chunk) in chunks.into_iter().enumerate() {
            let seq_u16 = u16::try_from(seq).unwrap_or(u16::MAX);
            if ss_tx
                .send(EncryptedFrame::StateChunk((seq_u16, total, chunk)))
                .await
                .is_err()
            {
                return false;
            }
        }
        true
    }
}

/// [`CLIENT_SILENCE_TIMEOUT_US`] microseconds.  Fires every 5 s; low overhead.
fn spawn_silence_watchdog(token: CancellationToken, last_rx_us: Arc<AtomicU64>) {
    let _watchdog = spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(5));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            select! {
                () = token.cancelled() => break,
                _ = ticker.tick() => {
                    let elapsed_us = now_micros().saturating_sub(last_rx_us.load(Ordering::Relaxed));
                    if elapsed_us > CLIENT_SILENCE_TIMEOUT_US {
                        info!("Client silence timeout (30 s): cancelling connection");
                        token.cancel();
                        break;
                    }
                }
            }
        }
    });
}

/// Single tick of the MTU probe state machine.
///
/// Returns `Some(new_mtu)` if the effective MTU tier changed this tick; `None` otherwise.
/// Extracted from [`spawn_mtu_probe_task`] so the state-transition logic can be tested
/// without async machinery.
fn mtu_probe_step(
    current_nak: u64,
    last_nak: &mut u64,
    tier: &mut usize,
    quiet_ticks: &mut u32,
    probe_ticks: &mut u32,
    probing: &mut bool,
) -> Option<usize> {
    let delta = current_nak.wrapping_sub(*last_nak);
    *last_nak = current_nak;
    let prev_tier = *tier;
    if *probing {
        if delta >= MTU_PROBE_FAIL_THRESHOLD {
            *tier = (*tier).saturating_sub(1);
            *probing = false;
            *quiet_ticks = 0;
            *probe_ticks = 0;
        } else {
            *probe_ticks += 1;
            if *probe_ticks >= MTU_PROBE_SUCCESS_TICKS {
                *probing = false;
                *quiet_ticks = 0;
                *probe_ticks = 0;
            }
        }
    } else if delta == 0 {
        *quiet_ticks += 1;
        if *quiet_ticks >= MTU_PROBE_QUIET_TICKS && *tier + 1 < MTU_TIERS.len() {
            *tier += 1;
            *probing = true;
            *probe_ticks = 0;
            *quiet_ticks = 0;
        }
    } else {
        *quiet_ticks = 0;
    }
    (*tier != prev_tier).then_some(MTU_TIERS[*tier])
}

/// Spawn a unified connection-health watchdog that combines two 200 ms tasks into one,
/// eliminating a tokio task and timer per connection.
///
/// Per tick it:
/// 1. **MTU probe** — adaptively adjusts the maximum PTY-chunk payload size, probing
///    successively larger tiers after [`MTU_PROBE_QUIET_TICKS`] × 200 ms of zero NAK
///    traffic and reverting on loss spikes (see [`mtu_probe_step`]).
/// 2. **Proactive repaint** — pushes a `ScreenStateCompressed` frame when the NAK delta
///    over the 200 ms window reaches [`PROACTIVE_REPAINT_NAK_THRESHOLD`], breaking the
///    dependency on a `RepaintRequest` that may itself be lost under high-loss conditions.
fn spawn_connection_health_task(
    tx: Sender<EncryptedFrame>,
    token: CancellationToken,
    nak_received_count: Arc<AtomicU64>,
    effective_mtu: Arc<AtomicUsize>,
    server_emulator: Arc<Mutex<vt100::Parser>>,
) {
    let _task = spawn(async move {
        // MTU probe state
        let mut tier: usize = 0;
        let mut last_nak: u64 = 0;
        let mut quiet_ticks: u32 = 0;
        let mut probe_ticks: u32 = 0;
        let mut probing = false;
        // Proactive repaint state
        let mut repaint_last_count: u64 = 0;
        // Backoff state: double the poll interval on each all-quiet tick, up to HEALTH_MAX_INTERVAL.
        let mut health_interval = MTU_POLL_INTERVAL;
        let mut health_quiet_ticks: u32 = 0;
        let mut next_wakeup = TokioInstant::now() + health_interval;
        loop {
            select! {
                () = token.cancelled() => break,
                () = sleep_until(next_wakeup) => {
                    let current = nak_received_count.load(Ordering::Relaxed);
                    // ── MTU probe ─────────────────────────────────────────────────
                    if let Some(new_mtu) = mtu_probe_step(
                        current,
                        &mut last_nak,
                        &mut tier,
                        &mut quiet_ticks,
                        &mut probe_ticks,
                        &mut probing,
                    ) {
                        effective_mtu.store(new_mtu, Ordering::Relaxed);
                    }
                    // ── Proactive repaint ──────────────────────────────────────────
                    let delta = current.wrapping_sub(repaint_last_count);
                    repaint_last_count = current;
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
                    // ── Adaptive backoff ───────────────────────────────────────────
                    // Any NAK activity this window snaps the interval back to the base
                    // rate.  Sustained silence doubles it up to HEALTH_MAX_INTERVAL,
                    // reducing the combined MTU-probe + repaint wakeup rate from 5 Hz
                    // to 0.5 Hz after a few seconds of idle.
                    if delta > 0 {
                        health_quiet_ticks = 0;
                        health_interval = MTU_POLL_INTERVAL;
                    } else {
                        health_quiet_ticks = health_quiet_ticks.saturating_add(1);
                        if health_quiet_ticks >= HEALTH_BACKOFF_TICKS {
                            health_interval =
                                (health_interval * 2).min(HEALTH_MAX_INTERVAL);
                        }
                    }
                    next_wakeup = TokioInstant::now() + health_interval;
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
    data_tx: Sender<EncryptedFrame>,
    control_tx: Sender<EncryptedFrame>,
    full_registry: &FullSessionRegistry,
) -> Result<(
    Sender<TerminalMessage>,
    Option<Receiver<TerminalMessage>>,
    Arc<Mutex<SessionOutputHandle>>,
    Arc<Mutex<VecDeque<u8>>>,
    Arc<Mutex<vt100::Parser>>,
    Arc<AtomicU64>,
    Arc<AtomicBool>,
    Arc<AtomicUsize>,
)> {
    let (term_tx, term_rx) = channel::<TerminalMessage>(256);
    let output_handle = Arc::new(Mutex::new(SessionOutputHandle {
        kex_uuid: kex.uuid(),
        data_tx: Some(data_tx),
        control_tx: Some(control_tx),
        conn_token: Some(conn_token.clone()),
        udp_port: Some(udp_port),
    }));
    let scrollback = Arc::new(Mutex::new(VecDeque::with_capacity(SCROLLBACK_CAPACITY)));
    let server_emulator = Arc::new(Mutex::new(vt100::Parser::new(24, 80, 0)));
    // Start at 1 so the first sync tick always sends an initial screen state.
    let dirty_counter = Arc::new(AtomicU64::new(1));
    let diff_in_flight = Arc::new(AtomicBool::new(false));
    let effective_mtu = Arc::new(AtomicUsize::new(MAX_UDP_PAYLOAD));

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
                effective_mtu: effective_mtu.clone(),
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
        effective_mtu,
    ))
}

/// Scan a byte slice for Primary / Secondary DA query sequences (`ESC [ c` / `ESC [ > c`)
/// emitted by the shell, and return the appropriate response bytes.  Used in `StateSync` mode
/// so the server answers terminal queries locally instead of forwarding them to the client.
fn server_intercept_queries(buf: &[u8], rows: u16, cols: u16) -> Vec<u8> {
    if !buf.contains(&0x1b) {
        return Vec::new();
    }
    let mut resp = Vec::new();
    let mut i = 0;
    while i < buf.len() {
        if buf[i] == 0x1b && i + 1 < buf.len() && buf[i + 1] == b'[' {
            i += 2;
            let marker = if i < buf.len() && matches!(buf[i], b'?' | b'>' | b'=') {
                let m = buf[i];
                i += 1;
                Some(m)
            } else {
                None
            };
            let p0 = i;
            while i < buf.len() && (buf[i].is_ascii_digit() || buf[i] == b';') {
                i += 1;
            }
            let params = &buf[p0..i];
            if i < buf.len() {
                let term = buf[i];
                i += 1;
                match (marker, params, term) {
                    (None, b"" | b"0", b'c') => resp.extend_from_slice(b"\x1b[?62c"),
                    (Some(b'>'), b"" | b"0", b'c') => resp.extend_from_slice(b"\x1b[>1;10;0c"),
                    (Some(b'='), b"" | b"0", b'c') => {
                        resp.extend_from_slice(b"\x1bP!|00000000\x1b\\");
                    }
                    (None, b"5", b'n') => resp.extend_from_slice(b"\x1b[0n"),
                    (Some(b'>'), _, b'q') => resp.extend_from_slice(b"\x1bP>|moshpit\x1b\\"),
                    (None, b"18", b't') => {
                        resp.extend_from_slice(format!("\x1b[8;{rows};{cols}t").as_bytes());
                    }
                    (None, b"14", b't') => resp.extend_from_slice(b"\x1b[4;0;0t"),
                    (None, b"16", b't') => resp.extend_from_slice(b"\x1b[6;0;0t"),
                    _ => {}
                }
            }
        } else {
            i += 1;
        }
    }
    resp
}

/// Spawn the background thread that reads PTY output, writes scrollback, and forwards
/// frames to the currently connected client.  Cleans up session state when the shell exits.
#[cfg_attr(nightly, allow(clippy::too_many_arguments, clippy::too_many_lines))]
#[cfg_attr(coverage_nightly, coverage(off))]
fn spawn_pty_reader(
    session_uuid: Uuid,
    mut term_out: Box<dyn std::io::Read + Send>,
    term_tx: Sender<TerminalMessage>,
    output_handle: Arc<Mutex<SessionOutputHandle>>,
    scrollback: Arc<Mutex<VecDeque<u8>>>,
    server_emulator: Arc<Mutex<vt100::Parser>>,
    dirty_counter: Arc<AtomicU64>,
    diff_in_flight: Arc<AtomicBool>,
    pacing_delay: Duration,
    port_pool: Arc<Mutex<BTreeSet<u16>>>,
    session_registry: SessionRegistry,
    full_registry: FullSessionRegistry,
    effective_mtu: Arc<AtomicUsize>,
    diff_mode: DiffMode,
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

                    server_emulator.blocking_lock().process(buf_slice);
                    let _ = dirty_counter.fetch_add(1, Ordering::Relaxed);

                    let send_ok = {
                        let h = output_handle.blocking_lock();
                        if diff_mode == DiffMode::StateSync {
                            // StateSync: statesync task handles delivery; only feed emulator.
                            // Intercept terminal queries and respond locally so the shell
                            // (e.g. fish) does not time out waiting for a DA response.
                            let (emu_rows, emu_cols) =
                                server_emulator.blocking_lock().screen().size();
                            let resp = server_intercept_queries(buf_slice, emu_rows, emu_cols);
                            if !resp.is_empty() {
                                drop(term_tx.try_send(TerminalMessage::Input(resp)));
                            }
                            drop(h);
                            true
                        } else if let Some(ref sender) = h.data_tx {
                            let uuid_wrapper = UuidWrapper::new(h.kex_uuid);
                            let sender_clone = sender.clone();
                            drop(h);
                            // Signal the screen-sync task that diffs are flowing.
                            diff_in_flight.store(true, Ordering::Relaxed);
                            // zstd level-1: if smaller, fits in one datagram (no burst).
                            // Otherwise chunk by MTU with adaptive inter-packet pacing.
                            if let Ok(compressed) = encode_all(buf_slice, 1)
                                && compressed.len() < buf_slice.len()
                            {
                                let frame =
                                    EncryptedFrame::CompressedBytes((uuid_wrapper, compressed));
                                sender_clone.blocking_send(frame).is_ok()
                            } else {
                                let mut ok = true;
                                let mtu = effective_mtu.load(Ordering::Relaxed);
                                // Bursts > 10 chunks (e.g. htop redraws) get 3× pacing.
                                let n = buf_slice.len().div_ceil(mtu);
                                let burst_pacing = pacing_delay * if n > 10 { 3 } else { 1 };
                                let mut chunks = buf_slice.chunks(mtu).peekable();
                                while let Some(chunk) = chunks.next() {
                                    let more = chunks.peek().is_some();
                                    let frame =
                                        EncryptedFrame::Bytes((uuid_wrapper, chunk.to_vec()));
                                    ok = sender_clone.blocking_send(frame).is_ok();
                                    if !ok {
                                        break;
                                    }
                                    if more && !burst_pacing.is_zero() {
                                        sleep(burst_pacing);
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
                        // Client dropped; clear both channels but keep the PTY running.
                        let mut h = output_handle.blocking_lock();
                        h.data_tx = None;
                        h.control_tx = None;
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

        // Notify the connected client that the PTY process has exited so it can exit
        // immediately instead of waiting for the silence timeout and entering the retry loop.
        {
            let h = output_handle.blocking_lock();
            if let Some(ref tx) = h.control_tx {
                drop(tx.blocking_send(EncryptedFrame::PtyExit));
            }
        }
        // Give the UdpSender one select! tick to deliver PtyExit before the token cancel
        // races with the send.
        sleep(Duration::from_millis(50));

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
            h.data_tx = None;
            h.control_tx = None;
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

#[cfg(unix)]
const PROTECTED_ENV: &[&str] = &["HOME", "USER", "LOGNAME", "SHELL", "TERM", "PATH"];

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
    term_tx: Sender<TerminalMessage>,
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
    effective_mtu: Arc<AtomicUsize>,
    diff_mode: DiffMode,
    #[cfg_attr(not(unix), allow(unused_variables))] accepted_client_env: Vec<(String, String)>,
    #[cfg_attr(not(unix), allow(unused_variables))] pty_path: String,
    #[cfg_attr(not(target_os = "linux"), allow(unused_variables))] namespace_escape: bool,
    #[cfg_attr(not(target_os = "linux"), allow(unused_variables))] use_logind: bool,
    #[cfg_attr(not(target_os = "linux"), allow(unused_variables))] remote_host: Option<String>,
) {
    let _term_handle = thread::spawn(move || {
        let pty_system = native_pty_system();
        let pair = match pty_system.openpty(PtySize {
            rows: 24,
            cols: 80,
            pixel_width: 0,
            pixel_height: 0,
        }) {
            Ok(p) => p,
            Err(e) => {
                error!("Failed to open PTY: {e}");
                return;
            }
        };

        // Held for the lifetime of the PTY thread; dropping it on thread exit
        // releases the logind session (closes the session fifo) when the shell
        // ends.
        #[cfg(target_os = "linux")]
        let mut logind_guard: Option<crate::logind::LogindSession> = None;

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

            let account = match resolve_user_account(&user, &shell) {
                Ok(account) => account,
                Err(e) => {
                    error!("Failed to resolve target account for {user}: {e}");
                    return;
                }
            };

            // Refuse the login like pam_nologin when /etc/nologin exists for a
            // non-root user; we print the file's contents instead of a shell.
            #[cfg(target_os = "linux")]
            let nologin_deny = account.uid != 0 && std::path::Path::new("/etc/nologin").exists();

            // Register a systemd-logind session (XDG_RUNTIME_DIR, user@UID.service,
            // the user D-Bus bus) like an SSH login does via pam_systemd.  Needs
            // root and a permitted (non-nologin) login.
            #[cfg(target_os = "linux")]
            let logind_enabled = use_logind && daemon_uid == 0 && !nologin_deny;
            #[cfg(not(target_os = "linux"))]
            let logind_enabled = false;

            // Program to run: the login shell normally, or — when /etc/nologin
            // denies a non-root login — print that message and exit.
            #[cfg(target_os = "linux")]
            let mut cmd = if nologin_deny {
                let mut cmd = std::process::Command::new("/bin/cat");
                let _ = cmd.arg("/etc/nologin");
                cmd
            } else {
                let mut cmd = std::process::Command::new(&account.shell);
                let _ = cmd.arg("-li");
                cmd
            };
            #[cfg(not(target_os = "linux"))]
            let mut cmd = {
                let mut cmd = std::process::Command::new(&account.shell);
                let _ = cmd.arg("-li");
                cmd
            };

            let _ = cmd.env_clear();

            // /etc/environment (the pam_env system file) is the lowest-precedence
            // source; the protected vars and XDG_RUNTIME_DIR below override it.
            for (k, v) in parse_etc_environment() {
                let _ = cmd.env(k, v);
            }

            let _ = cmd.env("HOME", &account.home);
            let _ = cmd.env("USER", &account.username);
            let _ = cmd.env("LOGNAME", &account.username);
            let _ = cmd.env("SHELL", &account.shell);
            let _ = cmd.env("TERM", &term_type);
            let _ = cmd.env("PATH", &pty_path);

            // XDG_RUNTIME_DIR points at /run/user/UID.  With logind enabled the
            // directory is created as part of the session registered below; in the
            // fallback path we only set it when it already exists.
            let xdg_path = format!("/run/user/{}", account.uid);
            if logind_enabled || std::path::Path::new(&xdg_path).exists() {
                let _ = cmd.env("XDG_RUNTIME_DIR", &xdg_path);
            }

            for (k, v) in &accepted_client_env {
                if PROTECTED_ENV.contains(&k.as_str()) {
                    continue;
                }
                let _ = cmd.env(k, v);
            }

            let Ok(home_cstr) = CString::new(account.home) else {
                error!("Home directory path for {user} contains a NUL byte");
                return;
            };

            let mut drop_creds: Option<(CString, libc::uid_t, libc::gid_t)> = None;

            if daemon_uid == 0 {
                let Ok(username_c) = CString::new(account.username.clone()) else {
                    error!("Target username contains invalid NUL byte");
                    return;
                };
                drop_creds = Some((username_c, account.uid, account.gid));
            }

            // Detect a restricted mount namespace (e.g. systemd ProtectSystem=) and
            // open init's namespace fd so the child can escape into it via setns()
            // before exec.  Only possible when running as root (CAP_SYS_ADMIN).
            // The fd has O_CLOEXEC so it closes automatically at exec even if the
            // child forgets to close it explicitly.
            #[cfg(target_os = "linux")]
            let ns_escape_fd: Option<i32> = if namespace_escape && daemon_uid == 0 {
                use std::os::unix::fs::MetadataExt as _;
                use std::os::unix::io::IntoRawFd as _;
                let self_ino = std::fs::metadata("/proc/self/ns/mnt").ok().map(|m| m.ino());
                let init_ino = std::fs::metadata("/proc/1/ns/mnt").ok().map(|m| m.ino());
                if self_ino.is_some() && self_ino != init_ino {
                    warn!(
                        "Daemon is in a restricted mount namespace (inode {:?} vs PID 1 {:?}); \
                         spawned shell will join the host mount namespace",
                        self_ino, init_ino
                    );
                    match std::fs::File::open("/proc/1/ns/mnt") {
                        Ok(f) => Some(f.into_raw_fd()),
                        Err(e) => {
                            warn!("Cannot open /proc/1/ns/mnt for namespace escape: {e}");
                            None
                        }
                    }
                } else {
                    None
                }
            } else {
                None
            };

            let _ = unsafe {
                cmd.pre_exec(move || {
                    let tiocsctty_request = tiocsctty_ioctl_request();

                    if libc::setsid() < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    if libc::ioctl(0, tiocsctty_request, 0) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }

                    // Escape restricted mount namespace before dropping root — setns(CLONE_NEWNS)
                    // requires CAP_SYS_ADMIN which is lost after setuid().
                    #[cfg(target_os = "linux")]
                    if let Some(fd) = ns_escape_fd {
                        // Non-fatal: if setns fails the shell still spawns in the restricted ns.
                        let _ = libc::setns(fd, libc::CLONE_NEWNS);
                        let _ = libc::close(fd);
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

                    // Set CWD to the user's home directory.
                    // Runs after setns (correct namespace) and after setuid (correct user).
                    // Non-fatal: if home doesn't exist the shell starts at '/', matching SSH.
                    let _ = libc::chdir(home_cstr.as_ptr());

                    Ok(())
                })
            };

            let _ = cmd
                .stdin(Stdio::from(stdin_file))
                .stdout(Stdio::from(stdout_file))
                .stderr(Stdio::from(stderr_file));

            let child = match cmd.spawn() {
                Ok(child) => child,
                Err(e) => {
                    error!("Failed to spawn shell for user {user}: {e}");
                    return;
                }
            };

            // Now that the shell exists, register its logind session using the
            // shell's PID as the session scope leader.  The shell has already
            // exec'd (spawn waits for exec), so the session is registered right
            // after it starts; XDG_RUNTIME_DIR is already set in its env and
            // logind creates /run/user/UID as part of CreateSession.
            #[cfg(target_os = "linux")]
            if logind_enabled {
                let tty_name = tty_path.to_string_lossy();
                let tty_name = tty_name.strip_prefix("/dev/").unwrap_or(&tty_name);
                match crate::logind::create_session(
                    account.uid,
                    child.id(),
                    tty_name,
                    remote_host.as_deref(),
                ) {
                    Ok(session) => {
                        info!(
                            session = %session.session_id,
                            runtime = %session.runtime_path,
                            "registered logind session for {user}"
                        );
                        logind_guard = Some(session);
                    }
                    Err(e) => {
                        warn!(
                            "logind CreateSession failed for {user}: {e:#}; \
                             continuing without a logind session"
                        );
                    }
                }
            }

            // Reap the shell when it exits so it does not linger as a zombie
            // (which would also keep its logind session scope from cleaning up).
            // PTY master EOF — not this wait — drives moshpit session teardown.
            let _reaper = thread::spawn(move || {
                let mut child = child;
                let _exit_status = child.wait();
            });

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

        let term_out = match master.try_clone_reader() {
            Ok(r) => r,
            Err(e) => {
                error!("Failed to clone PTY reader: {e}");
                return;
            }
        };
        let mut term_in = match master.take_writer() {
            Ok(w) => w,
            Err(e) => {
                error!("Failed to take PTY writer: {e}");
                return;
            }
        };

        spawn_pty_reader(
            session_uuid,
            term_out,
            term_tx,
            output_handle,
            scrollback,
            server_emulator.clone(),
            dirty_counter.clone(),
            diff_in_flight,
            pacing_delay,
            port_pool,
            session_registry,
            full_registry,
            effective_mtu,
            diff_mode,
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

        // PTY thread is ending: release the logind session (closes its fifo).
        #[cfg(target_os = "linux")]
        drop(logind_guard);
    });
}

/// Parse `/etc/environment` (the system file `pam_env` reads) into `KEY=VALUE`
/// pairs.  A missing or unreadable file yields an empty list.
#[cfg(unix)]
fn parse_etc_environment() -> Vec<(String, String)> {
    parse_environment_file(&std::fs::read_to_string("/etc/environment").unwrap_or_default())
}

/// Parse the contents of an `/etc/environment`-style file.  Blank lines and
/// `#` comments are ignored, an optional `export ` prefix is stripped, and a
/// single pair of surrounding single or double quotes is removed from values.
#[cfg(unix)]
fn parse_environment_file(contents: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").map_or(line, str::trim_start);
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if key.is_empty() {
            continue;
        }
        let value = value.trim();
        let value = value
            .strip_prefix('"')
            .and_then(|v| v.strip_suffix('"'))
            .or_else(|| value.strip_prefix('\'').and_then(|v| v.strip_suffix('\'')))
            .unwrap_or(value);
        out.push((key.to_string(), value.to_string()));
    }
    out
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
    use super::{
        current_daemon_user, parse_environment_file, parse_etc_environment, resolve_user_account,
    };
    use std::{
        sync::{
            Arc,
            atomic::{AtomicU64, AtomicUsize, Ordering},
        },
        time::Duration,
    };

    use super::{
        MAX_STATESYNC_DIFF_BYTES, MTU_PROBE_FAIL_THRESHOLD, MTU_PROBE_QUIET_TICKS,
        MTU_PROBE_SUCCESS_TICKS, MTU_TIERS, PROACTIVE_REPAINT_NAK_THRESHOLD, STATE_CHUNK_SIZE,
        mtu_probe_step, new_full_registry, new_session, now_micros, resolve_session,
        send_state_chunked, server_intercept_queries, spawn_connection_health_task,
        spawn_connection_watchdogs, spawn_silence_watchdog,
    };

    #[cfg(unix)]
    #[test]
    fn current_daemon_user_returns_some() {
        let user = current_daemon_user();
        assert!(user.is_some());
    }

    #[cfg(unix)]
    #[test]
    fn parse_environment_file_basic() {
        let contents = "\
            # a comment\n\
            \n\
            FOO=bar\n\
            export BAZ=qux\n\
            QUOTED=\"hello world\"\n\
            SINGLE='tick'\n\
            PATH=/usr/bin:/bin\n\
            =novalue\n\
            NOEQUALS\n";
        let parsed = parse_environment_file(contents);
        assert_eq!(
            parsed,
            vec![
                ("FOO".to_string(), "bar".to_string()),
                ("BAZ".to_string(), "qux".to_string()),
                ("QUOTED".to_string(), "hello world".to_string()),
                ("SINGLE".to_string(), "tick".to_string()),
                ("PATH".to_string(), "/usr/bin:/bin".to_string()),
            ]
        );
    }

    #[cfg(unix)]
    #[test]
    fn parse_environment_file_empty() {
        assert!(parse_environment_file("").is_empty());
        assert!(parse_environment_file("# only a comment\n\n").is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn parse_etc_environment_reads_system_file() {
        // Exercises the wrapper; reads the host's real /etc/environment, or
        // yields an empty Vec when the file is absent. Host-independent — every
        // entry is a non-empty key parsed from a `KEY=VALUE` line.
        for (key, _value) in parse_etc_environment() {
            assert!(!key.is_empty());
        }
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
    async fn new_session_registers_in_full_registry() -> anyhow::Result<()> {
        let kex = Kex::default();
        let conn_token = CancellationToken::new();
        let (data_tx, _data_rx) = channel::<EncryptedFrame>(4);
        let (control_tx, _control_rx) = channel::<EncryptedFrame>(4);
        let session_uuid = Uuid::new_v4();
        let registry = new_full_registry();

        let _reg_result = new_session(
            &kex,
            &conn_token,
            50_000,
            session_uuid,
            data_tx,
            control_tx,
            &registry,
        )
        .await?;

        assert!(registry.lock().await.contains_key(&session_uuid));
        Ok(())
    }

    #[tokio::test]
    async fn new_session_returns_some_term_rx() -> anyhow::Result<()> {
        let kex = Kex::default();
        let conn_token = CancellationToken::new();
        let (data_tx, _data_rx) = channel::<EncryptedFrame>(4);
        let (control_tx, _control_rx) = channel::<EncryptedFrame>(4);
        let session_uuid = Uuid::new_v4();
        let registry = new_full_registry();

        let (_, maybe_rx, _, _, _, _, _, _) = new_session(
            &kex,
            &conn_token,
            50_000,
            session_uuid,
            data_tx,
            control_tx,
            &registry,
        )
        .await?;
        assert!(maybe_rx.is_some());
        Ok(())
    }

    #[tokio::test]
    async fn new_session_output_handle_has_correct_kex_uuid() -> anyhow::Result<()> {
        let kex = Kex::default();
        let conn_token = CancellationToken::new();
        let (data_tx, _data_rx) = channel::<EncryptedFrame>(4);
        let (control_tx, _control_rx) = channel::<EncryptedFrame>(4);
        let session_uuid = Uuid::new_v4();
        let registry = new_full_registry();

        let (_, _, output_handle, _, _, _, _, _) = new_session(
            &kex,
            &conn_token,
            50_000,
            session_uuid,
            data_tx,
            control_tx,
            &registry,
        )
        .await?;
        assert_eq!(output_handle.lock().await.kex_uuid, kex.uuid());
        Ok(())
    }

    #[tokio::test]
    async fn new_session_scrollback_initially_empty() -> anyhow::Result<()> {
        let kex = Kex::default();
        let conn_token = CancellationToken::new();
        let (data_tx, _data_rx) = channel::<EncryptedFrame>(4);
        let (control_tx, _control_rx) = channel::<EncryptedFrame>(4);
        let session_uuid = Uuid::new_v4();
        let registry = new_full_registry();

        let (_, _, _, scrollback, _, _, _, _) = new_session(
            &kex,
            &conn_token,
            50_000,
            session_uuid,
            data_tx,
            control_tx,
            &registry,
        )
        .await?;
        assert!(scrollback.lock().await.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn new_session_emulator_default_size() -> anyhow::Result<()> {
        let kex = Kex::default();
        let conn_token = CancellationToken::new();
        let (data_tx, _data_rx) = channel::<EncryptedFrame>(4);
        let (control_tx, _control_rx) = channel::<EncryptedFrame>(4);
        let session_uuid = Uuid::new_v4();
        let registry = new_full_registry();

        let (_, _, _, _, emulator, _, _, _) = new_session(
            &kex,
            &conn_token,
            50_000,
            session_uuid,
            data_tx,
            control_tx,
            &registry,
        )
        .await?;
        let emu = emulator.lock().await;
        let screen = emu.screen();
        assert_eq!(screen.size(), (24, 80));
        Ok(())
    }

    // ── Phase 9: spawn_connection_watchdogs ────────────────────────────────────

    #[tokio::test]
    async fn watchdogs_keepalive_sends_frame() {
        let (control_tx, mut control_rx) = channel::<EncryptedFrame>(4);
        let conn_token = CancellationToken::new();
        let server_token = CancellationToken::new();
        spawn_connection_watchdogs(control_tx, conn_token.clone(), server_token);

        // The keepalive fires every 3 s with an immediate first tick.
        let frame = tokio::time::timeout(Duration::from_millis(200), control_rx.recv()).await;
        conn_token.cancel();
        let frame = frame
            .expect("timeout waiting for keepalive")
            .expect("channel closed");
        assert!(matches!(frame, EncryptedFrame::Keepalive(_)));
    }

    #[tokio::test]
    async fn watchdogs_server_cancel_sends_shutdown_then_cancels_conn() {
        let (control_tx, mut control_rx) = channel::<EncryptedFrame>(4);
        let conn_token = CancellationToken::new();
        let server_token = CancellationToken::new();
        spawn_connection_watchdogs(control_tx, conn_token.clone(), server_token.clone());

        server_token.cancel();

        // Allow the watcher task to run
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Drain frames looking for Shutdown
        let mut saw_shutdown = false;
        while let Ok(frame) = control_rx.try_recv() {
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
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(conn_token.is_cancelled());
    }

    #[tokio::test]
    async fn watchdogs_conn_cancel_stops_keepalive() {
        let (control_tx, mut control_rx) = channel::<EncryptedFrame>(4);
        let conn_token = CancellationToken::new();
        let server_token = CancellationToken::new();
        spawn_connection_watchdogs(control_tx, conn_token.clone(), server_token);

        // Cancel immediately — keepalive loop should stop
        conn_token.cancel();
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Drain any already-queued frames
        while control_rx.try_recv().is_ok() {}
        // No further Keepalive frames should arrive
        let result = tokio::time::timeout(Duration::from_millis(100), control_rx.recv()).await;
        // Either timeout (no frame) or channel closed — both are acceptable
        assert!(result.map_or(true, |v| v.is_none()));
    }

    // ── Phase 10: resolve_session ─────────────────────────────────────────────

    #[tokio::test]
    async fn resolve_session_new_session_path() -> anyhow::Result<()> {
        let kex = Kex::default();
        let session_uuid = Uuid::new_v4();
        let skex = ServerKex::builder()
            .user("alice".to_string())
            .shell("/usr/bin/fish".to_string())
            .session_uuid(session_uuid)
            .build();
        let conn_token = CancellationToken::new();
        let (data_tx, _data_rx) = channel::<EncryptedFrame>(4);
        let (control_tx, _control_rx) = channel::<EncryptedFrame>(4);
        let registry = new_full_registry();

        let (_, maybe_rx, _, _, _, _, _, _) = resolve_session(
            &kex,
            &skex,
            &conn_token,
            50_000,
            data_tx,
            control_tx,
            &registry,
        )
        .await?;
        // New session → PTY needs to be spawned → Some(term_rx)
        assert!(maybe_rx.is_some());
        Ok(())
    }

    #[tokio::test]
    async fn resolve_session_resume_existing() -> anyhow::Result<()> {
        let kex = Kex::default();
        let session_uuid = Uuid::new_v4();
        let conn_token = CancellationToken::new();
        let (data_tx, _data_rx) = channel::<EncryptedFrame>(16);
        let (control_tx, _control_rx) = channel::<EncryptedFrame>(4);
        let registry = new_full_registry();

        // First connection: create a session
        let _first_session = new_session(
            &kex,
            &conn_token,
            50_000,
            session_uuid,
            data_tx.clone(),
            control_tx.clone(),
            &registry,
        )
        .await?;

        // Second connection: resume
        let new_kex = Kex::default();
        let skex_resume = ServerKex::builder()
            .user("alice".to_string())
            .shell("/usr/bin/fish".to_string())
            .session_uuid(session_uuid)
            .is_resume(true)
            .build();
        let new_conn_token = CancellationToken::new();
        let (resume_data_tx, mut resume_data_rx) = channel::<EncryptedFrame>(16);
        let (resume_ctrl_tx, _resume_ctrl_rx) = channel::<EncryptedFrame>(4);

        let (_, maybe_rx, output_handle, _, _, _, _, _) = resolve_session(
            &new_kex,
            &skex_resume,
            &new_conn_token,
            50_001,
            resume_data_tx,
            resume_ctrl_tx,
            &registry,
        )
        .await?;

        // Resume → no new PTY → None
        assert!(maybe_rx.is_none());
        // Output handle should be updated with the new kex uuid
        assert_eq!(output_handle.lock().await.kex_uuid, new_kex.uuid());
        // A ScreenState frame should have been sent on the *new* connection's data channel
        let mut saw_screen_state = false;
        while let Ok(frame) = resume_data_rx.try_recv() {
            if matches!(
                frame,
                EncryptedFrame::ScreenState(_) | EncryptedFrame::ScreenStateCompressed(_)
            ) {
                saw_screen_state = true;
                break;
            }
        }
        assert!(saw_screen_state, "expected ScreenState frame on resume");
        Ok(())
    }

    #[tokio::test]
    async fn resolve_session_resume_expired() -> anyhow::Result<()> {
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
        let (data_tx, _data_rx) = channel::<EncryptedFrame>(4);
        let (control_tx, _control_rx) = channel::<EncryptedFrame>(4);
        let registry = new_full_registry();

        let (_, maybe_rx, _, _, _, _, _, _) = resolve_session(
            &kex,
            &skex,
            &conn_token,
            50_000,
            data_tx,
            control_tx,
            &registry,
        )
        .await?;
        // Falls back to new session → Some(term_rx)
        assert!(maybe_rx.is_some());
        Ok(())
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

    // ── Phase 9: mtu_probe_step (state machine unit tests) ────────────────────

    fn make_probe_state() -> (usize, u64, u32, u32, bool) {
        (0usize, 0u64, 0u32, 0u32, false)
    }

    #[test]
    fn mtu_probe_step_starts_at_base_mtu() {
        let (mut tier, mut last_nak, mut qt, mut pt, mut probing) = make_probe_state();
        let result = mtu_probe_step(0, &mut last_nak, &mut tier, &mut qt, &mut pt, &mut probing);
        assert!(result.is_none(), "no tier change on first quiet tick");
        assert_eq!(tier, 0);
    }

    #[test]
    fn mtu_probe_step_advances_tier_after_quiet_period() {
        let (mut tier, mut last_nak, mut qt, mut pt, mut probing) = make_probe_state();
        let mut changed = None;
        for _ in 0..MTU_PROBE_QUIET_TICKS {
            changed = mtu_probe_step(0, &mut last_nak, &mut tier, &mut qt, &mut pt, &mut probing);
        }
        assert_eq!(
            changed,
            Some(MTU_TIERS[1]),
            "tier upgrades on Nth quiet tick"
        );
        assert_eq!(tier, 1);
        assert!(probing);
    }

    #[test]
    fn mtu_probe_step_reverts_on_nak_spike_during_probe() {
        let (mut tier, mut last_nak, mut qt, mut pt, mut probing) = make_probe_state();
        // Advance to probing state.
        for _ in 0..MTU_PROBE_QUIET_TICKS {
            let _ = mtu_probe_step(0, &mut last_nak, &mut tier, &mut qt, &mut pt, &mut probing);
        }
        assert_eq!(tier, 1);
        assert!(probing);
        // Spike above the failure threshold.
        let nak = MTU_PROBE_FAIL_THRESHOLD;
        let result = mtu_probe_step(
            nak,
            &mut last_nak,
            &mut tier,
            &mut qt,
            &mut pt,
            &mut probing,
        );
        assert_eq!(result, Some(MTU_TIERS[0]), "tier reverts on NAK spike");
        assert_eq!(tier, 0);
        assert!(!probing);
    }

    #[test]
    fn mtu_probe_step_confirms_upgrade_after_success_ticks() {
        let (mut tier, mut last_nak, mut qt, mut pt, mut probing) = make_probe_state();
        for _ in 0..MTU_PROBE_QUIET_TICKS {
            let _ = mtu_probe_step(0, &mut last_nak, &mut tier, &mut qt, &mut pt, &mut probing);
        }
        assert!(probing, "should be probing after quiet period");
        // Run through all success ticks with zero NAK delta.
        for _ in 0..MTU_PROBE_SUCCESS_TICKS {
            let _ = mtu_probe_step(0, &mut last_nak, &mut tier, &mut qt, &mut pt, &mut probing);
        }
        assert!(!probing, "probe confirmed — no longer probing");
        assert_eq!(tier, 1, "tier stays at 1 after confirmation");
    }

    #[test]
    fn mtu_probe_step_no_upgrade_below_threshold() {
        let (mut tier, mut last_nak, mut qt, mut pt, mut probing) = make_probe_state();
        // Run one tick short of the upgrade threshold.
        for _ in 0..MTU_PROBE_QUIET_TICKS - 1 {
            let _ = mtu_probe_step(0, &mut last_nak, &mut tier, &mut qt, &mut pt, &mut probing);
        }
        assert_eq!(tier, 0, "no upgrade before quiet threshold");
        assert!(!probing);
    }

    #[test]
    fn mtu_probe_step_resets_quiet_on_any_nak() {
        let (mut tier, mut last_nak, mut qt, mut pt, mut probing) = make_probe_state();
        for _ in 0..MTU_PROBE_QUIET_TICKS - 1 {
            let _ = mtu_probe_step(0, &mut last_nak, &mut tier, &mut qt, &mut pt, &mut probing);
        }
        // One NAK resets quiet counter.
        let _ = mtu_probe_step(1, &mut last_nak, &mut tier, &mut qt, &mut pt, &mut probing);
        // Need a full quiet period again before upgrade.
        for _ in 0..MTU_PROBE_QUIET_TICKS - 1 {
            let _ = mtu_probe_step(1, &mut last_nak, &mut tier, &mut qt, &mut pt, &mut probing);
        }
        assert_eq!(tier, 0, "quiet counter reset — no upgrade yet");
    }

    #[tokio::test]
    async fn mtu_probe_task_starts_at_base_mtu() {
        let (tx, _rx) = channel::<EncryptedFrame>(4);
        let token = CancellationToken::new();
        let nak_count = Arc::new(AtomicU64::new(0));
        let effective_mtu = Arc::new(AtomicUsize::new(MTU_TIERS[0]));
        let emulator = Arc::new(tokio::sync::Mutex::new(vt100::Parser::new(24, 80, 0)));
        spawn_connection_health_task(
            tx,
            token.clone(),
            nak_count,
            effective_mtu.clone(),
            emulator,
        );
        token.cancel();
        assert_eq!(effective_mtu.load(Ordering::Relaxed), MTU_TIERS[0]);
    }

    // ── Phase 8: spawn_connection_health_task (proactive repaint) ─────────────

    #[tokio::test]
    async fn proactive_repaint_fires_on_nak_saturation() {
        let (tx, mut rx) = channel::<EncryptedFrame>(4);
        let token = CancellationToken::new();
        let nak_count = Arc::new(AtomicU64::new(0));
        let effective_mtu = Arc::new(AtomicUsize::new(MTU_TIERS[0]));
        let emulator = Arc::new(tokio::sync::Mutex::new(vt100::Parser::new(24, 80, 0)));

        spawn_connection_health_task(
            tx,
            token.clone(),
            nak_count.clone(),
            effective_mtu,
            emulator,
        );

        // Bump the counter above the threshold so the first watchdog tick triggers a push.
        nak_count.store(PROACTIVE_REPAINT_NAK_THRESHOLD, Ordering::Relaxed);

        // The watchdog polls every 200 ms — give it up to 500 ms to fire.
        let frame = tokio::time::timeout(Duration::from_millis(500), rx.recv()).await;
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
        let effective_mtu = Arc::new(AtomicUsize::new(MTU_TIERS[0]));
        let emulator = Arc::new(tokio::sync::Mutex::new(vt100::Parser::new(24, 80, 0)));

        spawn_connection_health_task(
            tx,
            token.clone(),
            nak_count.clone(),
            effective_mtu,
            emulator,
        );

        // Set count one below the threshold.
        nak_count.store(PROACTIVE_REPAINT_NAK_THRESHOLD - 1, Ordering::Relaxed);

        // Wait for at least one poll cycle — no frame should arrive.
        let result = tokio::time::timeout(Duration::from_millis(300), rx.recv()).await;
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
        let effective_mtu = Arc::new(AtomicUsize::new(MTU_TIERS[0]));
        let emulator = Arc::new(tokio::sync::Mutex::new(vt100::Parser::new(24, 80, 0)));

        spawn_connection_health_task(tx, token.clone(), nak_count, effective_mtu, emulator);

        // Cancel immediately before any tick fires.
        token.cancel();
        tokio::time::sleep(Duration::from_millis(250)).await;

        // Channel should be drained and no further frames arrive.
        while rx.try_recv().is_ok() {}
        let result = tokio::time::timeout(Duration::from_millis(100), rx.recv()).await;
        assert!(
            result.map_or(true, |v| v.is_none()),
            "watchdog kept sending after cancellation"
        );
    }

    // ── send_state_chunked ────────────────────────────────────────────────────

    #[tokio::test]
    async fn send_state_chunked_small_payload_sends_screen_state_compressed() {
        let (tx, mut rx) = channel::<EncryptedFrame>(8);
        let payload = vec![0u8; MAX_STATESYNC_DIFF_BYTES];
        let sent = send_state_chunked(&tx, payload.clone()).await;
        assert!(sent);
        let frame = rx.try_recv().expect("expected a frame");
        assert!(
            matches!(frame, EncryptedFrame::ScreenStateCompressed(ref d) if *d == payload),
            "expected ScreenStateCompressed, got {frame:?}"
        );
        assert!(rx.try_recv().is_err(), "expected exactly one frame");
    }

    #[tokio::test]
    async fn send_state_chunked_large_payload_sends_state_chunks() -> anyhow::Result<()> {
        let (tx, mut rx) = channel::<EncryptedFrame>(128);
        let payload = vec![0xABu8; MAX_STATESYNC_DIFF_BYTES + STATE_CHUNK_SIZE + 1];
        let sent = send_state_chunked(&tx, payload.clone()).await;
        assert!(sent);

        let expected_chunks = payload.chunks(STATE_CHUNK_SIZE).count();
        let total = u16::try_from(expected_chunks)?;
        let mut received = 0usize;
        while let Ok(frame) = rx.try_recv() {
            let EncryptedFrame::StateChunk((seq, t, data)) = frame else {
                panic!("expected StateChunk, got {frame:?}");
            };
            assert_eq!(seq, u16::try_from(received)?);
            assert_eq!(t, total);
            let expected_slice = &payload[received * STATE_CHUNK_SIZE
                ..((received + 1) * STATE_CHUNK_SIZE).min(payload.len())];
            assert_eq!(data, expected_slice);
            received += 1;
        }
        assert_eq!(received, expected_chunks);
        Ok(())
    }

    #[tokio::test]
    async fn send_state_chunked_closed_channel_returns_false() {
        let (tx, rx) = channel::<EncryptedFrame>(8);
        drop(rx);
        let payload = vec![0u8; MAX_STATESYNC_DIFF_BYTES + 1];
        let sent = send_state_chunked(&tx, payload).await;
        assert!(!sent);
    }

    // ── server_intercept_queries ──────────────────────────────────────────────

    #[test]
    fn server_intercept_queries_no_escape_returns_empty() {
        assert!(server_intercept_queries(b"hello world", 24, 80).is_empty());
    }

    #[test]
    fn server_intercept_queries_primary_da_returns_vt220() {
        assert_eq!(server_intercept_queries(b"\x1b[c", 24, 80), b"\x1b[?62c");
        assert_eq!(server_intercept_queries(b"\x1b[0c", 24, 80), b"\x1b[?62c");
    }

    #[test]
    fn server_intercept_queries_secondary_da_returns_response() {
        assert_eq!(
            server_intercept_queries(b"\x1b[>c", 24, 80),
            b"\x1b[>1;10;0c"
        );
        assert_eq!(
            server_intercept_queries(b"\x1b[>0c", 24, 80),
            b"\x1b[>1;10;0c"
        );
    }

    #[test]
    fn server_intercept_queries_tertiary_da_returns_response() {
        assert_eq!(
            server_intercept_queries(b"\x1b[=c", 24, 80),
            b"\x1bP!|00000000\x1b\\"
        );
        assert_eq!(
            server_intercept_queries(b"\x1b[=0c", 24, 80),
            b"\x1bP!|00000000\x1b\\"
        );
    }

    #[test]
    fn server_intercept_queries_dsr_returns_device_ok() {
        assert_eq!(server_intercept_queries(b"\x1b[5n", 24, 80), b"\x1b[0n");
    }

    #[test]
    fn server_intercept_queries_xtversion_returns_identity() {
        let resp = server_intercept_queries(b"\x1b[>q", 24, 80);
        assert_eq!(resp, b"\x1bP>|moshpit\x1b\\");
    }

    #[test]
    fn server_intercept_queries_xtwinops_18_returns_terminal_size() {
        let resp = server_intercept_queries(b"\x1b[18t", 30, 120);
        assert_eq!(resp, b"\x1b[8;30;120t");
    }

    #[test]
    fn server_intercept_queries_xtwinops_pixel_sizes_return_zeros() {
        assert_eq!(
            server_intercept_queries(b"\x1b[14t", 24, 80),
            b"\x1b[4;0;0t"
        );
        assert_eq!(
            server_intercept_queries(b"\x1b[16t", 24, 80),
            b"\x1b[6;0;0t"
        );
    }

    #[test]
    fn server_intercept_queries_unknown_sequence_returns_empty() {
        // Mode set — not a query
        assert!(server_intercept_queries(b"\x1b[?25h", 24, 80).is_empty());
        // Cursor position report — handled client-side, not server-side
        assert!(server_intercept_queries(b"\x1b[6n", 24, 80).is_empty());
    }

    #[test]
    fn server_intercept_queries_multiple_queries_returns_both_responses() {
        let input = b"\x1b[c\x1b[>c";
        let resp = server_intercept_queries(input, 24, 80);
        assert!(
            resp.starts_with(b"\x1b[?62c"),
            "missing primary DA response"
        );
        assert!(
            resp.ends_with(b"\x1b[>1;10;0c"),
            "missing secondary DA response"
        );
    }

    // ── spawn_silence_watchdog ────────────────────────────────────────────────

    #[tokio::test(start_paused = true)]
    async fn silence_watchdog_fires_on_stale_timestamp() {
        let token = CancellationToken::new();
        let last_rx_us = Arc::new(AtomicU64::new(0));
        spawn_silence_watchdog(token.clone(), last_rx_us);

        // Advance past two 5-second ticker intervals + the 30-second silence threshold.
        tokio::time::advance(Duration::from_secs(35)).await;
        // Yield so the spawned task can run.
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;

        assert!(
            token.is_cancelled(),
            "watchdog should have cancelled the token"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn silence_watchdog_does_not_fire_when_recently_active() {
        let token = CancellationToken::new();
        let last_rx_us = Arc::new(AtomicU64::new(now_micros()));
        spawn_silence_watchdog(token.clone(), last_rx_us.clone());

        // Advance one tick (5s) — well within the 30s silence threshold.
        tokio::time::advance(Duration::from_secs(5)).await;
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;

        assert!(
            !token.is_cancelled(),
            "watchdog should not fire within 30s silence threshold"
        );
        token.cancel();
    }

    #[tokio::test(start_paused = true)]
    async fn silence_watchdog_stops_on_explicit_cancel() {
        let token = CancellationToken::new();
        let last_rx_us = Arc::new(AtomicU64::new(0));
        spawn_silence_watchdog(token.clone(), last_rx_us);

        token.cancel();
        // Even with a stale timestamp the watchdog should not panic or loop.
        tokio::time::advance(Duration::from_mins(1)).await;
        tokio::task::yield_now().await;
        // Token is cancelled — just verify no crash.
        assert!(token.is_cancelled());
    }
}
