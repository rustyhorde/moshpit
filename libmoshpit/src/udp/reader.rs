// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

use std::{
    collections::{BTreeMap, HashMap, HashSet, hash_map::Entry},
    future::pending,
    io::Cursor,
    mem::take,
    net::SocketAddr,
    process,
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use ansi_control_codes::{
    c0, c1,
    parser::{Token, TokenStream},
};
use anyhow::Result;
use aws_lc_rs::{aead::LessSafeKey, hmac::Key};
use bon::Builder;
use bytes::BytesMut;
use tokio::{
    net::UdpSocket,
    select,
    sync::{mpsc::Sender, oneshot},
    time::{Instant as TokioInstant, sleep_until},
};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};
use uuid::Uuid;
use zstd::decode_all;

use super::DiffMode;
use crate::{
    Emulator, EncryptedFrame, MoshpitError, PredictionEngine, Renderer, TerminalMessage,
    UuidWrapper, paint_overlays_to_ansi, render_server_update, udp::sender::RETRANSMIT_WINDOW,
    utils::is_exit_title,
};

/// Floor for the adaptive NAK check interval.  On LAN paths where `nak_timeout`
/// converges to [`MIN_NAK_TIMEOUT`] (20 ms), the check fires every 5 ms; on
/// high-latency paths (500 ms) it fires every 125 ms, saving CPU and state-machine
/// churn.  Formula: `max(nak_timeout / 4, MIN_NAK_CHECK_INTERVAL)`.
const MIN_NAK_CHECK_INTERVAL: Duration = Duration::from_millis(5);
/// Minimum delay before requesting retransmission of a missing packet.
const NAK_TIMEOUT: Duration = Duration::from_millis(50);
/// Maximum backoff cap for repeated NAK retries (50 * 2^4 = 800 ms).
const NAK_BACKOFF_MAX_SHIFT: u32 = 4;
/// Maximum number of NAK retries before giving up on a permanently lost packet.
const MAX_NAK_RETRIES: u32 = 4;
/// Number of NAK retries after which the client sends a [`EncryptedFrame::RepaintRequest`]
/// to the server.  Fires exactly once per gap (when retry count reaches this value),
/// asking for an out-of-band full-screen snapshot to unblock the display without waiting
/// for retransmit to succeed or retry exhaustion.
const REPAINT_REQUEST_THRESHOLD: u32 = 1;
/// Number of frames buffered out-of-order before an immediate [`EncryptedFrame::RepaintRequest`]
/// is sent.  A large `recv_buffer` means many gaps exist simultaneously — the display is
/// stalled.  Firing early skips waiting for the first NAK retry cycle (~50 ms).
/// Set to 5 so that high-output programs (htop, vim) trigger fast repaint recovery
/// before a large backlog accumulates; at 1200 bytes/frame, 5 frames ≈ 6 KB of stall.
const RECV_BUFFER_REPAINT_THRESHOLD: usize = 5;
/// Maximum sequence jump allowed before dropping the frame to prevent `DoS`.
const MAX_SEQ_JUMP: u64 = 1024;
/// Floor for the adaptive NAK timeout EWMA estimate.
const MIN_NAK_TIMEOUT: Duration = Duration::from_millis(20);
/// Ceiling for the adaptive NAK timeout EWMA estimate.
const MAX_NAK_TIMEOUT: Duration = Duration::from_millis(500);

/// UDP reader for encrypted frames
#[derive(Builder, Debug)]
pub struct UdpReader {
    /// Underlying UDP socket
    socket: Arc<UdpSocket>,
    /// Client UUID
    id: Uuid,
    /// Key for decrypting UDP packets
    rnk: LessSafeKey,
    /// Key for verifying UDP packet HMAC
    hmac: Key,
    /// Byte length of the MAC tag written by the peer's HMAC algorithm.
    /// 64 for HMAC-SHA512 (default), 32 for HMAC-SHA256.
    #[builder(default = 64)]
    mac_tag_len: usize,
    /// Injects NAK frames into the outbound stream when gaps are detected
    nak_out_tx: Option<Sender<EncryptedFrame>>,
    /// Tells the local sender to retransmit when a NAK from the peer is received
    retransmit_tx: Option<Sender<Vec<u64>>>,
    /// Next expected sequence number
    #[builder(default)]
    next_seq: u64,
    /// Out-of-order frames waiting for missing predecessors
    #[builder(default)]
    recv_buffer: BTreeMap<u64, EncryptedFrame>,
    /// Tracks when each gap was first detected for NAK timeout
    #[builder(default)]
    gap_first_seen: HashMap<u64, Instant>,
    /// Number of NAK retries per gap, used to give up on permanently lost packets
    #[builder(default)]
    gap_nak_count: HashMap<u64, u32>,
    /// Per-gap NAK send timestamps for RTT measurement.  Populated when a NAK is
    /// sent; consumed when the gap closes to produce a round-trip sample for the
    /// adaptive EWMA.
    #[builder(default)]
    gap_nak_sent_at: HashMap<u64, Instant>,
    /// Highest sequence number ever received (excluding duplicates).
    /// Used to detect when a gap has fallen outside the sender's retransmit
    /// window so the client can give up immediately instead of waiting for
    /// [`MAX_NAK_RETRIES`] retries.
    #[builder(default)]
    highest_seq_seen: u64,
    /// Jacobson-Karels smoothed RTT (SRTT), RFC 6298 §2.
    /// `None` until the first NAK round-trip sample is observed.
    srtt: Option<Duration>,
    /// Jacobson-Karels RTT variance (RTTVAR), RFC 6298 §2.
    /// `None` until the first NAK round-trip sample is observed.
    rttvar: Option<Duration>,
    /// Retransmission timeout (RTO) derived from the Jacobson-Karels estimator:
    /// `RTO = SRTT + 4 × RTTVAR`, clamped to [`MIN_NAK_TIMEOUT`]..=[`MAX_NAK_TIMEOUT`].
    /// `None` falls back to [`NAK_TIMEOUT`] (50 ms).
    nak_timeout: Option<Duration>,
    /// If no frame is received within this duration the server is assumed unreachable.
    /// Triggers reconnect via [`reconnect_tx`](Self::reconnect_tx) when set, otherwise calls
    /// [`process::exit`].
    silence_timeout: Option<Duration>,
    /// Signals the caller that the server connection was lost and a reconnect should
    /// be attempted.  When absent, connection loss falls back to [`process::exit`].
    reconnect_tx: Option<Sender<()>>,
    /// Used by the client to send immediate responses to terminal queries (DSR/DA)
    /// that arrive from the server, without routing them through the local terminal.
    /// Prevents latency-induced query responses from appearing as keyboard input.
    query_response_tx: Option<Sender<EncryptedFrame>>,
    /// Foreground color returned for OSC 10 queries from the server shell.
    /// Format: `rgb:RRRR/GGGG/BBBB`.  Defaults to a light-gray when `None`.
    terminal_fg_color: Option<String>,
    /// Background color returned for OSC 11 queries from the server shell.
    /// Format: `rgb:RRRR/GGGG/BBBB`.  Defaults to a dark background when `None`.
    terminal_bg_color: Option<String>,
    /// Oneshot sender fired after the server has discovered the client's real post-NAT
    /// address via the first `recv_from`.  Carries the initial peer `SocketAddr` so
    /// that [`UdpSender`](crate::UdpSender) knows where to send before any roam event.
    peer_discovered_tx: Option<oneshot::Sender<SocketAddr>>,
    /// Signals mid-session NAT roam events to [`UdpSender`](crate::UdpSender).
    /// Sent whenever an authenticated packet arrives from a new source address.
    peer_addr_tx: Option<Sender<SocketAddr>>,
    /// Fired by the server's [`server_frame_loop`](Self::server_frame_loop) when a
    /// [`EncryptedFrame::RepaintRequest`] arrives from the client.  The paired receiver
    /// is held by a task in `moshpits` that responds with an immediate
    /// [`EncryptedFrame::ScreenState`].
    repaint_tx: Option<Sender<()>>,
    /// Running count of [`EncryptedFrame::Nak`] frames received from the client
    /// (server mode only).  The proactive-repaint watchdog in `moshpits` polls this
    /// counter every 200 ms; when the delta exceeds the saturation threshold a full
    /// [`EncryptedFrame::ScreenStateCompressed`] is pushed without waiting for an
    /// explicit [`EncryptedFrame::RepaintRequest`] that might itself be lost.
    nak_received_count: Option<Arc<AtomicU64>>,
    /// UDP diff transport mode for this session.
    /// In `Datagram` or `StateSync` mode the reorder buffer, gap tracking, and NAK
    /// sending are all disabled — frames are delivered immediately in arrival order.
    #[builder(default)]
    diff_mode: DiffMode,
    /// Client-mode `StateSync` state: the `contents_formatted()` snapshot of the
    /// client's screen at the point the last `StateSyncDiff` was applied.
    /// Empty before any diff is applied.
    #[builder(default)]
    ack_state: Vec<u8>,
    /// The `diff_id` of the last `StateSyncDiff` the client successfully applied.
    /// Zero before any diff is applied.  Used to validate incoming `base_id` fields.
    #[builder(default)]
    ack_state_seq: u64,
    /// Count of consecutive `StateSyncDiff` frames discarded due to `base_id` mismatch.
    /// When this reaches 3, the client sends a `RepaintRequest` and the counter resets.
    #[builder(default)]
    statesync_mismatch_count: u32,
    /// True once the client has received and processed the first complete full-state push
    /// (`ScreenStateCompressed` or a complete `StateChunk` assembly) in `StateSync` mode.
    /// Guards `StateSyncDiff` from being applied to a blank initial state when the initial
    /// full-state push is dropped by a NAT device.
    #[builder(default)]
    initial_state_received: bool,
    /// Legacy escape hatch: when `true`, raw server PTY bytes are written
    /// straight to the terminal (the pre-unified behavior) instead of being
    /// rendered exclusively through the [`Renderer`].  Defaults to `false`; the
    /// rendered path is the artifact-free default.
    #[builder(default)]
    passthrough: bool,
    /// Total chunk count for the in-progress `StateChunk` assembly.  Zero = no assembly active.
    #[builder(default)]
    pending_chunk_total: u16,
    /// Next expected `seq` value for the in-progress `StateChunk` assembly.
    #[builder(default)]
    pending_chunk_seq: u16,
    /// Accumulated payload bytes from the in-progress `StateChunk` assembly.
    #[builder(default)]
    pending_chunk_data: Vec<u8>,
    /// Server-mode: channel for forwarding `ClientAck(diff_id)` values from the UDP
    /// receive loop to the state-sync task in `moshpits/src/runtime.rs`, which uses
    /// them to advance the server's ack baseline.
    client_ack_tx: Option<Sender<u64>>,
    /// Timestamp (µs since UNIX epoch) of the last authenticated UDP frame received from
    /// the peer.  Updated on every successful parse in server mode.  The server-side silence
    /// watchdog in `moshpits` polls this counter and cancels zombie connections after 30 s
    /// of client silence.
    last_rx_us: Option<Arc<AtomicU64>>,
}

/// Current time as microseconds since the UNIX epoch, used for keepalive RTT timestamps.
fn now_micros() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros(),
    )
    .unwrap_or(0)
}

impl UdpReader {
    /// Return a clone of the shared last-receive-time counter, if set.
    #[must_use]
    pub fn last_rx_us(&self) -> Option<Arc<AtomicU64>> {
        self.last_rx_us.clone()
    }

    /// Signal the reconnect channel if set; otherwise exit the process.
    fn signal_reconnect_or_exit(&self, code: i32) {
        if let Some(ref tx) = self.reconnect_tx {
            let _ = tx.try_send(());
        } else {
            process::exit(code);
        }
    }

    /// Feed a NAK→retransmit round-trip sample into the Jacobson-Karels estimator
    /// (RFC 6298 §2) and update the derived RTO.
    ///
    /// **First measurement:**
    /// - `SRTT   = sample`
    /// - `RTTVAR = sample / 2`
    ///
    /// **Subsequent measurements:**
    /// - `RTTVAR = (3/4) × RTTVAR + (1/4) × |SRTT − sample|`
    /// - `SRTT   = (7/8) × SRTT   + (1/8) × sample`
    ///
    /// **RTO** (stored as `nak_timeout`):
    /// - `RTO = SRTT + 4 × RTTVAR`, clamped to
    ///   [`MIN_NAK_TIMEOUT`]..=[`MAX_NAK_TIMEOUT`].
    ///
    /// Also derives an updated [`Self::silence_timeout`] from the new RTO when
    /// one was previously set (client mode).  Formula:
    /// `max(rto × 30, 9 s)` — with a 3 s server keepalive this guarantees ≥ 3
    /// keepalives arrive before the silence window closes.
    fn update_rtt_estimate(&mut self, sample: Duration) {
        // Clamp samples that exceed 8× the current RTO to the ceiling value rather
        // than discarding them outright.  Pure discard causes a death spiral when
        // nak_timeout has converged to MIN_NAK_TIMEOUT (20 ms → ceiling = 160 ms):
        // every congestion-induced RTT spike is rejected, the estimator stays stuck at
        // the minimum, and aggressive 20 ms NAKs worsen NAT congestion indefinitely.
        // Clamping feeds a bounded signal into the estimator so nak_timeout can grow
        // upward and the system self-heals within 2–3 keepalive intervals.
        let ceiling = self.nak_timeout.unwrap_or(NAK_TIMEOUT) * 8;
        let sample = if sample > ceiling {
            debug!(
                "NAK RTT sample {:?} exceeds outlier ceiling {:?} — clamping",
                sample, ceiling
            );
            ceiling
        } else {
            sample
        };
        let (new_srtt, new_rttvar) = match (self.srtt, self.rttvar) {
            // First measurement (RFC 6298 §2.2).
            (None, _) | (_, None) => (sample, sample / 2),
            // Subsequent measurements (RFC 6298 §2.3).
            (Some(srtt), Some(rttvar)) => {
                let diff = srtt
                    .checked_sub(sample)
                    .unwrap_or_else(|| sample.checked_sub(srtt).unwrap_or_default());
                let new_rttvar = rttvar.saturating_sub(rttvar / 4) + diff / 4;
                let new_srtt = srtt.saturating_sub(srtt / 8) + sample / 8;
                (new_srtt, new_rttvar)
            }
        };
        // RTO = SRTT + 4 × RTTVAR, clamped to the allowed range.
        let rto = (new_srtt + new_rttvar * 4).clamp(MIN_NAK_TIMEOUT, MAX_NAK_TIMEOUT);
        debug!(
            "NAK RTT sample {:?} → srtt {:?} rttvar {:?} rto {:?}",
            sample, new_srtt, new_rttvar, rto
        );
        self.srtt = Some(new_srtt);
        self.rttvar = Some(new_rttvar);
        self.nak_timeout = Some(rto);
        // Only update silence_timeout when it was explicitly initialised
        // (client mode).  Servers leave it None so this remains a no-op there.
        if self.silence_timeout.is_some() {
            self.silence_timeout = Some((rto * 30).max(Duration::from_secs(9)));
        }
    }

    /// Compute the adaptive NAK check interval from the current RTT estimate.
    ///
    /// Formula: `max(nak_timeout / 4, MIN_NAK_CHECK_INTERVAL)`.
    fn nak_check_interval(&self) -> Duration {
        (self.nak_timeout.unwrap_or(NAK_TIMEOUT) / 4).max(MIN_NAK_CHECK_INTERVAL)
    }

    /// Intercept terminal queries in bytes arriving from the server, respond
    /// immediately via [`Self::query_response_tx`], and strip them from stdout.
    ///
    /// Intercepted CSI queries: DSR (`ESC[6n`), Primary/Secondary/Tertiary DA.
    /// Intercepted OSC queries: color queries 10, 11, 12 (`ESC]N;?ST`).
    ///
    /// Also normalises VT (0x0B) and FF (0x0C) to CR+LF.
    fn intercept_queries(&self, bytes: &[u8], emulator: &Arc<Mutex<Emulator>>) -> Vec<u8> {
        if !bytes.contains(&0x1b) && !bytes.contains(&0x0b) && !bytes.contains(&0x0c) {
            return bytes.to_vec();
        }
        let fg = self
            .terminal_fg_color
            .as_deref()
            .unwrap_or("rgb:d0d0/d0d0/d0d0");
        let bg = self
            .terminal_bg_color
            .as_deref()
            .unwrap_or("rgb:1c1c/1c1c/1c1c");
        let mut out = Vec::with_capacity(bytes.len());
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == 0x0b || bytes[i] == 0x0c {
                out.push(b'\r');
                out.push(b'\n');
                i += 1;
                continue;
            }
            if bytes[i] != 0x1b || i + 1 >= bytes.len() {
                out.push(bytes[i]);
                i += 1;
                continue;
            }
            match bytes[i + 1] {
                b'[' => self.handle_csi(bytes, &mut i, &mut out, emulator),
                b']' => self.handle_osc(bytes, &mut i, &mut out, fg, bg),
                _ => {
                    out.push(bytes[i]);
                    i += 1;
                }
            }
        }
        out
    }

    /// Handle one CSI sequence starting at `bytes[*i]` (`ESC [`).
    /// Advances `*i` past the sequence; appends passthrough bytes to `out`;
    /// sends recognised query responses via `query_response_tx`.
    fn handle_csi(
        &self,
        bytes: &[u8],
        i: &mut usize,
        out: &mut Vec<u8>,
        emulator: &Arc<Mutex<Emulator>>,
    ) {
        let seq_start = *i;
        *i += 2; // consume ESC [
        let marker = if *i < bytes.len() && matches!(bytes[*i], b'?' | b'>' | b'=') {
            let m = bytes[*i];
            *i += 1;
            Some(m)
        } else {
            None
        };
        let param_start = *i;
        while *i < bytes.len() && (bytes[*i].is_ascii_digit() || bytes[*i] == b';') {
            *i += 1;
        }
        let params = &bytes[param_start..*i];
        if *i >= bytes.len() {
            out.extend_from_slice(&bytes[seq_start..*i]);
            return;
        }
        let terminator = bytes[*i];
        *i += 1;
        let response: Option<Vec<u8>> = match (marker, params, terminator) {
            (None | Some(b'?'), b"6", b'n') => {
                let (row, col) = emulator
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .screen()
                    .cursor_position();
                Some(format!("\x1b[{};{}R", row + 1, col + 1).into_bytes())
            }
            (None, b"" | b"0", b'c') => Some(b"\x1b[?62c".to_vec()),
            (Some(b'>'), b"" | b"0", b'c') => Some(b"\x1b[>1;10;0c".to_vec()),
            (Some(b'='), b"" | b"0", b'c') => Some(b"\x1bP!|00000000\x1b\\".to_vec()),
            // DSR — device status (vi, htop, etc. probe this at startup)
            (None, b"5", b'n') => Some(b"\x1b[0n".to_vec()),
            // XTVERSION — terminal identity (vim, neovim)
            (Some(b'>'), _, b'q') => Some(b"\x1bP>|moshpit\x1b\\".to_vec()),
            // XTWINOPS — terminal size in characters
            (None, b"18", b't') => {
                let (rows, cols) = emulator
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .screen()
                    .size();
                Some(format!("\x1b[8;{rows};{cols}t").into_bytes())
            }
            // XTWINOPS — window/cell pixel sizes (unknown to the proxy → 0)
            (None, b"14", b't') => Some(b"\x1b[4;0;0t".to_vec()),
            (None, b"16", b't') => Some(b"\x1b[6;0;0t".to_vec()),
            _ => {
                out.extend_from_slice(&bytes[seq_start..*i]);
                None
            }
        };
        if let Some(resp) = response
            && let Some(ref tx) = self.query_response_tx
        {
            let frame = EncryptedFrame::Bytes((UuidWrapper::new(self.id), resp));
            if let Err(e) = tx.try_send(frame) {
                warn!("Failed to send CSI query response: {e}");
            }
        }
    }

    /// Handle one OSC sequence starting at `bytes[*i]` (`ESC ]`).
    /// Intercepts OSC 10/11/12 color queries and responds with BEL-terminated
    /// canned color strings.  All other OSC sequences pass through unchanged.
    ///
    /// **BEL termination** (`\x07`) is used deliberately instead of ST (`\e\\`).
    /// When the response is forwarded to the remote shell's stdin, fish's readline
    /// would otherwise consume the `\e` of `\e\\` as the start of an escape
    /// sequence and leave the trailing `\` as a literal character in the input
    /// buffer — causing it to appear before the next key typed (e.g. `\p`).
    fn handle_osc(&self, bytes: &[u8], i: &mut usize, out: &mut Vec<u8>, fg: &str, bg: &str) {
        let seq_start = *i;
        *i += 2; // consume ESC ]
        let param_start = *i;
        let mut osc_params: Option<&[u8]> = None;
        while *i < bytes.len() {
            if bytes[*i] == 0x07 {
                osc_params = Some(&bytes[param_start..*i]);
                *i += 1;
                break;
            }
            if bytes[*i] == 0x1b && *i + 1 < bytes.len() && bytes[*i + 1] == b'\\' {
                osc_params = Some(&bytes[param_start..*i]);
                *i += 2;
                break;
            }
            *i += 1;
        }
        let Some(params) = osc_params else {
            out.extend_from_slice(&bytes[seq_start..*i]);
            return;
        };
        let response: Option<Vec<u8>> = params.strip_suffix(b";?").and_then(|cmd| match cmd {
            b"10" => Some(format!("\x1b]10;{fg}\x07").into_bytes()),
            b"11" => Some(format!("\x1b]11;{bg}\x07").into_bytes()),
            b"12" => Some(format!("\x1b]12;{fg}\x07").into_bytes()),
            _ => None,
        });
        match response {
            Some(resp) => {
                if let Some(ref tx) = self.query_response_tx {
                    let frame = EncryptedFrame::Bytes((UuidWrapper::new(self.id), resp));
                    if let Err(e) = tx.try_send(frame) {
                        warn!("Failed to send OSC query response: {e}");
                    }
                }
            }
            None => out.extend_from_slice(&bytes[seq_start..*i]),
        }
    }

    /// Buffer an arrived `(frame, seq)` pair and return any frames now ready to deliver
    /// in order. NAK frames are routed to the retransmit channel inline and are not
    /// included in the returned `Vec`; they still participate in sequence tracking.
    #[cfg_attr(nightly, allow(clippy::too_many_lines))]
    fn handle_arrival(&mut self, frame: EncryptedFrame, seq: u64) -> Vec<EncryptedFrame> {
        // Duplicate or replay
        if seq < self.next_seq {
            return vec![];
        }

        // In Datagram or StateSync mode: skip reorder buffering and gap tracking
        // entirely.  Deliver the frame immediately regardless of arrival order,
        // advance next_seq past any gap, and never send NAKs or RepaintRequests.
        // ScreenState frames are still delivered through the fast path below.
        if self.diff_mode == DiffMode::Datagram || self.diff_mode == DiffMode::StateSync {
            self.next_seq = seq + 1;
            return self.route_or_deliver(frame).into_iter().collect();
        }

        // Prevent DoS memory exhaustion from an adversarial massive sequence jump.
        if seq > self.next_seq + MAX_SEQ_JUMP {
            warn!(
                "Dropping frame with sequence {seq} jumping too far ahead of {}",
                self.next_seq
            );
            return vec![];
        }

        // Track the furthest sequence we have ever seen.  Used by
        // check_nak_timeouts to detect when a gap has fallen outside the
        // sender's retransmit window.
        if seq > self.highest_seq_seen {
            self.highest_seq_seen = seq;
        }

        if seq == self.next_seq {
            self.next_seq += 1;
            let _removed = self.gap_first_seen.remove(&seq);
            let _removed = self.gap_nak_count.remove(&seq);
            if let Some(t) = self.gap_nak_sent_at.remove(&seq) {
                self.update_rtt_estimate(t.elapsed());
            }
            let mut ready = Vec::new();
            // NAK frames are consumed inline; all others are returned to the caller.
            if let Some(f) = self.route_or_deliver(frame) {
                ready.push(f);
            }
            // Drain consecutive buffered frames
            while let Some(buffered) = self.recv_buffer.remove(&self.next_seq) {
                let _removed = self.gap_first_seen.remove(&self.next_seq);
                let _removed = self.gap_nak_count.remove(&self.next_seq);
                if let Some(t) = self.gap_nak_sent_at.remove(&self.next_seq) {
                    self.update_rtt_estimate(t.elapsed());
                }
                self.next_seq += 1;
                if let Some(f) = self.route_or_deliver(buffered) {
                    ready.push(f);
                }
            }
            ready
        } else {
            // A ScreenState is a complete screen snapshot — it obsoletes every
            // preceding diff.  Deliver it immediately by discarding all pending
            // gaps and buffered frames with sequence numbers below `seq`, then
            // drain any already-buffered frames that follow it in order.
            if matches!(
                frame,
                EncryptedFrame::ScreenState(_) | EncryptedFrame::ScreenStateCompressed(_)
            ) {
                for obsolete in self.next_seq..seq {
                    let _removed = self.recv_buffer.remove(&obsolete);
                    let _removed = self.gap_first_seen.remove(&obsolete);
                    let _removed = self.gap_nak_count.remove(&obsolete);
                    let _removed = self.gap_nak_sent_at.remove(&obsolete);
                }
                let _removed = self.gap_first_seen.remove(&seq);
                let _removed = self.gap_nak_count.remove(&seq);
                let _removed = self.gap_nak_sent_at.remove(&seq);
                self.next_seq = seq + 1;
                let mut ready = Vec::new();
                if let Some(f) = self.route_or_deliver(frame) {
                    ready.push(f);
                }
                while let Some(buffered) = self.recv_buffer.remove(&self.next_seq) {
                    let _removed = self.gap_first_seen.remove(&self.next_seq);
                    let _removed = self.gap_nak_count.remove(&self.next_seq);
                    if let Some(t) = self.gap_nak_sent_at.remove(&self.next_seq) {
                        self.update_rtt_estimate(t.elapsed());
                    }
                    self.next_seq += 1;
                    if let Some(f) = self.route_or_deliver(buffered) {
                        ready.push(f);
                    }
                }
                return ready;
            }

            // Out of order: buffer the frame and record any new gaps.
            //
            // The arriving packet is no longer missing — remove it from gap
            // tracking in case it was recorded as a false gap by an earlier
            // out-of-order arrival.
            let _prev = self.recv_buffer.insert(seq, frame);
            let _removed = self.gap_first_seen.remove(&seq);
            let _removed = self.gap_nak_count.remove(&seq);

            // If the buffer has grown large, the display is stalled behind many simultaneous
            // gaps.  Send an immediate RepaintRequest instead of waiting for the first NAK
            // retry cycle to elapse (~50 ms).
            if self.recv_buffer.len() >= RECV_BUFFER_REPAINT_THRESHOLD
                && let Some(ref tx) = self.nak_out_tx
                && let Err(e) = tx.try_send(EncryptedFrame::RepaintRequest)
            {
                warn!("Failed to send early RepaintRequest: {e}");
            }

            // Only register positions that are genuinely absent — positions
            // already in recv_buffer will be delivered automatically once the
            // earlier gap is filled, so NAKing for them wastes bandwidth and
            // generates misleading "giving up" warnings.
            let now = Instant::now();
            let mut new_gaps = Vec::new();
            for missing in self.next_seq..seq {
                if !self.recv_buffer.contains_key(&missing) {
                    match self.gap_first_seen.entry(missing) {
                        Entry::Vacant(e) => {
                            let _ = e.insert(now);
                            new_gaps.push(missing);
                        }
                        Entry::Occupied(_) => {}
                    }
                }
            }
            // Send an immediate NAK for newly-discovered gaps without waiting for the
            // periodic check interval. Retries and backoff are still managed by
            // check_nak_timeouts; this only eliminates the first-NAK delay (up to
            // NAK_CHECK_INTERVAL + nak_timeout ≈ 70 ms on the default config).
            //
            // Also send a RepaintRequest alongside the NAK when recv_buffer already
            // holds frames (len > 1 because we just inserted the current frame):
            // for high-output programs (htop, top, vim) a single lost chunk blocks
            // the entire remaining burst in recv_buffer.  Retransmit alone costs
            // nak_timeout (20–500 ms) before the first retry fires.  The
            // RepaintRequest lets the server bypass the gap with a fresh
            // ScreenStateCompressed within one RTT instead.  The recv_buffer guard
            // avoids triggering on a lone reorder that resolves without intervention.
            if !new_gaps.is_empty() {
                for &s in &new_gaps {
                    let _prev = self.gap_nak_sent_at.insert(s, now);
                }
                if let Some(ref tx) = self.nak_out_tx {
                    if let Err(e) = tx.try_send(EncryptedFrame::Nak(new_gaps)) {
                        warn!("Failed to send immediate NAK for new gaps: {e}");
                    }
                    if self.recv_buffer.len() > 1
                        && let Err(e) = tx.try_send(EncryptedFrame::RepaintRequest)
                    {
                        warn!("Failed to send burst-gap RepaintRequest: {e}");
                    }
                }
            }
            vec![]
        }
    }

    /// Route a NAK frame to the retransmit channel (consuming it and returning
    /// `None`), or pass any other frame through as `Some(frame)`.
    ///
    /// Centralising routing here means NAK frames always participate in the
    /// normal sequence-ordering logic — the original bug was that `handle_arrival`
    /// returned early for NAKs before incrementing `next_seq`, creating a
    /// permanent false gap at the NAK's sequence position and a NAK storm.
    fn route_or_deliver(&self, frame: EncryptedFrame) -> Option<EncryptedFrame> {
        if let EncryptedFrame::Nak(ref seqs) = frame {
            if let Some(ref tx) = self.retransmit_tx
                && let Err(e) = tx.try_send(seqs.clone())
            {
                warn!("Failed to forward retransmit request: {e}");
            }
            if let Some(ref counter) = self.nak_received_count {
                let _ = counter.fetch_add(1, Ordering::Relaxed);
            }
            return None;
        }
        Some(frame)
    }

    /// Collect sequences to give up on (exceeded retries or outside retransmit window),
    /// remove their tracking state, advance `next_seq` past them, and return any frames
    /// that become deliverable as a result.
    fn drain_given_up_seqs(&mut self) -> Vec<EncryptedFrame> {
        let retry_give_up = self
            .gap_nak_count
            .iter()
            .filter_map(|(&seq, &count)| (count >= MAX_NAK_RETRIES).then_some(seq));
        // When the server has sent RETRANSMIT_WINDOW more packets past a gap it has
        // already evicted the lost packet; retransmit requests will silently fail.
        let window_give_up = self
            .gap_first_seen
            .keys()
            .filter(|&&seq| self.highest_seq_seen.saturating_sub(seq) > RETRANSMIT_WINDOW)
            .copied();
        let give_up_set: HashSet<u64> = retry_give_up.chain(window_give_up).collect();
        if give_up_set.is_empty() {
            return vec![];
        }
        for &seq in &give_up_set {
            if self
                .gap_nak_count
                .get(&seq)
                .is_some_and(|&c| c >= MAX_NAK_RETRIES)
            {
                warn!("Giving up on packet {seq} after {MAX_NAK_RETRIES} NAK retries");
            } else {
                warn!(
                    "Giving up on packet {seq}: outside sender retransmit window \
                     (highest_seen={})",
                    self.highest_seq_seen
                );
            }
            let _r = self.gap_first_seen.remove(&seq);
            let _r = self.gap_nak_count.remove(&seq);
            let _r = self.gap_nak_sent_at.remove(&seq);
        }
        let mut delivered = vec![];
        loop {
            if give_up_set.contains(&self.next_seq) {
                self.next_seq += 1;
            } else if let Some(buffered) = self.recv_buffer.remove(&self.next_seq) {
                let _r = self.gap_first_seen.remove(&self.next_seq);
                let _r = self.gap_nak_count.remove(&self.next_seq);
                let _r = self.gap_nak_sent_at.remove(&self.next_seq);
                self.next_seq += 1;
                if let Some(f) = self.route_or_deliver(buffered) {
                    delivered.push(f);
                }
            } else {
                break;
            }
        }
        delivered
    }

    /// Send NAKs for gaps whose timeout has elapsed, reset their timer for potential re-NAK,
    /// and skip any gaps that have exceeded the maximum retry count or the sender's retransmit
    /// window. Returns frames from `recv_buffer` that become deliverable after skipping
    /// permanently lost packets.
    fn check_nak_timeouts(&mut self) -> Vec<EncryptedFrame> {
        if self.diff_mode != DiffMode::Reliable {
            return vec![];
        }
        let now = Instant::now();
        let delivered = self.drain_given_up_seqs();

        // Request retransmission for recent gaps using exponential backoff:
        // timeout = base * 2^retry_count (capped at base * 2^NAK_BACKOFF_MAX_SHIFT).
        let base_nak_timeout = self.nak_timeout.unwrap_or(NAK_TIMEOUT);
        let timed_out: Vec<u64> = self
            .gap_first_seen
            .iter()
            .filter_map(|(&seq, &t)| {
                let retries = self.gap_nak_count.get(&seq).copied().unwrap_or(0);
                let shift = retries.min(NAK_BACKOFF_MAX_SHIFT);
                let backoff = base_nak_timeout * (1u32 << shift);
                (now.duration_since(t) >= backoff).then_some(seq)
            })
            .collect();
        if !timed_out.is_empty() {
            let mut send_repaint_request = false;
            for &seq in &timed_out {
                if let Some(t) = self.gap_first_seen.get_mut(&seq) {
                    *t = now;
                }
                let count = self.gap_nak_count.entry(seq).or_insert(0);
                *count += 1;
                if *count == REPAINT_REQUEST_THRESHOLD {
                    send_repaint_request = true;
                }
                let _prev = self.gap_nak_sent_at.insert(seq, now);
            }
            if let Some(ref tx) = self.nak_out_tx
                && let Err(e) = tx.try_send(EncryptedFrame::Nak(timed_out))
            {
                warn!("Failed to send NAK: {e}");
            }
            // When any gap reaches the repaint threshold, ask the server for an immediate
            // full-screen snapshot.
            if send_repaint_request
                && let Some(ref tx) = self.nak_out_tx
                && let Err(e) = tx.try_send(EncryptedFrame::RepaintRequest)
            {
                warn!("Failed to send RepaintRequest: {e}");
            }
        }

        delivered
    }

    /// Run the server frame reading loop
    ///
    /// # Errors
    /// * I/O error.
    /// * Frame parsing error.
    ///
    #[cfg_attr(nightly, allow(clippy::too_many_lines))]
    pub async fn server_frame_loop(
        &mut self,
        token: CancellationToken,
        term_tx: Sender<TerminalMessage>,
    ) -> Result<()> {
        // Wait for the first UDP datagram from the client to discover its real
        // post-NAT address.  The socket is intentionally NOT connected — it stays
        // unconnected for the session lifetime so that packets arriving from a new
        // address after a NAT rebind are not silently dropped by the OS.
        let mut current_peer: SocketAddr = {
            let mut buf = vec![0u8; 65535];
            let (first_len, peer_addr) = self.socket.recv_from(&mut buf).await?;
            if let Some(tx) = self.peer_discovered_tx.take() {
                let _ = tx.send(peer_addr);
            }
            // Process the first packet through the normal pipeline.
            let mut first_buf = BytesMut::from(&buf[..first_len]);
            match self.parse_encrypted_frame(&mut first_buf) {
                Ok(Some((frame, seq))) => {
                    if let Some(ref counter) = self.last_rx_us {
                        counter.store(now_micros(), Ordering::Relaxed);
                    }
                    for ready in self.handle_arrival(frame, seq) {
                        match ready {
                            EncryptedFrame::Bytes((_id, message)) => {
                                term_tx.send(TerminalMessage::Input(message)).await?;
                            }
                            EncryptedFrame::Resize((_id, columns, rows)) => {
                                term_tx
                                    .send(TerminalMessage::Resize { rows, columns })
                                    .await?;
                            }
                            EncryptedFrame::RepaintRequest => {
                                if let Some(ref tx) = self.repaint_tx
                                    && let Err(e) = tx.try_send(())
                                {
                                    warn!("Failed to signal repaint request: {e}");
                                }
                            }
                            EncryptedFrame::Keepalive(ts) => {
                                let rtt_us = now_micros().saturating_sub(ts);
                                if rtt_us > 0 && rtt_us < 30_000_000 {
                                    self.update_rtt_estimate(Duration::from_micros(rtt_us));
                                }
                            }
                            EncryptedFrame::Nak(_)
                            | EncryptedFrame::Shutdown
                            | EncryptedFrame::ScrollbackStart
                            | EncryptedFrame::ScrollbackEnd
                            | EncryptedFrame::ScreenState(_)
                            | EncryptedFrame::ScreenStateCompressed(_)
                            | EncryptedFrame::CompressedBytes(_)
                            | EncryptedFrame::StateSyncDiff(_)
                            | EncryptedFrame::PtyExit
                            | EncryptedFrame::StateChunk(_) => {}
                            EncryptedFrame::ClientAck(diff_id) => {
                                if let Some(ref tx) = self.client_ack_tx
                                    && let Err(e) = tx.try_send(diff_id)
                                {
                                    warn!("Failed to forward ClientAck: {e}");
                                }
                            }
                        }
                    }
                }
                Ok(None) => {}
                Err(e) => {
                    warn!("Failed to parse first UDP frame from client: {e}");
                }
            }
            peer_addr
        };

        // Park the NAK deadline far in the future when gap_first_seen is empty — there
        // is nothing to retransmit, so firing every 12.5 ms is pure overhead.  The
        // deadline is reset to nak_check_interval() each time a frame arrives (which
        // may open new gaps) or when gaps remain after check_nak_timeouts fires.
        let nak_park = Duration::from_hours(24);
        let mut nak_check_deadline = TokioInstant::now() + self.nak_check_interval();
        loop {
            select! {
                () = token.cancelled() => break,
                () = sleep_until(nak_check_deadline) => {
                    for ready in self.check_nak_timeouts() {
                        match ready {
                            EncryptedFrame::Bytes((_id, message)) => {
                                term_tx.send(TerminalMessage::Input(message)).await?;
                            }
                            EncryptedFrame::Resize((_id, columns, rows)) => {
                                term_tx.send(TerminalMessage::Resize { rows, columns }).await?;
                            }
                            EncryptedFrame::RepaintRequest => {
                                if let Some(ref tx) = self.repaint_tx
                                    && let Err(e) = tx.try_send(())
                                {
                                    warn!("Failed to signal repaint request: {e}");
                                }
                            }
                            EncryptedFrame::Keepalive(ts) => {
                                let rtt_us = now_micros().saturating_sub(ts);
                                if rtt_us > 0 && rtt_us < 30_000_000 {
                                    self.update_rtt_estimate(Duration::from_micros(rtt_us));
                                }
                            }
                            EncryptedFrame::Nak(_)
                            | EncryptedFrame::Shutdown
                            | EncryptedFrame::ScrollbackStart
                            | EncryptedFrame::ScrollbackEnd
                            | EncryptedFrame::ScreenState(_)
                            | EncryptedFrame::ScreenStateCompressed(_)
                            | EncryptedFrame::CompressedBytes(_)
                            | EncryptedFrame::StateSyncDiff(_)
                            | EncryptedFrame::PtyExit
                            | EncryptedFrame::StateChunk(_)
                            | EncryptedFrame::ClientAck(_) => {}
                        }
                    }
                    nak_check_deadline = TokioInstant::now() + if self.gap_first_seen.is_empty() {
                        nak_park
                    } else {
                        self.nak_check_interval()
                    };
                },
                frame_res = self.recv_frame_from() => {
                    match frame_res {
                        Ok(Some((frame, seq, src_addr))) => {
                            if let Some(ref counter) = self.last_rx_us {
                                counter.store(now_micros(), Ordering::Relaxed);
                            }
                            if src_addr != current_peer {
                                info!("NAT roam: peer {} → {}", current_peer, src_addr);
                                current_peer = src_addr;
                                if let Some(ref tx) = self.peer_addr_tx
                                    && let Err(e) = tx.try_send(src_addr)
                                {
                                    warn!("Failed to signal NAT roam: {e}");
                                }
                            }
                            for ready in self.handle_arrival(frame, seq) {
                                match ready {
                                    EncryptedFrame::Bytes((_id, message)) => {
                                        term_tx.send(TerminalMessage::Input(message)).await?;
                                    }
                                    EncryptedFrame::Resize((_id, columns, rows)) => {
                                        term_tx.send(TerminalMessage::Resize { rows, columns }).await?;
                                    }
                                    EncryptedFrame::RepaintRequest => {
                                        if let Some(ref tx) = self.repaint_tx
                                            && let Err(e) = tx.try_send(())
                                        {
                                            warn!("Failed to signal repaint request: {e}");
                                        }
                                    }
                                    EncryptedFrame::Keepalive(ts) => {
                                        let rtt_us = now_micros().saturating_sub(ts);
                                        if rtt_us > 0 && rtt_us < 30_000_000 {
                                            self.update_rtt_estimate(Duration::from_micros(rtt_us));
                                        }
                                    }
                                    EncryptedFrame::Nak(_)
                                    | EncryptedFrame::Shutdown
                                    | EncryptedFrame::ScrollbackStart
                                    | EncryptedFrame::ScrollbackEnd
                                    | EncryptedFrame::ScreenState(_)
                                    | EncryptedFrame::ScreenStateCompressed(_)
                                    | EncryptedFrame::CompressedBytes(_)
                                    | EncryptedFrame::StateSyncDiff(_)
                                    | EncryptedFrame::PtyExit
                                    | EncryptedFrame::StateChunk(_) => {}
                                    EncryptedFrame::ClientAck(diff_id) => {
                                        if let Some(ref tx) = self.client_ack_tx
                                            && let Err(e) = tx.try_send(diff_id)
                                        {
                                            warn!("Failed to forward ClientAck: {e}");
                                        }
                                    }
                                }
                            }
                            // A new frame may have opened gaps — rearm the NAK deadline so
                            // check_nak_timeouts fires promptly if needed.
                            nak_check_deadline = TokioInstant::now() + self.nak_check_interval();
                        }
                        Ok(None) => break,
                        Err(e) => {
                            error!("udp read error, client likely disconnected: {e}");
                            break;
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Apply an authoritative full-screen snapshot and return the bytes to
    /// repaint the terminal.
    ///
    /// `payload` is the server's `vt100` `contents_formatted()` bytes.  This:
    /// 1. Reconstructs the screen in a scratch parser, preserving the current
    ///    alternate-screen state (which `contents_formatted()` omits).
    /// 2. Refreshes `StateSync` ack bookkeeping when in that mode.
    /// 3. Resyncs the authoritative client [`Emulator`] to the snapshot so the
    ///    emulator stays the single source of truth for the renderer and the
    ///    prediction engine.
    /// 4. Renders a single clean update through the shared [`Renderer`] —
    ///    reconciling predictions and emitting a minimal diff (no forced
    ///    full-screen flash).
    fn apply_full_state(
        &mut self,
        payload: &[u8],
        emulator: &Arc<Mutex<Emulator>>,
        prediction: &Arc<Mutex<PredictionEngine>>,
        renderer: &Arc<Mutex<Renderer>>,
        in_alt_screen: &Arc<AtomicBool>,
    ) -> Vec<u8> {
        let (rows, cols) = {
            let emu = emulator.lock().unwrap_or_else(PoisonError::into_inner);
            emu.screen().size()
        };
        // `contents_formatted()` omits the `?1049h` alt-screen enter sequence, so
        // re-apply it when we are currently in alternate-screen mode to keep the
        // reconstructed screen (and the local display) in the right buffer.  The
        // prefix is display-only and does not affect diff content.
        let was_alt = in_alt_screen.load(Ordering::Relaxed);
        let mut tmp = vt100::Parser::new(rows, cols, 0);
        if was_alt {
            tmp.process(b"\x1b[?1049h");
        }
        tmp.process(payload);
        let is_alt = tmp.screen().alternate_screen();
        in_alt_screen.store(is_alt, Ordering::Relaxed);
        if self.diff_mode == DiffMode::StateSync {
            let mut ack = tmp.screen().contents_formatted();
            if is_alt {
                let mut prefixed = b"\x1b[?1049h".to_vec();
                prefixed.extend_from_slice(&ack);
                ack = prefixed;
            }
            self.ack_state = ack;
            self.ack_state_seq = 0;
            self.statesync_mismatch_count = 0;
            self.initial_state_received = true;
        }
        // Resync the authoritative emulator to the snapshot, then render.
        {
            let mut emu = emulator.lock().unwrap_or_else(PoisonError::into_inner);
            emu.replace_parser(tmp);
        }
        render_server_update(emulator, prediction, renderer, !is_alt)
    }

    /// Process one `StateChunk` frame in `StateSync` client mode.
    ///
    /// Accumulates chunks in order.  When the assembly is complete the combined payload
    /// is processed identically to a [`EncryptedFrame::ScreenStateCompressed`] frame
    /// via [`Self::apply_full_state`].  Out-of-order chunks trigger a
    /// [`EncryptedFrame::RepaintRequest`].
    #[cfg_attr(nightly, allow(clippy::too_many_arguments))]
    async fn handle_state_chunk(
        &mut self,
        seq: u16,
        total: u16,
        data: Vec<u8>,
        emulator: &Arc<Mutex<Emulator>>,
        prediction: &Arc<Mutex<PredictionEngine>>,
        renderer: &Arc<Mutex<Renderer>>,
        in_alt_screen: &Arc<AtomicBool>,
        stdout_tx: &Sender<Vec<u8>>,
    ) {
        if seq == 0 {
            self.pending_chunk_total = total;
            self.pending_chunk_seq = 0;
            self.pending_chunk_data = data;
        } else if seq == self.pending_chunk_seq && total == self.pending_chunk_total {
            self.pending_chunk_data.extend_from_slice(&data);
        } else {
            // Out-of-order or stale chunk — discard assembly and request a fresh push.
            self.pending_chunk_total = 0;
            self.pending_chunk_seq = 0;
            self.pending_chunk_data.clear();
            if let Some(ref tx) = self.nak_out_tx {
                drop(tx.try_send(EncryptedFrame::RepaintRequest));
            }
            return;
        }
        self.pending_chunk_seq += 1;
        if self.pending_chunk_seq == self.pending_chunk_total {
            // Assembly complete — process as ScreenStateCompressed.
            let payload_compressed = take(&mut self.pending_chunk_data);
            self.pending_chunk_seq = 0;
            self.pending_chunk_total = 0;
            match decode_all(payload_compressed.as_slice()) {
                Ok(payload) => {
                    let repaint = self.apply_full_state(
                        &payload,
                        emulator,
                        prediction,
                        renderer,
                        in_alt_screen,
                    );
                    if !repaint.is_empty()
                        && let Err(e) = stdout_tx.send(repaint).await
                    {
                        error!("Error sending StateChunk repaint to stdout channel: {e}");
                    }
                }
                Err(e) => {
                    error!("Failed to decompress StateChunk assembly: {e}");
                }
            }
        }
    }

    /// Run the client frame reading loop
    ///
    /// # Errors
    /// * I/O error.
    /// * Frame parsing error.
    ///
    /// # Panics
    /// Panics if the `emulator`, `prediction`, or `renderer` mutex is poisoned.
    ///
    /// # Parameters
    /// * `token` – cancellation token for the session.
    /// * `stdout_tx` – channel to the persistent stdout writer thread.
    /// * `emulator` – shared terminal emulator state; fed server bytes and
    ///   queried by the prediction engine.
    /// * `prediction` – shared prediction engine; culled after server bytes
    ///   arrive so that confirmed/invalidated overlays are reconciled.
    /// * `renderer` – differential renderer; used to emit a single clean
    ///   repaint after a scrollback replay block completes.
    #[cfg_attr(nightly, allow(clippy::too_many_lines, clippy::too_many_arguments))]
    pub async fn client_frame_loop(
        &mut self,
        token: CancellationToken,
        exit_token: CancellationToken,
        exit_msg: Arc<Mutex<Option<&'static [u8]>>>,
        stdout_tx: Sender<Vec<u8>>,
        emulator: Arc<Mutex<Emulator>>,
        prediction: Arc<Mutex<PredictionEngine>>,
        renderer: Arc<Mutex<Renderer>>,
        in_alt_screen: Arc<AtomicBool>,
    ) {
        let mut prev_bytes = BytesMut::with_capacity(1024);
        let mut osc_started = false;
        // Legacy raw-passthrough escape hatch (default off); captured once so the
        // per-frame helpers can read it without re-borrowing `self`.
        let passthrough = self.passthrough;
        // In Datagram and StateSync modes the NAK timer is never actually used
        // (check_nak_timeouts returns immediately), so we park the deadline far in
        // the future to keep the select! branch from firing on every loop iteration.
        let nak_park = Duration::from_hours(24);
        let mut nak_check_deadline = TokioInstant::now()
            + if self.diff_mode == DiffMode::Reliable {
                self.nak_check_interval()
            } else {
                nak_park
            };
        // When true, raw bytes are fed into the emulator only — not sent to
        // stdout.  Set by ScrollbackStart, cleared by ScrollbackEnd.
        let mut scrollback_mode = false;
        // Deadline after which silence is treated as a server disconnect.
        let mut silence_deadline: Option<TokioInstant> =
            self.silence_timeout.map(|d| TokioInstant::now() + d);

        'session: loop {
            select! {
                () = token.cancelled() => break 'session,
                () = sleep_until(nak_check_deadline) => {
                    for ready in self.check_nak_timeouts() {
                        match ready {
                            EncryptedFrame::Bytes((_id, message)) => {
                                let message = self.intercept_queries(&message, &emulator);
                                process_bytes_with_prediction(
                                    message,
                                    &mut prev_bytes,
                                    &mut osc_started,
                                    &stdout_tx,
                                    scrollback_mode,
                                    &exit_token,
                                    &emulator,
                                    &prediction,
                                    &in_alt_screen,
                                    &renderer,
                                    passthrough,
                                )
                                .await;
                            }
                            EncryptedFrame::Resize(_) => {
                                error!("Received Resize frame on client, which is unexpected");
                            }
                            EncryptedFrame::Keepalive(ts) => {
                                if let Some(ref tx) = self.nak_out_tx
                                    && let Err(e) = tx.try_send(EncryptedFrame::Keepalive(ts))
                                {
                                    warn!("Failed to echo keepalive: {e}");
                                }
                            }
                            EncryptedFrame::Nak(_)
                            | EncryptedFrame::RepaintRequest
                            | EncryptedFrame::StateSyncDiff(_)
                            | EncryptedFrame::ClientAck(_) => {}
                            EncryptedFrame::Shutdown => {
                                info!("Server is shutting down, reconnecting");
                                self.signal_reconnect_or_exit(0);
                                break 'session;
                            }
                            EncryptedFrame::ScrollbackStart => {
                                scrollback_mode = true;
                            }
                            EncryptedFrame::ScrollbackEnd => {
                                scrollback_mode = false;
                                let repaint = {
                                    let emu = emulator.lock().unwrap_or_else(PoisonError::into_inner);
                                    let screen = emu.screen();
                                    let mut rend = renderer.lock().unwrap_or_else(PoisonError::into_inner);
                                    rend.invalidate();
                                    rend.render(screen, &[], None)
                                };
                                if !repaint.is_empty()
                                    && let Err(e) = stdout_tx.send(repaint).await {
                                    error!("Error sending repaint to stdout channel: {e}");
                                }
                            }
                            EncryptedFrame::ScreenState(payload) => {
                                let repaint = self.apply_full_state(
                                    &payload,
                                    &emulator,
                                    &prediction,
                                    &renderer,
                                    &in_alt_screen,
                                );
                                if !repaint.is_empty()
                                    && let Err(e) = stdout_tx.send(repaint).await
                                {
                                    error!("Error sending ScreenState repaint to stdout channel: {e}");
                                }
                            }
                            EncryptedFrame::ScreenStateCompressed(compressed) => {
                                match decode_all(compressed.as_slice()) {
                                    Ok(payload) => {
                                        let repaint = self.apply_full_state(
                                            &payload,
                                            &emulator,
                                            &prediction,
                                            &renderer,
                                            &in_alt_screen,
                                        );
                                        if !repaint.is_empty()
                                            && let Err(e) = stdout_tx.send(repaint).await
                                        {
                                            error!("Error sending ScreenStateCompressed repaint to stdout channel: {e}");
                                        }
                                    }
                                    Err(e) => {
                                        error!("Failed to decompress ScreenStateCompressed: {e}");
                                    }
                                }
                            }
                            EncryptedFrame::PtyExit => {
                                *exit_msg
                                    .lock()
                                    .unwrap_or_else(PoisonError::into_inner) =
                                    Some(b"[moshpit] Remote session ended.\r\n");
                                exit_token.cancel();
                                break 'session;
                            }
                            EncryptedFrame::StateChunk((seq, total, data)) => {
                                self.handle_state_chunk(
                                    seq,
                                    total,
                                    data,
                                    &emulator,
                                    &prediction,
                                    &renderer,
                                    &in_alt_screen,
                                    &stdout_tx,
                                )
                                .await;
                            }
                            EncryptedFrame::CompressedBytes((_id, compressed)) => {
                                match decode_all(compressed.as_slice()) {
                                    Ok(decompressed) => {
                                        let message =
                                            self.intercept_queries(&decompressed, &emulator);
                                        process_bytes_with_prediction(
                                            message,
                                            &mut prev_bytes,
                                            &mut osc_started,
                                            &stdout_tx,
                                            scrollback_mode,
                                            &exit_token,
                                            &emulator,
                                            &prediction,
                                            &in_alt_screen,
                                            &renderer,
                                            passthrough,
                                        )
                                        .await;
                                    }
                                    Err(e) => {
                                        error!("Failed to decompress CompressedBytes: {e}");
                                    }
                                }
                            }
                        }
                    }
                    nak_check_deadline = TokioInstant::now()
                        + if self.diff_mode == DiffMode::Reliable {
                            if self.gap_first_seen.is_empty() {
                                nak_park
                            } else {
                                self.nak_check_interval()
                            }
                        } else {
                            nak_park
                        };
                },
                // Silence timeout: no frame received within `silence_timeout`.
                () = async {
                    match silence_deadline {
                        Some(dl) => sleep_until(dl).await,
                        None => pending().await,
                    }
                } => {
                    info!("Server not responding, signalling reconnect");
                    self.signal_reconnect_or_exit(1);
                    break;
                },
                frame_res = self.read_encrypted_frame() => {
                    // Reset silence deadline on every received frame.
                    if let Some(timeout) = self.silence_timeout {
                        silence_deadline = Some(TokioInstant::now() + timeout);
                    }
                    match frame_res {
                        Ok(Some((frame, seq))) => {
                            for ready in self.handle_arrival(frame, seq) {
                                match ready {
                                    EncryptedFrame::Resize(_) => {
                                        error!("Received Resize frame on client, which is unexpected");
                                    }
                                    EncryptedFrame::Keepalive(ts) => {
                                        if let Some(ref tx) = self.nak_out_tx
                                            && let Err(e) =
                                                tx.try_send(EncryptedFrame::Keepalive(ts))
                                        {
                                            warn!("Failed to echo keepalive: {e}");
                                        }
                                    }
                                    EncryptedFrame::Nak(_)
                                    | EncryptedFrame::RepaintRequest
                                    | EncryptedFrame::ClientAck(_) => {}
                                    EncryptedFrame::Shutdown => {
                                        info!("Server is shutting down, reconnecting");
                                        self.signal_reconnect_or_exit(0);
                                        break 'session;
                                    }
                                    EncryptedFrame::ScrollbackStart => {
                                        scrollback_mode = true;
                                    }
                                    EncryptedFrame::ScrollbackEnd => {
                                        scrollback_mode = false;
                                        let repaint = {
                                            let emu = emulator.lock().unwrap_or_else(PoisonError::into_inner);
                                            let screen = emu.screen();
                                            let mut rend = renderer.lock().unwrap_or_else(PoisonError::into_inner);
                                            rend.invalidate();
                                            rend.render(screen, &[], None)
                                        };
                                        if !repaint.is_empty()
                                            && let Err(e) = stdout_tx.send(repaint).await {
                                            error!("Error sending repaint to stdout channel: {e}");
                                        }
                                    }
                                    EncryptedFrame::ScreenState(payload) => {
                                        let repaint = self.apply_full_state(
                                            &payload,
                                            &emulator,
                                            &prediction,
                                            &renderer,
                                            &in_alt_screen,
                                        );
                                        if !repaint.is_empty()
                                            && let Err(e) = stdout_tx.send(repaint).await
                                        {
                                            error!("Error sending ScreenState repaint to stdout channel: {e}");
                                        }
                                    }
                                    EncryptedFrame::ScreenStateCompressed(compressed) => {
                                        match decode_all(compressed.as_slice()) {
                                            Ok(payload) => {
                                                let repaint = self.apply_full_state(
                                                    &payload,
                                                    &emulator,
                                                    &prediction,
                                                    &renderer,
                                                    &in_alt_screen,
                                                );
                                                if !repaint.is_empty()
                                                    && let Err(e) = stdout_tx.send(repaint).await
                                                {
                                                    error!("Error sending ScreenStateCompressed repaint to stdout channel: {e}");
                                                }
                                            }
                                            Err(e) => {
                                                error!("Failed to decompress ScreenStateCompressed: {e}");
                                            }
                                        }
                                    }
                                    EncryptedFrame::CompressedBytes((_id, compressed)) => {
                                        match decode_all(compressed.as_slice()) {
                                            Ok(decompressed) => {
                                                let message = self
                                                    .intercept_queries(&decompressed, &emulator);
                                                process_bytes_with_prediction(
                                                    message,
                                                    &mut prev_bytes,
                                                    &mut osc_started,
                                                    &stdout_tx,
                                                    scrollback_mode,
                                                    &exit_token,
                                                    &emulator,
                                                    &prediction,
                                                    &in_alt_screen,
                                                    &renderer,
                                                    passthrough,
                                                )
                                                .await;
                                            }
                                            Err(e) => {
                                                error!("Failed to decompress CompressedBytes: {e}");
                                            }
                                        }
                                    }
                                    EncryptedFrame::Bytes((_id, message)) => {
                                        let message =
                                            self.intercept_queries(&message, &emulator);
                                        process_bytes_with_prediction(
                                            message,
                                            &mut prev_bytes,
                                            &mut osc_started,
                                            &stdout_tx,
                                            scrollback_mode,
                                            &exit_token,
                                            &emulator,
                                            &prediction,
                                            &in_alt_screen,
                                            &renderer,
                                            passthrough,
                                        )
                                        .await;
                                    }
                                    EncryptedFrame::StateSyncDiff((base_id, diff_id, compressed)) => {
                                        if !self.initial_state_received {
                                            // Full state not yet received — discard and trigger a push.
                                            if let Some(ref tx) = self.nak_out_tx {
                                                drop(tx.try_send(EncryptedFrame::RepaintRequest));
                                            }
                                        } else if base_id == self.ack_state_seq {
                                            self.statesync_mismatch_count = 0;
                                            match decode_all(compressed.as_slice()) {
                                                Ok(diff_bytes) => {
                                                    let (rows, cols) = {
                                                        let emu = emulator.lock().unwrap_or_else(PoisonError::into_inner);
                                                        emu.screen().size()
                                                    };
                                                    let mut tmp = vt100::Parser::new(rows, cols, 0);
                                                    if !self.ack_state.is_empty() {
                                                        tmp.process(&self.ack_state);
                                                    }
                                                    tmp.process(&diff_bytes);
                                                    let is_alt = tmp.screen().alternate_screen();
                                                    in_alt_screen.store(is_alt, Ordering::Relaxed);
                                                    let mut new_ack = tmp.screen().contents_formatted();
                                                    if is_alt {
                                                        let mut prefixed = b"\x1b[?1049h".to_vec();
                                                        prefixed.extend_from_slice(&new_ack);
                                                        new_ack = prefixed;
                                                    }
                                                    self.ack_state = new_ack;
                                                    self.ack_state_seq = diff_id;
                                                    // Resync the authoritative emulator to the new
                                                    // state so the prediction engine (and the
                                                    // forwarder's local echo) work in StateSync mode,
                                                    // then render a single clean update — predictions
                                                    // reconciled — through the shared renderer.
                                                    {
                                                        let mut emu = emulator.lock().unwrap_or_else(PoisonError::into_inner);
                                                        emu.replace_parser(tmp);
                                                    }
                                                    let repaint = render_server_update(
                                                        &emulator,
                                                        &prediction,
                                                        &renderer,
                                                        !is_alt,
                                                    );
                                                    if !repaint.is_empty()
                                                        && let Err(e) = stdout_tx.send(repaint).await
                                                    {
                                                        error!("Error sending StateSyncDiff to stdout channel: {e}");
                                                    }
                                                    if let Some(ref tx) = self.nak_out_tx
                                                        && let Err(e) = tx.try_send(EncryptedFrame::ClientAck(diff_id))
                                                    {
                                                        warn!("Failed to send ClientAck: {e}");
                                                    }
                                                }
                                                Err(e) => {
                                                    error!("Failed to decompress StateSyncDiff: {e}");
                                                }
                                            }
                                        } else {
                                            self.statesync_mismatch_count += 1;
                                            if self.statesync_mismatch_count >= 3 {
                                                self.statesync_mismatch_count = 0;
                                                if let Some(ref tx) = self.nak_out_tx
                                                    && let Err(e) = tx.try_send(EncryptedFrame::RepaintRequest)
                                                {
                                                    warn!("Failed to send StateSync desync RepaintRequest: {e}");
                                                }
                                            }
                                        }
                                    }
                                    EncryptedFrame::PtyExit => {
                                        *exit_msg
                                            .lock()
                                            .unwrap_or_else(PoisonError::into_inner) =
                                            Some(b"[moshpit] Remote session ended.\r\n");
                                        exit_token.cancel();
                                        break 'session;
                                    }
                                    EncryptedFrame::StateChunk((seq, total, data)) => {
                                        self.handle_state_chunk(
                                            seq,
                                            total,
                                            data,
                                            &emulator,
                                            &prediction,
                                            &renderer,
                                            &in_alt_screen,
                                            &stdout_tx,
                                        )
                                        .await;
                                    }
                                }
                            }
                            // A new frame may have opened gaps — rearm the NAK deadline so
                            // check_nak_timeouts fires promptly if needed.
                            if self.diff_mode == DiffMode::Reliable {
                                nak_check_deadline =
                                    TokioInstant::now() + self.nak_check_interval();
                            }
                        }
                        Ok(None) => {
                            info!("server closed UDP connection");
                            self.signal_reconnect_or_exit(0);
                            break;
                        }
                        Err(e) => {
                            error!("udp read error, server likely disconnected: {e}");
                            self.signal_reconnect_or_exit(1);
                            break;
                        }
                    }
                }
            }
        }
    }
}

/// Feed server bytes through the emulator and render a single clean update.
///
/// Pipeline (default, unified rendering):
/// 1. Detect shell-exit via OSC title.
/// 2. Feed raw bytes into the terminal emulator (the single source of truth).
/// 3. Render the emulator's screen — with predictions reconciled and merged —
///    through the shared [`Renderer`], which is the sole writer to the terminal.
///
/// When `passthrough` is `true` the legacy behavior is used instead: raw bytes
/// are written straight to the terminal and prediction overlays are painted on
/// top out-of-band.  This is an escape hatch and is off by default.
#[cfg_attr(nightly, allow(clippy::too_many_arguments))]
async fn process_bytes_with_prediction(
    raw: Vec<u8>,
    prev_bytes: &mut BytesMut,
    osc_started: &mut bool,
    stdout_tx: &Sender<Vec<u8>>,
    // When true, raw bytes are silently fed into the emulator only; no stdout output is produced.
    scrollback_mode: bool,
    exit_token: &CancellationToken,
    emulator: &Arc<Mutex<Emulator>>,
    prediction: &Arc<Mutex<PredictionEngine>>,
    in_alt_screen: &Arc<AtomicBool>,
    renderer: &Arc<Mutex<Renderer>>,
    passthrough: bool,
) {
    // ── 1. OSC exit detection ─────────────────────────────────────────────
    let message = if prev_bytes.is_empty() {
        raw.clone()
    } else {
        let mut combined = BytesMut::with_capacity(prev_bytes.len() + raw.len());
        combined.extend_from_slice(prev_bytes);
        combined.extend_from_slice(&raw);
        prev_bytes.clear();
        combined.freeze().to_vec()
    };
    prev_bytes.clear();
    let mut valid_utf8 = String::new();
    for chunk in message.utf8_chunks() {
        valid_utf8.push_str(chunk.valid());
        if !chunk.invalid().is_empty() {
            prev_bytes.extend_from_slice(chunk.invalid());
        }
    }
    let result = TokenStream::from(&valid_utf8).collect::<Vec<Token<'_>>>();
    for part in &result {
        match part {
            Token::String(osc_cmd_string) => {
                if *osc_started && is_exit_title(osc_cmd_string, false) {
                    exit_token.cancel();
                }
            }
            Token::ControlFunction(control_function) => {
                if *osc_started && (*control_function == c1::ST || *control_function == c0::BEL) {
                    *osc_started = false;
                } else if *control_function == c1::OSC && !*osc_started {
                    *osc_started = true;
                }
            }
        }
    }

    // ── 2. (legacy) forward raw bytes to stdout ──────────────────────────
    // In passthrough mode the physical terminal is driven directly by the
    // server's PTY bytes (the pre-unified behavior).  In the default rendered
    // path the renderer is the sole writer and raw bytes are never emitted.
    // In scrollback_mode the bytes are absorbed silently regardless — the
    // renderer emits a single clean repaint when ScrollbackEnd arrives.
    if passthrough
        && !scrollback_mode
        && let Err(e) = stdout_tx.send(raw.clone()).await
    {
        error!("Error sending to stdout channel: {e}");
        return;
    }

    // ── 3. Feed raw bytes into the emulator (the single source of truth) ──
    let was_alt = in_alt_screen.load(Ordering::Relaxed);
    let is_alt = {
        let mut emu = emulator.lock().unwrap_or_else(PoisonError::into_inner);
        emu.process(&raw);
        let is_alt = emu.screen().alternate_screen();
        in_alt_screen.store(is_alt, Ordering::Relaxed);
        is_alt
    };
    // A full-screen app (vi, htop) entering alternate screen can leave the OSC
    // state machine in a stuck state if its escape output spans frame boundaries.
    // Reset on entry to prevent a spurious exit detection after the app quits.
    if is_alt && !was_alt {
        *osc_started = false;
    }

    // While absorbing scrollback we produce no output — the renderer emits a
    // single clean repaint when ScrollbackEnd arrives.
    if scrollback_mode {
        return;
    }

    // ── 4. Render the update ──────────────────────────────────────────────
    // Predictions are skipped in alternate-screen mode (vi, htop, etc.) — the
    // app owns the screen and prediction only adds contention.
    if passthrough {
        // Legacy: paint prediction overlays on top of the raw bytes.
        if !is_alt {
            let (overlays, cursor) = {
                let emu = emulator.lock().unwrap_or_else(PoisonError::into_inner);
                let screen = emu.screen();
                let mut pred = prediction.lock().unwrap_or_else(PoisonError::into_inner);
                pred.cull(screen);
                pred.apply(screen)
            };
            let overlay_out = paint_overlays_to_ansi(&overlays, cursor);
            if !overlay_out.is_empty()
                && let Err(e) = stdout_tx.send(overlay_out).await
            {
                error!("Error sending overlays to stdout channel: {e}");
            }
        }
    } else {
        // Unified: the renderer is the sole writer; predictions are reconciled
        // and merged into the diffed framebuffer so culled predictions heal.
        let out = render_server_update(emulator, prediction, renderer, !is_alt);
        if !out.is_empty()
            && let Err(e) = stdout_tx.send(out).await
        {
            error!("Error sending render to stdout channel: {e}");
        }
    }
}

impl UdpReader {
    /// Read a single `Frame` value from the underlying stream.
    ///
    /// The function waits until it has retrieved enough data to parse a frame.
    /// Any data remaining in the read buffer after the frame has been parsed is
    /// kept there for the next call to `read_frame`.
    ///
    /// # Returns
    ///
    /// On success, the received frame is returned. If the `TcpStream`
    /// is closed in a way that doesn't break a frame in half, it returns
    /// `None`. Otherwise, an error is returned.
    ///
    /// # Errors
    /// * Connection reset by peer.
    /// * I/O error.
    /// * Frame parsing error.
    ///
    pub async fn read_encrypted_frame(&mut self) -> Result<Option<(EncryptedFrame, u64)>> {
        loop {
            let mut buffer = BytesMut::with_capacity(8192);

            let len = self.socket.recv_buf(&mut buffer).await?;
            if len == 0 {
                // The remote closed the connection. For this to be a clean
                // shutdown, there should be no data in the read buffer. If
                // there is, this means that the peer closed the socket while
                // sending a frame.
                if buffer.is_empty() {
                    info!("empty buffer after 0 bytes read, returning None");
                    return Ok(None);
                }
                return Err(MoshpitError::ConnectionResetByPeer.into());
            }

            // Attempt to parse a frame from the buffered data. If enough data
            // has been buffered, the frame is returned.
            match self.parse_encrypted_frame(&mut buffer) {
                Ok(Some((frame, seq))) => return Ok(Some((frame, seq))),
                Ok(None) => {
                    // Not enough data has been buffered yet to parse a full
                    // frame. Continue the loop to read more data from the socket.
                }
                Err(err) => {
                    warn!("Failed to parse encrypted frame: {err}");
                }
            }
        }
    }

    /// Receives one UDP datagram via `recv_from`, parses and authenticates it, and
    /// returns the decoded frame, its sequence number, and the sender's address.
    /// Used by `server_frame_loop` so that the source address of every packet is
    /// visible for NAT roam detection without connecting the socket.
    async fn recv_frame_from(&self) -> Result<Option<(EncryptedFrame, u64, SocketAddr)>> {
        let mut buf = vec![0u8; 65535];
        loop {
            let (len, src) = self.socket.recv_from(&mut buf).await?;
            if len == 0 {
                return Ok(None);
            }
            let mut buffer = BytesMut::from(&buf[..len]);
            match self.parse_encrypted_frame(&mut buffer) {
                Ok(Some((frame, seq))) => return Ok(Some((frame, seq, src))),
                Ok(None) => {}
                Err(e) => {
                    warn!("Failed to parse UDP frame from {src}: {e}");
                }
            }
        }
    }

    /// Tries to parse a frame from the buffer. Returns the frame and its sequence number on
    /// success, `Ok(None)` when the buffer has insufficient data, or `Err` on a bad frame.
    fn parse_encrypted_frame(
        &self,
        buffer: &mut BytesMut,
    ) -> Result<Option<(EncryptedFrame, u64)>> {
        let mut buf = Cursor::new(&buffer[..]);
        buf.set_position(0);

        match EncryptedFrame::parse(&mut buf, self.id, &self.hmac, &self.rnk, self.mac_tag_len) {
            Ok(Some((frame, seq))) => {
                buffer.clear();
                Ok(Some((frame, seq)))
            }
            Ok(None) => Ok(None),
            Err(err) => Err(err),
        }
    }
}

#[cfg(test)]
mod tests {
    use aws_lc_rs::{
        aead::{AES_256_GCM_SIV, UnboundKey},
        hmac::HMAC_SHA512,
    };

    use std::sync::Mutex as StdMutex;
    use std::{
        sync::{
            Arc, Mutex,
            atomic::{AtomicBool, AtomicU64, Ordering},
        },
        time::{Duration, Instant},
    };

    use anyhow::Result;
    use aws_lc_rs::aead::LessSafeKey;
    use aws_lc_rs::hmac::Key;
    use bytes::BytesMut;
    use tokio::{
        net::UdpSocket,
        runtime::Runtime,
        spawn,
        sync::mpsc::{Receiver, Sender, channel},
        time::sleep,
    };
    use tokio_util::sync::CancellationToken;
    use uuid::Uuid;

    use super::{
        DiffMode, EncryptedFrame, MAX_NAK_RETRIES, MAX_NAK_TIMEOUT, MAX_SEQ_JUMP,
        MIN_NAK_CHECK_INTERVAL, MIN_NAK_TIMEOUT, RECV_BUFFER_REPAINT_THRESHOLD,
        REPAINT_REQUEST_THRESHOLD, UdpReader, process_bytes_with_prediction,
    };
    use crate::udp::sender::RETRANSMIT_WINDOW;
    use crate::{Emulator, PredictionEngine, Renderer, TerminalMessage};

    #[tokio::test]
    async fn test_handle_arrival_seq_jump() -> Result<()> {
        // Build a minimal UdpReader
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);

        let mut reader = UdpReader::builder()
            .socket(socket)
            .id(Uuid::new_v4())
            .rnk(LessSafeKey::new(
                UnboundKey::new(&AES_256_GCM_SIV, &[0u8; 32])
                    .expect("test AES-256-GCM-SIV key setup"),
            ))
            .hmac(Key::new(HMAC_SHA512, &[0u8; 64]))
            .build();

        // First packet arrives normally
        let frame1 = EncryptedFrame::Keepalive(0);
        let ready1 = reader.handle_arrival(frame1, 0);
        assert_eq!(ready1.len(), 1);
        assert_eq!(reader.next_seq, 1);
        assert!(reader.gap_first_seen.is_empty());

        // Massive sequence jump
        let oversized_jump_seq = 1 + MAX_SEQ_JUMP + 10;
        let frame2 = EncryptedFrame::Keepalive(0);
        let ready2 = reader.handle_arrival(frame2, oversized_jump_seq);

        // Should drop the frame
        assert!(ready2.is_empty());
        assert_eq!(reader.next_seq, 1); // Unchanged
        assert!(reader.gap_first_seen.is_empty()); // No gaps recorded!

        // Small sequence jump (within limits)
        let frame3 = EncryptedFrame::Keepalive(0);
        let ready3 = reader.handle_arrival(frame3, 3);

        // Should buffer the frame and record gaps for 1 and 2
        assert!(ready3.is_empty());
        assert_eq!(reader.next_seq, 1);
        assert_eq!(reader.gap_first_seen.len(), 2);
        assert!(reader.gap_first_seen.contains_key(&1));
        assert!(reader.gap_first_seen.contains_key(&2));
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Property tests (proptest)
    // -----------------------------------------------------------------------

    use proptest::{prop_assert, prop_assert_eq, proptest};

    fn make_reader_sync() -> UdpReader {
        // Build a UdpReader synchronously using a blocking socket creation.
        // proptest strategy closures cannot be async, so we use a blocking handle.
        let rt = Runtime::new().expect("tokio runtime");
        let socket = rt.block_on(async {
            UdpSocket::bind("127.0.0.1:0")
                .await
                .expect("bind test socket")
        });
        UdpReader::builder()
            .socket(Arc::new(socket))
            .id(Uuid::new_v4())
            .rnk(LessSafeKey::new(
                UnboundKey::new(&AES_256_GCM_SIV, &[0u8; 32])
                    .expect("test AES-256-GCM-SIV key setup"),
            ))
            .hmac(Key::new(HMAC_SHA512, &[0u8; 64]))
            .build()
    }

    proptest! {
        /// For any sequence of in-order frames `[0..N]`, every frame is delivered
        /// exactly once and in order.
        #[test]
        fn prop_in_order_delivery(n in 1u64..64u64) {
            let mut reader = make_reader_sync();
            let mut delivered = Vec::new();
            for seq in 0..n {
                let ready = reader.handle_arrival(EncryptedFrame::Keepalive(0), seq);
                delivered.extend(ready);
            }
            // All N frames should have been delivered immediately.
            prop_assert_eq!(delivered.len() as u64, n);
            prop_assert_eq!(reader.next_seq, n);
        }

        /// A single out-of-order pair (seq+1 arrives before seq) is reordered
        /// correctly: after the gap is filled both frames are delivered.
        #[test]
        fn prop_single_gap_reorder(base in 0u64..1000u64) {
            let mut reader = make_reader_sync();

            // Deliver base first so next_seq = base+1 is established.
            if base > 0 {
                for s in 0..base {
                    drop(reader.handle_arrival(EncryptedFrame::Keepalive(0), s));
                }
            }

            // Deliver base+1 (out of order — gap at `base` if base==0 else at base).
            // Simplified: just send seq=1 before seq=0 from a fresh reader.
            let mut reader2 = make_reader_sync();
            let late = reader2.handle_arrival(EncryptedFrame::Keepalive(0), 1);
            // seq=1 arrives before seq=0 — buffered, none delivered yet.
            prop_assert!(late.is_empty(), "frame buffered, not delivered yet");
            prop_assert_eq!(reader2.next_seq, 0);

            // Now deliver the missing seq=0.
            let flushed = reader2.handle_arrival(EncryptedFrame::Keepalive(0), 0);
            // Both seq=0 and the buffered seq=1 should now be delivered.
            prop_assert_eq!(flushed.len(), 2);
            prop_assert_eq!(reader2.next_seq, 2);
        }

        /// Any frame whose seq exceeds next_seq + MAX_SEQ_JUMP is dropped.
        /// `next_seq` and gap tracking must be unchanged.
        #[test]
        fn prop_seq_jump_rejected(jump in (MAX_SEQ_JUMP + 1)..(MAX_SEQ_JUMP * 4)) {
            let mut reader = make_reader_sync();
            let seq = reader.next_seq + jump;
            let ready = reader.handle_arrival(EncryptedFrame::Keepalive(0), seq);
            prop_assert!(ready.is_empty(), "oversized seq-jump frame must be dropped");
            prop_assert_eq!(reader.next_seq, 0, "next_seq must be unchanged");
            prop_assert!(reader.gap_first_seen.is_empty(), "no gap state must be recorded");
            prop_assert!(reader.recv_buffer.is_empty(), "no buffer entry must be created");
        }

        /// A frame with a seq < next_seq is a replay/duplicate — must be discarded.
        #[test]
        fn prop_replay_rejected(n in 2u64..32u64) {
            let mut reader = make_reader_sync();
            // Deliver n frames in order to advance next_seq to n.
            for seq in 0..n {
                drop(reader.handle_arrival(EncryptedFrame::Keepalive(0), seq));
            }
            prop_assert_eq!(reader.next_seq, n);

            // Now re-deliver any already-seen sequence number.
            for old_seq in 0..n {
                let ready = reader.handle_arrival(EncryptedFrame::Keepalive(0), old_seq);
                prop_assert!(ready.is_empty(), "replayed frame {old_seq} must be discarded");
            }
            prop_assert_eq!(reader.next_seq, n, "next_seq must be unchanged after replays");
        }

        /// Under arbitrary reordering within the allowed window, recv_buffer
        /// never grows beyond MAX_SEQ_JUMP entries.
        #[test]
        fn prop_recv_buffer_bounded(seqs in proptest::collection::vec(0u64..MAX_SEQ_JUMP, 0..128)) {
            let mut reader = make_reader_sync();
            for seq in seqs {
                drop(reader.handle_arrival(EncryptedFrame::Keepalive(0), seq));
                prop_assert!(
                    reader.recv_buffer.len() as u64 <= MAX_SEQ_JUMP,
                    "recv_buffer must stay bounded: len={}", reader.recv_buffer.len()
                );
            }
        }
    }

    // ── Phase 1: intercept_queries ─────────────────────────────────────────────

    /// Build a `UdpReader` wired with a `query_response_tx` so CSI/OSC responses
    /// can be observed in tests.
    async fn make_reader_with_response_rx() -> (UdpReader, Receiver<EncryptedFrame>) {
        let socket = Arc::new(
            UdpSocket::bind("127.0.0.1:0")
                .await
                .expect("bind test socket"),
        );
        let (tx, rx) = channel::<EncryptedFrame>(16);
        let reader = UdpReader::builder()
            .socket(socket)
            .id(Uuid::new_v4())
            .rnk(LessSafeKey::new(
                UnboundKey::new(&AES_256_GCM_SIV, &[0u8; 32])
                    .expect("test AES-256-GCM-SIV key setup"),
            ))
            .hmac(Key::new(HMAC_SHA512, &[0u8; 64]))
            .query_response_tx(tx)
            .build();
        (reader, rx)
    }

    fn make_emulator() -> Arc<Mutex<Emulator>> {
        Arc::new(Mutex::new(Emulator::new(24, 80)))
    }

    // --- plain bytes passthrough ---

    #[tokio::test]
    async fn intercept_queries_plain_bytes_passthrough() {
        let (reader, _rx) = make_reader_with_response_rx().await;
        let emu = make_emulator();
        let input = b"hello world";
        let out = reader.intercept_queries(input, &emu);
        assert_eq!(out, input);
    }

    #[tokio::test]
    async fn intercept_queries_empty_passthrough() {
        let (reader, _rx) = make_reader_with_response_rx().await;
        let emu = make_emulator();
        let out = reader.intercept_queries(b"", &emu);
        assert!(out.is_empty());
    }

    // --- VT (0x0B) and FF (0x0C) normalisation to CR+LF ---

    #[tokio::test]
    async fn intercept_queries_vt_normalized_to_crlf() {
        let (reader, _rx) = make_reader_with_response_rx().await;
        let emu = make_emulator();
        let out = reader.intercept_queries(b"\x0b", &emu);
        assert_eq!(out, b"\r\n");
    }

    #[tokio::test]
    async fn intercept_queries_ff_normalized_to_crlf() {
        let (reader, _rx) = make_reader_with_response_rx().await;
        let emu = make_emulator();
        let out = reader.intercept_queries(b"\x0c", &emu);
        assert_eq!(out, b"\r\n");
    }

    #[tokio::test]
    async fn intercept_queries_multiple_vt_ff() {
        let (reader, _rx) = make_reader_with_response_rx().await;
        let emu = make_emulator();
        let out = reader.intercept_queries(b"\x0ba\x0c", &emu);
        assert_eq!(out, b"\r\na\r\n");
    }

    // --- unknown ESC sequence passes through unchanged ---

    #[tokio::test]
    async fn intercept_queries_unknown_esc_passthrough() {
        let (reader, mut rx) = make_reader_with_response_rx().await;
        let emu = make_emulator();
        // ESC M (reverse index) — not a CSI or OSC, passes through unchanged
        let input = b"\x1bM";
        let out = reader.intercept_queries(input, &emu);
        // Unknown ESC sequences pass through unmodified
        assert_eq!(out, input);
        assert!(rx.try_recv().is_err(), "no response frame for unknown ESC");
    }

    // --- CSI queries: intercept DSR (ESC[6n) ---

    #[tokio::test]
    async fn intercept_queries_csi_dsr_sends_response_and_strips_from_stdout() {
        let (reader, mut rx) = make_reader_with_response_rx().await;
        let emu = make_emulator();
        // DSR: ESC [ 6 n
        let out = reader.intercept_queries(b"\x1b[6n", &emu);
        // The query should be stripped from output
        assert!(out.is_empty(), "DSR query must not pass through to stdout");
        // A response frame should have been sent
        let frame = rx.try_recv().expect("expected a response frame");
        let EncryptedFrame::Bytes((_id, resp)) = frame else {
            panic!("expected Bytes frame, got {frame:?}");
        };
        // Response format: ESC [ row ; col R
        let s = String::from_utf8(resp).expect("valid UTF-8 response");
        assert!(s.starts_with("\x1b["), "response must start with ESC [");
        assert!(s.ends_with('R'), "response must end with R");
    }

    // --- CSI DA1 (ESC[0c) ---

    #[tokio::test]
    async fn intercept_queries_csi_da1_sends_response() {
        let (reader, mut rx) = make_reader_with_response_rx().await;
        let emu = make_emulator();
        let out = reader.intercept_queries(b"\x1b[0c", &emu);
        assert!(out.is_empty(), "DA1 query must not pass through");
        let frame = rx.try_recv().expect("expected response for DA1");
        let EncryptedFrame::Bytes((_id, resp)) = frame else {
            panic!("expected Bytes frame");
        };
        assert_eq!(resp, b"\x1b[?62c");
    }

    // --- CSI DA1 with empty param (ESC[c) ---

    #[tokio::test]
    async fn intercept_queries_csi_da1_empty_param_sends_response() {
        let (reader, mut rx) = make_reader_with_response_rx().await;
        let emu = make_emulator();
        let out = reader.intercept_queries(b"\x1b[c", &emu);
        assert!(
            out.is_empty(),
            "DA1 (empty param) query must not pass through"
        );
        let frame = rx
            .try_recv()
            .expect("expected response for DA1 empty param");
        let EncryptedFrame::Bytes((_id, resp)) = frame else {
            panic!("expected Bytes frame");
        };
        assert_eq!(resp, b"\x1b[?62c");
    }

    // --- CSI DA2 (ESC[>0c) ---

    #[tokio::test]
    async fn intercept_queries_csi_da2_sends_response() {
        let (reader, mut rx) = make_reader_with_response_rx().await;
        let emu = make_emulator();
        let out = reader.intercept_queries(b"\x1b[>0c", &emu);
        assert!(out.is_empty(), "DA2 query must not pass through");
        let frame = rx.try_recv().expect("expected response for DA2");
        let EncryptedFrame::Bytes((_id, resp)) = frame else {
            panic!("expected Bytes frame");
        };
        assert_eq!(resp, b"\x1b[>1;10;0c");
    }

    // --- CSI DA3 (ESC[=0c) ---

    #[tokio::test]
    async fn intercept_queries_csi_da3_sends_response() {
        let (reader, mut rx) = make_reader_with_response_rx().await;
        let emu = make_emulator();
        let out = reader.intercept_queries(b"\x1b[=0c", &emu);
        assert!(out.is_empty(), "DA3 query must not pass through");
        let frame = rx.try_recv().expect("expected response for DA3");
        let EncryptedFrame::Bytes((_id, resp)) = frame else {
            panic!("expected Bytes frame");
        };
        assert_eq!(resp, b"\x1bP!|00000000\x1b\\");
    }

    // --- CSI DSR (ESC[5n) ---

    #[tokio::test]
    async fn intercept_queries_csi_dsr_status_sends_device_ok() {
        let (reader, mut rx) = make_reader_with_response_rx().await;
        let emu = make_emulator();
        let out = reader.intercept_queries(b"\x1b[5n", &emu);
        assert!(out.is_empty(), "DSR query must not pass through");
        let frame = rx.try_recv().expect("expected DSR response");
        let EncryptedFrame::Bytes((_id, resp)) = frame else {
            panic!("expected Bytes frame");
        };
        assert_eq!(resp, b"\x1b[0n");
    }

    // --- XTVERSION (ESC[>q) ---

    #[tokio::test]
    async fn intercept_queries_csi_xtversion_sends_identity() {
        let (reader, mut rx) = make_reader_with_response_rx().await;
        let emu = make_emulator();
        let out = reader.intercept_queries(b"\x1b[>q", &emu);
        assert!(out.is_empty(), "XTVERSION query must not pass through");
        let frame = rx.try_recv().expect("expected XTVERSION response");
        let EncryptedFrame::Bytes((_id, resp)) = frame else {
            panic!("expected Bytes frame");
        };
        assert_eq!(resp, b"\x1bP>|moshpit\x1b\\");
    }

    // --- XTWINOPS terminal size (ESC[18t) ---

    #[tokio::test]
    async fn intercept_queries_csi_xtwinops_18_sends_terminal_size() {
        let (reader, mut rx) = make_reader_with_response_rx().await;
        let emu = make_emulator();
        let out = reader.intercept_queries(b"\x1b[18t", &emu);
        assert!(out.is_empty(), "XTWINOPS 18t must not pass through");
        let frame = rx.try_recv().expect("expected XTWINOPS 18t response");
        let EncryptedFrame::Bytes((_id, resp)) = frame else {
            panic!("expected Bytes frame");
        };
        let s = String::from_utf8(resp).expect("valid UTF-8 response");
        assert!(
            s.starts_with("\x1b[8;"),
            "response must start with ESC[8; — got {s:?}"
        );
        assert!(s.ends_with('t'), "response must end with 't'");
    }

    // --- XTWINOPS pixel sizes (ESC[14t, ESC[16t) ---

    #[tokio::test]
    async fn intercept_queries_csi_xtwinops_pixel_sizes_return_zeros() {
        let (reader, mut rx) = make_reader_with_response_rx().await;
        let emu = make_emulator();

        let out14 = reader.intercept_queries(b"\x1b[14t", &emu);
        assert!(out14.is_empty(), "XTWINOPS 14t must not pass through");
        let frame14 = rx.try_recv().expect("expected XTWINOPS 14t response");
        let EncryptedFrame::Bytes((_id, resp14)) = frame14 else {
            panic!("expected Bytes frame");
        };
        assert_eq!(resp14, b"\x1b[4;0;0t");

        let out16 = reader.intercept_queries(b"\x1b[16t", &emu);
        assert!(out16.is_empty(), "XTWINOPS 16t must not pass through");
        let frame16 = rx.try_recv().expect("expected XTWINOPS 16t response");
        let EncryptedFrame::Bytes((_id, resp16)) = frame16 else {
            panic!("expected Bytes frame");
        };
        assert_eq!(resp16, b"\x1b[6;0;0t");
    }

    // --- unrecognised CSI passes through ---

    #[tokio::test]
    async fn intercept_queries_csi_unrecognised_passes_through() {
        let (reader, mut rx) = make_reader_with_response_rx().await;
        let emu = make_emulator();
        // ESC [ 2 J (erase screen) — not a recognised query
        let input = b"\x1b[2J";
        let out = reader.intercept_queries(input, &emu);
        assert_eq!(out, input, "unrecognised CSI must pass through unchanged");
        assert!(rx.try_recv().is_err(), "no response frame expected");
    }

    // --- OSC 10 color query (foreground) ---

    #[tokio::test]
    async fn intercept_queries_osc10_fg_color_sends_response() {
        let (reader, mut rx) = make_reader_with_response_rx().await;
        let emu = make_emulator();
        // OSC 10 ;? BEL  — foreground color query
        let out = reader.intercept_queries(b"\x1b]10;?\x07", &emu);
        assert!(out.is_empty(), "OSC 10 query must not pass through");
        let frame = rx.try_recv().expect("expected OSC 10 response");
        let EncryptedFrame::Bytes((_id, resp)) = frame else {
            panic!("expected Bytes frame");
        };
        let s = String::from_utf8(resp).expect("valid UTF-8 response");
        assert!(s.starts_with("\x1b]10;"), "response must be OSC 10");
        assert!(s.ends_with('\x07'), "response must be BEL-terminated");
    }

    // --- OSC 11 color query (background) ---

    #[tokio::test]
    async fn intercept_queries_osc11_bg_color_sends_response() {
        let (reader, mut rx) = make_reader_with_response_rx().await;
        let emu = make_emulator();
        let out = reader.intercept_queries(b"\x1b]11;?\x07", &emu);
        assert!(out.is_empty(), "OSC 11 query must not pass through");
        let frame = rx.try_recv().expect("expected OSC 11 response");
        let EncryptedFrame::Bytes((_id, resp)) = frame else {
            panic!("expected Bytes frame");
        };
        let s = String::from_utf8(resp).expect("valid UTF-8 response");
        assert!(s.starts_with("\x1b]11;"), "response must be OSC 11");
    }

    // --- OSC 12 color query (cursor color) ---

    #[tokio::test]
    async fn intercept_queries_osc12_cursor_color_sends_response() {
        let (reader, mut rx) = make_reader_with_response_rx().await;
        let emu = make_emulator();
        let out = reader.intercept_queries(b"\x1b]12;?\x07", &emu);
        assert!(out.is_empty(), "OSC 12 query must not pass through");
        let frame = rx.try_recv().expect("expected OSC 12 response");
        let EncryptedFrame::Bytes((_id, resp)) = frame else {
            panic!("expected Bytes frame");
        };
        let s = String::from_utf8(resp).expect("valid UTF-8 response");
        assert!(s.starts_with("\x1b]12;"));
    }

    // --- unrecognised OSC passes through ---

    #[tokio::test]
    async fn intercept_queries_osc_unrecognised_passes_through() {
        let (reader, mut rx) = make_reader_with_response_rx().await;
        let emu = make_emulator();
        // OSC 0 (title) — not a color query
        let input = b"\x1b]0;title\x07";
        let out = reader.intercept_queries(input, &emu);
        assert_eq!(out, input, "unrecognised OSC must pass through unchanged");
        assert!(rx.try_recv().is_err(), "no response frame expected");
    }

    // --- OSC with ST terminator (ESC \) ---

    #[tokio::test]
    async fn intercept_queries_osc_st_terminator_recognized() {
        let (reader, mut rx) = make_reader_with_response_rx().await;
        let emu = make_emulator();
        // OSC 10 ;? ST  (ST = ESC \)
        let out = reader.intercept_queries(b"\x1b]10;?\x1b\\", &emu);
        assert!(
            out.is_empty(),
            "OSC 10 with ST terminator must not pass through"
        );
        let frame = rx.try_recv().expect("expected OSC 10 response");
        assert!(matches!(frame, EncryptedFrame::Bytes(_)));
    }

    // --- NAK routing via handle_arrival ---

    #[tokio::test]
    async fn handle_arrival_nak_routed_to_retransmit_tx() -> Result<()> {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
        let (retransmit_tx, mut retransmit_rx) = channel::<Vec<u64>>(4);
        let mut reader = UdpReader::builder()
            .socket(socket)
            .id(Uuid::new_v4())
            .rnk(LessSafeKey::new(
                UnboundKey::new(&AES_256_GCM_SIV, &[0u8; 32])
                    .expect("test AES-256-GCM-SIV key setup"),
            ))
            .hmac(Key::new(HMAC_SHA512, &[0u8; 64]))
            .retransmit_tx(retransmit_tx)
            .build();

        let nak_frame = EncryptedFrame::Nak(vec![5, 6, 7]);
        let ready = reader.handle_arrival(nak_frame, 0);
        // NAK frames are consumed; not delivered to the caller
        assert!(
            ready.is_empty(),
            "NAK frames must not be returned from handle_arrival"
        );
        // Retransmit request must have been forwarded
        let seqs = retransmit_rx
            .try_recv()
            .expect("expected retransmit request");
        assert_eq!(seqs, vec![5, 6, 7]);
        Ok(())
    }

    // --- window give-up path in check_nak_timeouts ---

    #[tokio::test]
    async fn check_nak_timeouts_window_give_up_advances_next_seq() -> Result<()> {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
        let mut reader = UdpReader::builder()
            .socket(socket)
            .id(Uuid::new_v4())
            .rnk(LessSafeKey::new(
                UnboundKey::new(&AES_256_GCM_SIV, &[0u8; 32])
                    .expect("test AES-256-GCM-SIV key setup"),
            ))
            .hmac(Key::new(HMAC_SHA512, &[0u8; 64]))
            .build();

        // Simulate a gap at seq=0: record it in gap_first_seen
        let _ = reader.gap_first_seen.insert(0, Instant::now());
        // Set highest_seq_seen so that seq=0 is outside the retransmit window
        reader.highest_seq_seen = RETRANSMIT_WINDOW + 1;
        // next_seq is still 0
        assert_eq!(reader.next_seq, 0);

        let delivered = reader.check_nak_timeouts();
        // Gap is given up on — next_seq should advance past it
        assert_eq!(
            reader.next_seq, 1,
            "next_seq must advance past given-up gap"
        );
        assert!(reader.gap_first_seen.is_empty(), "gap must be cleared");
        assert!(delivered.is_empty(), "no buffered frames to deliver");
        Ok(())
    }

    // ── Option A + Option D ────────────────────────────────────────────────────

    #[test]
    fn repaint_request_threshold_is_one() {
        assert_eq!(REPAINT_REQUEST_THRESHOLD, 1);
    }

    #[test]
    fn update_rtt_estimate_first_sample_jacobson_karels() {
        let mut reader = make_reader_sync();
        // First measurement: SRTT = 100ms, RTTVAR = 50ms, RTO = 100 + 4*50 = 300ms.
        reader.update_rtt_estimate(Duration::from_millis(100));
        assert_eq!(reader.srtt, Some(Duration::from_millis(100)));
        assert_eq!(reader.rttvar, Some(Duration::from_millis(50)));
        let rto = reader
            .nak_timeout
            .expect("nak_timeout set after first sample");
        assert_eq!(
            rto,
            Duration::from_millis(300),
            "first-sample RTO = srtt + 4*rttvar"
        );
    }

    #[test]
    fn update_rtt_estimate_second_sample_updates_variance() {
        let mut reader = make_reader_sync();
        // First: SRTT=100ms, RTTVAR=50ms, RTO=300ms.
        reader.update_rtt_estimate(Duration::from_millis(100));
        // Second: sample=200ms, |SRTT - sample| = 100ms.
        // Duration arithmetic uses nanosecond precision:
        // RTTVAR = 50ms - 50ms/4 + 100ms/4 = 50 - 12.5 + 25 = 62.5ms.
        // SRTT   = 100ms - 100ms/8 + 200ms/8 = 100 - 12.5 + 25 = 112.5ms.
        // RTO    = 112.5 + 4*62.5 = 112.5 + 250 = 362.5ms.
        reader.update_rtt_estimate(Duration::from_millis(200));
        let srtt = reader.srtt.expect("srtt set after second sample");
        let rttvar = reader.rttvar.expect("rttvar set after second sample");
        let rto = reader
            .nak_timeout
            .expect("nak_timeout set after second sample");
        assert_eq!(
            srtt,
            Duration::from_micros(112_500),
            "SRTT after second sample"
        );
        assert_eq!(
            rttvar,
            Duration::from_micros(62_500),
            "RTTVAR after second sample"
        );
        assert_eq!(rto, Duration::from_micros(362_500), "RTO = srtt + 4*rttvar");
    }

    #[test]
    fn update_rtt_estimate_low_jitter_path_converges_rto_down() {
        let mut reader = make_reader_sync();
        // Drive the estimator with repeated 20ms samples (LAN path).
        // RTTVAR should converge to near-zero and RTO should converge toward
        // MIN_NAK_TIMEOUT (20ms).
        for _ in 0..64 {
            reader.update_rtt_estimate(Duration::from_millis(20));
        }
        let rto = reader
            .nak_timeout
            .expect("nak_timeout set after 64 samples");
        assert!(
            rto <= Duration::from_millis(60),
            "low-jitter LAN path RTO must converge toward MIN: got {rto:?}"
        );
    }

    #[test]
    fn update_rtt_estimate_high_jitter_inflates_rto() {
        let mut reader = make_reader_sync();
        // Alternate between 10ms and 200ms to simulate high jitter.
        for i in 0..8 {
            let sample = if i % 2 == 0 { 10 } else { 200 };
            reader.update_rtt_estimate(Duration::from_millis(sample));
        }
        let rto = reader.nak_timeout.expect("nak_timeout set after 8 samples");
        // With high jitter, RTTVAR grows large, pushing RTO up.
        assert!(
            rto > Duration::from_millis(100),
            "high-jitter path RTO must be inflated: got {rto:?}"
        );
    }

    #[test]
    fn update_rtt_estimate_clamped_to_min() {
        let mut reader = make_reader_sync();
        reader.nak_timeout = Some(Duration::from_millis(25));
        reader.update_rtt_estimate(Duration::from_millis(1));
        assert!(reader.nak_timeout.expect("nak_timeout set") >= MIN_NAK_TIMEOUT);
    }

    #[test]
    fn update_rtt_estimate_clamped_to_max() {
        let mut reader = make_reader_sync();
        reader.nak_timeout = Some(Duration::from_millis(490));
        reader.update_rtt_estimate(Duration::from_secs(2));
        assert!(reader.nak_timeout.expect("nak_timeout set") <= MAX_NAK_TIMEOUT);
    }

    #[test]
    fn handle_arrival_measures_rtt_on_gap_close() {
        let mut reader = make_reader_sync();
        // Inject a NAK timestamp as if we NAKed for seq=0 ~50 ms ago.
        let sent = Instant::now()
            .checked_sub(Duration::from_millis(50))
            .expect("time far enough in the past");
        let _prev = reader.gap_nak_sent_at.insert(0, sent);
        // Deliver seq=0 in order — gap closes, RTT sample taken.
        drop(reader.handle_arrival(EncryptedFrame::Keepalive(0), 0));
        assert!(reader.nak_timeout.is_some(), "nak_timeout must be updated");
        assert!(reader.gap_nak_sent_at.is_empty(), "entry must be consumed");
    }

    #[tokio::test]
    async fn handle_arrival_sends_immediate_nak_for_new_gaps() -> Result<()> {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
        let (nak_tx, mut nak_rx) = channel::<EncryptedFrame>(16);
        let mut reader = UdpReader::builder()
            .socket(socket)
            .id(Uuid::new_v4())
            .rnk(LessSafeKey::new(
                UnboundKey::new(&AES_256_GCM_SIV, &[0u8; 32])
                    .expect("test AES-256-GCM-SIV key setup"),
            ))
            .hmac(Key::new(HMAC_SHA512, &[0u8; 64]))
            .nak_out_tx(nak_tx)
            .build();

        // seq=2 arrives out of order — gaps 0 and 1 are newly discovered.
        let ready = reader.handle_arrival(EncryptedFrame::Keepalive(0), 2);
        assert!(ready.is_empty(), "out-of-order frame must be buffered");
        assert_eq!(reader.gap_first_seen.len(), 2);

        // An immediate NAK must fire without waiting for the poll tick.
        let frame = nak_rx.try_recv().expect("expected immediate NAK");
        let EncryptedFrame::Nak(mut seqs) = frame else {
            panic!("expected Nak frame, got {frame:?}");
        };
        seqs.sort_unstable();
        assert_eq!(seqs, vec![0, 1]);
        assert_eq!(
            reader.gap_nak_sent_at.len(),
            2,
            "RTT timestamps must be set"
        );

        // seq=4 arrives — gap 3 is new; gaps 0 and 1 are already tracked.
        let ready2 = reader.handle_arrival(EncryptedFrame::Keepalive(0), 4);
        assert!(ready2.is_empty());
        let frame2 = nak_rx
            .try_recv()
            .expect("expected NAK for newly-discovered gap 3");
        let EncryptedFrame::Nak(seqs2) = frame2 else {
            panic!("expected Nak frame");
        };
        assert_eq!(
            seqs2,
            vec![3],
            "only the newly-discovered gap must be NAKed"
        );
        Ok(())
    }

    #[tokio::test]
    async fn handle_arrival_no_duplicate_immediate_nak_for_known_gaps() -> Result<()> {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
        let (nak_tx, mut nak_rx) = channel::<EncryptedFrame>(16);
        let mut reader = UdpReader::builder()
            .socket(socket)
            .id(Uuid::new_v4())
            .rnk(LessSafeKey::new(
                UnboundKey::new(&AES_256_GCM_SIV, &[0u8; 32])
                    .expect("test AES-256-GCM-SIV key setup"),
            ))
            .hmac(Key::new(HMAC_SHA512, &[0u8; 64]))
            .nak_out_tx(nak_tx)
            .build();

        // seq=2 arrives — creates gaps 0 and 1, immediate NAK fires.
        drop(reader.handle_arrival(EncryptedFrame::Keepalive(0), 2));
        drop(nak_rx.try_recv().expect("first immediate NAK"));

        // seq=3 arrives — gaps 0 and 1 are already known (in gap_first_seen);
        // gap 2 is in recv_buffer and excluded. No new gaps → no NAK.
        drop(reader.handle_arrival(EncryptedFrame::Keepalive(0), 3));
        assert!(
            nak_rx.try_recv().is_err(),
            "no immediate NAK when all gaps are already tracked"
        );
        Ok(())
    }

    #[test]
    fn check_nak_timeouts_give_up_clears_gap_nak_sent_at() {
        let mut reader = make_reader_sync();
        let _prev = reader.gap_first_seen.insert(0, Instant::now());
        let _prev = reader.gap_nak_count.insert(0, MAX_NAK_RETRIES);
        let _prev = reader.gap_nak_sent_at.insert(0, Instant::now());
        drop(reader.check_nak_timeouts());
        assert!(
            reader.gap_nak_sent_at.is_empty(),
            "give-up must clear gap_nak_sent_at"
        );
    }

    #[test]
    fn update_rtt_estimate_updates_silence_timeout_when_set() {
        let mut reader = make_reader_sync();
        // Simulate client mode: silence_timeout was set.
        reader.silence_timeout = Some(Duration::from_secs(15));
        reader.update_rtt_estimate(Duration::from_millis(100));
        let nak = reader
            .nak_timeout
            .expect("nak_timeout set after rtt update");
        let silence = reader
            .silence_timeout
            .expect("silence_timeout set after rtt update");
        assert_eq!(silence, (nak * 30).max(Duration::from_secs(9)));
    }

    #[test]
    fn update_rtt_estimate_leaves_silence_timeout_none_when_unset() {
        let mut reader = make_reader_sync();
        // Simulate server mode: silence_timeout was never set.
        assert!(reader.silence_timeout.is_none());
        reader.update_rtt_estimate(Duration::from_millis(100));
        assert!(
            reader.silence_timeout.is_none(),
            "server-mode reader must not acquire a silence_timeout"
        );
    }

    #[test]
    fn nak_check_interval_default_uses_nak_timeout_quarter() {
        let reader = make_reader_sync();
        // nak_timeout = None → falls back to NAK_TIMEOUT (50 ms); interval = max(50/4, 5) = 12.5 ms
        // Duration division truncates to nanoseconds: 50_000_000 ns / 4 = 12_500_000 ns = 12.5 ms.
        let interval = reader.nak_check_interval();
        assert_eq!(interval, Duration::from_micros(12_500));
    }

    #[test]
    fn nak_check_interval_scales_with_nak_timeout() {
        let mut reader = make_reader_sync();
        reader.nak_timeout = Some(MAX_NAK_TIMEOUT); // 500 ms → interval = max(125, 5) = 125 ms
        assert_eq!(reader.nak_check_interval(), Duration::from_millis(125));
    }

    #[tokio::test]
    async fn route_or_deliver_nak_increments_received_count() -> Result<()> {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
        let counter = Arc::new(AtomicU64::new(0));
        let mut reader = UdpReader::builder()
            .socket(socket)
            .id(Uuid::new_v4())
            .rnk(LessSafeKey::new(
                UnboundKey::new(&AES_256_GCM_SIV, &[0u8; 32])
                    .expect("test AES-256-GCM-SIV key setup"),
            ))
            .hmac(Key::new(HMAC_SHA512, &[0u8; 64]))
            .nak_received_count(counter.clone())
            .build();

        // Deliver a NAK frame — the counter must be incremented exactly once.
        let nak = EncryptedFrame::Nak(vec![0, 1]);
        let result = reader.handle_arrival(nak, 0);
        assert!(result.is_empty(), "NAK frames must not be returned");
        assert_eq!(
            counter.load(Ordering::Relaxed),
            1,
            "counter must be incremented when a NAK is routed"
        );

        // Non-NAK frames must not increment.
        let keepalive = EncryptedFrame::Keepalive(0);
        drop(reader.handle_arrival(keepalive, 1));
        assert_eq!(
            counter.load(Ordering::Relaxed),
            1,
            "non-NAK frames must not increment the counter"
        );
        Ok(())
    }

    #[test]
    fn nak_check_interval_clamped_to_min() {
        let mut reader = make_reader_sync();
        reader.nak_timeout = Some(MIN_NAK_TIMEOUT); // 20 ms → 20/4 = 5 ms = MIN_NAK_CHECK_INTERVAL
        assert_eq!(reader.nak_check_interval(), MIN_NAK_CHECK_INTERVAL);
    }

    // ── Outlier RTT clamping ──────────────────────────────────────────────────

    #[test]
    fn update_rtt_estimate_clamps_outlier_to_ceiling() {
        let mut reader = make_reader_sync();
        // Default ceiling = NAK_TIMEOUT × 8 = 50 ms × 8 = 400 ms.
        // A 7-second sample is clamped to 400 ms, which IS fed into the estimator.
        // This breaks the "stuck at MIN" death spiral: the clamped value raises
        // nak_timeout so the next real spike can pass through the larger ceiling.
        reader.update_rtt_estimate(Duration::from_secs(7));
        assert!(
            reader.nak_timeout.is_some(),
            "clamped outlier must still update nak_timeout"
        );
        // The effective sample was 400 ms (ceiling), not 7 s.
        // First measurement: SRTT=400ms, RTTVAR=200ms, RTO=400+800=1200ms → MAX=500ms.
        assert_eq!(
            reader
                .nak_timeout
                .expect("nak_timeout set after rtt update"),
            MAX_NAK_TIMEOUT
        );
    }

    #[test]
    fn update_rtt_estimate_accepts_sample_just_within_ceiling() {
        let mut reader = make_reader_sync();
        // Ceiling = 50 ms × 8 = 400 ms. A 399 ms sample is below ceiling, no clamp.
        reader.update_rtt_estimate(Duration::from_millis(399));
        assert!(
            reader.nak_timeout.is_some(),
            "sample within ceiling must update nak_timeout"
        );
    }

    #[test]
    fn update_rtt_estimate_ceiling_scales_with_current_nak_timeout() {
        let mut reader = make_reader_sync();
        // Set nak_timeout to 25 ms → ceiling = 25 × 8 = 200 ms.
        reader.nak_timeout = Some(Duration::from_millis(25));
        reader.srtt = Some(Duration::from_millis(25));
        reader.rttvar = Some(Duration::from_millis(12));
        // 300 ms exceeds ceiling (200 ms) → clamped to 200 ms, not discarded.
        // nak_timeout must grow upward (out of the MIN neighbourhood).
        reader.update_rtt_estimate(Duration::from_millis(300));
        assert!(
            reader
                .nak_timeout
                .expect("nak_timeout set after rtt update")
                > Duration::from_millis(25),
            "clamped sample must grow nak_timeout above the prior value"
        );
    }

    /// Regression test for the "stuck at MIN" NAT death spiral.
    /// When `nak_timeout` converges to MIN (20 ms), ceiling = 160 ms.
    /// A 7 s congestion spike must be clamped — not discarded — so the estimator
    /// can grow `nak_timeout` upward and break the death spiral.
    #[test]
    fn update_rtt_estimate_nat_death_spiral_self_heals() {
        let mut reader = make_reader_sync();
        // Drive the estimator to MIN by feeding repeated fast samples.
        for _ in 0..64 {
            reader.update_rtt_estimate(Duration::from_millis(5));
        }
        assert_eq!(
            reader
                .nak_timeout
                .expect("nak_timeout set after many rtt updates"),
            MIN_NAK_TIMEOUT,
            "setup: nak_timeout must be at MIN before the spike"
        );
        // Inject a 7 s NAT congestion spike. With pure discard this would leave
        // nak_timeout stuck at 20 ms. With clamping it must grow.
        reader.update_rtt_estimate(Duration::from_secs(7));
        assert!(
            reader.nak_timeout.expect("nak_timeout set after spike") > MIN_NAK_TIMEOUT,
            "clamped spike must grow nak_timeout above MIN — death spiral broken"
        );
    }

    // ── handle_arrival: ScreenState obsoletes prior gaps ─────────────────────

    #[tokio::test]
    async fn handle_arrival_screen_state_obsoletes_gaps() -> Result<()> {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
        let mut reader = UdpReader::builder()
            .socket(socket)
            .id(Uuid::new_v4())
            .rnk(LessSafeKey::new(
                UnboundKey::new(&AES_256_GCM_SIV, &[0u8; 32])
                    .expect("test AES-256-GCM-SIV key setup"),
            ))
            .hmac(Key::new(HMAC_SHA512, &[0u8; 64]))
            .build();

        // seq 0 delivered normally
        drop(reader.handle_arrival(EncryptedFrame::Keepalive(0), 0));
        // Seq 3 arrives out-of-order → gaps 1 and 2 recorded
        drop(reader.handle_arrival(EncryptedFrame::Keepalive(0), 3));
        assert_eq!(reader.gap_first_seen.len(), 2);

        // ScreenState at seq 5 must discard gaps 1, 2, 3 and deliver itself
        let ready = reader.handle_arrival(EncryptedFrame::ScreenState(vec![]), 5);
        assert!(
            ready
                .iter()
                .any(|f| matches!(f, EncryptedFrame::ScreenState(_))),
            "ScreenState must be in the returned ready list"
        );
        assert!(
            reader.gap_first_seen.is_empty(),
            "all gaps must be discarded after ScreenState"
        );
        assert_eq!(reader.next_seq, 6);
        Ok(())
    }

    #[tokio::test]
    async fn handle_arrival_screen_state_drains_following_buffered_frames() -> Result<()> {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
        let mut reader = UdpReader::builder()
            .socket(socket)
            .id(Uuid::new_v4())
            .rnk(LessSafeKey::new(
                UnboundKey::new(&AES_256_GCM_SIV, &[0u8; 32])
                    .expect("test AES-256-GCM-SIV key setup"),
            ))
            .hmac(Key::new(HMAC_SHA512, &[0u8; 64]))
            .build();

        // seq 0 delivered
        drop(reader.handle_arrival(EncryptedFrame::Keepalive(0), 0));
        // Pre-buffer seq 6 (next after the upcoming ScreenState at 5)
        drop(reader.handle_arrival(EncryptedFrame::Keepalive(0), 6));

        // ScreenState at seq 5 — should deliver itself AND drain buffered seq 6
        let ready = reader.handle_arrival(EncryptedFrame::ScreenState(vec![]), 5);
        assert_eq!(
            ready.len(),
            2,
            "ready must contain the ScreenState and the following buffered frame"
        );
        assert_eq!(reader.next_seq, 7);
        assert!(reader.recv_buffer.is_empty());
        Ok(())
    }

    // ── process_bytes_with_prediction: alternate screen tracking ─────────────

    type PredState = (
        Sender<Vec<u8>>,
        Receiver<Vec<u8>>,
        Arc<Mutex<Emulator>>,
        Arc<Mutex<PredictionEngine>>,
        Arc<AtomicBool>,
        CancellationToken,
        Arc<Mutex<Renderer>>,
    );

    /// Helper: build the shared state needed to call `process_bytes_with_prediction`.
    fn make_prediction_state() -> PredState {
        use crate::DisplayPreference;
        let (stdout_tx, stdout_rx) = channel::<Vec<u8>>(16);
        let emulator = make_emulator();
        let prediction = Arc::new(Mutex::new(PredictionEngine::new(DisplayPreference::Never)));
        let in_alt_screen = Arc::new(AtomicBool::new(false));
        let exit_token = CancellationToken::new();
        let renderer = Arc::new(Mutex::new(Renderer::new(24, 80)));
        (
            stdout_tx,
            stdout_rx,
            emulator,
            prediction,
            in_alt_screen,
            exit_token,
            renderer,
        )
    }

    #[tokio::test]
    async fn process_bytes_with_prediction_sets_in_alt_screen_on_entry() {
        let (stdout_tx, _rx, emulator, prediction, in_alt_screen, exit_token, renderer) =
            make_prediction_state();
        let mut prev_bytes = BytesMut::new();
        let mut osc_started = false;

        // DECSET 1049 enters the alternate screen buffer
        process_bytes_with_prediction(
            b"\x1b[?1049h".to_vec(),
            &mut prev_bytes,
            &mut osc_started,
            &stdout_tx,
            false,
            &exit_token,
            &emulator,
            &prediction,
            &in_alt_screen,
            &renderer,
            false,
        )
        .await;

        assert!(
            in_alt_screen.load(Ordering::Relaxed),
            "in_alt_screen must be true after ESC[?1049h"
        );
    }

    #[tokio::test]
    async fn process_bytes_with_prediction_clears_in_alt_screen_on_exit() {
        let (stdout_tx, _rx, emulator, prediction, in_alt_screen, exit_token, renderer) =
            make_prediction_state();
        let mut prev_bytes = BytesMut::new();
        let mut osc_started = false;

        // Enter alternate screen
        process_bytes_with_prediction(
            b"\x1b[?1049h".to_vec(),
            &mut prev_bytes,
            &mut osc_started,
            &stdout_tx,
            false,
            &exit_token,
            &emulator,
            &prediction,
            &in_alt_screen,
            &renderer,
            false,
        )
        .await;
        assert!(
            in_alt_screen.load(Ordering::Relaxed),
            "precondition: must be in alt screen"
        );

        // Exit alternate screen
        process_bytes_with_prediction(
            b"\x1b[?1049l".to_vec(),
            &mut prev_bytes,
            &mut osc_started,
            &stdout_tx,
            false,
            &exit_token,
            &emulator,
            &prediction,
            &in_alt_screen,
            &renderer,
            false,
        )
        .await;

        assert!(
            !in_alt_screen.load(Ordering::Relaxed),
            "in_alt_screen must be false after ESC[?1049l"
        );
    }

    #[tokio::test]
    async fn process_bytes_with_prediction_resets_osc_started_on_alt_screen_entry() {
        let (stdout_tx, _rx, emulator, prediction, in_alt_screen, exit_token, renderer) =
            make_prediction_state();
        let mut prev_bytes = BytesMut::new();
        let mut osc_started = true; // simulate a stuck OSC state machine

        // Entering alt screen must reset the stuck state
        process_bytes_with_prediction(
            b"\x1b[?1049h".to_vec(),
            &mut prev_bytes,
            &mut osc_started,
            &stdout_tx,
            false,
            &exit_token,
            &emulator,
            &prediction,
            &in_alt_screen,
            &renderer,
            false,
        )
        .await;

        assert!(
            !osc_started,
            "osc_started must be reset to false on alternate screen entry"
        );
    }

    #[tokio::test]
    async fn process_bytes_with_prediction_passthrough_forwards_raw_bytes() {
        let (stdout_tx, mut rx, emulator, prediction, in_alt_screen, exit_token, renderer) =
            make_prediction_state();
        let mut prev_bytes = BytesMut::new();
        let mut osc_started = false;

        // Legacy passthrough: the raw server bytes must be written straight to
        // stdout (the pre-unified behavior).
        process_bytes_with_prediction(
            b"hello".to_vec(),
            &mut prev_bytes,
            &mut osc_started,
            &stdout_tx,
            false,
            &exit_token,
            &emulator,
            &prediction,
            &in_alt_screen,
            &renderer,
            true,
        )
        .await;

        let out = rx
            .try_recv()
            .expect("passthrough must forward the raw bytes");
        assert_eq!(out, b"hello", "raw server bytes must be forwarded verbatim");
    }

    #[tokio::test]
    async fn process_bytes_with_prediction_rendered_path_emits_rendered_output() {
        let (stdout_tx, mut rx, emulator, prediction, in_alt_screen, exit_token, renderer) =
            make_prediction_state();
        let mut prev_bytes = BytesMut::new();
        let mut osc_started = false;

        // Default (rendered) path: the renderer is the sole writer.  The output
        // is a clean rendered update, not the raw bytes, but it must contain the
        // server content 'hi'.
        process_bytes_with_prediction(
            b"hi".to_vec(),
            &mut prev_bytes,
            &mut osc_started,
            &stdout_tx,
            false,
            &exit_token,
            &emulator,
            &prediction,
            &in_alt_screen,
            &renderer,
            false,
        )
        .await;

        let out = rx
            .try_recv()
            .expect("rendered path must emit a rendered update");
        // Feed the rendered bytes into a stand-in terminal and check the glyphs.
        let mut term = vt100::Parser::new(24, 80, 0);
        term.process(&out);
        assert_eq!(
            term.screen().cell(0, 0).map(vt100::Cell::contents),
            Some("h"),
            "rendered output must paint the server content"
        );
    }

    #[tokio::test]
    async fn process_bytes_with_prediction_scrollback_absorbs_silently() {
        let (stdout_tx, mut rx, emulator, prediction, in_alt_screen, exit_token, renderer) =
            make_prediction_state();
        let mut prev_bytes = BytesMut::new();
        let mut osc_started = false;

        // In scrollback_mode no output is emitted regardless of passthrough —
        // the renderer emits a single clean repaint when ScrollbackEnd arrives.
        process_bytes_with_prediction(
            b"absorb me".to_vec(),
            &mut prev_bytes,
            &mut osc_started,
            &stdout_tx,
            true,
            &exit_token,
            &emulator,
            &prediction,
            &in_alt_screen,
            &renderer,
            false,
        )
        .await;

        assert!(
            rx.try_recv().is_err(),
            "scrollback mode must absorb bytes without emitting output"
        );
        // ...but the emulator still tracked the bytes for later repaint.
        assert_eq!(
            emulator
                .lock()
                .unwrap()
                .screen()
                .cell(0, 0)
                .map(vt100::Cell::contents),
            Some("a"),
            "scrollback bytes must still be fed into the emulator"
        );
    }

    #[tokio::test]
    async fn handle_arrival_screen_state_compressed_also_obsoletes_gaps() -> Result<()> {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
        let mut reader = UdpReader::builder()
            .socket(socket)
            .id(Uuid::new_v4())
            .rnk(LessSafeKey::new(
                UnboundKey::new(&AES_256_GCM_SIV, &[0u8; 32])
                    .expect("test AES-256-GCM-SIV key setup"),
            ))
            .hmac(Key::new(HMAC_SHA512, &[0u8; 64]))
            .build();

        drop(reader.handle_arrival(EncryptedFrame::Keepalive(0), 0));
        drop(reader.handle_arrival(EncryptedFrame::Keepalive(0), 3));
        assert!(!reader.gap_first_seen.is_empty());

        let ready = reader.handle_arrival(EncryptedFrame::ScreenStateCompressed(vec![]), 5);
        assert!(
            ready
                .iter()
                .any(|f| matches!(f, EncryptedFrame::ScreenStateCompressed(_))),
        );
        assert!(reader.gap_first_seen.is_empty());
        Ok(())
    }

    // ── handle_arrival: burst gap threshold + immediate NAK ──────────────────

    #[tokio::test]
    async fn handle_arrival_burst_triggers_repaint_request_at_threshold() -> Result<()> {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
        let (nak_tx, mut nak_rx) = channel::<EncryptedFrame>(32);
        let mut reader = UdpReader::builder()
            .socket(socket)
            .id(Uuid::new_v4())
            .rnk(LessSafeKey::new(
                UnboundKey::new(&AES_256_GCM_SIV, &[0u8; 32])
                    .expect("test AES-256-GCM-SIV key setup"),
            ))
            .hmac(Key::new(HMAC_SHA512, &[0u8; 64]))
            .nak_out_tx(nak_tx)
            .build();

        // Deliver frames out-of-order to fill recv_buffer to RECV_BUFFER_REPAINT_THRESHOLD.
        // next_seq starts at 0; deliver seq RECV_BUFFER_REPAINT_THRESHOLD through
        // RECV_BUFFER_REPAINT_THRESHOLD * 2 so there are that many frames in the buffer.
        let threshold = RECV_BUFFER_REPAINT_THRESHOLD;
        for i in 0..=threshold {
            let seq = u64::try_from(threshold + 1 + i).expect("seq fits in u64");
            drop(reader.handle_arrival(EncryptedFrame::Keepalive(0), seq));
        }

        // Drain NAK frames; verify at least one RepaintRequest was sent.
        let mut saw_repaint = false;
        while let Ok(frame) = nak_rx.try_recv() {
            if matches!(frame, EncryptedFrame::RepaintRequest) {
                saw_repaint = true;
            }
        }
        assert!(
            saw_repaint,
            "expected RepaintRequest when recv_buffer reaches threshold"
        );
        Ok(())
    }

    #[tokio::test]
    async fn handle_arrival_new_gap_triggers_immediate_nak() -> Result<()> {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
        let (nak_tx, mut nak_rx) = channel::<EncryptedFrame>(32);
        let mut reader = UdpReader::builder()
            .socket(socket)
            .id(Uuid::new_v4())
            .rnk(LessSafeKey::new(
                UnboundKey::new(&AES_256_GCM_SIV, &[0u8; 32])
                    .expect("test AES-256-GCM-SIV key setup"),
            ))
            .hmac(Key::new(HMAC_SHA512, &[0u8; 64]))
            .nak_out_tx(nak_tx)
            .build();

        // seq=5 arrives when next_seq=0 → gaps 0..4 are new → immediate NAK
        drop(reader.handle_arrival(EncryptedFrame::Keepalive(0), 5));

        let frame = nak_rx.try_recv().expect("expected an immediate NAK frame");
        let EncryptedFrame::Nak(seqs) = frame else {
            panic!("expected Nak frame, got {frame:?}");
        };
        assert_eq!(seqs.len(), 5, "expected gaps 0..4 in NAK");
        for i in 0u64..5 {
            assert!(seqs.contains(&i), "gap {i} missing from NAK");
        }
        Ok(())
    }

    // ── drain_given_up_seqs: consecutive give-ups with buffered frames ────────

    #[test]
    fn drain_given_up_seqs_consecutive_give_ups_with_buffered_frames() {
        let mut reader = make_reader_sync();

        // Set up: seq 0 and seq 2 are given up (retry count at MAX), seq 1 is buffered.
        let past = Instant::now()
            .checked_sub(Duration::from_mins(1))
            .expect("time far enough in the past");
        let _r = reader.gap_first_seen.insert(0, past);
        let _r = reader.gap_nak_count.insert(0, MAX_NAK_RETRIES);
        let _r = reader.recv_buffer.insert(1, EncryptedFrame::Keepalive(0));
        let _r = reader.gap_first_seen.insert(2, past);
        let _r = reader.gap_nak_count.insert(2, MAX_NAK_RETRIES);
        let _r = reader.recv_buffer.insert(3, EncryptedFrame::Keepalive(0));

        let delivered = reader.drain_given_up_seqs();

        // seq 1 and 3 (buffered after the give-ups) should be delivered
        assert_eq!(
            delivered.len(),
            2,
            "buffered frames after give-ups should be delivered"
        );
        assert_eq!(reader.next_seq, 4);
        assert!(reader.gap_first_seen.is_empty());
        assert!(reader.gap_nak_count.is_empty());
    }

    // ── check_nak_timeouts: multiple timed-out gaps send a single Nak ─────────

    #[tokio::test]
    async fn check_nak_timeouts_multiple_gaps_sends_single_nak() -> Result<()> {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
        let (nak_tx, mut nak_rx) = channel::<EncryptedFrame>(16);
        let mut reader = UdpReader::builder()
            .socket(socket)
            .id(Uuid::new_v4())
            .rnk(LessSafeKey::new(
                UnboundKey::new(&AES_256_GCM_SIV, &[0u8; 32])
                    .expect("test AES-256-GCM-SIV key setup"),
            ))
            .hmac(Key::new(HMAC_SHA512, &[0u8; 64]))
            .nak_out_tx(nak_tx)
            .build();

        // Insert 3 gaps with an old timestamp so they all time out immediately.
        let past = Instant::now()
            .checked_sub(Duration::from_secs(10))
            .expect("time far enough in the past");
        for seq in [1u64, 3, 5] {
            let _r = reader.gap_first_seen.insert(seq, past);
            let _r = reader.gap_nak_count.insert(seq, 0);
        }

        drop(reader.check_nak_timeouts());

        // Collect all frames sent by check_nak_timeouts (Nak + optional RepaintRequest).
        let mut frames = Vec::new();
        while let Ok(f) = nak_rx.try_recv() {
            frames.push(f);
        }
        let nak_frame = frames
            .into_iter()
            .find(|f| matches!(f, EncryptedFrame::Nak(_)))
            .expect("expected a Nak frame");
        let EncryptedFrame::Nak(seqs) = nak_frame else {
            unreachable!()
        };
        assert_eq!(seqs.len(), 3, "all 3 gaps should appear in a single NAK");
        for s in [1u64, 3, 5] {
            assert!(seqs.contains(&s), "gap {s} missing from NAK");
        }
        Ok(())
    }

    // ── RTT: ceiling exact boundary ───────────────────────────────────────────

    #[test]
    fn update_rtt_estimate_sample_at_exact_ceiling_is_not_clamped() {
        let mut reader = make_reader_sync();
        // Default ceiling = NAK_TIMEOUT (50ms) × 8 = 400ms.
        // A sample exactly at 400ms must NOT be clamped (condition is `> ceiling`).
        reader.update_rtt_estimate(Duration::from_millis(400));
        // The estimator should have used 400ms directly (not clamped), producing
        // SRTT=400ms → nak_timeout = MAX (500ms).
        assert_eq!(
            reader
                .nak_timeout
                .expect("nak_timeout set after rtt update"),
            MAX_NAK_TIMEOUT,
            "sample equal to ceiling should not be clamped and should raise nak_timeout"
        );
    }

    // ── handle_state_chunk ────────────────────────────────────────────────────

    #[tokio::test]
    async fn handle_state_chunk_single_chunk_completes_assembly() -> Result<()> {
        use std::sync::Mutex as StdMutex;
        use zstd::encode_all;

        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
        let mut reader = UdpReader::builder()
            .socket(socket)
            .id(Uuid::new_v4())
            .rnk(LessSafeKey::new(
                UnboundKey::new(&AES_256_GCM_SIV, &[0u8; 32])
                    .expect("test AES-256-GCM-SIV key setup"),
            ))
            .hmac(Key::new(HMAC_SHA512, &[0u8; 64]))
            .build();

        let emulator = Arc::new(StdMutex::new(Emulator::new(24, 80)));
        let renderer = Arc::new(StdMutex::new(Renderer::new(24, 80)));
        let prediction = Arc::new(StdMutex::new(PredictionEngine::new(
            crate::DisplayPreference::Never,
        )));
        let in_alt_screen = Arc::new(AtomicBool::new(false));
        let (stdout_tx, _stdout_rx) = channel::<Vec<u8>>(8);

        let raw = b"hello";
        let compressed = encode_all(raw.as_slice(), 0).expect("zstd compression");

        // Single-chunk assembly: seq=0, total=1
        reader
            .handle_state_chunk(
                0,
                1,
                compressed,
                &emulator,
                &prediction,
                &renderer,
                &in_alt_screen,
                &stdout_tx,
            )
            .await;

        // After completion the assembly state must be reset
        assert_eq!(reader.pending_chunk_seq, 0);
        assert_eq!(reader.pending_chunk_total, 0);
        assert!(reader.pending_chunk_data.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn handle_state_chunk_out_of_order_clears_and_requests_repaint() -> Result<()> {
        use std::sync::Mutex as StdMutex;

        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
        let (nak_tx, mut nak_rx) = channel::<EncryptedFrame>(8);
        let mut reader = UdpReader::builder()
            .socket(socket)
            .id(Uuid::new_v4())
            .rnk(LessSafeKey::new(
                UnboundKey::new(&AES_256_GCM_SIV, &[0u8; 32])
                    .expect("test AES-256-GCM-SIV key setup"),
            ))
            .hmac(Key::new(HMAC_SHA512, &[0u8; 64]))
            .nak_out_tx(nak_tx)
            .build();

        let emulator = Arc::new(StdMutex::new(Emulator::new(24, 80)));
        let renderer = Arc::new(StdMutex::new(Renderer::new(24, 80)));
        let prediction = Arc::new(StdMutex::new(PredictionEngine::new(
            crate::DisplayPreference::Never,
        )));
        let in_alt_screen = Arc::new(AtomicBool::new(false));
        let (stdout_tx, _stdout_rx) = channel::<Vec<u8>>(8);

        // Start assembly: seq=0, total=3
        reader
            .handle_state_chunk(
                0,
                3,
                vec![0xAA; 10],
                &emulator,
                &prediction,
                &renderer,
                &in_alt_screen,
                &stdout_tx,
            )
            .await;

        // Out-of-order: seq=2 (skipping seq=1) → discard and send RepaintRequest
        reader
            .handle_state_chunk(
                2,
                3,
                vec![0xBB; 10],
                &emulator,
                &prediction,
                &renderer,
                &in_alt_screen,
                &stdout_tx,
            )
            .await;

        assert!(
            reader.pending_chunk_data.is_empty(),
            "assembly must be cleared"
        );
        let frame = nak_rx.try_recv().expect("expected RepaintRequest");
        assert!(
            matches!(frame, EncryptedFrame::RepaintRequest),
            "expected RepaintRequest after out-of-order chunk"
        );
        Ok(())
    }

    // ── apply_full_state ──────────────────────────────────────────────────────

    /// A reader plus the shared render state for `apply_full_state` tests.
    type FullStateFixtures = (
        UdpReader,
        Arc<StdMutex<Emulator>>,
        Arc<StdMutex<PredictionEngine>>,
        Arc<StdMutex<Renderer>>,
        Arc<AtomicBool>,
    );

    /// Build a reader plus the shared render state for `apply_full_state` tests.
    fn make_full_state_fixtures(diff_mode: DiffMode) -> FullStateFixtures {
        let reader = make_reader_sync_with_diff_mode(diff_mode);
        let emulator = Arc::new(StdMutex::new(Emulator::new(24, 80)));
        let prediction = Arc::new(StdMutex::new(PredictionEngine::new(
            crate::DisplayPreference::Never,
        )));
        let renderer = Arc::new(StdMutex::new(Renderer::new(24, 80)));
        let in_alt_screen = Arc::new(AtomicBool::new(false));
        (reader, emulator, prediction, renderer, in_alt_screen)
    }

    fn make_reader_sync_with_diff_mode(diff_mode: DiffMode) -> UdpReader {
        let rt = Runtime::new().expect("tokio runtime");
        let socket = rt.block_on(async {
            UdpSocket::bind("127.0.0.1:0")
                .await
                .expect("bind test socket")
        });
        UdpReader::builder()
            .socket(Arc::new(socket))
            .id(Uuid::new_v4())
            .rnk(LessSafeKey::new(
                UnboundKey::new(&AES_256_GCM_SIV, &[0u8; 32])
                    .expect("test AES-256-GCM-SIV key setup"),
            ))
            .hmac(Key::new(HMAC_SHA512, &[0u8; 64]))
            .diff_mode(diff_mode)
            .build()
    }

    #[test]
    fn apply_full_state_resyncs_emulator_and_returns_repaint() {
        let (mut reader, emulator, prediction, renderer, in_alt_screen) =
            make_full_state_fixtures(DiffMode::Datagram);
        // Pre-load the emulator with stale content that the snapshot replaces.
        emulator.lock().unwrap().process(b"stale content");

        let snapshot = {
            let mut p = vt100::Parser::new(24, 80, 0);
            p.process(b"fresh");
            p.screen().contents_formatted()
        };
        let repaint =
            reader.apply_full_state(&snapshot, &emulator, &prediction, &renderer, &in_alt_screen);

        // The authoritative emulator must now reflect the snapshot.
        assert_eq!(
            emulator
                .lock()
                .unwrap()
                .screen()
                .cell(0, 0)
                .map(vt100::Cell::contents),
            Some("f"),
            "emulator must be resynced to the snapshot"
        );
        // And the returned repaint must render that content to a terminal.
        let mut term = vt100::Parser::new(24, 80, 0);
        term.process(&repaint);
        assert_eq!(
            term.screen().cell(0, 0).map(vt100::Cell::contents),
            Some("f"),
            "repaint bytes must paint the snapshot content"
        );
        assert!(
            !in_alt_screen.load(Ordering::Relaxed),
            "a main-screen snapshot must clear the alt-screen flag"
        );
    }

    #[test]
    fn apply_full_state_preserves_alt_screen_across_snapshot() {
        let (mut reader, emulator, prediction, renderer, in_alt_screen) =
            make_full_state_fixtures(DiffMode::Datagram);
        // We are already in the alternate screen buffer (set earlier by the
        // DECSET passthrough).  `contents_formatted()` omits the `?1049h` enter
        // sequence, so `apply_full_state` must re-apply it from `was_alt` to
        // keep the reconstructed screen in the alt buffer.
        in_alt_screen.store(true, Ordering::Relaxed);

        let snapshot = {
            let mut p = vt100::Parser::new(24, 80, 0);
            p.process(b"app");
            p.screen().contents_formatted()
        };
        drop(reader.apply_full_state(&snapshot, &emulator, &prediction, &renderer, &in_alt_screen));

        assert!(
            in_alt_screen.load(Ordering::Relaxed),
            "alt-screen state must be preserved across a full-state snapshot"
        );
    }

    #[test]
    fn apply_full_state_statesync_refreshes_ack_bookkeeping() {
        let (mut reader, emulator, prediction, renderer, in_alt_screen) =
            make_full_state_fixtures(DiffMode::StateSync);
        // Dirty the ack bookkeeping so we can observe it being refreshed.
        reader.ack_state_seq = 42;
        reader.statesync_mismatch_count = 7;
        assert!(!reader.initial_state_received);

        let snapshot = {
            let mut p = vt100::Parser::new(24, 80, 0);
            p.process(b"sync");
            p.screen().contents_formatted()
        };
        drop(reader.apply_full_state(&snapshot, &emulator, &prediction, &renderer, &in_alt_screen));

        assert_eq!(reader.ack_state_seq, 0, "ack sequence must reset to 0");
        assert_eq!(
            reader.statesync_mismatch_count, 0,
            "mismatch counter must reset"
        );
        assert!(
            reader.initial_state_received,
            "initial_state_received must be set"
        );
        assert_eq!(
            reader.ack_state, snapshot,
            "ack_state must capture the reconstructed snapshot"
        );
    }

    #[test]
    fn apply_full_state_datagram_does_not_touch_ack_bookkeeping() {
        let (mut reader, emulator, prediction, renderer, in_alt_screen) =
            make_full_state_fixtures(DiffMode::Datagram);
        assert!(!reader.initial_state_received);

        let snapshot = {
            let mut p = vt100::Parser::new(24, 80, 0);
            p.process(b"data");
            p.screen().contents_formatted()
        };
        drop(reader.apply_full_state(&snapshot, &emulator, &prediction, &renderer, &in_alt_screen));

        // Datagram mode skips the StateSync ack-bookkeeping branch entirely.
        assert!(
            !reader.initial_state_received,
            "Datagram mode must not set initial_state_received"
        );
        assert!(
            reader.ack_state.is_empty(),
            "Datagram mode must not populate ack_state"
        );
    }

    // ── server_frame_loop / client_frame_loop integration tests ──────────────

    /// `server_frame_loop` parks the NAK deadline when no gaps exist after the timer fires
    /// and rearms it when a subsequent frame arrives.
    #[tokio::test]
    async fn server_frame_loop_parks_nak_when_no_gaps() -> Result<()> {
        use crate::UdpSender;
        use tokio::sync::mpsc::channel as mpsc_channel;

        let key_bytes = [0u8; 32];
        let hmac_bytes = [0u8; 64];
        let session_id = Uuid::new_v4();

        // Server socket: unconnected so recv_from can capture the client's address.
        let server_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
        let server_addr = server_sock.local_addr()?;

        // Client socket: connected to server — sender uses send() without an explicit peer.
        let client_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
        client_sock.connect(server_addr).await?;

        let (term_tx, _term_rx) = mpsc_channel::<TerminalMessage>(16);
        let token = CancellationToken::new();

        let mut reader = UdpReader::builder()
            .socket(server_sock)
            .id(session_id)
            .rnk(LessSafeKey::new(
                UnboundKey::new(&AES_256_GCM_SIV, &key_bytes)
                    .expect("test AES-256-GCM-SIV key setup"),
            ))
            .hmac(Key::new(HMAC_SHA512, &hmac_bytes))
            .build();

        let (_ctrl_tx, ctrl_rx) = mpsc_channel::<EncryptedFrame>(4);
        let (frame_tx, frame_rx) = mpsc_channel::<EncryptedFrame>(4);
        let (_ret_tx, ret_rx) = mpsc_channel::<Vec<u64>>(4);

        let mut sender = UdpSender::builder()
            .id(session_id)
            .rnk(LessSafeKey::new(
                UnboundKey::new(&AES_256_GCM_SIV, &key_bytes)
                    .expect("test AES-256-GCM-SIV key setup"),
            ))
            .hmac(Key::new(HMAC_SHA512, &hmac_bytes))
            .socket(client_sock)
            .control_rx(ctrl_rx)
            .rx(frame_rx)
            .retransmit_rx(ret_rx)
            .build();

        let t_sender = token.clone();
        let t_reader = token.clone();

        let sender_handle = spawn(async move { drop(sender.frame_loop(t_sender).await) });
        let reader_handle = spawn(async move { reader.server_frame_loop(t_reader, term_tx).await });

        // First Keepalive triggers initial peer-discovery recv_from and enters the loop.
        frame_tx
            .send(EncryptedFrame::Keepalive(0))
            .await
            .expect("test channel send");

        // Allow time for the NAK timer to fire (≥1 tick at nak_check_interval ≈ 5–12ms)
        // and park the deadline because gap_first_seen is empty.
        sleep(Duration::from_millis(40)).await;

        // Second Keepalive exercises the rearm-on-recv path inside the main loop.
        frame_tx
            .send(EncryptedFrame::Keepalive(0))
            .await
            .expect("test channel send");
        sleep(Duration::from_millis(10)).await;

        token.cancel();
        drop(sender_handle.await);
        let result = reader_handle.await?;
        assert!(result.is_ok());
        Ok(())
    }

    /// In `DiffMode::Datagram` the NAK deadline is parked immediately (24-hour horizon)
    /// so the timer branch never fires.  This exercises the `else { nak_park }` branch
    /// in `client_frame_loop` initialization.
    #[tokio::test]
    async fn client_frame_loop_nak_deadline_parked_in_datagram_mode() -> Result<()> {
        use crate::DisplayPreference;
        use std::sync::atomic::AtomicBool;
        use tokio::sync::mpsc::channel as mpsc_channel;

        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
        let token = CancellationToken::new();
        let exit_token = CancellationToken::new();

        let mut reader = UdpReader::builder()
            .socket(socket)
            .id(Uuid::new_v4())
            .rnk(LessSafeKey::new(
                UnboundKey::new(&AES_256_GCM_SIV, &[0u8; 32])
                    .expect("test AES-256-GCM-SIV key setup"),
            ))
            .hmac(Key::new(HMAC_SHA512, &[0u8; 64]))
            .diff_mode(DiffMode::Datagram)
            .build();

        let (stdout_tx, _stdout_rx) = mpsc_channel::<Vec<u8>>(4);
        let emulator = Arc::new(Mutex::new(Emulator::new(24, 80)));
        let prediction = Arc::new(Mutex::new(PredictionEngine::new(
            DisplayPreference::default(),
        )));
        let renderer = Arc::new(Mutex::new(Renderer::new(24, 80)));
        let in_alt = Arc::new(AtomicBool::new(false));

        // Cancel before the loop starts so we don't block on recv_buf.
        token.cancel();
        let exit_msg = Arc::new(Mutex::new(None));
        reader
            .client_frame_loop(
                token, exit_token, exit_msg, stdout_tx, emulator, prediction, renderer, in_alt,
            )
            .await;
        Ok(())
    }

    /// In `DiffMode::Reliable` the NAK check timer fires and parks the deadline when
    /// `gap_first_seen` is empty, exercising the parking logic inside `client_frame_loop`.
    #[tokio::test]
    async fn client_frame_loop_parks_nak_deadline_when_no_gaps() -> Result<()> {
        use crate::DisplayPreference;
        use std::sync::atomic::AtomicBool;
        use tokio::sync::mpsc::channel as mpsc_channel;

        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
        let token = CancellationToken::new();
        let exit_token = CancellationToken::new();

        let mut reader = UdpReader::builder()
            .socket(socket)
            .id(Uuid::new_v4())
            .rnk(LessSafeKey::new(
                UnboundKey::new(&AES_256_GCM_SIV, &[0u8; 32])
                    .expect("test AES-256-GCM-SIV key setup"),
            ))
            .hmac(Key::new(HMAC_SHA512, &[0u8; 64]))
            .build();

        let (stdout_tx, _stdout_rx) = mpsc_channel::<Vec<u8>>(4);
        let emulator = Arc::new(Mutex::new(Emulator::new(24, 80)));
        let prediction = Arc::new(Mutex::new(PredictionEngine::new(
            DisplayPreference::default(),
        )));
        let renderer = Arc::new(Mutex::new(Renderer::new(24, 80)));
        let in_alt = Arc::new(AtomicBool::new(false));

        let t = token.clone();
        let exit_msg = Arc::new(Mutex::new(None));
        let handle = spawn(async move {
            reader
                .client_frame_loop(
                    t, exit_token, exit_msg, stdout_tx, emulator, prediction, renderer, in_alt,
                )
                .await;
        });

        // Let the NAK timer fire at least once (nak_check_interval ≈ 5–12ms on loopback)
        // and execute the parking logic (gap_first_seen is empty → park to 24h).
        sleep(Duration::from_millis(40)).await;

        token.cancel();
        handle.await.expect("client_frame_loop task");
        Ok(())
    }
}
