// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

use std::{
    collections::{BTreeMap, HashMap},
    io::Cursor,
    process,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use ansi_control_codes::{
    c0, c1,
    parser::{Token, TokenStream},
};
use anyhow::Result;
use aws_lc_rs::{
    aead::{AES_256_GCM_SIV, RandomizedNonceKey},
    hmac::{HMAC_SHA512, Key},
};
use bon::Builder;
use bytes::BytesMut;
use tokio::{
    net::UdpSocket,
    select,
    sync::{mpsc::Sender, oneshot},
    time::{Instant as TokioInstant, interval, sleep, sleep_until},
};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};
use uuid::Uuid;
use zstd::decode_all;

use crate::{
    Emulator, EncryptedFrame, MoshpitError, PredictionEngine, Renderer, TerminalMessage,
    UuidWrapper, paint_overlays_to_ansi, udp::sender::RETRANSMIT_WINDOW, utils::is_exit_title,
};

/// Interval between NAK timeout checks.
const NAK_CHECK_INTERVAL: Duration = Duration::from_millis(20);
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
const RECV_BUFFER_REPAINT_THRESHOLD: usize = 25;
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
    #[builder(with = |key: [u8; 32]| -> Result<_> { RandomizedNonceKey::new(&AES_256_GCM_SIV, &key).map_err(Into::into) })]
    rnk: RandomizedNonceKey,
    /// Key for verifying UDP packet HMAC
    #[builder(with = |key: [u8; 64]| { Key::new(HMAC_SHA512, &key) })]
    hmac: Key,
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
    /// Base NAK timeout derived from the measured TCP key-exchange round-trip time.
    /// When set, replaces the hardcoded [`NAK_TIMEOUT`] constant as the base for
    /// the exponential backoff schedule, adapting retransmit requests to the
    /// observed network latency.  `None` falls back to [`NAK_TIMEOUT`] (50 ms).
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
    /// address via the first `recv_from` and connected the UDP socket to it.  The
    /// paired [`UdpSender`](crate::UdpSender) awaits this signal before sending any
    /// packets so it never calls `send()` on an unconnected socket.
    peer_discovered_tx: Option<oneshot::Sender<()>>,
    /// Fired by the server's [`server_frame_loop`](Self::server_frame_loop) when a
    /// [`EncryptedFrame::RepaintRequest`] arrives from the client.  The paired receiver
    /// is held by a task in `moshpits` that responds with an immediate
    /// [`EncryptedFrame::ScreenState`].
    repaint_tx: Option<Sender<()>>,
}

impl UdpReader {
    /// Signal the reconnect channel if set; otherwise exit the process.
    fn signal_reconnect_or_exit(&self, code: i32) {
        if let Some(ref tx) = self.reconnect_tx {
            let _ = tx.try_send(());
        } else {
            process::exit(code);
        }
    }

    /// Feed a NAK→retransmit round-trip sample into the EWMA (α = 1/8) and
    /// clamp the result to [`MIN_NAK_TIMEOUT`]..=[`MAX_NAK_TIMEOUT`].
    fn update_rtt_estimate(&mut self, sample: Duration) {
        let current = self.nak_timeout.unwrap_or(NAK_TIMEOUT);
        // 7/8 * current + 1/8 * sample using integer Duration arithmetic.
        let updated = current.saturating_sub(current / 8) + sample / 8;
        let clamped = updated.clamp(MIN_NAK_TIMEOUT, MAX_NAK_TIMEOUT);
        debug!("NAK RTT sample {:?} → nak_timeout {:?}", sample, clamped);
        self.nak_timeout = Some(clamped);
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
                let (row, col) = emulator.lock().unwrap().screen().cursor_position();
                Some(format!("\x1b[{};{}R", row + 1, col + 1).into_bytes())
            }
            (None, b"" | b"0", b'c') => Some(b"\x1b[?62c".to_vec()),
            (Some(b'>'), b"" | b"0", b'c') => Some(b"\x1b[>1;10;0c".to_vec()),
            (Some(b'='), b"" | b"0", b'c') => Some(b"\x1bP!|00000000\x1b\\".to_vec()),
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
    fn handle_arrival(&mut self, frame: EncryptedFrame, seq: u64) -> Vec<EncryptedFrame> {
        // Duplicate or replay
        if seq < self.next_seq {
            return vec![];
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
            for missing in self.next_seq..seq {
                if !self.recv_buffer.contains_key(&missing) {
                    let _entry = self
                        .gap_first_seen
                        .entry(missing)
                        .or_insert_with(Instant::now);
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
            return None;
        }
        Some(frame)
    }

    /// Send NAKs for gaps whose timeout has elapsed, reset their timer for potential re-NAK,
    /// and skip any gaps that have exceeded the maximum retry count or the sender's retransmit
    /// window. Returns frames from `recv_buffer` that become deliverable after skipping
    /// permanently lost packets.
    fn check_nak_timeouts(&mut self) -> Vec<EncryptedFrame> {
        let now = Instant::now();

        // 1a. Gaps that have exceeded the retry limit.
        let retry_give_up: Vec<u64> = self
            .gap_nak_count
            .iter()
            .filter_map(|(&seq, &count)| {
                if count >= MAX_NAK_RETRIES {
                    Some(seq)
                } else {
                    None
                }
            })
            .collect();

        // 1b. Gaps that have fallen outside the sender's retransmit window.
        //
        // When the server has sent RETRANSMIT_WINDOW more packets past a gap,
        // it has already evicted the lost packet from its buffer and retransmit
        // requests for it will silently fail.  Giving up immediately avoids the
        // full MAX_NAK_RETRIES × backoff wait (≈750 ms) during which all
        // subsequent output is stalled in recv_buffer.
        let window_give_up: Vec<u64> = self
            .gap_first_seen
            .keys()
            .filter(|&&seq| self.highest_seq_seen.saturating_sub(seq) > RETRANSMIT_WINDOW)
            .copied()
            .collect();

        // Merge both give-up sources, deduplicated.
        let mut give_up_set = std::collections::HashSet::new();
        for seq in retry_give_up.iter().chain(window_give_up.iter()) {
            let _inserted = give_up_set.insert(*seq);
        }

        let mut delivered = vec![];

        if !give_up_set.is_empty() {
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
                let _removed = self.gap_first_seen.remove(&seq);
                let _removed = self.gap_nak_count.remove(&seq);
                let _removed = self.gap_nak_sent_at.remove(&seq);
            }

            // Advance next_seq past given-up and buffered frames.
            loop {
                if give_up_set.contains(&self.next_seq) {
                    self.next_seq += 1;
                } else if let Some(buffered) = self.recv_buffer.remove(&self.next_seq) {
                    let _removed = self.gap_first_seen.remove(&self.next_seq);
                    let _removed = self.gap_nak_count.remove(&self.next_seq);
                    let _removed = self.gap_nak_sent_at.remove(&self.next_seq);
                    self.next_seq += 1;
                    if let Some(f) = self.route_or_deliver(buffered) {
                        delivered.push(f);
                    }
                } else {
                    break;
                }
            }
        }

        // 2. Normal NAK logic — request retransmission for recent gaps.
        // Each gap uses an exponentially backed-off timeout based on how many
        // times it has already been NAKed: timeout = base * 2^retry_count
        // (capped at base * 2^NAK_BACKOFF_MAX_SHIFT), so repeated misses
        // back off rather than flooding the sender with duplicate retransmit requests.
        // The base is the RTT-derived nak_timeout when available, else NAK_TIMEOUT.
        let base_nak_timeout = self.nak_timeout.unwrap_or(NAK_TIMEOUT);
        let timed_out: Vec<u64> = self
            .gap_first_seen
            .iter()
            .filter_map(|(&seq, &t)| {
                let retries = self.gap_nak_count.get(&seq).copied().unwrap_or(0);
                let shift = retries.min(NAK_BACKOFF_MAX_SHIFT);
                let backoff = base_nak_timeout * (1u32 << shift);
                if now.duration_since(t) >= backoff {
                    Some(seq)
                } else {
                    None
                }
            })
            .collect();
        if !timed_out.is_empty() {
            // Reset each gap's timer so the next backoff interval starts from now.
            // Track whether any gap just hit the RepaintRequest threshold.
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
                // Record when we sent this NAK so handle_arrival can measure RTT.
                let _prev = self.gap_nak_sent_at.insert(seq, now);
            }
            if let Some(ref tx) = self.nak_out_tx
                && let Err(e) = tx.try_send(EncryptedFrame::Nak(timed_out))
            {
                warn!("Failed to send NAK: {e}");
            }
            // When any gap reaches the repaint threshold, ask the server for an immediate
            // full-screen snapshot.  This unblocks the display without waiting for
            // retransmit to succeed or retries to be exhausted.
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
        // Wait for the first UDP datagram from the client.  This reveals the
        // client's real post-NAT address which we then connect the socket to.
        // The peer_discovered_tx oneshot is fired afterwards so that UdpSender
        // can start sending once the socket is connected.
        {
            let mut buf = vec![0u8; 65535];
            let (first_len, peer_addr) = self.socket.recv_from(&mut buf).await?;
            self.socket.connect(peer_addr).await?;
            if let Some(tx) = self.peer_discovered_tx.take() {
                let _ = tx.send(());
            }
            // Process the first packet through the normal pipeline.
            let mut first_buf = BytesMut::from(&buf[..first_len]);
            match self.parse_encrypted_frame(&mut first_buf) {
                Ok(Some((frame, seq))) => {
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
                            EncryptedFrame::Nak(_)
                            | EncryptedFrame::Shutdown
                            | EncryptedFrame::Keepalive
                            | EncryptedFrame::ScrollbackStart
                            | EncryptedFrame::ScrollbackEnd
                            | EncryptedFrame::ScreenState(_)
                            | EncryptedFrame::ScreenStateCompressed(_) => {}
                        }
                    }
                }
                Ok(None) => {}
                Err(e) => {
                    warn!("Failed to parse first UDP frame from client: {e}");
                }
            }
        }

        let mut nak_check = interval(NAK_CHECK_INTERVAL);
        loop {
            select! {
                () = token.cancelled() => break,
                _ = nak_check.tick() => {
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
                            EncryptedFrame::Nak(_) | EncryptedFrame::Shutdown | EncryptedFrame::Keepalive
                            | EncryptedFrame::ScrollbackStart | EncryptedFrame::ScrollbackEnd
                            | EncryptedFrame::ScreenState(_)
                            | EncryptedFrame::ScreenStateCompressed(_) => {}
                        }
                    }
                },
                frame_res = self.read_encrypted_frame() => {
                    match frame_res {
                        Ok(Some((frame, seq))) => {
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
                                    EncryptedFrame::Nak(_) | EncryptedFrame::Shutdown | EncryptedFrame::Keepalive
                                    | EncryptedFrame::ScrollbackStart | EncryptedFrame::ScrollbackEnd
                                    | EncryptedFrame::ScreenState(_)
                                    | EncryptedFrame::ScreenStateCompressed(_) => {}
                                }
                            }
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
    #[cfg_attr(nightly, allow(clippy::too_many_lines))]
    pub async fn client_frame_loop(
        &mut self,
        token: CancellationToken,
        stdout_tx: Sender<Vec<u8>>,
        emulator: Arc<Mutex<Emulator>>,
        prediction: Arc<Mutex<PredictionEngine>>,
        renderer: Arc<Mutex<Renderer>>,
    ) {
        let mut prev_bytes = BytesMut::with_capacity(1024);
        let mut osc_started = false;
        let mut nak_check = interval(NAK_CHECK_INTERVAL);
        // When true, raw bytes are fed into the emulator only — not sent to
        // stdout.  Set by ScrollbackStart, cleared by ScrollbackEnd.
        let mut scrollback_mode = false;
        // Deadline after which silence is treated as a server disconnect.
        let mut silence_deadline: Option<TokioInstant> =
            self.silence_timeout.map(|d| TokioInstant::now() + d);

        'session: loop {
            select! {
                () = token.cancelled() => process::exit(0),
                _ = nak_check.tick() => {
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
                                    &token,
                                    &emulator,
                                    &prediction,
                                )
                                .await;
                            }
                            EncryptedFrame::Resize(_) => {
                                error!("Received Resize frame on client, which is unexpected");
                            }
                            EncryptedFrame::Nak(_) | EncryptedFrame::Keepalive | EncryptedFrame::RepaintRequest => {}
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
                                    let emu = emulator.lock().unwrap();
                                    let screen = emu.screen();
                                    let mut rend = renderer.lock().unwrap();
                                    rend.invalidate();
                                    rend.render(screen, &[], None)
                                };
                                if !repaint.is_empty()
                                    && let Err(e) = stdout_tx.send(repaint).await {
                                    error!("Error sending repaint to stdout channel: {e}");
                                }
                            }
                            EncryptedFrame::ScreenState(payload) => {
                                let (rows, cols) = {
                                    let emu = emulator.lock().unwrap();
                                    emu.screen().size()
                                };
                                let mut tmp = vt100::Parser::new(rows, cols, 0);
                                tmp.process(&payload);
                                let repaint = {
                                    let mut rend = renderer.lock().unwrap();
                                    rend.invalidate();
                                    rend.render(tmp.screen(), &[], None)
                                };
                                if !repaint.is_empty()
                                    && let Err(e) = stdout_tx.send(repaint).await
                                {
                                    error!("Error sending ScreenState repaint to stdout channel: {e}");
                                }
                            }
                            EncryptedFrame::ScreenStateCompressed(compressed) => {
                                match decode_all(compressed.as_slice()) {
                                    Ok(payload) => {
                                        let (rows, cols) = {
                                            let emu = emulator.lock().unwrap();
                                            emu.screen().size()
                                        };
                                        let mut tmp = vt100::Parser::new(rows, cols, 0);
                                        tmp.process(&payload);
                                        let repaint = {
                                            let mut rend = renderer.lock().unwrap();
                                            rend.invalidate();
                                            rend.render(tmp.screen(), &[], None)
                                        };
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
                        }
                    }
                },
                // Silence timeout: no frame received within `silence_timeout`.
                () = async {
                    match silence_deadline {
                        Some(dl) => sleep_until(dl).await,
                        None => std::future::pending().await,
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
                                    EncryptedFrame::Nak(_) | EncryptedFrame::Keepalive | EncryptedFrame::RepaintRequest => {}
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
                                            let emu = emulator.lock().unwrap();
                                            let screen = emu.screen();
                                            let mut rend = renderer.lock().unwrap();
                                            rend.invalidate();
                                            rend.render(screen, &[], None)
                                        };
                                        if !repaint.is_empty()
                                            && let Err(e) = stdout_tx.send(repaint).await {
                                            error!("Error sending repaint to stdout channel: {e}");
                                        }
                                    }
                                    EncryptedFrame::ScreenState(payload) => {
                                        let (rows, cols) = {
                                            let emu = emulator.lock().unwrap();
                                            emu.screen().size()
                                        };
                                        let mut tmp = vt100::Parser::new(rows, cols, 0);
                                        tmp.process(&payload);
                                        let repaint = {
                                            let mut rend = renderer.lock().unwrap();
                                            rend.invalidate();
                                            rend.render(tmp.screen(), &[], None)
                                        };
                                        if !repaint.is_empty()
                                            && let Err(e) = stdout_tx.send(repaint).await
                                        {
                                            error!("Error sending ScreenState repaint to stdout channel: {e}");
                                        }
                                    }
                                    EncryptedFrame::ScreenStateCompressed(compressed) => {
                                        match decode_all(compressed.as_slice()) {
                                            Ok(payload) => {
                                                let (rows, cols) = {
                                                    let emu = emulator.lock().unwrap();
                                                    emu.screen().size()
                                                };
                                                let mut tmp = vt100::Parser::new(rows, cols, 0);
                                                tmp.process(&payload);
                                                let repaint = {
                                                    let mut rend = renderer.lock().unwrap();
                                                    rend.invalidate();
                                                    rend.render(tmp.screen(), &[], None)
                                                };
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
                                    EncryptedFrame::Bytes((_id, message)) => {
                                        let message =
                                            self.intercept_queries(&message, &emulator);
                                        process_bytes_with_prediction(
                                            message,
                                            &mut prev_bytes,
                                            &mut osc_started,
                                            &stdout_tx,
                                            scrollback_mode,
                                            &token,
                                            &emulator,
                                            &prediction,
                                        )
                                        .await;
                                    }
                                }
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

/// Feed server bytes through the prediction pipeline and write output to
/// the stdout channel.
///
/// Pipeline:
/// 1. Detect shell-exit via OSC title.
/// 2. Forward raw bytes to stdout unchanged (preserves normal terminal
///    rendering exactly as before prediction was added).
/// 3. Feed raw bytes into the terminal emulator (for prediction state).
/// 4. Cull confirmed/invalid predictions against the new screen state.
/// 5. Paint any active prediction overlays on top via ANSI sequences.
#[cfg_attr(nightly, allow(clippy::too_many_arguments))]
async fn process_bytes_with_prediction(
    raw: Vec<u8>,
    prev_bytes: &mut BytesMut,
    osc_started: &mut bool,
    stdout_tx: &Sender<Vec<u8>>,
    // When true, raw bytes are silently fed into the emulator only; no stdout output is produced.
    scrollback_mode: bool,
    token: &CancellationToken,
    emulator: &Arc<Mutex<Emulator>>,
    prediction: &Arc<Mutex<PredictionEngine>>,
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
                    sleep(Duration::from_millis(500)).await;
                    token.cancel();
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

    // ── 2. Forward raw bytes to stdout ───────────────────────────────────
    // The physical terminal drives its own display from the server's PTY
    // bytes.  We do not replace them with a computed representation; the
    // emulator is used only to track screen state for the prediction engine.
    // In scrollback_mode the bytes are absorbed silently — the renderer will
    // emit a single clean repaint when ScrollbackEnd arrives.
    if !scrollback_mode && let Err(e) = stdout_tx.send(raw.clone()).await {
        error!("Error sending to stdout channel: {e}");
        return;
    }

    // ── 3. Feed raw bytes into the emulator ──────────────────────────────
    {
        let mut emu = emulator.lock().unwrap();
        emu.process(&raw);
    }

    // ── 4+5. Cull predictions and paint overlays ─────────────────────────
    // Skip overlay painting while absorbing scrollback — there are no active
    // predictions during reconnect and we do not want flickering output.
    if !scrollback_mode {
        let (overlays, cursor) = {
            let emu = emulator.lock().unwrap();
            let screen = emu.screen();
            let mut pred = prediction.lock().unwrap();
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

    /// Tries to parse a frame from the buffer. Returns the frame and its sequence number on
    /// success, `Ok(None)` when the buffer has insufficient data, or `Err` on a bad frame.
    fn parse_encrypted_frame(
        &self,
        buffer: &mut BytesMut,
    ) -> Result<Option<(EncryptedFrame, u64)>> {
        let mut buf = Cursor::new(&buffer[..]);
        buf.set_position(0);

        match EncryptedFrame::parse(&mut buf, self.id, &self.hmac, &self.rnk) {
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
    use super::*;

    #[tokio::test]
    async fn test_handle_arrival_seq_jump() {
        // Build a minimal UdpReader
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());

        let mut reader = UdpReader::builder()
            .socket(socket)
            .id(Uuid::new_v4())
            .rnk([0u8; 32])
            .unwrap()
            .hmac([0u8; 64])
            .build();

        // First packet arrives normally
        let frame1 = EncryptedFrame::Keepalive;
        let ready1 = reader.handle_arrival(frame1, 0);
        assert_eq!(ready1.len(), 1);
        assert_eq!(reader.next_seq, 1);
        assert!(reader.gap_first_seen.is_empty());

        // Massive sequence jump
        let oversized_jump_seq = 1 + MAX_SEQ_JUMP + 10;
        let frame2 = EncryptedFrame::Keepalive;
        let ready2 = reader.handle_arrival(frame2, oversized_jump_seq);

        // Should drop the frame
        assert!(ready2.is_empty());
        assert_eq!(reader.next_seq, 1); // Unchanged
        assert!(reader.gap_first_seen.is_empty()); // No gaps recorded!

        // Small sequence jump (within limits)
        let frame3 = EncryptedFrame::Keepalive;
        let ready3 = reader.handle_arrival(frame3, 3);

        // Should buffer the frame and record gaps for 1 and 2
        assert!(ready3.is_empty());
        assert_eq!(reader.next_seq, 1);
        assert_eq!(reader.gap_first_seen.len(), 2);
        assert!(reader.gap_first_seen.contains_key(&1));
        assert!(reader.gap_first_seen.contains_key(&2));
    }

    // -----------------------------------------------------------------------
    // Property tests (proptest)
    // -----------------------------------------------------------------------

    use proptest::prelude::*;

    fn make_reader_sync() -> UdpReader {
        // Build a UdpReader synchronously using a blocking socket creation.
        // proptest strategy closures cannot be async, so we use a blocking handle.
        let rt = tokio::runtime::Runtime::new().unwrap();
        let socket = rt.block_on(async { UdpSocket::bind("127.0.0.1:0").await.unwrap() });
        UdpReader::builder()
            .socket(Arc::new(socket))
            .id(Uuid::new_v4())
            .rnk([0u8; 32])
            .unwrap()
            .hmac([0u8; 64])
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
                let ready = reader.handle_arrival(EncryptedFrame::Keepalive, seq);
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
                    drop(reader.handle_arrival(EncryptedFrame::Keepalive, s));
                }
            }

            // Deliver base+1 (out of order — gap at `base` if base==0 else at base).
            // Simplified: just send seq=1 before seq=0 from a fresh reader.
            let mut reader2 = make_reader_sync();
            let late = reader2.handle_arrival(EncryptedFrame::Keepalive, 1);
            // seq=1 arrives before seq=0 — buffered, none delivered yet.
            prop_assert!(late.is_empty(), "frame buffered, not delivered yet");
            prop_assert_eq!(reader2.next_seq, 0);

            // Now deliver the missing seq=0.
            let flushed = reader2.handle_arrival(EncryptedFrame::Keepalive, 0);
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
            let ready = reader.handle_arrival(EncryptedFrame::Keepalive, seq);
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
                drop(reader.handle_arrival(EncryptedFrame::Keepalive, seq));
            }
            prop_assert_eq!(reader.next_seq, n);

            // Now re-deliver any already-seen sequence number.
            for old_seq in 0..n {
                let ready = reader.handle_arrival(EncryptedFrame::Keepalive, old_seq);
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
                drop(reader.handle_arrival(EncryptedFrame::Keepalive, seq));
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
    async fn make_reader_with_response_rx()
    -> (UdpReader, tokio::sync::mpsc::Receiver<EncryptedFrame>) {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let (tx, rx) = tokio::sync::mpsc::channel::<EncryptedFrame>(16);
        let reader = UdpReader::builder()
            .socket(socket)
            .id(Uuid::new_v4())
            .rnk([0u8; 32])
            .unwrap()
            .hmac([0u8; 64])
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
        let s = String::from_utf8(resp).unwrap();
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
        let s = String::from_utf8(resp).unwrap();
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
        let s = String::from_utf8(resp).unwrap();
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
        let s = String::from_utf8(resp).unwrap();
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
    async fn handle_arrival_nak_routed_to_retransmit_tx() {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let (retransmit_tx, mut retransmit_rx) = tokio::sync::mpsc::channel::<Vec<u64>>(4);
        let mut reader = UdpReader::builder()
            .socket(socket)
            .id(Uuid::new_v4())
            .rnk([0u8; 32])
            .unwrap()
            .hmac([0u8; 64])
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
    }

    // --- window give-up path in check_nak_timeouts ---

    #[tokio::test]
    async fn check_nak_timeouts_window_give_up_advances_next_seq() {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let mut reader = UdpReader::builder()
            .socket(socket)
            .id(Uuid::new_v4())
            .rnk([0u8; 32])
            .unwrap()
            .hmac([0u8; 64])
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
    }

    // ── Option A + Option D ────────────────────────────────────────────────────

    #[test]
    fn repaint_request_threshold_is_one() {
        assert_eq!(REPAINT_REQUEST_THRESHOLD, 1);
    }

    #[test]
    fn update_rtt_estimate_ewma_basic() {
        let mut reader = make_reader_sync();
        // Start from NAK_TIMEOUT (50 ms); 100 ms sample:
        // new = 7/8*50 + 1/8*100 = 43 + 12 = 55 ms (integer arithmetic)
        reader.update_rtt_estimate(Duration::from_millis(100));
        let t = reader.nak_timeout.unwrap();
        assert!(
            t >= Duration::from_millis(50) && t <= Duration::from_millis(65),
            "expected ~55ms, got {t:?}"
        );
    }

    #[test]
    fn update_rtt_estimate_clamped_to_min() {
        let mut reader = make_reader_sync();
        reader.nak_timeout = Some(Duration::from_millis(25));
        reader.update_rtt_estimate(Duration::from_millis(1));
        assert!(reader.nak_timeout.unwrap() >= MIN_NAK_TIMEOUT);
    }

    #[test]
    fn update_rtt_estimate_clamped_to_max() {
        let mut reader = make_reader_sync();
        reader.nak_timeout = Some(Duration::from_millis(490));
        reader.update_rtt_estimate(Duration::from_secs(2));
        assert!(reader.nak_timeout.unwrap() <= MAX_NAK_TIMEOUT);
    }

    #[test]
    fn handle_arrival_measures_rtt_on_gap_close() {
        let mut reader = make_reader_sync();
        // Inject a NAK timestamp as if we NAKed for seq=0 ~50 ms ago.
        let sent = Instant::now()
            .checked_sub(Duration::from_millis(50))
            .unwrap();
        let _prev = reader.gap_nak_sent_at.insert(0, sent);
        // Deliver seq=0 in order — gap closes, RTT sample taken.
        drop(reader.handle_arrival(EncryptedFrame::Keepalive, 0));
        assert!(reader.nak_timeout.is_some(), "nak_timeout must be updated");
        assert!(reader.gap_nak_sent_at.is_empty(), "entry must be consumed");
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
}
