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
    sync::mpsc::Sender,
    time::{Instant as TokioInstant, interval, sleep, sleep_until},
};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};
use uuid::Uuid;

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
const MAX_NAK_RETRIES: u32 = 10;

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
    /// Highest sequence number ever received (excluding duplicates).
    /// Used to detect when a gap has fallen outside the sender's retransmit
    /// window so the client can give up immediately instead of waiting for
    /// [`MAX_NAK_RETRIES`] retries.
    #[builder(default)]
    highest_seq_seen: u64,
    /// If no frame is received within this duration the server is assumed unreachable.
    /// Triggers reconnect via [`reconnect_tx`] when set, otherwise calls
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
            let mut ready = Vec::new();
            // NAK frames are consumed inline; all others are returned to the caller.
            if let Some(f) = self.route_or_deliver(frame) {
                ready.push(f);
            }
            // Drain consecutive buffered frames
            while let Some(buffered) = self.recv_buffer.remove(&self.next_seq) {
                let _removed = self.gap_first_seen.remove(&self.next_seq);
                let _removed = self.gap_nak_count.remove(&self.next_seq);
                self.next_seq += 1;
                if let Some(f) = self.route_or_deliver(buffered) {
                    ready.push(f);
                }
            }
            ready
        } else {
            // Out of order: buffer the frame and record any new gaps.
            //
            // The arriving packet is no longer missing — remove it from gap
            // tracking in case it was recorded as a false gap by an earlier
            // out-of-order arrival.
            let _prev = self.recv_buffer.insert(seq, frame);
            let _removed = self.gap_first_seen.remove(&seq);
            let _removed = self.gap_nak_count.remove(&seq);

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
        // full MAX_NAK_RETRIES × backoff wait (≈5.5 s) during which all
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
            }

            // Advance next_seq past given-up and buffered frames.
            loop {
                if give_up_set.contains(&self.next_seq) {
                    self.next_seq += 1;
                } else if let Some(buffered) = self.recv_buffer.remove(&self.next_seq) {
                    let _removed = self.gap_first_seen.remove(&self.next_seq);
                    let _removed = self.gap_nak_count.remove(&self.next_seq);
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
        // times it has already been NAKed: timeout = NAK_TIMEOUT * 2^retry_count
        // (capped at NAK_TIMEOUT * 2^NAK_BACKOFF_MAX_SHIFT), so repeated misses
        // back off rather than flooding the sender with duplicate retransmit requests.
        let timed_out: Vec<u64> = self
            .gap_first_seen
            .iter()
            .filter_map(|(&seq, &t)| {
                let retries = self.gap_nak_count.get(&seq).copied().unwrap_or(0);
                let shift = retries.min(NAK_BACKOFF_MAX_SHIFT);
                let backoff = NAK_TIMEOUT * (1u32 << shift);
                if now.duration_since(t) >= backoff {
                    Some(seq)
                } else {
                    None
                }
            })
            .collect();
        if !timed_out.is_empty() {
            // Reset each gap's timer so the next backoff interval starts from now.
            for &seq in &timed_out {
                if let Some(t) = self.gap_first_seen.get_mut(&seq) {
                    *t = now;
                }
                *self.gap_nak_count.entry(seq).or_insert(0) += 1;
            }
            if let Some(ref tx) = self.nak_out_tx
                && let Err(e) = tx.try_send(EncryptedFrame::Nak(timed_out))
            {
                warn!("Failed to send NAK: {e}");
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
    pub async fn server_frame_loop(
        &mut self,
        token: CancellationToken,
        term_tx: Sender<TerminalMessage>,
    ) -> Result<()> {
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
                            EncryptedFrame::Nak(_) | EncryptedFrame::Shutdown | EncryptedFrame::Keepalive
                            | EncryptedFrame::ScrollbackStart | EncryptedFrame::ScrollbackEnd => {}
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
                                    EncryptedFrame::Nak(_) | EncryptedFrame::Shutdown | EncryptedFrame::Keepalive
                                    | EncryptedFrame::ScrollbackStart | EncryptedFrame::ScrollbackEnd => {}
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
                            EncryptedFrame::Nak(_) | EncryptedFrame::Keepalive => {}
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
                                    EncryptedFrame::Nak(_) | EncryptedFrame::Keepalive => {}
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
