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
    sync::Arc,
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
    sync::mpsc::UnboundedSender,
    time::{interval, sleep},
};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::{EncryptedFrame, MoshpitError, TerminalMessage, utils::is_exit_title};

/// Interval between NAK timeout checks.
const NAK_CHECK_INTERVAL: Duration = Duration::from_millis(20);
/// Delay before requesting retransmission of a missing packet.
const NAK_TIMEOUT: Duration = Duration::from_millis(50);
/// Maximum number of NAK retries before giving up on a permanently lost packet.
const MAX_NAK_RETRIES: u32 = 50;

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
    nak_out_tx: Option<UnboundedSender<EncryptedFrame>>,
    /// Tells the local sender to retransmit when a NAK from the peer is received
    retransmit_tx: Option<UnboundedSender<Vec<u64>>>,
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
}

impl UdpReader {
    /// Buffer an arrived `(frame, seq)` pair and return any frames now ready to deliver
    /// in order. Incoming `Nak` frames are routed to the local sender's retransmit channel
    /// rather than returned.
    fn handle_arrival(&mut self, frame: EncryptedFrame, seq: u64) -> Vec<EncryptedFrame> {
        // Peer is requesting us to retransmit — forward to the local sender
        if let EncryptedFrame::Nak(ref seqs) = frame {
            if let Some(ref tx) = self.retransmit_tx {
                drop(tx.send(seqs.clone()));
            }
            return vec![];
        }

        // Duplicate or replay
        if seq < self.next_seq {
            return vec![];
        }

        if seq == self.next_seq {
            self.next_seq += 1;
            let _removed = self.gap_first_seen.remove(&seq);
            let _removed = self.gap_nak_count.remove(&seq);
            let mut ready = vec![frame];
            // Drain consecutive buffered frames
            while let Some(buffered) = self.recv_buffer.remove(&self.next_seq) {
                let _removed = self.gap_first_seen.remove(&self.next_seq);
                let _removed = self.gap_nak_count.remove(&self.next_seq);
                self.next_seq += 1;
                ready.push(buffered);
            }
            ready
        } else {
            // Out of order: buffer and record gaps
            let _prev = self.recv_buffer.insert(seq, frame);
            for missing in self.next_seq..seq {
                let _entry = self
                    .gap_first_seen
                    .entry(missing)
                    .or_insert_with(Instant::now);
            }
            vec![]
        }
    }

    /// Send NAKs for gaps whose timeout has elapsed, reset their timer for potential re-NAK,
    /// and skip any gaps that have exceeded the maximum retry count. Returns frames from
    /// `recv_buffer` that become deliverable after skipping permanently lost packets.
    fn check_nak_timeouts(&mut self) -> Vec<EncryptedFrame> {
        let now = Instant::now();

        // 1. Find gaps that have exceeded the retry limit — these packets are permanently lost
        let give_up: Vec<u64> = self
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

        let mut delivered = vec![];

        if !give_up.is_empty() {
            for &seq in &give_up {
                warn!("Giving up on packet {seq} after {MAX_NAK_RETRIES} NAK retries");
                let _removed = self.gap_first_seen.remove(&seq);
                let _removed = self.gap_nak_count.remove(&seq);
            }

            // Advance next_seq past given-up and buffered frames
            let give_up_set: std::collections::HashSet<u64> = give_up.into_iter().collect();
            loop {
                if give_up_set.contains(&self.next_seq) {
                    // Permanently lost packet — skip it
                    self.next_seq += 1;
                } else if let Some(buffered) = self.recv_buffer.remove(&self.next_seq) {
                    // Buffered packet now deliverable
                    let _removed = self.gap_first_seen.remove(&self.next_seq);
                    let _removed = self.gap_nak_count.remove(&self.next_seq);
                    delivered.push(buffered);
                    self.next_seq += 1;
                } else {
                    break;
                }
            }
        }

        // 2. Normal NAK logic — request retransmission for recent gaps
        let timed_out: Vec<u64> = self
            .gap_first_seen
            .iter()
            .filter_map(|(&seq, &t)| {
                if now.duration_since(t) >= NAK_TIMEOUT {
                    Some(seq)
                } else {
                    None
                }
            })
            .collect();
        if !timed_out.is_empty() {
            // Reset timers so we re-NAK if the retransmitted packet is also dropped
            for &seq in &timed_out {
                if let Some(t) = self.gap_first_seen.get_mut(&seq) {
                    *t = now;
                }
                *self.gap_nak_count.entry(seq).or_insert(0) += 1;
            }
            if let Some(ref tx) = self.nak_out_tx {
                drop(tx.send(EncryptedFrame::Nak(timed_out)));
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
        term_tx: UnboundedSender<TerminalMessage>,
    ) -> Result<()> {
        let mut nak_check = interval(NAK_CHECK_INTERVAL);
        loop {
            select! {
                () = token.cancelled() => break,
                _ = nak_check.tick() => {
                    for ready in self.check_nak_timeouts() {
                        match ready {
                            EncryptedFrame::Bytes((_id, message)) => {
                                term_tx.send(TerminalMessage::Input(message))?;
                            }
                            EncryptedFrame::Resize((_id, columns, rows)) => {
                                term_tx.send(TerminalMessage::Resize { rows, columns })?;
                            }
                            EncryptedFrame::Nak(_) | EncryptedFrame::Shutdown => {}
                        }
                    }
                },
                frame_res = self.read_encrypted_frame() => {
                    match frame_res {
                        Ok(Some((frame, seq))) => {
                            for ready in self.handle_arrival(frame, seq) {
                                match ready {
                                    EncryptedFrame::Bytes((_id, message)) => {
                                        term_tx.send(TerminalMessage::Input(message))?;
                                    }
                                    EncryptedFrame::Resize((_id, columns, rows)) => {
                                        term_tx.send(TerminalMessage::Resize { rows, columns })?;
                                    }
                                    EncryptedFrame::Nak(_) | EncryptedFrame::Shutdown => {}
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
    pub async fn client_frame_loop(
        &mut self,
        token: CancellationToken,
        stdout_tx: UnboundedSender<Vec<u8>>,
    ) {
        let mut prev_bytes = BytesMut::with_capacity(1024);
        let mut osc_started = false;
        let mut nak_check = interval(NAK_CHECK_INTERVAL);

        loop {
            select! {
                () = token.cancelled() => process::exit(0),
                _ = nak_check.tick() => {
                    for ready in self.check_nak_timeouts() {
                        match ready {
                            EncryptedFrame::Bytes((_id, message)) => {
                                if let Err(e) = stdout_tx.send(message) {
                                    error!("Error sending to stdout channel: {e}");
                                }
                            }
                            EncryptedFrame::Resize(_) => {
                                error!("Received Resize frame on client, which is unexpected");
                            }
                            EncryptedFrame::Nak(_) => {}
                            EncryptedFrame::Shutdown => {
                                info!("Server is shutting down, exiting");
                                process::exit(0);
                            }
                        }
                    }
                },
                frame_res = self.read_encrypted_frame() => {
                    match frame_res {
                        Ok(Some((frame, seq))) => {
                            for ready in self.handle_arrival(frame, seq) {
                                match ready {
                                    EncryptedFrame::Resize(_) => {
                                        error!("Received Resize frame on client, which is unexpected");
                                    }
                                    EncryptedFrame::Nak(_) => {}
                                    EncryptedFrame::Shutdown => {
                                        info!("Server is shutting down, exiting");
                                        process::exit(0);
                                    }
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
                                        prev_bytes.extend_from_slice(chunk.invalid());
                                    }
                                }
                                let result = TokenStream::from(&valid_utf8).collect::<Vec<Token<'_>>>();

                                for part in &result {
                                    match part {
                                        Token::String(osc_cmd_string) => if osc_started && is_exit_title(osc_cmd_string, false) {
                                            sleep(Duration::from_millis(500)).await;
                                            token.cancel();
                                        }
                                        Token::ControlFunction(control_function) => {
                                            if osc_started
                                                && (*control_function == c1::ST
                                                    || *control_function == c0::BEL)
                                            {
                                                osc_started = false;
                                            } else if *control_function == c1::OSC && !osc_started {
                                                osc_started = true;
                                            }
                                        }
                                    }
                                }
                                if let Err(e) = stdout_tx.send(valid_utf8.into_bytes()) {
                                    error!("Error sending to stdout channel: {e}");
                                }
                                    }
                                }
                            }
                        }
                        Ok(None) => {
                            info!("server closed UDP connection");
                            process::exit(0);
                        }
                        Err(e) => {
                            error!("udp read error, server likely disconnected: {e}");
                            process::exit(1);
                        }
                    }
                }
            }
        }
    }

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
                Err(_err) => {}
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
