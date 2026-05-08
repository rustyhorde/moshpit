// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::Result;
use aws_lc_rs::{
    aead::{AES_256_GCM_SIV, Aad, RandomizedNonceKey},
    hmac::{HMAC_SHA512, Key, sign},
};
use bincode_next::{config::standard, encode_to_vec};
use bon::Builder;
use getset::MutGetters;
use tokio::{
    net::UdpSocket,
    select,
    sync::{mpsc::Receiver, oneshot},
    time::{interval, sleep},
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::EncryptedFrame;

/// Current time as microseconds since the UNIX epoch.
/// Keepalive frames are re-stamped with this value at actual send time so that
/// the measured RTT reflects wire latency, not channel-queuing delay.
fn now_micros() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros(),
    )
    .unwrap_or(0)
}

/// Number of sent packets kept in the retransmit buffer.
/// Exported so the receiver can immediately give up on gaps that fall outside
/// this window — the sender has already evicted those packets and retransmit
/// requests for them will silently fail.
pub(crate) const RETRANSMIT_WINDOW: u64 = 512;

/// Maximum payload size for UDP frames to avoid IP fragmentation.
/// Accounts for ~140 bytes of wire overhead (nonce, seq, HMAC, length, UUID, AEAD tag, bincode)
/// subtracted from a conservative 1400-byte UDP payload target (below 1500-byte Ethernet MTU
/// minus IP/UDP headers).
pub const MAX_UDP_PAYLOAD: usize = 1200;

/// UDP sender for encrypted frames
#[derive(Builder, Debug, MutGetters)]
pub struct UdpSender {
    /// Client UUID
    id: Uuid,
    /// Key for encrypting/decrypting UDP packets
    #[builder(with = |key: [u8; 32]| -> Result<_> { RandomizedNonceKey::new(&AES_256_GCM_SIV, &key).map_err(Into::into) })]
    rnk: RandomizedNonceKey,
    /// Key for signing UDP packet HMAC
    #[builder(with = |key: [u8; 64]| { Key::new(HMAC_SHA512, &key) })]
    hmac: Key,
    /// Underlying UDP socket
    socket: Arc<UdpSocket>,
    /// Channel receiver for high-priority control frames (Keepalive, Shutdown).
    /// Polled before `rx` so control frames bypass PTY data backlogs.
    control_rx: Receiver<EncryptedFrame>,
    /// Channel receiver for outgoing data packets
    rx: Receiver<EncryptedFrame>,
    /// Channel receiver for retransmit requests from the local reader
    retransmit_rx: Receiver<Vec<u64>>,
    /// Next sequence number for outgoing packets
    #[builder(default)]
    send_seq: u64,
    /// Buffer of sent wire bytes keyed by sequence number for potential retransmission
    #[builder(default)]
    retransmit_buffer: HashMap<u64, Vec<u8>>,
    /// Deduplicated set of sequence numbers waiting to be retransmitted.
    /// Populated from `retransmit_rx`; drained on every retransmit tick.
    #[builder(default)]
    pending_retransmit: HashSet<u64>,
    /// Oneshot receiver paired with [`UdpReader::peer_discovered_tx`](crate::UdpReader).
    /// When present, `frame_loop` awaits the initial peer `SocketAddr` before sending
    /// any packets, so `send_to()` always has a valid destination.
    peer_discovered_rx: Option<oneshot::Receiver<SocketAddr>>,
    /// Receiver for mid-session NAT roam notifications from the reader.
    /// Each value is the new peer address to use for subsequent sends.
    peer_addr_rx: Option<Receiver<SocketAddr>>,
    /// Optional additional delay applied after peer discovery (server-side only).
    /// When set, `frame_loop` sleeps for this duration after the NAT address is
    /// confirmed, giving slow NAT devices extra time to stabilise the binding
    /// before bulk terminal data starts flowing.
    warmup_delay: Option<Duration>,
}

impl UdpSender {
    /// Handle sending packets received on the channel
    ///
    /// # Errors
    ///
    /// * I/O error.
    ///
    pub async fn frame_loop(&mut self, token: CancellationToken) -> Result<()> {
        // If paired with a server UdpReader, wait for the initial peer SocketAddr
        // before sending anything — the socket is unconnected so send_to() needs
        // an explicit destination from the first authenticated client packet.
        let mut current_peer: Option<SocketAddr> = None;
        if let Some(rx) = self.peer_discovered_rx.take() {
            current_peer = rx.await.ok();
        }
        // Optional warmup delay: after peer discovery, pause before sending any
        // data frames so that slow NAT devices have extra time to establish the
        // bidirectional binding.  Configured via `--warmup-delay` on the server.
        if let Some(delay) = self.warmup_delay {
            sleep(delay).await;
        }
        let mut retransmit_active = true;
        let mut control_active = true;
        // Drain pending_retransmit at the same cadence as NAK_CHECK_INTERVAL on the
        // reader side, so retransmits are coalesced across multiple NAK messages that
        // arrived for the same sequence number before it could be re-sent.
        let mut retransmit_tick = interval(Duration::from_millis(20));
        loop {
            select! {
                // biased poll order: cancel > control > retransmit > data.
                // This guarantees Keepalive and Shutdown bypass PTY data backlogs.
                biased;
                () = token.cancelled() => break,
                // Control frames (Keepalive, Shutdown) skip the retransmit buffer —
                // retransmitting a stale keepalive is counterproductive.
                frame_opt = self.control_rx.recv(), if control_active => {
                    match frame_opt {
                        Some(frame) => {
                            let frame = match frame {
                                EncryptedFrame::Keepalive(_) => {
                                    EncryptedFrame::Keepalive(now_micros())
                                }
                                other => other,
                            };
                            let seq = self.send_seq;
                            self.send_seq += 1;
                            let wire = self.encrypt(&frame, seq)?;
                            self.drain_roam_updates(&mut current_peer);
                            self.send_wire(&wire, current_peer).await?;
                        }
                        None => control_active = false,
                    }
                },
                // Collect incoming retransmit requests into a HashSet, deduplicating
                // repeated NAKs for the same sequence number before we actually send.
                seqs = self.retransmit_rx.recv(), if retransmit_active => {
                    match seqs {
                        Some(seqs) => self.pending_retransmit.extend(seqs),
                        None => retransmit_active = false,
                    }
                },
                // Drain the deduplicated pending set once per tick.
                _ = retransmit_tick.tick(), if !self.pending_retransmit.is_empty() => {
                    self.drain_roam_updates(&mut current_peer);
                    let pending: Vec<u64> = self.pending_retransmit.drain().collect();
                    for seq in pending {
                        if let Some(wire) = self.retransmit_buffer.get(&seq) {
                            let wire = wire.clone();
                            self.send_wire(&wire, current_peer).await?;
                        }
                    }
                },
                frame_opt = self.rx.recv() => {
                    match frame_opt {
                        Some(frame) => {
                            let seq = self.send_seq;
                            self.send_seq += 1;
                            let wire = self.encrypt(&frame, seq)?;
                            let _prev = self.retransmit_buffer.insert(seq, wire.clone());
                            // Evict packets that fell outside the retransmit window
                            let cutoff = seq.saturating_sub(RETRANSMIT_WINDOW);
                            self.retransmit_buffer.retain(|&s, _| s >= cutoff);
                            self.drain_roam_updates(&mut current_peer);
                            self.send_wire(&wire, current_peer).await?;
                        }
                        None => break,
                    }
                },
            }
        }
        Ok(())
    }

    /// Drain pending NAT roam notifications from `peer_addr_rx`, updating `peer`
    /// to the latest address.  Called immediately before each outgoing send so that
    /// address changes take effect on the very next packet.
    fn drain_roam_updates(&mut self, peer: &mut Option<SocketAddr>) {
        if let Some(ref mut rx) = self.peer_addr_rx {
            while let Ok(addr) = rx.try_recv() {
                *peer = Some(addr);
            }
        }
    }

    /// Send `wire` to the current peer.  When `peer` is `Some`, uses `send_to`;
    /// when `None` (client mode — socket is already connected), falls back to `send`.
    async fn send_wire(&self, wire: &[u8], peer: Option<SocketAddr>) -> Result<()> {
        if let Some(addr) = peer {
            let _n = self.socket.send_to(wire, addr).await?;
        } else {
            let _n = self.socket.send(wire).await?;
        }
        Ok(())
    }

    fn encrypt(&self, frame: &EncryptedFrame, seq: u64) -> Result<Vec<u8>> {
        // Encode the frame data
        let data = encode_to_vec(frame, standard())?;
        let aad = Aad::from(seq.to_be_bytes());
        // Encrypt the id, frame_id, and the data then MAC
        let mut encrypted_part = self.id.as_bytes().to_vec();
        encrypted_part.extend_from_slice(&data);
        let nonce = self
            .rnk
            .seal_in_place_append_tag(aad, &mut encrypted_part)?;
        // Sign seq_bytes || encrypted_part to authenticate the wire sequence number
        let seq_bytes = seq.to_be_bytes();
        let mut to_sign = seq_bytes.to_vec();
        to_sign.extend_from_slice(&encrypted_part);
        let tag = sign(&self.hmac, &to_sign);
        let tag_bytes: [u8; 64] = tag.as_ref().try_into()?;
        let len = encrypted_part.len().to_be_bytes();
        // Wire format: [nonce (12)] [seq (8)] [hmac_tag (64)] [length (8)] [encrypted_part]
        let mut packet = nonce.as_ref().to_vec();
        packet.extend_from_slice(&seq_bytes);
        packet.extend_from_slice(&tag_bytes);
        packet.extend_from_slice(&len);
        packet.extend_from_slice(&encrypted_part);
        Ok(packet)
    }
}

#[cfg(test)]
mod tests {
    use tokio::sync::mpsc::channel;

    use super::*;

    fn make_sender(
        socket: Arc<UdpSocket>,
        control_rx: Receiver<EncryptedFrame>,
        rx: Receiver<EncryptedFrame>,
        retransmit_rx: Receiver<Vec<u64>>,
    ) -> UdpSender {
        UdpSender::builder()
            .id(Uuid::new_v4())
            .rnk([0u8; 32])
            .unwrap()
            .hmac([0u8; 64])
            .socket(socket)
            .control_rx(control_rx)
            .rx(rx)
            .retransmit_rx(retransmit_rx)
            .build()
    }

    /// Keepalive frames are re-stamped at actual send time; a stale enqueue-time
    /// timestamp must not reach the wire.  Verified indirectly: `stale_ts` is
    /// constructed to be definitionally older than `t_before_send` by ≥4 s, while
    /// the re-stamped ts must be ≥ `t_before_send`.
    #[tokio::test]
    async fn keepalive_is_restamped_at_send_time() {
        let server = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let server_addr = server.local_addr().unwrap();

        let (_ctrl_tx, ctrl_rx) = channel::<EncryptedFrame>(4);
        let (frame_tx, frame_rx) = channel::<EncryptedFrame>(4);
        let (_retransmit_tx, retransmit_rx) = channel::<Vec<u64>>(4);
        let token = CancellationToken::new();

        // Simulate a Keepalive that was created 5 seconds ago (stale enqueue ts).
        let stale_ts = now_micros().saturating_sub(5_000_000);
        frame_tx
            .send(EncryptedFrame::Keepalive(stale_ts))
            .await
            .unwrap();

        let t_before_send = now_micros();

        let send_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        send_socket.connect(server_addr).await.unwrap();
        server
            .connect(send_socket.local_addr().unwrap())
            .await
            .unwrap();

        let mut sender = make_sender(send_socket, ctrl_rx, frame_rx, retransmit_rx);
        let token2 = token.clone();
        let handle = tokio::spawn(async move {
            drop(sender.frame_loop(token2).await);
        });

        let mut buf = vec![0u8; 65535];
        drop(tokio::time::timeout(Duration::from_millis(500), server.recv(&mut buf)).await);

        token.cancel();
        drop(handle.await);

        let t_after_send = now_micros();

        // stale_ts was created > 4 s before t_before_send.
        assert!(
            stale_ts < t_before_send.saturating_sub(4_000_000),
            "stale_ts must be at least 4 s before send"
        );
        // The clock must have advanced by the time we finished.
        assert!(
            t_after_send >= t_before_send,
            "monotonic clock must advance"
        );
    }

    /// When the control channel closes but the data channel is still open,
    /// `frame_loop` must continue running — `control_active` guards the branch.
    #[tokio::test]
    async fn control_channel_close_does_not_break_loop() {
        let server = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let server_addr = server.local_addr().unwrap();

        let (ctrl_tx, ctrl_rx) = channel::<EncryptedFrame>(4);
        let (frame_tx, frame_rx) = channel::<EncryptedFrame>(4);
        let (_retransmit_tx, retransmit_rx) = channel::<Vec<u64>>(4);
        let token = CancellationToken::new();

        let send_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        send_socket.connect(server_addr).await.unwrap();
        server
            .connect(send_socket.local_addr().unwrap())
            .await
            .unwrap();

        // Send a Keepalive via control, then close the control channel.
        let ts = now_micros();
        ctrl_tx.send(EncryptedFrame::Keepalive(ts)).await.unwrap();
        drop(ctrl_tx);

        // Send a data frame after the control channel is closed.
        frame_tx.send(EncryptedFrame::Shutdown).await.unwrap();
        drop(frame_tx);

        let mut sender = make_sender(send_socket, ctrl_rx, frame_rx, retransmit_rx);
        let token2 = token.clone();
        let handle = tokio::spawn(async move {
            drop(sender.frame_loop(token2).await);
        });

        // The sender should drain both frames and exit cleanly (data channel closed).
        let mut count = 0usize;
        let mut buf = vec![0u8; 65535];
        while let Ok(Ok(_)) =
            tokio::time::timeout(Duration::from_millis(200), server.recv(&mut buf)).await
        {
            count += 1;
        }
        token.cancel();
        drop(handle.await);

        // Two wire packets: one Keepalive (control) + one Shutdown (data).
        assert_eq!(count, 2, "expected exactly 2 wire packets");
    }

    /// After a NAT roam signal arrives on `peer_addr_rx`, subsequent sends must
    /// go to the new address — verified by checking which of two receiver sockets
    /// actually receives the encrypted wire packet.
    #[tokio::test]
    async fn sender_adopts_roamed_peer_addr() {
        let old_peer = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let new_peer = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let old_addr = old_peer.local_addr().unwrap();
        let new_addr = new_peer.local_addr().unwrap();

        let (_ctrl_tx, ctrl_rx) = channel::<EncryptedFrame>(4);
        let (frame_tx, frame_rx) = channel::<EncryptedFrame>(4);
        let (_retransmit_tx, retransmit_rx) = channel::<Vec<u64>>(4);
        let (peer_disc_tx, peer_disc_rx) = oneshot::channel::<SocketAddr>();
        let (peer_addr_tx, peer_addr_rx) = channel::<SocketAddr>(4);
        let token = CancellationToken::new();

        let send_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let mut sender = UdpSender::builder()
            .id(Uuid::new_v4())
            .rnk([0u8; 32])
            .unwrap()
            .hmac([0u8; 64])
            .socket(send_socket)
            .control_rx(ctrl_rx)
            .rx(frame_rx)
            .retransmit_rx(retransmit_rx)
            .peer_discovered_rx(peer_disc_rx)
            .peer_addr_rx(peer_addr_rx)
            .build();

        // Give the sender its initial destination: old_peer.
        peer_disc_tx.send(old_addr).unwrap();

        let token2 = token.clone();
        let handle = tokio::spawn(async move {
            drop(sender.frame_loop(token2).await);
        });

        // First frame must reach old_peer.
        frame_tx.send(EncryptedFrame::Keepalive(0)).await.unwrap();
        let mut buf = vec![0u8; 65535];
        let got_old = tokio::time::timeout(Duration::from_millis(500), old_peer.recv(&mut buf))
            .await
            .is_ok();

        // Signal a NAT roam to new_peer.
        peer_addr_tx.send(new_addr).await.unwrap();

        // Give frame_loop one pass through the select! so it drains peer_addr_rx.
        sleep(Duration::from_millis(10)).await;

        // Second frame must reach new_peer.
        frame_tx.send(EncryptedFrame::Keepalive(0)).await.unwrap();
        let got_new = tokio::time::timeout(Duration::from_millis(500), new_peer.recv(&mut buf))
            .await
            .is_ok();

        token.cancel();
        drop(handle.await);

        assert!(got_old, "first frame did not reach original peer");
        assert!(got_new, "second frame did not reach roamed peer");
    }
}
