// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

//! TCP data-channel transport: encrypted [`EncryptedFrame`]s delivered over a
//! persistent TCP connection instead of UDP datagrams.
//!
//! [`TcpTransportSender`] and [`TcpTransportReader`] mirror the public API of
//! [`UdpSender`](crate::UdpSender) and [`UdpReader`](crate::UdpReader) but use
//! length-prefixed TCP framing (via [`ConnectionWriter::write_data`] /
//! [`ConnectionReader::read_data`]) instead of UDP datagrams.
//!
//! Dropped features vs UDP: NAK / retransmission, out-of-order reorder buffer,
//! RTT estimation, NAT roam detection.  TCP handles ordering and retransmission
//! at the OS level; keepalives are still useful for silence detection.
//!
//! `StateSync` diff mode is not supported over TCP in this release; use
//! `Reliable` or `Datagram`.

use std::{
    future::pending,
    io::Cursor,
    process,
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use anyhow::Result;
use aws_lc_rs::{
    aead::{Aad, LessSafeKey, NONCE_LEN, Nonce},
    hmac::{Key, sign},
    rand,
};
use bincode_next::{config::standard, encode_to_vec};
use bon::Builder;
use bytes::BytesMut;
use tokio::{
    select,
    sync::mpsc::{Receiver, Sender},
    time::{Instant as TokioInstant, sleep_until},
};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::{
    ConnectionReader, ConnectionWriter, Emulator, EncryptedFrame, TerminalMessage, UuidWrapper,
    udp::reader::{
        ClientRenderCtx, apply_full_state_rendering, decode_all_capped, intercept_queries_core,
        process_bytes_with_prediction,
    },
};

/// Sends [`EncryptedFrame`]s over a TCP data connection.
///
/// Wire format is identical to the UDP sender (nonce + seq + HMAC + ciphertext)
/// but delivered via length-prefixed TCP framing so the receiver can determine
/// frame boundaries.  No retransmit buffer or NAT roam handling — TCP handles
/// these at the OS level.
#[derive(Builder, Debug)]
pub struct TcpTransportSender {
    /// Per-connection UUID embedded in every encrypted payload.
    id: Uuid,
    /// AEAD key for encrypting frame payloads.
    rnk: LessSafeKey,
    /// HMAC key for authenticating the wire sequence number.
    hmac: Key,
    /// TCP writer for the data channel.
    writer: ConnectionWriter,
    /// High-priority channel for Keepalive and Shutdown frames.
    control_rx: Receiver<EncryptedFrame>,
    /// Channel for regular data frames (screen diffs, bytes, etc.).
    rx: Receiver<EncryptedFrame>,
    /// Next outgoing sequence number.
    #[builder(default)]
    send_seq: u64,
}

impl TcpTransportSender {
    /// Drive the send loop until `token` is cancelled or both input channels close.
    ///
    /// # Errors
    /// * I/O error writing to the TCP stream.
    pub async fn frame_loop(&mut self, token: CancellationToken) -> Result<()> {
        let mut control_active = true;
        loop {
            select! {
                biased;
                () = token.cancelled() => break,
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
                            self.writer.write_data(&wire).await?;
                        }
                        None => control_active = false,
                    }
                },
                frame_opt = self.rx.recv() => {
                    match frame_opt {
                        Some(frame) => {
                            let seq = self.send_seq;
                            self.send_seq += 1;
                            let wire = self.encrypt(&frame, seq)?;
                            self.writer.write_data(&wire).await?;
                        }
                        None => break,
                    }
                },
            }
        }
        Ok(())
    }

    fn encrypt(&self, frame: &EncryptedFrame, seq: u64) -> Result<Vec<u8>> {
        let data = encode_to_vec(frame, standard())?;
        let aad = Aad::from(seq.to_be_bytes());
        let mut encrypted_part = self.id.as_bytes().to_vec();
        encrypted_part.extend_from_slice(&data);
        let mut nonce_bytes = [0u8; NONCE_LEN];
        rand::fill(&mut nonce_bytes)?;
        let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes)?;
        self.rnk
            .seal_in_place_append_tag(nonce, aad, &mut encrypted_part)?;
        let seq_bytes = seq.to_be_bytes();
        let mut to_sign = seq_bytes.to_vec();
        to_sign.extend_from_slice(&encrypted_part);
        let tag = sign(&self.hmac, &to_sign);
        let tag_bytes = tag.as_ref();
        let len = encrypted_part.len().to_be_bytes();
        let mut packet = nonce_bytes.to_vec();
        packet.extend_from_slice(&seq_bytes);
        packet.extend_from_slice(tag_bytes);
        packet.extend_from_slice(&len);
        packet.extend_from_slice(&encrypted_part);
        Ok(packet)
    }
}

/// Receives and dispatches [`EncryptedFrame`]s from a TCP data connection.
///
/// Client-side: renders terminal output, echoes keepalives, detects silence.
/// Server-side: forwards input and resize events to the PTY.
#[derive(Builder, Debug)]
pub struct TcpTransportReader {
    /// Per-connection UUID for AEAD / HMAC validation.
    id: Uuid,
    /// AEAD key for decrypting frame payloads.
    rnk: LessSafeKey,
    /// HMAC key for verifying the wire sequence number.
    hmac: Key,
    /// Length of the HMAC tag in bytes (32 for SHA-256, 64 for SHA-512).
    mac_tag_len: usize,
    /// TCP reader for the data channel.
    reader: ConnectionReader,
    /// Duration of silence before treating the connection as dead (client mode).
    /// `None` disables silence detection.
    silence_timeout: Option<Duration>,
    /// Channel for echoing keepalives back to the sender (client mode).
    nak_out_tx: Option<Sender<EncryptedFrame>>,
    /// Channel to signal the runtime to reconnect (client mode).
    reconnect_tx: Option<Sender<()>>,
    /// Counter updated on every received frame (server mode, for silence watchdog).
    last_rx_us: Option<Arc<AtomicU64>>,
    /// Channel to forward repaint requests to the screen-sync task (server mode).
    repaint_tx: Option<Sender<()>>,
    /// Channel to forward `ClientAck` frames to the `StateSync` task (server mode).
    client_ack_tx: Option<Sender<u64>>,
    /// Whether to use legacy raw-passthrough rendering (client mode).
    #[builder(default)]
    passthrough: bool,
}

impl TcpTransportReader {
    /// Client-side frame loop.
    ///
    /// Reads `EncryptedFrame`s from the TCP data channel, renders terminal output,
    /// echoes keepalives, and respects the silence timeout.  Returns when `token`
    /// is cancelled, the connection closes, or the server signals shutdown/exit.
    #[cfg_attr(nightly, allow(clippy::too_many_lines))]
    pub async fn client_frame_loop(
        &mut self,
        token: CancellationToken,
        exit_token: CancellationToken,
        exit_msg: Arc<Mutex<Option<&'static [u8]>>>,
        ctx: ClientRenderCtx,
    ) {
        let stdout_tx = ctx.stdout_tx().clone();
        let emulator = ctx.emulator().clone();
        let prediction = ctx.prediction().clone();
        let renderer = ctx.renderer().clone();
        let in_alt_screen = ctx.in_alt_screen().clone();

        let mut prev_bytes = BytesMut::with_capacity(1024);
        let mut osc_started = false;
        let passthrough = self.passthrough;
        let mut scrollback_mode = false;
        let mut silence_deadline: Option<TokioInstant> =
            self.silence_timeout.map(|d| TokioInstant::now() + d);

        'session: loop {
            select! {
                biased;
                () = token.cancelled() => break 'session,
                () = async {
                    match silence_deadline {
                        Some(dl) => sleep_until(dl).await,
                        None => pending().await,
                    }
                } => {
                    info!("TCP data channel: server not responding, signalling reconnect");
                    self.signal_reconnect_or_exit(1);
                    break 'session;
                },
                frame_res = self.read_frame() => {
                    // Reset silence deadline on every received frame.
                    if let Some(timeout) = self.silence_timeout {
                        silence_deadline = Some(TokioInstant::now() + timeout);
                    }
                    match frame_res {
                        Ok(Some(frame)) => {
                            match frame {
                                EncryptedFrame::Bytes((_id, message)) => {
                                    let message = self.intercept_queries(&message, &emulator);
                                    process_bytes_with_prediction(
                                        message,
                                        &mut prev_bytes,
                                        &mut osc_started,
                                        &ctx,
                                        scrollback_mode,
                                        &exit_token,
                                        passthrough,
                                    )
                                    .await;
                                }
                                EncryptedFrame::CompressedBytes((_id, compressed)) => {
                                    match decode_all_capped(compressed.as_slice()) {
                                        Ok(decompressed) => {
                                            let message = self.intercept_queries(&decompressed, &emulator);
                                            process_bytes_with_prediction(
                                                message,
                                                &mut prev_bytes,
                                                &mut osc_started,
                                                &ctx,
                                                scrollback_mode,
                                                &exit_token,
                                                passthrough,
                                            )
                                            .await;
                                        }
                                        Err(e) => {
                                            error!("TCP transport: failed to decompress CompressedBytes: {e}");
                                        }
                                    }
                                }
                                EncryptedFrame::ScreenState(payload) => {
                                    let repaint = apply_full_state_rendering(
                                        &payload, &emulator, &prediction, &renderer, &in_alt_screen,
                                    );
                                    if !repaint.is_empty()
                                        && let Err(e) = stdout_tx.send(repaint).await
                                    {
                                        error!("TCP transport: error sending ScreenState repaint: {e}");
                                    }
                                }
                                EncryptedFrame::ScreenStateCompressed(compressed) => {
                                    match decode_all_capped(compressed.as_slice()) {
                                        Ok(payload) => {
                                            let repaint = apply_full_state_rendering(
                                                &payload, &emulator, &prediction, &renderer, &in_alt_screen,
                                            );
                                            if !repaint.is_empty()
                                                && let Err(e) = stdout_tx.send(repaint).await
                                            {
                                                error!("TCP transport: error sending ScreenStateCompressed repaint: {e}");
                                            }
                                        }
                                        Err(e) => {
                                            error!("TCP transport: failed to decompress ScreenStateCompressed: {e}");
                                        }
                                    }
                                }
                                EncryptedFrame::Keepalive(ts) => {
                                    if let Some(ref tx) = self.nak_out_tx
                                        && let Err(e) = tx.try_send(EncryptedFrame::Keepalive(ts))
                                    {
                                        warn!("TCP transport: failed to echo keepalive: {e}");
                                    }
                                }
                                EncryptedFrame::Shutdown => {
                                    info!("TCP transport: server is shutting down, reconnecting");
                                    self.signal_reconnect_or_exit(0);
                                    break 'session;
                                }
                                EncryptedFrame::PtyExit => {
                                    *exit_msg
                                        .lock()
                                        .unwrap_or_else(PoisonError::into_inner) =
                                        Some(b"[moshpit] Remote session ended.\r\n");
                                    exit_token.cancel();
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
                                        && let Err(e) = stdout_tx.send(repaint).await
                                    {
                                        error!("TCP transport: error sending scrollback repaint: {e}");
                                    }
                                }
                                EncryptedFrame::StateSyncDiff(_) => {
                                    warn!("TCP transport: StateSyncDiff not supported, ignoring");
                                }
                                EncryptedFrame::StateChunk(_) => {
                                    warn!("TCP transport: StateChunk not supported, ignoring");
                                }
                                EncryptedFrame::Resize(_)
                                | EncryptedFrame::Nak(_)
                                | EncryptedFrame::RepaintRequest
                                | EncryptedFrame::ClientAck(_) => {}
                            }
                        }
                        Ok(None) => {
                            info!("TCP data channel closed by server");
                            self.signal_reconnect_or_exit(1);
                            break 'session;
                        }
                        Err(e) => {
                            error!("TCP transport read error: {e}");
                            self.signal_reconnect_or_exit(1);
                            break 'session;
                        }
                    }
                },
            }
        }
    }

    /// Intercept CSI/OSC terminal queries (DA1/DA2/DA3, DSR, color, etc.) in the
    /// server's output, strip them from what is rendered, and send the synthetic
    /// responses back to the server's PTY via `nak_out_tx` so the remote program
    /// (e.g. fish's Primary Device Attribute probe) does not block waiting for a
    /// reply.  Mirrors `UdpReader::intercept_queries`; without sending the
    /// responses the shell stalls until its query timeout (~10 s).
    fn intercept_queries(&self, bytes: &[u8], emulator: &Arc<Mutex<Emulator>>) -> Vec<u8> {
        let (out, responses) =
            intercept_queries_core(bytes, "rgb:d0d0/d0d0/d0d0", "rgb:1c1c/1c1c/1c1c", emulator);
        if let Some(ref tx) = self.nak_out_tx {
            for resp in responses {
                let frame = EncryptedFrame::Bytes((UuidWrapper::new(self.id), resp));
                if let Err(e) = tx.try_send(frame) {
                    warn!("TCP transport: failed to send query response: {e}");
                }
            }
        }
        out
    }

    /// Server-side frame loop.
    ///
    /// Reads `EncryptedFrame`s from the TCP data channel and dispatches them to
    /// the PTY.  Returns when `token` is cancelled or the connection closes.
    ///
    /// # Errors
    /// * Channel send error when the PTY task has exited.
    pub async fn server_frame_loop(
        &mut self,
        token: CancellationToken,
        term_tx: Sender<TerminalMessage>,
    ) -> Result<()> {
        loop {
            select! {
                biased;
                () = token.cancelled() => break,
                frame_res = self.read_frame() => {
                    match frame_res {
                        Ok(Some(frame)) => {
                            if let Some(ref counter) = self.last_rx_us {
                                counter.store(now_micros(), Ordering::Relaxed);
                            }
                            match frame {
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
                                        warn!("TCP transport: failed to signal repaint request: {e}");
                                    }
                                }
                                EncryptedFrame::Keepalive(ts) => {
                                    // Echo the keepalive back so the client can measure RTT.
                                    if let Some(ref tx) = self.nak_out_tx
                                        && let Err(e) = tx.try_send(EncryptedFrame::Keepalive(ts))
                                    {
                                        warn!("TCP transport: failed to echo keepalive: {e}");
                                    }
                                }
                                EncryptedFrame::ClientAck(diff_id) => {
                                    if let Some(ref tx) = self.client_ack_tx
                                        && let Err(e) = tx.try_send(diff_id)
                                    {
                                        warn!("TCP transport: failed to forward ClientAck: {e}");
                                    }
                                }
                                _ => {}
                            }
                        }
                        Ok(None) => {
                            info!("TCP data channel: client closed connection");
                            break;
                        }
                        Err(e) => {
                            error!("TCP transport read error: {e}");
                            break;
                        }
                    }
                },
            }
        }
        Ok(())
    }

    fn signal_reconnect_or_exit(&self, code: i32) {
        if let Some(ref tx) = self.reconnect_tx {
            let _ = tx.try_send(());
        } else {
            process::exit(code);
        }
    }

    async fn read_frame(&mut self) -> Result<Option<EncryptedFrame>> {
        match self.reader.read_data().await? {
            None => Ok(None),
            Some(bytes) => {
                let mut buf = BytesMut::from(bytes.as_slice());
                let mut cursor = Cursor::new(&buf[..]);
                match EncryptedFrame::parse(
                    &mut cursor,
                    self.id,
                    &self.hmac,
                    &self.rnk,
                    self.mac_tag_len,
                ) {
                    Ok(Some((frame, _seq))) => {
                        buf.clear();
                        Ok(Some(frame))
                    }
                    Ok(None) => {
                        warn!(
                            "TCP transport: received data blob that could not be parsed as EncryptedFrame"
                        );
                        Ok(None)
                    }
                    Err(e) => Err(e),
                }
            }
        }
    }
}

fn now_micros() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_micros()).unwrap_or(u64::MAX))
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            Arc, Mutex,
            atomic::{AtomicBool, AtomicU64, Ordering},
        },
        time::Duration,
    };

    use aws_lc_rs::{
        aead::{AES_256_GCM_SIV, LessSafeKey, UnboundKey},
        hmac::{HMAC_SHA512, Key},
    };
    use tokio::{
        net::{TcpListener, TcpStream},
        sync::mpsc::{Receiver, Sender, channel},
        time::timeout,
    };
    use tokio_util::sync::CancellationToken;
    use uuid::Uuid;

    use super::{TcpTransportReader, TcpTransportSender};
    use crate::{
        ClientRenderCtx, ConnectionReader, ConnectionWriter, DisplayPreference, Emulator,
        EncryptedFrame, PredictionEngine, Renderer, TerminalMessage, UuidWrapper,
    };

    /// Wire-format HMAC tag length for HMAC-SHA512 (64 bytes).  The TCP transport
    /// always signs with SHA-512, so the reader must parse a 64-byte tag.
    const MAC_TAG_LEN: usize = 64;

    /// Shared AEAD key bytes so a sender and reader built independently agree.
    const AEAD_BYTES: [u8; 32] = [7u8; 32];
    /// Shared HMAC key bytes so a sender and reader built independently agree.
    const HMAC_BYTES: [u8; 64] = [9u8; 64];

    fn aead() -> LessSafeKey {
        LessSafeKey::new(UnboundKey::new(&AES_256_GCM_SIV, &AEAD_BYTES).expect("test AEAD key"))
    }

    fn hmac() -> Key {
        Key::new(HMAC_SHA512, &HMAC_BYTES)
    }

    /// Build a single TCP loopback link, returning a `ConnectionWriter` on the
    /// client end and a `ConnectionReader` on the server end.  Bytes written to
    /// the writer arrive on the reader (client → server direction).
    async fn make_link() -> (ConnectionWriter, ConnectionReader) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test listener");
        let addr = listener.local_addr().expect("local addr");
        let (server, client) = tokio::join!(
            async { listener.accept().await.map(|(s, _)| s).expect("accept") },
            async { TcpStream::connect(addr).await.expect("connect") },
        );
        let (_, client_w) = client.into_split();
        let (server_r, _) = server.into_split();
        let writer = ConnectionWriter::builder().writer(client_w).build();
        let reader = ConnectionReader::builder().reader(server_r).build();
        (writer, reader)
    }

    /// Build a `TcpTransportSender` over `writer`, returning the control-channel
    /// and data-channel `Sender`s so the test can feed it frames.
    fn make_sender(
        writer: ConnectionWriter,
        id: Uuid,
    ) -> (
        TcpTransportSender,
        Sender<EncryptedFrame>,
        Sender<EncryptedFrame>,
    ) {
        let (control_tx, control_rx) = channel::<EncryptedFrame>(16);
        let (data_tx, rx) = channel::<EncryptedFrame>(16);
        let sender = TcpTransportSender::builder()
            .id(id)
            .rnk(aead())
            .hmac(hmac())
            .writer(writer)
            .control_rx(control_rx)
            .rx(rx)
            .build();
        (sender, control_tx, data_tx)
    }

    /// Build a `TcpTransportReader` whose `nak_out_tx` (the path back to the
    /// server's PTY) is captured so tests can observe query responses.  The
    /// `reader` half is a throwaway loopback socket — `intercept_queries` never
    /// reads from it.
    async fn make_reader_with_response_rx() -> (TcpTransportReader, Receiver<EncryptedFrame>) {
        let (_writer, reader) = make_link().await;
        let (tx, rx) = channel::<EncryptedFrame>(16);
        let transport_reader = TcpTransportReader::builder()
            .id(Uuid::new_v4())
            .rnk(aead())
            .hmac(hmac())
            .mac_tag_len(MAC_TAG_LEN)
            .reader(reader)
            .nak_out_tx(tx)
            .passthrough(false)
            .build();
        (transport_reader, rx)
    }

    fn make_emulator() -> Arc<Mutex<Emulator>> {
        Arc::new(Mutex::new(Emulator::new(24, 80)))
    }

    /// Build a `ClientRenderCtx` backed by real emulator/prediction/renderer
    /// instances, returning the stdout receiver and a handle to the emulator.
    fn make_render_ctx() -> (ClientRenderCtx, Receiver<Vec<u8>>) {
        let (stdout_tx, stdout_rx) = channel::<Vec<u8>>(64);
        let emulator = make_emulator();
        let prediction = Arc::new(Mutex::new(PredictionEngine::new(DisplayPreference::Never)));
        let renderer = Arc::new(Mutex::new(Renderer::new(24, 80)));
        let in_alt_screen = Arc::new(AtomicBool::new(false));
        let ctx = ClientRenderCtx::new(stdout_tx, emulator, prediction, renderer, in_alt_screen);
        (ctx, stdout_rx)
    }

    #[tokio::test]
    async fn intercept_queries_da1_sends_response_to_server() {
        let (reader, mut rx) = make_reader_with_response_rx().await;
        let emu = make_emulator();
        // Primary Device Attribute query (the one fish sends on startup).
        let out = reader.intercept_queries(b"\x1b[c", &emu);
        assert!(out.is_empty(), "DA1 query must be stripped from stdout");
        let frame = rx
            .try_recv()
            .expect("a DA1 response frame must be sent back");
        let EncryptedFrame::Bytes((_id, resp)) = frame else {
            panic!("expected Bytes frame, got {frame:?}");
        };
        assert_eq!(resp, b"\x1b[?62c", "DA1 response payload");
    }

    #[tokio::test]
    async fn intercept_queries_plain_bytes_pass_through_without_response() {
        let (reader, mut rx) = make_reader_with_response_rx().await;
        let emu = make_emulator();
        let out = reader.intercept_queries(b"hello world", &emu);
        assert_eq!(
            out, b"hello world",
            "non-query bytes pass through unchanged"
        );
        assert!(
            rx.try_recv().is_err(),
            "no response should be sent for plain output"
        );
    }

    /// Build a bare server-mode `TcpTransportReader` (no output channels) for
    /// exercising `read_frame` directly against a sender.
    fn make_plain_reader(reader: ConnectionReader, id: Uuid) -> TcpTransportReader {
        TcpTransportReader::builder()
            .id(id)
            .rnk(aead())
            .hmac(hmac())
            .mac_tag_len(MAC_TAG_LEN)
            .reader(reader)
            .build()
    }

    /// Build a server-mode `TcpTransportReader` with every dispatch channel
    /// captured, plus the `last_rx_us` watchdog counter.
    fn make_server_reader(
        reader: ConnectionReader,
        id: Uuid,
    ) -> (
        TcpTransportReader,
        Receiver<EncryptedFrame>,
        Receiver<()>,
        Receiver<u64>,
        Arc<AtomicU64>,
    ) {
        let (nak_tx, nak_rx) = channel::<EncryptedFrame>(16);
        let (repaint_tx, repaint_rx) = channel::<()>(4);
        let (ack_tx, ack_rx) = channel::<u64>(4);
        let last_rx_us = Arc::new(AtomicU64::new(0));
        let r = TcpTransportReader::builder()
            .id(id)
            .rnk(aead())
            .hmac(hmac())
            .mac_tag_len(MAC_TAG_LEN)
            .reader(reader)
            .nak_out_tx(nak_tx)
            .repaint_tx(repaint_tx)
            .client_ack_tx(ack_tx)
            .last_rx_us(Arc::clone(&last_rx_us))
            .build();
        (r, nak_rx, repaint_rx, ack_rx, last_rx_us)
    }

    /// Build a client-mode `TcpTransportReader` with `reconnect_tx` set (so the
    /// silence / shutdown paths signal a reconnect instead of `process::exit`)
    /// and `nak_out_tx` captured for keepalive echoes.
    fn make_client_reader(
        reader: ConnectionReader,
        id: Uuid,
    ) -> (TcpTransportReader, Receiver<()>, Receiver<EncryptedFrame>) {
        let (reconnect_tx, reconnect_rx) = channel::<()>(4);
        let (nak_tx, nak_rx) = channel::<EncryptedFrame>(16);
        let r = TcpTransportReader::builder()
            .id(id)
            .rnk(aead())
            .hmac(hmac())
            .mac_tag_len(MAC_TAG_LEN)
            .reader(reader)
            .reconnect_tx(reconnect_tx)
            .nak_out_tx(nak_tx)
            .passthrough(false)
            .build();
        (r, reconnect_rx, nak_rx)
    }

    // ── Sender ────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn sender_frame_loop_delivers_data_frames_in_order() {
        let (writer, reader) = make_link().await;
        let id = Uuid::new_v4();
        let (mut sender, _control_tx, data_tx) = make_sender(writer, id);
        let token = CancellationToken::new();
        let loop_token = token.clone();
        let handle = tokio::spawn(async move { sender.frame_loop(loop_token).await });

        data_tx
            .send(EncryptedFrame::Bytes((
                UuidWrapper::new(id),
                b"one".to_vec(),
            )))
            .await
            .expect("send one");
        data_tx
            .send(EncryptedFrame::Bytes((
                UuidWrapper::new(id),
                b"two".to_vec(),
            )))
            .await
            .expect("send two");

        let mut rdr = make_plain_reader(reader, id);
        let f1 = rdr.read_frame().await.expect("read1").expect("some1");
        let f2 = rdr.read_frame().await.expect("read2").expect("some2");
        let EncryptedFrame::Bytes((_, b1)) = f1 else {
            panic!("expected Bytes, got {f1:?}");
        };
        let EncryptedFrame::Bytes((_, b2)) = f2 else {
            panic!("expected Bytes, got {f2:?}");
        };
        assert_eq!(b1, b"one");
        assert_eq!(b2, b"two");

        token.cancel();
        drop(data_tx);
        let _joined = handle.await;
    }

    #[tokio::test]
    async fn sender_frame_loop_rewrites_keepalive_timestamp() {
        let (writer, reader) = make_link().await;
        let id = Uuid::new_v4();
        let (mut sender, control_tx, _data_tx) = make_sender(writer, id);
        let token = CancellationToken::new();
        let loop_token = token.clone();
        let handle = tokio::spawn(async move { sender.frame_loop(loop_token).await });

        // A zero timestamp must be replaced with the current time before sending.
        control_tx
            .send(EncryptedFrame::Keepalive(0))
            .await
            .expect("send keepalive");

        let mut rdr = make_plain_reader(reader, id);
        let frame = rdr.read_frame().await.expect("read").expect("some");
        let EncryptedFrame::Keepalive(ts) = frame else {
            panic!("expected Keepalive, got {frame:?}");
        };
        assert!(ts > 0, "keepalive timestamp must be rewritten to now");

        token.cancel();
        drop(control_tx);
        let _joined = handle.await;
    }

    // ── Server frame loop ───────────────────────────────────────────────────

    #[tokio::test]
    async fn server_frame_loop_forwards_input_and_resize() {
        let (writer, reader) = make_link().await;
        let id = Uuid::new_v4();
        let (mut sender, _control_tx, data_tx) = make_sender(writer, id);
        let sender_token = CancellationToken::new();
        let st = sender_token.clone();
        let sender_handle = tokio::spawn(async move { sender.frame_loop(st).await });

        let (mut srv, _nak, _repaint, _ack, last_rx_us) = make_server_reader(reader, id);
        let (term_tx, mut term_rx) = channel::<TerminalMessage>(16);
        let srv_token = CancellationToken::new();
        let srv_t = srv_token.clone();
        let srv_handle = tokio::spawn(async move { srv.server_frame_loop(srv_t, term_tx).await });

        data_tx
            .send(EncryptedFrame::Bytes((
                UuidWrapper::new(id),
                b"abc".to_vec(),
            )))
            .await
            .expect("send input");
        data_tx
            .send(EncryptedFrame::Resize((UuidWrapper::new(id), 100, 40)))
            .await
            .expect("send resize");

        let input = timeout(Duration::from_secs(2), term_rx.recv())
            .await
            .expect("input timeout")
            .expect("input frame");
        assert_eq!(input, TerminalMessage::Input(b"abc".to_vec()));
        let resize = timeout(Duration::from_secs(2), term_rx.recv())
            .await
            .expect("resize timeout")
            .expect("resize frame");
        assert_eq!(
            resize,
            TerminalMessage::Resize {
                rows: 40,
                columns: 100
            }
        );
        assert!(
            last_rx_us.load(Ordering::Relaxed) > 0,
            "watchdog counter must advance on receipt"
        );

        srv_token.cancel();
        sender_token.cancel();
        srv_handle.await.expect("srv join").expect("srv loop");
        let _joined = sender_handle.await;
    }

    #[tokio::test]
    async fn server_frame_loop_echoes_keepalive_and_forwards_control() {
        let (writer, reader) = make_link().await;
        let id = Uuid::new_v4();
        let (mut sender, _control_tx, data_tx) = make_sender(writer, id);
        let sender_token = CancellationToken::new();
        let st = sender_token.clone();
        let sender_handle = tokio::spawn(async move { sender.frame_loop(st).await });

        let (mut srv, mut nak_rx, mut repaint_rx, mut ack_rx, _last) =
            make_server_reader(reader, id);
        let (term_tx, _term_rx) = channel::<TerminalMessage>(16);
        let srv_token = CancellationToken::new();
        let srv_t = srv_token.clone();
        let srv_handle = tokio::spawn(async move { srv.server_frame_loop(srv_t, term_tx).await });

        data_tx
            .send(EncryptedFrame::Keepalive(42))
            .await
            .expect("send keepalive");
        data_tx
            .send(EncryptedFrame::RepaintRequest)
            .await
            .expect("send repaint");
        data_tx
            .send(EncryptedFrame::ClientAck(7))
            .await
            .expect("send ack");

        let echoed = timeout(Duration::from_secs(2), nak_rx.recv())
            .await
            .expect("keepalive echo timeout")
            .expect("keepalive echo");
        assert!(matches!(echoed, EncryptedFrame::Keepalive(42)));
        timeout(Duration::from_secs(2), repaint_rx.recv())
            .await
            .expect("repaint timeout")
            .expect("repaint signal");
        let ack = timeout(Duration::from_secs(2), ack_rx.recv())
            .await
            .expect("ack timeout")
            .expect("ack value");
        assert_eq!(ack, 7);

        srv_token.cancel();
        sender_token.cancel();
        srv_handle.await.expect("srv join").expect("srv loop");
        let _joined = sender_handle.await;
    }

    #[tokio::test]
    async fn server_frame_loop_returns_on_eof() {
        let (writer, reader) = make_link().await;
        let id = Uuid::new_v4();
        let (sender, _control_tx, _data_tx) = make_sender(writer, id);
        // Dropping the sender (and its writer half) closes the connection.
        drop(sender);

        let (mut srv, _nak, _repaint, _ack, _last) = make_server_reader(reader, id);
        let (term_tx, _term_rx) = channel::<TerminalMessage>(16);
        let token = CancellationToken::new();
        let res = timeout(
            Duration::from_secs(2),
            srv.server_frame_loop(token, term_tx),
        )
        .await
        .expect("loop should return promptly on EOF");
        assert!(res.is_ok(), "clean EOF returns Ok(())");
    }

    // ── Client frame loop ─────────────────────────────────────────────────

    #[tokio::test]
    async fn client_frame_loop_renders_bytes_to_stdout() {
        let (writer, reader) = make_link().await;
        let id = Uuid::new_v4();
        let (mut sender, _control_tx, data_tx) = make_sender(writer, id);
        let sender_token = CancellationToken::new();
        let st = sender_token.clone();
        let sender_handle = tokio::spawn(async move { sender.frame_loop(st).await });

        let (mut client, _reconnect_rx, _nak_rx) = make_client_reader(reader, id);
        let (ctx, mut stdout_rx) = make_render_ctx();
        let token = CancellationToken::new();
        let exit_token = CancellationToken::new();
        let exit_msg = Arc::new(Mutex::new(None));
        let ct = token.clone();
        let et = exit_token.clone();
        let em = Arc::clone(&exit_msg);
        let client_handle =
            tokio::spawn(async move { client.client_frame_loop(ct, et, em, ctx).await });

        data_tx
            .send(EncryptedFrame::Bytes((
                UuidWrapper::new(id),
                b"hello".to_vec(),
            )))
            .await
            .expect("send bytes");

        let out = timeout(Duration::from_secs(2), stdout_rx.recv())
            .await
            .expect("stdout timeout")
            .expect("stdout frame");
        assert!(!out.is_empty(), "rendered output must reach stdout");

        token.cancel();
        sender_token.cancel();
        let _joined = timeout(Duration::from_secs(2), client_handle).await;
        let _joined = sender_handle.await;
    }

    #[tokio::test]
    async fn client_frame_loop_pty_exit_sets_message_and_cancels() {
        let (writer, reader) = make_link().await;
        let id = Uuid::new_v4();
        let (mut sender, _control_tx, data_tx) = make_sender(writer, id);
        let sender_token = CancellationToken::new();
        let st = sender_token.clone();
        let sender_handle = tokio::spawn(async move { sender.frame_loop(st).await });

        let (mut client, _reconnect_rx, _nak_rx) = make_client_reader(reader, id);
        let (ctx, _stdout_rx) = make_render_ctx();
        let token = CancellationToken::new();
        let exit_token = CancellationToken::new();
        let exit_msg: Arc<Mutex<Option<&'static [u8]>>> = Arc::new(Mutex::new(None));
        let et = exit_token.clone();
        let em = Arc::clone(&exit_msg);
        let client_handle = tokio::spawn(async move {
            client.client_frame_loop(token, et, em, ctx).await;
        });

        data_tx
            .send(EncryptedFrame::PtyExit)
            .await
            .expect("send pty exit");

        // The loop breaks after PtyExit, so the task completes.
        timeout(Duration::from_secs(2), client_handle)
            .await
            .expect("client loop should finish")
            .expect("client join");
        assert!(exit_token.is_cancelled(), "PtyExit cancels the exit token");
        assert!(
            exit_msg.lock().unwrap().is_some(),
            "PtyExit sets the exit message"
        );

        sender_token.cancel();
        let _joined = sender_handle.await;
    }

    #[tokio::test]
    async fn client_frame_loop_shutdown_signals_reconnect() {
        let (writer, reader) = make_link().await;
        let id = Uuid::new_v4();
        let (mut sender, _control_tx, data_tx) = make_sender(writer, id);
        let sender_token = CancellationToken::new();
        let st = sender_token.clone();
        let sender_handle = tokio::spawn(async move { sender.frame_loop(st).await });

        let (mut client, mut reconnect_rx, _nak_rx) = make_client_reader(reader, id);
        let (ctx, _stdout_rx) = make_render_ctx();
        let token = CancellationToken::new();
        let exit_token = CancellationToken::new();
        let exit_msg = Arc::new(Mutex::new(None));
        let client_handle = tokio::spawn(async move {
            client
                .client_frame_loop(token, exit_token, exit_msg, ctx)
                .await;
        });

        data_tx
            .send(EncryptedFrame::Shutdown)
            .await
            .expect("send shutdown");

        timeout(Duration::from_secs(2), reconnect_rx.recv())
            .await
            .expect("reconnect timeout")
            .expect("reconnect signal");

        sender_token.cancel();
        let _joined = timeout(Duration::from_secs(2), client_handle).await;
        let _joined = sender_handle.await;
    }

    #[tokio::test]
    async fn client_frame_loop_echoes_keepalive() {
        let (writer, reader) = make_link().await;
        let id = Uuid::new_v4();
        let (mut sender, _control_tx, data_tx) = make_sender(writer, id);
        let sender_token = CancellationToken::new();
        let st = sender_token.clone();
        let sender_handle = tokio::spawn(async move { sender.frame_loop(st).await });

        let (mut client, _reconnect_rx, mut nak_rx) = make_client_reader(reader, id);
        let (ctx, _stdout_rx) = make_render_ctx();
        let token = CancellationToken::new();
        let exit_token = CancellationToken::new();
        let exit_msg = Arc::new(Mutex::new(None));
        let ct = token.clone();
        let client_handle = tokio::spawn(async move {
            client
                .client_frame_loop(ct, exit_token, exit_msg, ctx)
                .await;
        });

        data_tx
            .send(EncryptedFrame::Keepalive(99))
            .await
            .expect("send keepalive");

        let echoed = timeout(Duration::from_secs(2), nak_rx.recv())
            .await
            .expect("keepalive echo timeout")
            .expect("keepalive echo");
        assert!(matches!(echoed, EncryptedFrame::Keepalive(99)));

        token.cancel();
        sender_token.cancel();
        let _joined = timeout(Duration::from_secs(2), client_handle).await;
        let _joined = sender_handle.await;
    }

    #[tokio::test]
    async fn signal_reconnect_or_exit_sends_on_reconnect_tx() {
        let (_writer, reader) = make_link().await;
        let id = Uuid::new_v4();
        let (client, mut reconnect_rx, _nak_rx) = make_client_reader(reader, id);
        client.signal_reconnect_or_exit(0);
        assert!(
            reconnect_rx.try_recv().is_ok(),
            "reconnect signal must be sent when reconnect_tx is set"
        );
    }
}
