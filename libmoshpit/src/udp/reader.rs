// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

use std::{
    io::Cursor,
    process,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
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
use tokio::{net::UdpSocket, select, sync::mpsc::UnboundedSender, time::sleep};
use tokio_util::sync::CancellationToken;
use tracing::{error, info};
use uuid::Uuid;

use crate::{EncryptedFrame, MoshpitError, TerminalMessage, utils::is_exit_title};

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
    #[builder(default = AtomicUsize::new(0))]
    recv_count: AtomicUsize,
}

impl UdpReader {
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
        loop {
            select! {
                () = token.cancelled() => break,
                frame_res = self.read_encrypted_frame() =>{
                    if let Ok(Some(frame)) = frame_res {
                        match frame {
                            EncryptedFrame::Bytes((_id, message)) => {
                                term_tx.send(TerminalMessage::Input(message))?;
                            }
                            EncryptedFrame::Resize((_id, columns, rows)) => {
                                term_tx.send(TerminalMessage::Resize { rows, columns })?;
                            }
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

        loop {
            select! {
                () = token.cancelled() => process::exit(0),
                frame_res = self.read_encrypted_frame() =>{
                    if let Ok(Some(frame)) = frame_res {
                        match frame {
                            EncryptedFrame::Resize(_) => {
                                error!("Received Resize frame on client, which is unexpected");
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
                                        info!("Received invalid UTF-8 chunk");
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
    pub async fn read_encrypted_frame(&mut self) -> Result<Option<EncryptedFrame>> {
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
                Ok(Some(frame)) => return Ok(Some(frame)),
                Ok(None) => {
                    // Not enough data has been buffered yet to parse a full
                    // frame. Continue the loop to read more data from the socket.
                }
                Err(_err) => {
                    error!("Error parsing frame");
                }
            }
        }
    }

    /// Tries to parse a frame from the buffer. If the buffer contains enough
    /// data, the frame is returned and the data removed from the buffer. If not
    /// enough data has been buffered yet, `Ok(None)` is returned. If the
    /// buffered data does not represent a valid frame, `Err` is returned.
    fn parse_encrypted_frame(&mut self, buffer: &mut BytesMut) -> Result<Option<EncryptedFrame>> {
        // Cursor is used to track the "current" location in the
        // buffer. Cursor also implements `Buf` from the `bytes` crate
        // which provides a number of helpful utilities for working
        // with bytes.
        let mut buf = Cursor::new(&buffer[..]);
        let count = self.recv_count.fetch_add(1, Ordering::SeqCst);

        // The first step is to check if enough data has been buffered to parse
        // a single frame. This step is usually much faster than doing a full
        // parse of the frame, and allows us to skip allocating data structures
        // to hold the frame data unless we know the full frame has been
        // received.

        // Reset the position to zero before passing the cursor to `Frame::parse`.
        buf.set_position(0);

        match EncryptedFrame::parse(&mut buf, self.id, &self.hmac, &self.rnk, count) {
            Ok(Some(frame)) => {
                // The `parse` function will have advanced the cursor until the
                // end of the frame. Since the cursor had position set to zero
                // before `Frame::parse` was called, we obtain the length of the
                // frame by checking the cursor position.
                let _len = usize::try_from(buf.position())?;
                // Discard the parsed data from the read buffer.
                //
                // When `advance` is called on the read buffer, all of the data
                // up to `len` is discarded. The details of how this works is
                // left to `BytesMut`. This is often done by moving an internal
                // cursor, but it may be done by reallocating and copying data.
                // self.buffer.advance(len);
                buffer.clear();

                // Return the parsed frame to the caller.
                Ok(Some(frame))
            }
            Ok(None) => {
                let _count = self.recv_count.fetch_sub(1, Ordering::SeqCst);
                // There is not enough data present in the read buffer to parse
                // a single frame. We must wait for more data to be received
                // from the socket. Reading from the socket will be done in the
                // statement after this `match`.
                //
                // We do not want to return `Err` from here as this "error" is
                // an expected runtime condition.
                Ok(None)
            }
            Err(err) => {
                error!("Error parsing frame: {err}");
                Err(err)
            }
        }
    }
}
