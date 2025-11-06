// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

use std::io::Cursor;

use anyhow::Result;
use bon::Builder;
use bytes::{Buf as _, BytesMut};
use tokio::{io::AsyncReadExt as _, net::tcp::OwnedReadHalf};
use tracing::trace;

use crate::{Frame, error::Error};

/// A reader over a `ReadHalf` and `BytesMut` buffer.
#[derive(Builder, Debug)]
pub struct ConnectionReader {
    /// The `ReadHalf` of a TCP stream.
    reader: OwnedReadHalf,
    // The buffer for reading frames.
    #[builder(default = BytesMut::with_capacity(4096))]
    buffer: BytesMut,
}

impl ConnectionReader {
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
    pub async fn read_frame(&mut self) -> Result<Option<Frame>> {
        loop {
            trace!("Reading frame...");
            // Attempt to parse a frame from the buffered data. If enough data
            // has been buffered, the frame is returned.
            if let Some(frame) = self.parse_frame()? {
                trace!("Parsed frame: {frame}");
                return Ok(Some(frame));
            }

            // There is not enough buffered data to read a frame. Attempt to
            // read more data from the socket.
            //
            // On success, the number of bytes is returned. `0` indicates "end
            // of stream".
            trace!("Reading buffer...");
            if 0 == self.reader.read_buf(&mut self.buffer).await? {
                // The remote closed the connection. For this to be a clean
                // shutdown, there should be no data in the read buffer. If
                // there is, this means that the peer closed the socket while
                // sending a frame.
                if self.buffer.is_empty() {
                    return Ok(None);
                }
                return Err(Error::ConnectionResetByPeer.into());
            }
            trace!("Read {} bytes from socket", self.buffer.len());
        }
    }

    /// Tries to parse a frame from the buffer. If the buffer contains enough
    /// data, the frame is returned and the data removed from the buffer. If not
    /// enough data has been buffered yet, `Ok(None)` is returned. If the
    /// buffered data does not represent a valid frame, `Err` is returned.
    fn parse_frame(&mut self) -> Result<Option<Frame>> {
        // Cursor is used to track the "current" location in the
        // buffer. Cursor also implements `Buf` from the `bytes` crate
        // which provides a number of helpful utilities for working
        // with bytes.
        let mut buf = Cursor::new(&self.buffer[..]);

        // The first step is to check if enough data has been buffered to parse
        // a single frame. This step is usually much faster than doing a full
        // parse of the frame, and allows us to skip allocating data structures
        // to hold the frame data unless we know the full frame has been
        // received.
        match Frame::parse(&mut buf) {
            Ok(Some(frame)) => {
                // The `parse` function will have advanced the cursor until the
                // end of the frame. Since the cursor had position set to zero
                // before `Frame::parse` was called, we obtain the length of the
                // frame by checking the cursor position.
                let len = usize::try_from(buf.position())?;

                // Discard the parsed data from the read buffer.
                //
                // When `advance` is called on the read buffer, all of the data
                // up to `len` is discarded. The details of how this works is
                // left to `BytesMut`. This is often done by moving an internal
                // cursor, but it may be done by reallocating and copying data.
                self.buffer.advance(len);

                // Return the parsed frame to the caller.
                Ok(Some(frame))
            }
            Ok(None) => {
                // There is not enough data present in the read buffer to parse
                // a single frame. We must wait for more data to be received
                // from the socket. Reading from the socket will be done in the
                // statement after this `match`.
                //
                // We do not want to return `Err` from here as this "error" is
                // an expected runtime condition.
                Ok(None)
            }
            Err(err) => Err(err),
        }
    }
}
