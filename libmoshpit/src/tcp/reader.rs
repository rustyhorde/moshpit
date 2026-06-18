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

use crate::{Frame, error::Error, frames::encframe::MAX_ENCFRAME_LENGTH};

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
    /// Read a length-prefixed data blob written by `ConnectionWriter::write_data`.
    ///
    /// Returns `None` when the stream closes cleanly between blobs.
    ///
    /// # Errors
    /// * Data payload exceeds the maximum frame length (64 KiB).
    /// * I/O error or mid-blob EOF.
    ///
    pub async fn read_data(&mut self) -> Result<Option<Vec<u8>>> {
        // Read the 8-byte big-endian length.  A clean EOF before any bytes is Ok(None).
        let mut len_buf = [0u8; 8];
        match self.reader.read_exact(&mut len_buf).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e.into()),
        }
        let length = usize::try_from(u64::from_be_bytes(len_buf))?;
        if length > MAX_ENCFRAME_LENGTH {
            return Err(Error::FrameTooLarge.into());
        }
        let mut buf = vec![0u8; length];
        let _ = self
            .reader
            .read_exact(&mut buf)
            .await
            .map_err(|_| Error::ConnectionResetByPeer)?;
        Ok(Some(buf))
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
    pub async fn read_frame(&mut self) -> Result<Option<Frame>> {
        loop {
            // Attempt to parse a frame from the buffered data. If enough data
            // has been buffered, the frame is returned.
            if let Some(frame) = self.parse_frame()? {
                return Ok(Some(frame));
            }

            // There is not enough buffered data to read a frame. Attempt to
            // read more data from the socket.
            //
            // On success, the number of bytes is returned. `0` indicates "end
            // of stream".
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
        // Reset the position to zero before passing the cursor to `Frame::parse`.
        buf.set_position(0);

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

#[cfg(test)]
mod tests {
    use tokio::net::{TcpListener, TcpStream};

    use super::{ConnectionReader, Frame};
    use crate::ConnectionWriter;
    use anyhow::Result;

    async fn make_loopback() -> Result<(ConnectionReader, ConnectionWriter)> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let (server, client) = tokio::join!(
            async { listener.accept().await.map(|(s, _)| s) },
            TcpStream::connect(addr),
        );
        let (server_r, _) = server?.into_split();
        let (_, client_w) = client?.into_split();
        let reader = ConnectionReader::builder().reader(server_r).build();
        let writer = ConnectionWriter::builder().writer(client_w).build();
        Ok((reader, writer))
    }

    #[tokio::test]
    async fn read_data_round_trips() -> Result<()> {
        let (mut reader, mut writer) = make_loopback().await?;
        let payload = b"hello data channel";
        writer.write_data(payload).await?;
        drop(writer);
        let received = reader.read_data().await?.expect("expected Some");
        assert_eq!(received, payload);
        Ok(())
    }

    #[tokio::test]
    async fn read_data_eof_returns_none() -> Result<()> {
        let (mut reader, writer) = make_loopback().await?;
        drop(writer);
        let result = reader.read_data().await?;
        assert!(result.is_none());
        Ok(())
    }

    #[tokio::test]
    async fn read_frame_round_trip() -> Result<()> {
        let (mut reader, mut writer) = make_loopback().await?;
        writer.write_frame(&Frame::KexFailure).await?;
        drop(writer);
        let frame = reader.read_frame().await?;
        assert_eq!(frame, Some(Frame::KexFailure));
        Ok(())
    }

    #[tokio::test]
    async fn read_frame_eof_returns_none() -> Result<()> {
        let (mut reader, writer) = make_loopback().await?;
        drop(writer);
        let frame = reader.read_frame().await?;
        assert_eq!(frame, None);
        Ok(())
    }
}
