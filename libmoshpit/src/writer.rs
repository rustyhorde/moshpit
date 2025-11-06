// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

use anyhow::Result;
use bincode::{config::standard, encode_to_vec};
use bon::Builder;
use tokio::{io::AsyncWriteExt as _, net::tcp::OwnedWriteHalf};
use tracing::trace;

use crate::Frame;

/// A writer over a `WriteHalf` and `BytesMut` buffer.
#[derive(Builder, Debug)]
pub struct ConnectionWriter {
    /// The `WriteHalf` of a TCP stream.
    writer: OwnedWriteHalf,
}

impl ConnectionWriter {
    /// Write a single `Frame` value to the underlying stream.
    ///
    /// The `Frame` value is written to the socket using the various `write_*`
    /// functions provided by `AsyncWrite`. Calling these functions directly on
    /// a `TcpStream` is **not** advised, as this will result in a large number of
    /// syscalls. However, it is fine to call these functions on a *buffered*
    /// write stream. The data will be written to the buffer. Once the buffer is
    /// full, it is flushed to the underlying socket.
    ///
    /// # Errors
    /// * I/O error.
    /// * Encoding error.
    ///
    pub async fn write_frame(&mut self, frame: &Frame) -> Result<()> {
        let id = frame.id();
        trace!("Writing frame of type id={}", id);
        let encoded = encode_to_vec(frame, standard())?;
        let len = encoded.len();
        self.writer.write_u8(0).await?;
        self.writer.write_all(len.to_be_bytes().as_slice()).await?;
        self.writer.write_all(&encoded).await?;

        // Ensure the encoded frame is written to the socket. The calls above
        // are to the buffered stream and writes. Calling `flush` writes the
        // remaining contents of the buffer to the socket.
        self.writer.flush().await.map_err(Into::into)
    }

    /// Write raw bytes to the underlying stream.
    ///
    /// # Errors
    /// * I/O error.
    ///
    pub async fn write_bytes(&mut self, bytes: &[u8]) -> Result<()> {
        self.writer.write_all(bytes).await?;
        self.writer.flush().await.map_err(Into::into)
    }
}
