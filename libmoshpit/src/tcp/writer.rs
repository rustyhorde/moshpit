// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

use anyhow::Result;
use bincode_next::{config::standard, encode_to_vec};
use bon::Builder;
use tokio::{io::AsyncWriteExt as _, net::tcp::OwnedWriteHalf};

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
        let encoded = encode_to_vec(frame, standard())?;
        let len = encoded.len();
        self.writer.write_u8(id).await?;
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

    /// Write a length-prefixed data blob to the stream.
    ///
    /// Writes an 8-byte big-endian length followed by the payload.  Used by the
    /// TCP data channel to frame [`EncryptedFrame`](crate::EncryptedFrame) wire
    /// bytes independently of the KEX [`Frame`] framing.
    ///
    /// # Errors
    /// * I/O error.
    ///
    pub async fn write_data(&mut self, bytes: &[u8]) -> Result<()> {
        self.writer.write_u64(u64::try_from(bytes.len())?).await?;
        self.writer.write_all(bytes).await?;
        self.writer.flush().await.map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use tokio::net::{TcpListener, TcpStream};

    use super::{ConnectionWriter, Frame};
    use anyhow::Result;

    #[tokio::test]
    async fn write_frame_succeeds() -> Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let (server, client) = tokio::join!(
            async { listener.accept().await.map(|(s, _)| s) },
            TcpStream::connect(addr),
        );
        let _server = server?;
        let (_, client_w) = client?.into_split();
        let mut writer = ConnectionWriter::builder().writer(client_w).build();
        writer.write_frame(&Frame::KexFailure).await?;
        Ok(())
    }

    #[tokio::test]
    async fn write_data_round_trips() -> Result<()> {
        use tokio::{
            io::AsyncReadExt as _,
            net::{TcpListener, TcpStream},
        };
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let (server, client) = tokio::join!(
            async { listener.accept().await.map(|(s, _)| s) },
            TcpStream::connect(addr),
        );
        let (server_r, _) = server?.into_split();
        let (_, client_w) = client?.into_split();
        let mut writer = ConnectionWriter::builder().writer(client_w).build();
        let payload = b"hello data channel";
        writer.write_data(payload).await?;
        drop(writer);
        let mut reader_raw = server_r;
        let mut len_buf = [0u8; 8];
        let _ = reader_raw.read_exact(&mut len_buf).await?;
        let len = usize::try_from(u64::from_be_bytes(len_buf))?;
        let mut data = vec![0u8; len];
        let _ = reader_raw.read_exact(&mut data).await?;
        assert_eq!(data, payload);
        Ok(())
    }

    #[tokio::test]
    async fn write_bytes_succeeds() -> Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let (server, client) = tokio::join!(
            async { listener.accept().await.map(|(s, _)| s) },
            TcpStream::connect(addr),
        );
        let _server = server?;
        let (_, client_w) = client?.into_split();
        let mut writer = ConnectionWriter::builder().writer(client_w).build();
        writer.write_bytes(b"hello").await?;
        Ok(())
    }
}
