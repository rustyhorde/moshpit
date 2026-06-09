// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

use anyhow::Result;
use bon::Builder;
use tokio::sync::mpsc::UnboundedReceiver;

use crate::{ConnectionWriter, Frame};

/// The key exchange sender for the moshpit
#[derive(Builder, Debug)]
pub struct KexSender {
    /// The connection writer
    writer: ConnectionWriter,
    /// The receiver for frames to send
    rx: UnboundedReceiver<Frame>,
}

impl KexSender {
    /// Handle sending frames
    ///
    /// # Errors
    ///
    /// * `write_frame` errors
    ///
    pub async fn handle_send_frames(&mut self) -> Result<()> {
        while let Some(frame) = self.rx.recv().await {
            self.writer.write_frame(&frame).await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use tokio::{
        net::{TcpListener, TcpStream},
        sync::mpsc::unbounded_channel,
    };

    use super::{ConnectionWriter, Frame, KexSender};
    use crate::ConnectionReader;
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
    async fn kex_sender_relays_frame() -> Result<()> {
        let (mut reader, writer) = make_loopback().await?;
        let (tx, rx) = unbounded_channel();
        let mut sender = KexSender::builder().writer(writer).rx(rx).build();
        tx.send(Frame::KexFailure).expect("test channel send");
        drop(tx);
        sender.handle_send_frames().await?;
        let frame = reader.read_frame().await?;
        assert_eq!(frame, Some(Frame::KexFailure));
        Ok(())
    }

    #[tokio::test]
    async fn kex_sender_stops_on_channel_close() -> Result<()> {
        let (_, writer) = make_loopback().await?;
        let (tx, rx) = unbounded_channel::<Frame>();
        drop(tx);
        let mut sender = KexSender::builder().writer(writer).rx(rx).build();
        sender.handle_send_frames().await?;
        Ok(())
    }
}
