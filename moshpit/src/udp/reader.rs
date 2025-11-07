// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

use std::sync::Arc;

use anyhow::Result;
use bon::Builder;
use bytes::BytesMut;
use tokio::net::UdpSocket;
use tracing::trace;

#[derive(Builder)]
pub(crate) struct UdpReader {
    socket: Arc<UdpSocket>,
    #[builder(default = BytesMut::with_capacity(4096))]
    buf: BytesMut,
}

impl UdpReader {
    pub(crate) async fn handle_read(&mut self) -> Result<()> {
        loop {
            let len = self.socket.recv_buf(&mut self.buf).await?;
            trace!("Received {len} bytes over UDP");
            self.handle_bytes(len);
        }
    }

    fn handle_bytes(&mut self, len: usize) {
        let read = self.buf.split_to(len);
        trace!("read {} bytes", String::from_utf8_lossy(&read));
    }
}
