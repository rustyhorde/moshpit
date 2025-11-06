// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use anyhow::Result;
use bon::Builder;
use bytes::BytesMut;
use libmoshpit::UuidWrapper;
use tokio::{net::UdpSocket, sync::mpsc::UnboundedSender};

#[derive(Builder, Clone)]
pub(crate) struct UdpHandler {
    sender: Arc<UdpSocket>,
    tx: UnboundedSender<Vec<u8>>,
    clients: HashMap<UuidWrapper, SocketAddr>,
    // The buffer for reading frames. Here we do manually buffer handling.
    // A more high level approach would be to use `tokio_util::codec`, and
    // implement your own codec for decoding and encoding frames.
    #[builder(default = BytesMut::with_capacity(4096))]
    buffer: BytesMut,
}

impl UdpHandler {
    pub(crate) async fn send_frame(&mut self, _frame: Vec<u8>) -> Result<()> {
        loop {
            // let (len, addr) = self.sender.send_to(&frame, addr).await?;
            // println!("{len:?} bytes received from {addr}");
        }
    }
}
