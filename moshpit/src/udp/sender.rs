// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

use std::sync::Arc;

use anyhow::Result;
use aws_lc_rs::aead::{AES_256_GCM_SIV, Aad, RandomizedNonceKey};
use bon::Builder;
use getset::MutGetters;
use tokio::{net::UdpSocket, sync::mpsc::UnboundedReceiver};
use tracing::trace;
use uuid::Uuid;

#[derive(Builder, MutGetters)]
pub(crate) struct UdpSender {
    id: Uuid,
    #[builder(with = |key: [u8; 32]| -> Result<_> { RandomizedNonceKey::new(&AES_256_GCM_SIV, &key).map_err(Into::into) })]
    rnk: RandomizedNonceKey,
    socket: Arc<UdpSocket>,
    rx: UnboundedReceiver<Vec<u8>>,
}

impl UdpSender {
    pub(crate) async fn handle_send(&mut self) -> Result<()> {
        while let Some(bytes) = self.rx.recv().await {
            let packet = self.encrypt(&bytes)?;
            let len = self.socket.send(&packet).await?;
            trace!("Sent {len} bytes over UDP");
        }
        Ok(())
    }

    fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        let len = data.len().to_be_bytes();
        let mut encrypted_part = self.id.as_bytes().to_vec();
        encrypted_part.extend_from_slice(&len);
        encrypted_part.extend_from_slice(data);
        let nonce = self
            .rnk
            .seal_in_place_append_tag(Aad::empty(), &mut encrypted_part)?;
        let mut packet = nonce.as_ref().to_vec();
        packet.extend_from_slice(&encrypted_part);
        Ok(packet)
    }
}
