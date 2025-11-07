// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

use std::sync::Arc;

use anyhow::Result;
use aws_lc_rs::aead::{AES_256_GCM_SIV, Aad, NONCE_LEN, Nonce, RandomizedNonceKey};
use bon::Builder;
use bytes::BytesMut;
use tokio::net::UdpSocket;
use tracing::{info, trace};
use uuid::Uuid;

const UUID_LEN: usize = 16;
const USIZE_LEN: usize = 8;

#[derive(Builder)]
#[allow(dead_code)]
pub(crate) struct UdpReader {
    socket: Arc<UdpSocket>,
    #[builder(default = BytesMut::with_capacity(4096))]
    buf: BytesMut,
    id: Uuid,
    #[builder(with = |key: [u8; 32]| -> Result<_> { RandomizedNonceKey::new(&AES_256_GCM_SIV, &key).map_err(Into::into) })]
    rnk: RandomizedNonceKey,
}

impl UdpReader {
    pub(crate) async fn handle_read(&mut self) -> Result<()> {
        loop {
            let len = self.socket.recv_buf(&mut self.buf).await?;
            trace!("Received {len} bytes over UDP");
            self.handle_bytes(len)?;
        }
    }

    fn handle_bytes(&mut self, len: usize) -> Result<()> {
        if len < NONCE_LEN + UUID_LEN + USIZE_LEN + 1 {
            trace!("packet too short");
            return Ok(());
        }
        let read = self.buf.split_to(len);
        let (nonce_bytes, ciphertext) = read.split_at(NONCE_LEN);
        let mut data = ciphertext.to_vec();
        let nonce = Nonce::try_assume_unique_for_key(nonce_bytes)?;
        info!("nonce: {:?}", nonce.as_ref());
        let _ = self.rnk.open_in_place(nonce, Aad::empty(), &mut data)?;
        info!("trying to parse uuid");
        let (uuid_bytes, rest) = data.split_at(UUID_LEN);
        let uuid = Uuid::from_bytes(uuid_bytes.try_into()?);
        trace!("uuid: {uuid}");
        let (len_bytes, message_bytes) = rest.split_at(USIZE_LEN);
        let message_len = usize::from_be_bytes(len_bytes.try_into()?);
        if message_bytes.len() < message_len {
            trace!("message too short");
            return Ok(());
        }
        let message = &message_bytes[..message_len];
        trace!("message length: {}", message.len());
        trace!("message: {}", String::from_utf8_lossy(message));
        Ok(())
    }
}
