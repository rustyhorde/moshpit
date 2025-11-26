// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use anyhow::Result;
use aws_lc_rs::{
    aead::{AES_256_GCM_SIV, Aad, RandomizedNonceKey},
    hmac::{HMAC_SHA512, Key, sign},
};
use bincode::{config::standard, encode_to_vec};
use bon::Builder;
use getset::MutGetters;
use tokio::{net::UdpSocket, select, sync::mpsc::UnboundedReceiver};
use tokio_util::sync::CancellationToken;
use tracing::{info, trace};
use uuid::Uuid;

use crate::EncryptedFrame;

/// UDP sender for encrypted frames
#[derive(Builder, Debug, MutGetters)]
pub struct UdpSender {
    /// Client UUID
    id: Uuid,
    /// Key for encrypting/decrypting UDP packets
    #[builder(with = |key: [u8; 32]| -> Result<_> { RandomizedNonceKey::new(&AES_256_GCM_SIV, &key).map_err(Into::into) })]
    rnk: RandomizedNonceKey,
    /// Key for signing UDP packet HMAC
    #[builder(with = |key: [u8; 64]| { Key::new(HMAC_SHA512, &key) })]
    hmac: Key,
    /// Underlying UDP socket
    socket: Arc<UdpSocket>,
    /// Channel receiver for outgoing packets
    rx: UnboundedReceiver<EncryptedFrame>,
    /// Count of frames sent
    #[builder(default = AtomicUsize::new(0))]
    send_count: AtomicUsize,
}

impl UdpSender {
    /// Handle sending packets received on the channel
    ///
    /// # Errors
    ///
    /// * I/O error.
    ///
    pub async fn frame_loop(&mut self, token: CancellationToken) -> Result<()> {
        loop {
            select! {
                () = token.cancelled() => break,
                frame_opt = self.rx.recv() => {
                    trace!("Sending UDP frame");
                    if let Some(frame) = frame_opt {
                        let count = self.send_count.fetch_add(1, Ordering::SeqCst);
                        info!("Sending UDP frame #{count}");
                        let _bytes_sent = self.socket.send(&self.encrypt(&frame, count)?).await?;
                    }
                }
            }
        }
        Ok(())
    }

    fn encrypt(&self, frame: &EncryptedFrame, count: usize) -> Result<Vec<u8>> {
        // Encode the frame data
        let data = encode_to_vec(frame, standard())?;
        let aad = Aad::from(count.to_be_bytes());
        // Encrypt the id, frame_id, and the data then MAC
        let mut encrypted_part = self.id.as_bytes().to_vec();
        encrypted_part.extend_from_slice(&data);
        let nonce = self
            .rnk
            .seal_in_place_append_tag(aad, &mut encrypted_part)?;
        // Sign the encrypted part
        let tag = sign(&self.hmac, &encrypted_part);
        let tag_bytes: [u8; 64] = tag.as_ref().try_into()?;
        let len = encrypted_part.len().to_be_bytes();
        // Prepend the nonce and length
        let mut packet = nonce.as_ref().to_vec();
        packet.extend_from_slice(&tag_bytes);
        packet.extend_from_slice(&len);
        packet.extend_from_slice(&encrypted_part);
        Ok(packet)
    }
}
