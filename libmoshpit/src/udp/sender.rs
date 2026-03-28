// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

use std::{collections::HashMap, sync::Arc};

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
use uuid::Uuid;

use crate::EncryptedFrame;

/// Number of sent packets kept in the retransmit buffer.
const RETRANSMIT_WINDOW: u64 = 512;

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
    /// Channel receiver for retransmit requests from the local reader
    retransmit_rx: UnboundedReceiver<Vec<u64>>,
    /// Next sequence number for outgoing packets
    #[builder(default)]
    send_seq: u64,
    /// Buffer of sent wire bytes keyed by sequence number for potential retransmission
    #[builder(default)]
    retransmit_buffer: HashMap<u64, Vec<u8>>,
}

impl UdpSender {
    /// Handle sending packets received on the channel
    ///
    /// # Errors
    ///
    /// * I/O error.
    ///
    pub async fn frame_loop(&mut self, token: CancellationToken) -> Result<()> {
        let mut retransmit_active = true;
        loop {
            select! {
                () = token.cancelled() => break,
                frame_opt = self.rx.recv() => {
                    match frame_opt {
                        Some(frame) => {
                            let seq = self.send_seq;
                            self.send_seq += 1;
                            let wire = self.encrypt(&frame, seq)?;
                            let _prev = self.retransmit_buffer.insert(seq, wire.clone());
                            // Evict packets that fell outside the retransmit window
                            let cutoff = seq.saturating_sub(RETRANSMIT_WINDOW);
                            self.retransmit_buffer.retain(|&s, _| s >= cutoff);
                            let _bytes_sent = self.socket.send(&wire).await?;
                        }
                        None => break,
                    }
                },
                seqs = self.retransmit_rx.recv(), if retransmit_active => {
                    match seqs {
                        Some(seqs) => {
                            for seq in seqs {
                                if let Some(wire) = self.retransmit_buffer.get(&seq) {
                                    let wire = wire.clone();
                                    let _bytes_sent = self.socket.send(&wire).await?;
                                }
                            }
                        }
                        None => retransmit_active = false,
                    }
                }
            }
        }
        Ok(())
    }

    fn encrypt(&self, frame: &EncryptedFrame, seq: u64) -> Result<Vec<u8>> {
        // Encode the frame data
        let data = encode_to_vec(frame, standard())?;
        let aad = Aad::from(seq.to_be_bytes());
        // Encrypt the id, frame_id, and the data then MAC
        let mut encrypted_part = self.id.as_bytes().to_vec();
        encrypted_part.extend_from_slice(&data);
        let nonce = self
            .rnk
            .seal_in_place_append_tag(aad, &mut encrypted_part)?;
        // Sign seq_bytes || encrypted_part to authenticate the wire sequence number
        let seq_bytes = seq.to_be_bytes();
        let mut to_sign = seq_bytes.to_vec();
        to_sign.extend_from_slice(&encrypted_part);
        let tag = sign(&self.hmac, &to_sign);
        let tag_bytes: [u8; 64] = tag.as_ref().try_into()?;
        let len = encrypted_part.len().to_be_bytes();
        // Wire format: [nonce (12)] [seq (8)] [hmac_tag (64)] [length (8)] [encrypted_part]
        let mut packet = nonce.as_ref().to_vec();
        packet.extend_from_slice(&seq_bytes);
        packet.extend_from_slice(&tag_bytes);
        packet.extend_from_slice(&len);
        packet.extend_from_slice(&encrypted_part);
        Ok(packet)
    }
}
