// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

use anyhow::Result;
use aws_lc_rs::{
    aead::{AES_256_GCM_SIV, Aad, RandomizedNonceKey},
    agreement::{EphemeralPrivateKey, UnparsedPublicKey, X25519, agree_ephemeral},
    digest::SHA512_OUTPUT_LEN,
    error::Unspecified,
    hkdf::{HKDF_SHA256, HKDF_SHA512, Salt},
};
use bon::Builder;
use libmoshpit::{ConnectionReader, Frame, UdpState};
use tokio::sync::mpsc::UnboundedSender;
use tracing::{error, info};

#[derive(Builder)]
pub(crate) struct FrameReader {
    reader: ConnectionReader,
    tx: UnboundedSender<Frame>,
    tx_udp: UnboundedSender<UdpState>,
}

impl FrameReader {
    pub(crate) async fn handle_connection(&mut self, epk: EphemeralPrivateKey) -> Result<()> {
        if let Some(frame) = self.reader.read_frame().await?
            && let Frame::PeerInitialize(pk, salt_bytes) = frame
        {
            info!("Received peer initialize frame");
            let peer_public_key = UnparsedPublicKey::new(&X25519, &pk);
            let salt = Salt::new(HKDF_SHA256, &salt_bytes);

            agree_ephemeral(epk, peer_public_key, Unspecified, |key_material| {
                let pseudo_random_key = salt.extract(key_material);
                let mut check = b"Yoda".to_vec();

                // Derive UnboundKey for AES-256-GCM-SIV
                let okm_aes = pseudo_random_key.expand(&[b"aead key"], &AES_256_GCM_SIV)?;
                let mut key_bytes = [0u8; 32];
                okm_aes.fill(&mut key_bytes)?;
                // Derive the HMAC key and send it over UDP
                let okm_hmac =
                    pseudo_random_key.expand(&[b"hmac key"], HKDF_SHA512.hmac_algorithm())?;
                let mut hmac_key_bytes = [0u8; SHA512_OUTPUT_LEN];
                okm_hmac.fill(&mut hmac_key_bytes)?;
                error!("Derived HMAC key bytes: {}", hex::encode(hmac_key_bytes));
                self.tx_udp
                    .send(UdpState::Key(key_bytes))
                    .map_err(|_| Unspecified)?;
                self.tx_udp
                    .send(UdpState::HmacKey(hmac_key_bytes))
                    .map_err(|_| Unspecified)?;
                let rnk = RandomizedNonceKey::new(&AES_256_GCM_SIV, &key_bytes)?;
                let nonce = rnk.seal_in_place_append_tag(Aad::empty(), &mut check)?;

                self.tx
                    .send(Frame::Check(*nonce.as_ref(), check))
                    .map_err(|_| Unspecified)?;
                info!("Sent check frame with encrypted check message");
                Ok(())
            })?;
        }
        if let Some(frame) = self.reader.read_frame().await?
            && let Frame::KeyAgreement(uuid) = frame
        {
            info!("Received key agreement frame with UUID: {}", uuid);
            self.tx_udp
                .send(UdpState::Uuid(*uuid.as_ref()))
                .map_err(|_| Unspecified)?;
        }
        Ok(())
    }
}
