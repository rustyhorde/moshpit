// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU16, Ordering},
    },
};

use anyhow::Result;
use aws_lc_rs::{
    aead::{AES_256_GCM_SIV, Aad, Nonce, RandomizedNonceKey},
    agreement::{EphemeralPrivateKey, UnparsedPublicKey, X25519, agree_ephemeral},
    cipher::AES_256_KEY_LEN,
    digest::SHA512_OUTPUT_LEN,
    error::Unspecified,
    hkdf::{HKDF_SHA256, HKDF_SHA512, Salt},
    rand::{SystemRandom, fill},
};
use bon::Builder;
use tokio::{net::UdpSocket, sync::mpsc::UnboundedSender};
use tracing::error;
use uuid::Uuid;

use crate::{ConnectionReader, Frame, KexEvent, MoshpitError, UuidWrapper};

static CURRENT_UDP_PORT: AtomicU16 = AtomicU16::new(50000);

/// The key exchange reader for the moshpit
#[derive(Builder, Debug)]
pub struct KexReader {
    /// The connection reader
    reader: ConnectionReader,
    /// The frame sender
    tx: UnboundedSender<Frame>,
    /// The key exchange event sender
    tx_event: UnboundedSender<KexEvent>,
}

impl KexReader {
    /// Perform the client side of a key exchange
    ///
    /// # Errors
    ///
    pub async fn client_kex(&mut self, epk: EphemeralPrivateKey) -> Result<()> {
        if let Some(frame) = self.reader.read_frame().await?
            && let Frame::PeerInitialize(pk, salt_bytes) = frame
        {
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

                self.tx_event
                    .send(KexEvent::KeyMaterial(key_bytes))
                    .map_err(|_| Unspecified)?;
                self.tx_event
                    .send(KexEvent::HMACKeyMaterial(hmac_key_bytes))
                    .map_err(|_| Unspecified)?;
                let rnk = RandomizedNonceKey::new(&AES_256_GCM_SIV, &key_bytes)?;
                let nonce = rnk.seal_in_place_append_tag(Aad::empty(), &mut check)?;

                self.tx
                    .send(Frame::Check(*nonce.as_ref(), check))
                    .map_err(|_| Unspecified)?;
                Ok(())
            })?;
        }
        if let Some(frame) = self.reader.read_frame().await?
            && let Frame::KeyAgreement(uuid) = frame
        {
            self.tx_event
                .send(KexEvent::Uuid(*uuid.as_ref()))
                .map_err(|_| Unspecified)?;
        }

        if let Some(frame) = self.reader.read_frame().await?
            && let Frame::MoshpitsAddr(addr) = frame
        {
            self.tx_event
                .send(KexEvent::MoshpitsAddr(addr))
                .map_err(|_| Unspecified)?;
        }
        Ok(())
    }

    /// Perform the server side of a key exchange
    ///
    /// # Errors
    ///
    pub async fn server_kex(&mut self, socket_addr: SocketAddr) -> Result<Arc<UdpSocket>> {
        let rnk = if let Some(frame) = self.reader.read_frame().await? {
            if let Frame::Initialize(pk) = frame {
                self.handle_initialize(&pk, &self.tx_event.clone())?
            } else {
                error!("Expected initialize frame from mp");
                return Err(MoshpitError::InvalidFrame.into());
            }
        } else {
            error!("Expected initialize frame from mp");
            return Err(MoshpitError::InvalidFrame.into());
        };

        if let Some(frame) = self.reader.read_frame().await? {
            if let Frame::Check(nonce, enc) = frame {
                self.handle_check(&rnk, nonce, enc, &self.tx_event.clone())?;
            } else {
                error!("Expected check frame from mp");
                return Err(MoshpitError::InvalidFrame.into());
            }
        } else {
            error!("Expected check frame from mp");
            return Err(MoshpitError::InvalidFrame.into());
        }

        let udp_arc = self.handle_udp_setup(socket_addr).await?;

        if let Some(frame) = self.reader.read_frame().await? {
            if let Frame::MoshpitAddr(moshpit_addr) = frame {
                udp_arc.connect(moshpit_addr).await?;
            } else {
                error!("Expected moshpit address frame");
                return Err(MoshpitError::InvalidFrame.into());
            }
        } else {
            error!("Expected moshpit address frame");
            return Err(MoshpitError::InvalidFrame.into());
        }

        Ok(udp_arc)
    }

    fn handle_initialize(
        &mut self,
        pk: &[u8],
        tx_event: &UnboundedSender<KexEvent>,
    ) -> Result<RandomizedNonceKey> {
        let rng = SystemRandom::new();

        // Generate our ephemeral key pair
        let ephemeral_priv_key = EphemeralPrivateKey::generate(&X25519, &rng)?;
        let public_key = ephemeral_priv_key.compute_public_key()?;
        let unparsed_public_key = UnparsedPublicKey::new(&X25519, &pk);

        // Generate a (non-secret) salt value
        let mut salt_bytes = [0u8; 32];
        fill(&mut salt_bytes)?;

        // Send the public key and salt back to the peer
        let peer_initialize =
            Frame::PeerInitialize(public_key.as_ref().to_vec(), salt_bytes.to_vec());
        self.tx.send(peer_initialize)?;

        // Extract pseudo-random key from secret keying materials
        let salt = Salt::new(HKDF_SHA256, &salt_bytes);

        // Setup the rnk and wait for a check frame
        let rnk = agree_ephemeral(
            ephemeral_priv_key,
            unparsed_public_key,
            Unspecified,
            |key_material| {
                let pseudo_random_key = salt.extract(key_material);
                let okm = pseudo_random_key.expand(&[b"aead key"], &AES_256_GCM_SIV)?;
                let mut key_bytes = [0u8; AES_256_KEY_LEN];
                okm.fill(&mut key_bytes)?;
                // Derive the HMAC key and send it over UDP
                let okm_hmac =
                    pseudo_random_key.expand(&[b"hmac key"], HKDF_SHA512.hmac_algorithm())?;
                let mut hmac_key_bytes = [0u8; SHA512_OUTPUT_LEN];
                okm_hmac.fill(&mut hmac_key_bytes)?;

                tx_event
                    .send(KexEvent::KeyMaterial(key_bytes))
                    .map_err(|_| Unspecified)?;
                tx_event
                    .send(KexEvent::HMACKeyMaterial(hmac_key_bytes))
                    .map_err(|_| Unspecified)?;
                let rnk = RandomizedNonceKey::new(&AES_256_GCM_SIV, &key_bytes)?;
                Ok(rnk)
            },
        )?;
        Ok(rnk)
    }

    fn handle_check(
        &mut self,
        rnk: &RandomizedNonceKey,
        nonce_bytes: [u8; 12],
        mut check_bytes: Vec<u8>,
        tx_event: &UnboundedSender<KexEvent>,
    ) -> Result<()> {
        let nonce = Nonce::from(&nonce_bytes);
        let decrypted_data = rnk
            .open_in_place(nonce, Aad::empty(), &mut check_bytes)
            .map_err(|_| MoshpitError::DecryptionFailed)?;
        if decrypted_data == b"Yoda" {
            let id = Uuid::new_v4();
            tx_event.send(KexEvent::Uuid(id)).map_err(|_| Unspecified)?;
            self.tx.send(Frame::KeyAgreement(UuidWrapper::new(id)))?;
        } else {
            error!("Check frame verification failed");
            return Err(MoshpitError::DecryptionFailed.into());
        }
        Ok(())
    }

    async fn handle_udp_setup(&mut self, mut socket_addr: SocketAddr) -> Result<Arc<UdpSocket>> {
        let next_port = CURRENT_UDP_PORT.fetch_add(1, Ordering::SeqCst);
        socket_addr.set_port(next_port);
        self.tx.send(Frame::MoshpitsAddr(socket_addr))?;
        let udp_listener = UdpSocket::bind(socket_addr).await?;
        Ok(Arc::new(udp_listener))
    }
}
