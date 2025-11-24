// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

use std::{collections::BTreeSet, net::SocketAddr, path::PathBuf, sync::Arc};

use anyhow::Result;
use aws_lc_rs::{
    aead::{AES_256_GCM_SIV, Aad, Nonce, RandomizedNonceKey},
    agreement::{ParsedPublicKey, PrivateKey, UnparsedPublicKey, X25519, agree},
    cipher::AES_256_KEY_LEN,
    digest::SHA512_OUTPUT_LEN,
    error::Unspecified,
    hkdf::{HKDF_SHA256, HKDF_SHA512, Salt},
    rand::fill,
};
use bon::Builder;
use local_ip_address::local_ip;
use tokio::{
    net::UdpSocket,
    process::Command,
    sync::{Mutex, mpsc::UnboundedSender},
};
use tracing::{error, trace};
use uuid::Uuid;

use crate::{
    ConnectionReader, Frame, KexEvent, MoshpitError, UuidWrapper, load_private_key, load_public_key,
};

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
    pub async fn client_kex(&mut self, epk: &PrivateKey) -> Result<()> {
        if let Some(frame) = self.reader.read_frame().await?
            && let Frame::PeerInitialize(pk, salt_bytes) = frame
        {
            let peer_public_key = UnparsedPublicKey::new(&X25519, &pk);
            let salt = Salt::new(HKDF_SHA256, &salt_bytes);

            agree(epk, peer_public_key, Unspecified, |key_material| {
                let pseudo_random_key = salt.extract(key_material);
                let mut check = b"Yoda".to_vec();

                // Derive UnboundKey for AES-256-GCM-SIV
                let okm_aes = pseudo_random_key.expand(&[b"aead key"], &AES_256_GCM_SIV)?;
                let mut key_bytes = [0u8; AES_256_KEY_LEN];
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
    pub async fn server_kex(
        &mut self,
        socket_addr: SocketAddr,
        port_pool: Arc<Mutex<BTreeSet<u16>>>,
        private_key_path: &PathBuf,
        public_key_path: &PathBuf,
    ) -> Result<Arc<UdpSocket>> {
        let rnk = if let Some(frame) = self.reader.read_frame().await? {
            if let Frame::Initialize(user, pk, fpk) = frame {
                let user_str = String::from_utf8_lossy(&user);
                let (_home_dir, _shell) = if self.validate_user(&user_str).await? {
                    self.get_home_dir_shell(&user_str).await?
                } else {
                    return Err(MoshpitError::KeyNotEstablished.into());
                };
                trace!("Full public key: {}", String::from_utf8_lossy(&fpk));
                self.handle_initialize(
                    &pk,
                    &self.tx_event.clone(),
                    private_key_path,
                    public_key_path,
                )?
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

        let udp_arc = self.handle_udp_setup(socket_addr, port_pool).await?;

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
        private_key_path: &PathBuf,
        public_key_path: &PathBuf,
    ) -> Result<RandomizedNonceKey> {
        // Load the moshpits public and private key
        let (unenc_key_pair_opt, _enc_key_pair_opt) = load_private_key(private_key_path)?;
        let (_, public_key_bytes) = load_public_key(public_key_path)?;

        let (private_key, public_key) = if let Some(unenc_key_pair) = unenc_key_pair_opt {
            unenc_key_pair.take()
        } else {
            return Err(anyhow::anyhow!("No valid private key found"));
        };

        if public_key.as_ref() != public_key_bytes.as_slice() {
            return Err(anyhow::anyhow!(
                "public key from file does not match computed public key"
            ));
        }

        // Setup the public key from the peer
        let unparsed_public_key = UnparsedPublicKey::new(&X25519, &pk);
        let parsed_public_key = ParsedPublicKey::try_from(&unparsed_public_key)?;

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
        let rnk = agree(
            &private_key,
            parsed_public_key,
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

    async fn handle_udp_setup(
        &mut self,
        mut socket_addr: SocketAddr,
        port_pool: Arc<Mutex<BTreeSet<u16>>>,
    ) -> Result<Arc<UdpSocket>> {
        let mut port_p = port_pool.lock().await;
        let next_port = port_p.pop_first().unwrap_or(49999);
        socket_addr.set_port(next_port);
        let my_local_ip = local_ip()?;
        let udp_socket_addr = SocketAddr::new(my_local_ip, socket_addr.port());
        trace!("binding moshpits socket at {udp_socket_addr}");
        self.tx.send(Frame::MoshpitsAddr(udp_socket_addr))?;
        let udp_listener = UdpSocket::bind(udp_socket_addr).await?;
        Ok(Arc::new(udp_listener))
    }

    #[cfg(target_os = "linux")]
    async fn validate_user(&self, user: &str) -> Result<bool> {
        let mut is_valid_user = Command::new("id");
        let _ = is_valid_user.arg(user);
        let output = is_valid_user
            .output()
            .await
            .map_err(|_e| MoshpitError::KeyNotEstablished)?;
        Ok(output.status.success())
    }

    #[cfg(target_os = "macos")]
    async fn validate_user(&self, user: &str) -> Result<bool> {
        let mut is_valid_user = Command::new("dscl");
        let _ = is_valid_user.args([".", "-read", format!("/Users/{user}").as_str()]);
        let output = is_valid_user
            .output()
            .await
            .map_err(|_e| MoshpitError::KeyNotEstablished)?;
        Ok(output.status.success())
    }

    #[cfg(target_os = "linux")]
    async fn get_home_dir_shell(&self, user: &str) -> Result<(String, String)> {
        let mut cmd = Command::new("getent");
        let _ = cmd.args(["passwd", user]);
        let output = cmd
            .output()
            .await
            .map_err(|_e| MoshpitError::KeyNotEstablished)?;
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let parts: Vec<&str> = stdout.split(':').collect();
            if parts.len() >= 7 {
                let home_dir = parts[5].to_string();
                let shell = parts[6].trim().to_string();
                trace!("User '{user}' home directory: {home_dir}, shell: {shell}");
                return Ok((home_dir, shell));
            }
        }
        Err(MoshpitError::KeyNotEstablished.into())
    }

    #[cfg(target_os = "macos")]
    async fn get_home_dir_shell(&self, user: &str) -> Result<(String, String)> {
        let mut cmd = Command::new("dscl");
        let _ = cmd.args([
            ".",
            "-read",
            format!("/Users/{user}").as_str(),
            "NFSHomeDirectory",
            "UserShell",
        ]);
        let output = cmd
            .output()
            .await
            .map_err(|_e| MoshpitError::KeyNotEstablished)?;
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let mut home_dir = String::new();
            let mut shell = String::new();
            for line in stdout.lines() {
                if let Some(stripped) = line.strip_prefix("NFSHomeDirectory:") {
                    home_dir = stripped.trim().to_string();
                } else if let Some(stripped) = line.strip_prefix("UserShell:") {
                    shell = stripped.trim().to_string();
                }
            }
            trace!("User '{user}' home directory: {home_dir}, shell: {shell}");
            return Ok((home_dir, shell));
        }
        Err(MoshpitError::KeyNotEstablished.into())
    }
}
