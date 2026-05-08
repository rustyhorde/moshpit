// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

use std::{
    collections::BTreeSet,
    fs::OpenOptions,
    io::{BufRead, BufReader},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::Arc,
};

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
use base64::{Engine as _, engine::general_purpose::STANDARD};
use bon::Builder;
use socket2::SockRef;
use tokio::{
    net::UdpSocket,
    process::Command,
    sync::{Mutex, mpsc::UnboundedSender},
};
use tracing::{error, trace};
use uuid::Uuid;

use crate::kex::HostKeyMismatchFn;
use crate::{
    ConnectionReader, Frame, KexEvent, MoshpitError, ServerKex, UuidWrapper, kex::TofuFn,
    load_private_key, load_public_key, session::SessionRegistry, udp::DiffMode,
};

const AEAD_KEY_INFO: &[u8] = b"AEAD KEY";
const HMAC_KEY_INFO: &[u8] = b"HMAC KEY";

/// The key exchange reader for the moshpit
#[derive(Builder)]
pub struct KexReader {
    /// The connection reader
    reader: ConnectionReader,
    /// The frame sender
    tx: UnboundedSender<Frame>,
    /// The key exchange event sender
    tx_event: UnboundedSender<KexEvent>,
    /// The session UUID the client is requesting to resume (None for fresh connections).
    requested_session_uuid: Option<Uuid>,
    /// The server destination hostname or IP
    server_destination: Option<String>,
    /// The callback for TOFU interactive prompt
    tofu_fn: Option<TofuFn>,
    /// Callback for known-host key mismatch replacement prompt.
    host_key_mismatch_fn: Option<HostKeyMismatchFn>,
    /// UDP diff transport mode requested by this client.  When `Datagram` or
    /// `StateSync`, the client sends a `Frame::ClientOptions(1)` or `(2)` before
    /// the `Check` frame so the server can enable the appropriate delivery path
    /// for this session.  Defaults to `Reliable` (no `ClientOptions` frame sent).
    #[builder(default)]
    diff_mode: DiffMode,
}

impl std::fmt::Debug for KexReader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KexReader")
            .field("reader", &self.reader)
            .field("tx", &self.tx)
            .field("tx_event", &self.tx_event)
            .field("requested_session_uuid", &self.requested_session_uuid)
            .field("server_destination", &self.server_destination)
            .field(
                "tofu_fn",
                &if self.tofu_fn.is_some() {
                    "Some(<fn>)"
                } else {
                    "None"
                },
            )
            .field(
                "host_key_mismatch_fn",
                &if self.host_key_mismatch_fn.is_some() {
                    "Some(<fn>)"
                } else {
                    "None"
                },
            )
            .field("diff_mode", &self.diff_mode)
            .finish()
    }
}

impl KexReader {
    /// Perform the client side of a key exchange
    ///
    /// # Errors
    ///
    #[cfg_attr(nightly, allow(clippy::too_many_lines))]
    pub async fn client_kex(&mut self, epk: &PrivateKey) -> Result<()> {
        trace!("client_kex: waiting for PeerInitialize");
        match self.reader.read_frame().await? {
            None => {
                error!("client_kex: server closed connection before sending PeerInitialize");
                return Err(anyhow::anyhow!(
                    "Server closed connection during key exchange"
                ));
            }
            Some(Frame::PeerInitialize(pk, salt_bytes)) => {
                trace!(
                    "client_kex: received PeerInitialize ({} byte pubkey)",
                    pk.len()
                );

                if let Some(host) = &self.server_destination {
                    trace!("client_kex: checking known_hosts for host '{host}'");
                    match check_known_hosts(
                        host,
                        &pk,
                        self.tofu_fn.as_ref(),
                        self.host_key_mismatch_fn.as_ref(),
                    ) {
                        Err(e) => {
                            error!("client_kex: known_hosts check error for '{host}': {e}");
                            let _ = self.tx_event.send(KexEvent::Failure);
                            return Err(e);
                        }
                        Ok(false) => {
                            error!("client_kex: host key verification rejected for '{host}'");
                            let _ = self.tx_event.send(KexEvent::Failure);
                            return Err(MoshpitError::HostKeyRejected.into());
                        }
                        Ok(true) => {
                            trace!("client_kex: host key verified for '{host}'");
                        }
                    }
                } else {
                    trace!("client_kex: no server_destination set, skipping host-key check");
                }

                let peer_public_key = UnparsedPublicKey::new(&X25519, &pk);
                let salt = Salt::new(HKDF_SHA256, &salt_bytes);

                trace!("client_kex: running ECDH agree()");
                agree(epk, peer_public_key, Unspecified, |key_material| {
                    let pseudo_random_key = salt.extract(key_material);
                    let mut check = b"Yoda".to_vec();

                    // Derive UnboundKey for AES-256-GCM-SIV
                    let okm_aes = pseudo_random_key.expand(&[AEAD_KEY_INFO], &AES_256_GCM_SIV)?;
                    let mut key_bytes = [0u8; AES_256_KEY_LEN];
                    okm_aes.fill(&mut key_bytes)?;
                    // Derive the HMAC key and send it over UDP
                    let okm_hmac =
                        pseudo_random_key.expand(&[HMAC_KEY_INFO], HKDF_SHA512.hmac_algorithm())?;
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

                    match self.diff_mode {
                        DiffMode::Datagram => self
                            .tx
                            .send(Frame::ClientOptions(1))
                            .map_err(|_| Unspecified)?,
                        DiffMode::StateSync => self
                            .tx
                            .send(Frame::ClientOptions(2))
                            .map_err(|_| Unspecified)?,
                        DiffMode::Reliable => {}
                    }
                    self.tx
                        .send(Frame::Check(*nonce.as_ref(), check))
                        .map_err(|_| Unspecified)?;
                    Ok(())
                })
                .inspect(|()| trace!("client_kex: agree() succeeded, Check frame sent"))
                .inspect_err(|_| {
                    error!(
                        "client_kex: agree() failed — channel closed or crypto error \
                         (wrong passphrase?)"
                    );
                })?;
            }
            Some(other) => {
                error!(
                    "client_kex: expected PeerInitialize but got frame id={}",
                    other.id()
                );
                let _ = self.tx_event.send(KexEvent::Failure);
                return Err(MoshpitError::KeyNotEstablished.into());
            }
        }

        trace!("client_kex: waiting for KeyAgreement");
        match self.reader.read_frame().await? {
            Some(Frame::KeyAgreement(uuid)) => {
                trace!("client_kex: received KeyAgreement uuid={}", uuid);
                self.tx_event
                    .send(KexEvent::Uuid(*uuid.as_ref()))
                    .map_err(|_| Unspecified)?;
            }
            Some(other) => {
                error!(
                    "client_kex: expected KeyAgreement but got frame id={}",
                    other.id()
                );
                return Err(MoshpitError::KeyNotEstablished.into());
            }
            None => {
                error!("client_kex: server closed connection before sending KeyAgreement");
                return Err(anyhow::anyhow!(
                    "Server closed connection before KeyAgreement"
                ));
            }
        }

        // Receive stable session token (sent by server after KeyAgreement)
        trace!("client_kex: waiting for SessionToken");
        match self.reader.read_frame().await? {
            Some(Frame::SessionToken(session_uuid_wrapper)) => {
                let session_uuid = *session_uuid_wrapper.as_ref();
                let is_resume = self.requested_session_uuid == Some(session_uuid);
                trace!("client_kex: received SessionToken {session_uuid} (resume={is_resume})");
                self.tx_event
                    .send(KexEvent::SessionInfo(session_uuid, is_resume))
                    .map_err(|_| Unspecified)?;
            }
            Some(other) => {
                error!(
                    "client_kex: expected SessionToken but got frame id={}",
                    other.id()
                );
                return Err(MoshpitError::KeyNotEstablished.into());
            }
            None => {
                error!("client_kex: server closed connection before sending SessionToken");
                return Err(anyhow::anyhow!(
                    "Server closed connection before SessionToken"
                ));
            }
        }

        trace!("client_kex: waiting for MoshpitsAddr");
        match self.reader.read_frame().await? {
            Some(Frame::MoshpitsAddr(addr)) => {
                trace!("client_kex: received MoshpitsAddr {addr}");
                self.tx_event
                    .send(KexEvent::MoshpitsAddr(addr))
                    .map_err(|_| Unspecified)?;
            }
            Some(other) => {
                error!(
                    "client_kex: expected MoshpitsAddr but got frame id={}",
                    other.id()
                );
                return Err(MoshpitError::KeyNotEstablished.into());
            }
            None => {
                error!("client_kex: server closed connection before sending MoshpitsAddr");
                return Err(anyhow::anyhow!(
                    "Server closed connection before MoshpitsAddr"
                ));
            }
        }

        trace!("client_kex: complete");
        Ok(())
    }

    /// Perform the server side of a key exchange
    ///
    /// # Errors
    ///
    #[cfg_attr(nightly, allow(clippy::too_many_lines))]
    pub async fn server_kex(
        &mut self,
        socket_addr: SocketAddr,
        port_pool: Arc<Mutex<BTreeSet<u16>>>,
        private_key_path: &PathBuf,
        public_key_path: &PathBuf,
        session_registry: Option<SessionRegistry>,
    ) -> Result<(ServerKex, Arc<UdpSocket>)> {
        trace!("server_kex: waiting for Initialize/ResumeRequest from client");
        let (rnk, user_str, shell, requested_session_uuid_opt) =
            match self.reader.read_frame().await? {
                None => {
                    error!("server_kex: client closed connection before sending Initialize");
                    return Err(MoshpitError::InvalidFrame.into());
                }
                Some(frame) => {
                    let (user, pk, fpk, req_uuid) = match frame {
                        Frame::Initialize(user, pk, fpk) => {
                            trace!("server_kex: received Initialize from client");
                            (user, pk, fpk, None)
                        }
                        Frame::ResumeRequest(session_uuid_wrapper, user, pk, fpk) => {
                            trace!(
                                "server_kex: received ResumeRequest for session {}",
                                session_uuid_wrapper
                            );
                            (user, pk, fpk, Some(*session_uuid_wrapper.as_ref()))
                        }
                        other => {
                            error!(
                                "server_kex: expected Initialize/ResumeRequest but got frame id={}",
                                other.id()
                            );
                            return Err(MoshpitError::InvalidFrame.into());
                        }
                    };
                    let user_str = String::from_utf8_lossy(&user).to_string();
                    trace!(
                        "server_kex: validating system account for user '{}'",
                        user_str
                    );
                    let (home_dir, shell) = if self.validate_user(&user_str).await? {
                        trace!(
                            "server_kex: user '{}' is valid, getting home/shell",
                            user_str
                        );
                        self.get_home_dir_shell(&user_str).await?
                    } else {
                        error!("server_kex: '{}' is not a valid system account", user_str);
                        return Err(MoshpitError::KeyNotEstablished.into());
                    };
                    trace!(
                        "server_kex: home_dir='{}', checking authorized_keys",
                        home_dir
                    );
                    if !check_authorized_keys(&home_dir, &fpk)? {
                        error!(
                            "server_kex: client pubkey not in '{home_dir}/.mp/authorized_keys' \
                             (file missing, wrong permissions, or key not added)",
                        );
                        return Err(MoshpitError::KeyNotEstablished.into());
                    }
                    trace!("server_kex: authorized_keys OK, running handle_initialize");
                    let rnk = self.handle_initialize(
                        &pk,
                        &self.tx_event.clone(),
                        private_key_path,
                        public_key_path,
                    )?;
                    trace!("server_kex: PeerInitialize sent to client");
                    (rnk, user_str, shell, req_uuid)
                }
            };

        // Read the next frame: clients that requested datagram mode send
        // `ClientOptions` before `Check`; older/reliable clients send `Check`
        // directly.  Any other frame type is a protocol error.
        trace!("server_kex: waiting for ClientOptions or Check frame");
        let negotiated_diff_mode = match self.reader.read_frame().await? {
            Some(Frame::ClientOptions(mode_byte)) => {
                let mode = match mode_byte {
                    1 => {
                        trace!("server_kex: client requested DiffMode::Datagram");
                        DiffMode::Datagram
                    }
                    2 => {
                        trace!("server_kex: client requested DiffMode::StateSync");
                        DiffMode::StateSync
                    }
                    other => {
                        trace!("server_kex: ClientOptions mode_byte={other}, using Reliable");
                        DiffMode::Reliable
                    }
                };
                // Now read the Check frame
                match self.reader.read_frame().await? {
                    Some(Frame::Check(nonce, enc)) => {
                        trace!("server_kex: received Check frame after ClientOptions, verifying");
                        self.handle_check(&rnk, nonce, enc, &self.tx_event.clone())?;
                        trace!("server_kex: Check verified, KeyAgreement sent");
                    }
                    Some(other) => {
                        error!(
                            "server_kex: expected Check after ClientOptions but got frame id={}",
                            other.id()
                        );
                        return Err(MoshpitError::InvalidFrame.into());
                    }
                    None => {
                        error!("server_kex: client closed connection after ClientOptions");
                        return Err(MoshpitError::InvalidFrame.into());
                    }
                }
                mode
            }
            Some(Frame::Check(nonce, enc)) => {
                trace!("server_kex: received Check frame (no ClientOptions), verifying");
                self.handle_check(&rnk, nonce, enc, &self.tx_event.clone())?;
                trace!("server_kex: Check verified, KeyAgreement sent");
                DiffMode::Reliable
            }
            Some(other) => {
                error!(
                    "server_kex: expected ClientOptions or Check but got frame id={}",
                    other.id()
                );
                return Err(MoshpitError::InvalidFrame.into());
            }
            None => {
                error!("server_kex: client closed connection before sending Check");
                return Err(MoshpitError::InvalidFrame.into());
            }
        };

        // Determine session UUID: reuse the requested session if user matches,
        // else create new.  Any live connection on the same session will be
        // displaced by `resolve_session` when it cancels the old conn_token.
        let (session_uuid, is_resume) = match (requested_session_uuid_opt, &session_registry) {
            (Some(req_uuid), Some(registry)) => {
                let reg = registry.lock().await;
                if let Some(stored_user) = reg.get(&req_uuid) {
                    if *stored_user == user_str {
                        (req_uuid, true)
                    } else {
                        (Uuid::new_v4(), false)
                    }
                } else {
                    (Uuid::new_v4(), false)
                }
            }
            _ => (Uuid::new_v4(), false),
        };

        // Register new sessions in the lightweight registry
        if !is_resume && let Some(ref registry) = session_registry {
            let mut reg = registry.lock().await;
            drop(reg.insert(session_uuid, user_str.clone()));
        }

        // Inform the client of its stable session UUID
        self.tx
            .send(Frame::SessionToken(UuidWrapper::new(session_uuid)))?;

        let udp_arc = self.handle_udp_setup(socket_addr, port_pool).await?;

        let skex = ServerKex::builder()
            .user(user_str)
            .shell(shell)
            .session_uuid(session_uuid)
            .is_resume(is_resume)
            .diff_mode(negotiated_diff_mode)
            .build();

        Ok((skex, udp_arc))
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
                let okm = pseudo_random_key.expand(&[AEAD_KEY_INFO], &AES_256_GCM_SIV)?;
                let mut key_bytes = [0u8; AES_256_KEY_LEN];
                okm.fill(&mut key_bytes)?;
                // Derive the HMAC key and send it over UDP
                let okm_hmac =
                    pseudo_random_key.expand(&[HMAC_KEY_INFO], HKDF_SHA512.hmac_algorithm())?;
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
        socket_addr: SocketAddr,
        port_pool: Arc<Mutex<BTreeSet<u16>>>,
    ) -> Result<Arc<UdpSocket>> {
        let mut port_p = port_pool.lock().await;
        let next_port = port_p.pop_first().unwrap_or(49999);

        // Advertise the IP that the client used to reach us (the TCP connection's
        // local address).  This is the IP the client can actually route UDP packets
        // to, regardless of which bind address the listener was configured with.
        let udp_addr_for_client = SocketAddr::new(socket_addr.ip(), next_port);
        trace!("advertising moshpits UDP socket at {udp_addr_for_client}");
        self.tx.send(Frame::MoshpitsAddr(udp_addr_for_client))?;

        // Bind to all interfaces so we can receive from the client regardless of
        // NAT, multi-homing, or routing asymmetry.
        let unspecified = match socket_addr {
            SocketAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            SocketAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        };
        let bind_addr = SocketAddr::new(unspecified, next_port);
        trace!("binding moshpits UDP socket at {bind_addr}");
        let udp_listener = UdpSocket::bind(bind_addr).await?;
        let sock = SockRef::from(&udp_listener);
        drop(sock.set_recv_buffer_size(4 * 1024 * 1024));
        drop(sock.set_send_buffer_size(4 * 1024 * 1024));
        // DSCP Expedited Forwarding (EF, DSCP 46 = TOS byte 0xB8): give terminal
        // traffic priority on QoS-aware networks.  Silently ignored on platforms
        // where the socket option is unavailable.
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        if bind_addr.is_ipv4() {
            drop(sock.set_tos_v4(0xB8));
        } else {
            drop(sock.set_tclass_v6(0xB8));
        }
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

    #[cfg(target_os = "windows")]
    async fn validate_user(&self, user: &str) -> Result<bool> {
        let mut is_valid_user = Command::new("net");
        let _ = is_valid_user.args(["user", user]);
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
            return Ok((home_dir, shell));
        }
        Err(MoshpitError::KeyNotEstablished.into())
    }

    #[cfg(target_os = "windows")]
    async fn get_home_dir_shell(&self, user: &str) -> Result<(String, String)> {
        let mut cmd = Command::new("net");
        let _ = cmd.args(["user", user]);
        let output = cmd
            .output()
            .await
            .map_err(|_e| MoshpitError::KeyNotEstablished)?;
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let mut home_dir = String::new();
            for line in stdout.lines() {
                if line.to_lowercase().starts_with("home directory") {
                    home_dir = line[14..].trim().to_string();
                    break;
                }
            }
            if home_dir.is_empty() {
                home_dir = format!("C:\\Users\\{user}");
            }
            return Ok((home_dir, String::from("cmd.exe")));
        }
        Err(MoshpitError::KeyNotEstablished.into())
    }
}

fn check_authorized_keys(home_dir: &str, fpk: &[u8]) -> Result<bool> {
    let moshpit_path = PathBuf::from(home_dir).join(".mp");
    let authorized_keys_path = moshpit_path.join("authorized_keys");
    if check_permissions(&moshpit_path, &authorized_keys_path)? {
        let authorized_keys_file = OpenOptions::new()
            .read(true)
            .open(&authorized_keys_path)
            .map_err(|_e| MoshpitError::KeyNotEstablished)?;
        let buffered_reader = BufReader::new(authorized_keys_file);
        let fpk_str = String::from_utf8_lossy(fpk);

        for line in buffered_reader.lines().map_while(Result::ok) {
            if line == fpk_str {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

#[cfg_attr(windows, allow(clippy::unnecessary_wraps))]
fn check_permissions(moshpit_path: &Path, authorized_keys_path: &Path) -> Result<bool> {
    #[cfg(target_family = "unix")]
    {
        use std::os::unix::fs::MetadataExt;

        let moshpit_metadata = moshpit_path.metadata()?;
        let authorized_keys_metadata = authorized_keys_path.metadata()?;

        // Check that .mp directory has mode 0o700 (rwx------ = 0o40700 with S_IFDIR bit)
        // We mask with 0o777 to get just the permission bits
        let dir_perms = moshpit_metadata.mode() & 0o777;
        if dir_perms != 0o700 {
            return Ok(false);
        }

        // Check that authorized_keys file is owned by the user and not writable by others
        let file_perms = authorized_keys_metadata.mode() & 0o777;
        if file_perms != 0o600 {
            return Ok(false);
        }
    }
    #[cfg(target_os = "windows")]
    {
        if !windows_only_owner_has_access(moshpit_path)
            || !windows_only_owner_has_access(authorized_keys_path)
        {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Verify that every `ACCESS_ALLOWED` ACE on `path` belongs to the file owner
/// or the SYSTEM account, which is the Windows equivalent of `mode 0o700/0o600`.
#[cfg(target_os = "windows")]
fn windows_only_owner_has_access(path: &Path) -> bool {
    use std::os::windows::ffi::OsStrExt;
    use windows::{
        Win32::Foundation::{HLOCAL, LocalFree},
        Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT},
        Win32::Security::{
            ACCESS_ALLOWED_ACE, ACL, ACL_SIZE_INFORMATION, AclSizeInformation, CreateWellKnownSid,
            DACL_SECURITY_INFORMATION, EqualSid, GetAce, GetAclInformation,
            OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, WinLocalSystemSid,
        },
        core::PCWSTR,
    };

    let wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut p_dacl: *mut ACL = std::ptr::null_mut();
    let mut p_owner = PSID(std::ptr::null_mut());
    let mut p_sd = PSECURITY_DESCRIPTOR(std::ptr::null_mut());

    // Retrieve the DACL and owner SID for the path.
    let err = unsafe {
        GetNamedSecurityInfoW(
            PCWSTR(wide.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION,
            Some(&raw mut p_owner),
            None,
            Some(&raw mut p_dacl),
            None,
            &raw mut p_sd,
        )
    };
    if err.0 != 0 {
        return false;
    }

    // Build the SYSTEM SID; SYSTEM is permitted to have access on Windows.
    let mut system_sid_buf = [0u8; 68];
    let mut system_sid_size: u32 = 68;
    let system_sid = PSID(system_sid_buf.as_mut_ptr().cast());
    let ok = unsafe {
        CreateWellKnownSid(
            WinLocalSystemSid,
            None,
            Some(system_sid),
            &raw mut system_sid_size,
        )
    };
    if ok.is_err() {
        unsafe {
            let _ = LocalFree(Some(HLOCAL(p_sd.0)));
        }
        return false;
    }

    let result = if p_dacl.is_null() {
        // A null DACL grants unrestricted access to everyone — not secure.
        false
    } else {
        let mut acl_info = ACL_SIZE_INFORMATION::default();
        let ok = unsafe {
            GetAclInformation(
                p_dacl,
                std::ptr::addr_of_mut!(acl_info).cast::<core::ffi::c_void>(),
                u32::try_from(size_of::<ACL_SIZE_INFORMATION>())
                    .expect("ACL_SIZE_INFORMATION fits in u32"),
                AclSizeInformation,
            )
        };
        if ok.is_err() {
            unsafe {
                let _ = LocalFree(Some(HLOCAL(p_sd.0)));
            }
            return false;
        }

        let mut secure = true;
        for i in 0..acl_info.AceCount {
            let mut p_ace: *mut core::ffi::c_void = std::ptr::null_mut();
            if unsafe { GetAce(p_dacl, i, &raw mut p_ace) }.is_ok() {
                let ace = unsafe { &*(p_ace as *const ACCESS_ALLOWED_ACE) };
                // AceType 0 == ACCESS_ALLOWED_ACE_TYPE; deny ACEs for others are fine.
                if ace.Header.AceType == 0u8 {
                    let ace_sid = PSID(std::ptr::addr_of!(ace.SidStart) as *mut core::ffi::c_void);
                    let is_owner = unsafe { EqualSid(ace_sid, p_owner) }.is_ok();
                    let is_system = unsafe { EqualSid(ace_sid, system_sid) }.is_ok();
                    if !is_owner && !is_system {
                        secure = false;
                        break;
                    }
                }
            }
        }
        secure
    };

    unsafe {
        let _ = LocalFree(Some(HLOCAL(p_sd.0)));
    }
    result
}

fn check_known_hosts(
    host: &str,
    pk: &[u8],
    tofu_fn: Option<&TofuFn>,
    mismatch_fn: Option<&HostKeyMismatchFn>,
) -> Result<bool> {
    use aws_lc_rs::digest::{SHA256, digest};

    let home = dirs2::home_dir().ok_or_else(|| anyhow::anyhow!("No home directory found"))?;
    let known_hosts_path = home.join(".mp").join("known_hosts");
    let pk_b64 = STANDARD.encode(pk);

    if known_hosts_path.exists() {
        let content = std::fs::read_to_string(&known_hosts_path)?;
        for line in content.lines() {
            let mut parts = line.split_whitespace();
            if let (Some(h), Some(k)) = (parts.next(), parts.next())
                && h == host
            {
                if k == pk_b64 {
                    return Ok(true);
                }
                let old_fingerprint = key_fingerprint_from_b64(k);
                let new_fingerprint = STANDARD.encode(digest(&SHA256, pk));
                error!("HOST KEY VERIFICATION FAILED for {host}!");
                if let Some(prompt_replace) = mismatch_fn
                    && prompt_replace(host, &old_fingerprint, &new_fingerprint)?
                {
                    replace_known_host_key(host, &pk_b64)?;
                    return Ok(true);
                }
                return Ok(false);
            }
        }
    }

    // Not found, do TOFU
    if let Some(tofu) = tofu_fn {
        let fingerprint = STANDARD.encode(digest(&SHA256, pk));
        if tofu(host, &fingerprint)? {
            // Save it
            use std::io::Write;
            if let Some(parent) = known_hosts_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let mut file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&known_hosts_path)?;
            writeln!(file, "{host} {pk_b64}")?;
            Ok(true)
        } else {
            Ok(false)
        }
    } else {
        error!("Unknown host {host}, no TOFU callback provided");
        Ok(false)
    }
}

fn key_fingerprint_from_b64(key_b64: &str) -> String {
    use aws_lc_rs::digest::{SHA256, digest};

    let key_bytes = STANDARD
        .decode(key_b64.as_bytes())
        .unwrap_or_else(|_| key_b64.as_bytes().to_vec());
    STANDARD.encode(digest(&SHA256, &key_bytes))
}

fn replace_known_host_key(host: &str, new_pk_b64: &str) -> Result<()> {
    let home = dirs2::home_dir().ok_or_else(|| anyhow::anyhow!("No home directory found"))?;
    let known_hosts_path = home.join(".mp").join("known_hosts");
    if let Some(parent) = known_hosts_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let mut replaced = false;
    let mut out_lines: Vec<String> = Vec::new();

    if known_hosts_path.exists() {
        let content = std::fs::read_to_string(&known_hosts_path)?;
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                out_lines.push(line.to_string());
                continue;
            }
            let mut parts = line.split_whitespace();
            if let Some(existing_host) = parts.next()
                && existing_host == host
            {
                if !replaced {
                    out_lines.push(format!("{host} {new_pk_b64}"));
                    replaced = true;
                }
                continue;
            }
            out_lines.push(line.to_string());
        }
    }

    if !replaced {
        out_lines.push(format!("{host} {new_pk_b64}"));
    }

    let mut updated = out_lines.join("\n");
    if !updated.is_empty() {
        updated.push('\n');
    }
    std::fs::write(known_hosts_path, updated)?;
    Ok(())
}

#[cfg(test)]
#[cfg(unix)]
#[allow(unsafe_code)]
mod tests {
    use std::{
        io::Write,
        os::unix::fs::{DirBuilderExt, OpenOptionsExt},
        sync::{Arc, Mutex, OnceLock},
    };

    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use tempfile::TempDir;

    use super::{check_authorized_keys, check_known_hosts};
    use crate::kex::{HostKeyMismatchFn, TofuFn};

    /// Tests that mutate the `HOME` environment variable must hold this lock
    /// to prevent races with concurrently-running tests in the same process.
    fn home_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(Mutex::default)
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /// Write a `.mp/known_hosts` file inside `dir` with `host <pk_b64>` line.
    fn write_known_hosts(dir: &TempDir, host: &str, pk: &[u8]) {
        let mp = dir.path().join(".mp");
        std::fs::create_dir_all(&mp).unwrap();
        let kh = mp.join("known_hosts");
        let mut f = std::fs::File::create(kh).unwrap();
        writeln!(f, "{host} {}", STANDARD.encode(pk)).unwrap();
    }

    /// Write a `.mp/authorized_keys` file with the given bytes as content and
    /// apply the supplied `mode` bits.
    fn write_authorized_keys(dir: &TempDir, content: &[u8], mode: u32) {
        let mp = dir.path().join(".mp");
        std::fs::DirBuilder::new().mode(0o700).create(&mp).unwrap();
        let ak = mp.join("authorized_keys");
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .mode(mode)
            .open(ak)
            .unwrap();
        f.write_all(content).unwrap();
    }

    // -----------------------------------------------------------------------
    // check_known_hosts tests
    // -----------------------------------------------------------------------

    /// A key that exactly matches the pinned entry is accepted.
    #[test]
    fn check_known_hosts_match() {
        let _guard = home_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        let pk = b"server-public-key-bytes";
        let host = "192.0.2.1";
        write_known_hosts(&dir, host, pk);
        // Point HOME at the temp dir so check_known_hosts finds our file.
        // SAFETY: test-only; serialized via home_lock.
        unsafe { std::env::set_var("HOME", dir.path()) };
        let result = check_known_hosts(host, pk, None, None).unwrap();
        assert!(result, "matching key should be accepted");
    }

    /// A different key for a known host is a MITM — must be rejected.
    #[test]
    fn check_known_hosts_mismatch() {
        let _guard = home_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        let pinned_pk = b"real-server-key";
        let attacker_pk = b"mitm-attacker-key";
        let host = "192.0.2.2";
        write_known_hosts(&dir, host, pinned_pk);
        // SAFETY: test-only; serialized via home_lock.
        unsafe { std::env::set_var("HOME", dir.path()) };
        let result = check_known_hosts(host, attacker_pk, None, None).unwrap();
        assert!(!result, "mismatched host key must be rejected");
    }

    /// A mismatched key can be explicitly accepted and replaced by callback.
    #[test]
    fn check_known_hosts_mismatch_replace_accept() {
        let _guard = home_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        let old_pk = b"old-server-key";
        let new_pk = b"new-server-key";
        let host = "192.0.2.20";
        write_known_hosts(&dir, host, old_pk);
        // SAFETY: test-only; serialized via home_lock.
        unsafe { std::env::set_var("HOME", dir.path()) };

        let mismatch_fn: HostKeyMismatchFn = Arc::new(|_h, _old_fp, _new_fp| Ok(true));
        let result = check_known_hosts(host, new_pk, None, Some(&mismatch_fn)).unwrap();
        assert!(result, "accepted replacement should return true");

        let content = std::fs::read_to_string(dir.path().join(".mp").join("known_hosts")).unwrap();
        assert!(content.contains(host));
        assert!(content.contains(&STANDARD.encode(new_pk)));
        assert!(!content.contains(&STANDARD.encode(old_pk)));
    }

    /// A mismatched key rejected by callback must keep existing `known_hosts` entry.
    #[test]
    fn check_known_hosts_mismatch_replace_reject_keeps_old_key() {
        let _guard = home_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        let old_pk = b"old-server-key";
        let new_pk = b"new-server-key";
        let host = "192.0.2.21";
        write_known_hosts(&dir, host, old_pk);
        // SAFETY: test-only; serialized via home_lock.
        unsafe { std::env::set_var("HOME", dir.path()) };

        let mismatch_fn: HostKeyMismatchFn = Arc::new(|_h, _old_fp, _new_fp| Ok(false));
        let result = check_known_hosts(host, new_pk, None, Some(&mismatch_fn)).unwrap();
        assert!(!result, "rejected replacement should return false");

        let content = std::fs::read_to_string(dir.path().join(".mp").join("known_hosts")).unwrap();
        assert!(content.contains(host));
        assert!(content.contains(&STANDARD.encode(old_pk)));
        assert!(!content.contains(&STANDARD.encode(new_pk)));
    }

    /// Invalid base64 `known_hosts` values still produce a deterministic fingerprint.
    #[test]
    fn key_fingerprint_from_b64_handles_invalid_input() {
        let fp = super::key_fingerprint_from_b64("not-base64-@@@");
        assert!(!fp.is_empty());
    }

    /// Unknown host + TOFU callback that returns `true` → accepted and saved.
    #[test]
    fn check_known_hosts_tofu_accept() {
        let _guard = home_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        let pk = b"brand-new-server-key";
        let host = "192.0.2.3";
        // No existing known_hosts file; just ensure the .mp dir exists.
        std::fs::create_dir_all(dir.path().join(".mp")).unwrap();
        // SAFETY: test-only; serialized via home_lock.
        unsafe { std::env::set_var("HOME", dir.path()) };
        let tofu_fn: TofuFn = Arc::new(|_host, _fp| Ok(true));
        let result = check_known_hosts(host, pk, Some(&tofu_fn), None).unwrap();
        assert!(result, "TOFU accept should return true");
        // Key should now be persisted.
        let kh_content =
            std::fs::read_to_string(dir.path().join(".mp").join("known_hosts")).unwrap();
        assert!(
            kh_content.contains(host),
            "host should be saved to known_hosts"
        );
    }

    /// Unknown host + TOFU callback that returns `false` → rejected.
    #[test]
    fn check_known_hosts_tofu_reject() {
        let _guard = home_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        let pk = b"unknown-server-key";
        let host = "192.0.2.4";
        std::fs::create_dir_all(dir.path().join(".mp")).unwrap();
        // SAFETY: test-only; serialized via home_lock.
        unsafe { std::env::set_var("HOME", dir.path()) };
        let tofu_fn: TofuFn = Arc::new(|_host, _fp| Ok(false));
        let result = check_known_hosts(host, pk, Some(&tofu_fn), None).unwrap();
        assert!(!result, "TOFU reject should return false");
    }

    /// Unknown host with no TOFU callback → rejected (fail closed).
    #[test]
    fn check_known_hosts_no_tofu() {
        let _guard = home_lock().lock().unwrap();
        let dir = TempDir::new().unwrap();
        let pk = b"some-server-key";
        let host = "192.0.2.5";
        std::fs::create_dir_all(dir.path().join(".mp")).unwrap();
        // SAFETY: test-only; serialized via home_lock.
        unsafe { std::env::set_var("HOME", dir.path()) };
        let result = check_known_hosts(host, pk, None, None).unwrap();
        assert!(!result, "no TOFU callback must fail closed");
    }

    // -----------------------------------------------------------------------
    // check_authorized_keys tests
    // -----------------------------------------------------------------------

    /// Key present in `authorized_keys` with correct permissions → accepted.
    #[test]
    fn check_authorized_keys_match() {
        let dir = TempDir::new().unwrap();
        let key_bytes = b"my-full-public-key-bytes";
        write_authorized_keys(&dir, key_bytes, 0o600);
        let home_str = dir.path().to_str().unwrap();
        let result = check_authorized_keys(home_str, key_bytes).unwrap();
        assert!(result, "matching key in authorized_keys should be accepted");
    }

    /// Key NOT present in `authorized_keys` → rejected.
    #[test]
    fn check_authorized_keys_mismatch() {
        let dir = TempDir::new().unwrap();
        let stored_key = b"stored-key";
        let presented_key = b"different-key";
        write_authorized_keys(&dir, stored_key, 0o600);
        let home_str = dir.path().to_str().unwrap();
        let result = check_authorized_keys(home_str, presented_key).unwrap();
        assert!(!result, "key not in authorized_keys should be rejected");
    }

    /// `authorized_keys` with 0o644 permissions (group/world-readable) → rejected.
    #[test]
    fn check_authorized_keys_bad_perms() {
        let dir = TempDir::new().unwrap();
        let key_bytes = b"my-full-public-key-bytes";
        write_authorized_keys(&dir, key_bytes, 0o644);
        let home_str = dir.path().to_str().unwrap();
        let result = check_authorized_keys(home_str, key_bytes).unwrap();
        assert!(
            !result,
            "world-readable authorized_keys must be rejected (permission check)"
        );
    }

    // -----------------------------------------------------------------------
    // Helpers for KexReader / client_kex / handle_check / handle_udp_setup tests
    // -----------------------------------------------------------------------

    use std::collections::BTreeSet;
    use std::sync::Arc as StdArc;

    use aws_lc_rs::{
        aead::{AES_256_GCM_SIV, Aad, RandomizedNonceKey},
        agreement::{PrivateKey, X25519},
    };
    use tokio::sync::Mutex as TokioMutex;
    use tokio::{
        net::{TcpListener, TcpStream, UdpSocket},
        sync::mpsc::unbounded_channel,
    };

    use crate::{ConnectionReader, ConnectionWriter, Frame, KexEvent, UuidWrapper};

    /// Create two connected TCP stream pairs.
    /// Returns `(client_reader, client_writer, server_reader, server_writer)`.
    async fn make_bidirectional_loopback() -> (
        ConnectionReader,
        ConnectionWriter,
        ConnectionReader,
        ConnectionWriter,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (server_stream, client_stream) = tokio::join!(
            async { listener.accept().await.map(|(s, _)| s).unwrap() },
            TcpStream::connect(addr),
        );
        let client_stream = client_stream.unwrap();
        let (server_r, server_w) = server_stream.into_split();
        let (client_r, client_w) = client_stream.into_split();
        (
            ConnectionReader::builder().reader(client_r).build(),
            ConnectionWriter::builder().writer(client_w).build(),
            ConnectionReader::builder().reader(server_r).build(),
            ConnectionWriter::builder().writer(server_w).build(),
        )
    }

    /// Build a `KexReader` around `reader` and return channel receivers
    /// so tests can observe outbound frames and events.
    fn make_test_kex_reader(
        reader: ConnectionReader,
    ) -> (
        super::super::KexReader,
        tokio::sync::mpsc::UnboundedReceiver<Frame>,
        tokio::sync::mpsc::UnboundedReceiver<KexEvent>,
    ) {
        let (tx, rx_frames) = unbounded_channel::<Frame>();
        let (tx_event, rx_events) = unbounded_channel::<KexEvent>();
        let kex_reader = super::super::KexReader::builder()
            .reader(reader)
            .tx(tx)
            .tx_event(tx_event)
            .build();
        (kex_reader, rx_frames, rx_events)
    }

    // -----------------------------------------------------------------------
    // handle_udp_setup tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn handle_udp_setup_pops_first_port_from_pool() {
        let (client_reader, _client_writer, _server_reader, _server_writer) =
            make_bidirectional_loopback().await;
        let (mut kex_reader, mut rx_frames, _rx_events) = make_test_kex_reader(client_reader);

        // Ask the OS for a free port so the test doesn't conflict with a running
        // moshpit server that may already hold a port in the 50000-59999 range.
        let free_port = {
            let probe = UdpSocket::bind("0.0.0.0:0").await.unwrap();
            probe.local_addr().unwrap().port()
            // probe drops here, releasing the port before handle_udp_setup re-binds it
        };

        let mut pool = BTreeSet::new();
        let _ = pool.insert(free_port);
        let port_pool = StdArc::new(TokioMutex::new(pool));
        let socket_addr: std::net::SocketAddr = "127.0.0.1:9000".parse().unwrap();

        let udp_arc = kex_reader
            .handle_udp_setup(socket_addr, port_pool)
            .await
            .unwrap();

        let frame = rx_frames.recv().await.unwrap();
        let advertised_port = match frame {
            Frame::MoshpitsAddr(a) => a.port(),
            other => panic!("expected MoshpitsAddr, got {other:?}"),
        };
        assert_eq!(advertised_port, free_port);
        // Socket should be bound (local_addr succeeds)
        assert!(udp_arc.local_addr().is_ok());
    }

    #[tokio::test]
    async fn handle_udp_setup_empty_pool_falls_back_to_port_49999() {
        let (client_reader, _client_writer, _server_reader, _server_writer) =
            make_bidirectional_loopback().await;
        let (mut kex_reader, mut rx_frames, _rx_events) = make_test_kex_reader(client_reader);

        let pool: BTreeSet<u16> = BTreeSet::new();
        let port_pool = StdArc::new(TokioMutex::new(pool));
        let socket_addr: std::net::SocketAddr = "127.0.0.1:9000".parse().unwrap();

        let _udp_arc = kex_reader
            .handle_udp_setup(socket_addr, port_pool)
            .await
            .unwrap();

        let frame = rx_frames.recv().await.unwrap();
        let advertised_port = match frame {
            Frame::MoshpitsAddr(a) => a.port(),
            other => panic!("expected MoshpitsAddr, got {other:?}"),
        };
        assert_eq!(advertised_port, 49999);
    }

    // -----------------------------------------------------------------------
    // handle_check tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn handle_check_valid_yoda_payload_succeeds() {
        let (client_reader, _cw, _sr, _sw) = make_bidirectional_loopback().await;
        let (mut kex_reader, mut rx_frames, _rx_events) = make_test_kex_reader(client_reader);

        let key_bytes = [1u8; 32];
        let rnk = RandomizedNonceKey::new(&AES_256_GCM_SIV, &key_bytes).unwrap();

        // Encrypt "Yoda" the same way client_kex does
        let mut plaintext = b"Yoda".to_vec();
        let nonce = rnk
            .seal_in_place_append_tag(Aad::empty(), &mut plaintext)
            .unwrap();

        let (tx_event_clone, _rx_event_clone) = unbounded_channel::<KexEvent>();
        kex_reader
            .handle_check(&rnk, *nonce.as_ref(), plaintext, &tx_event_clone)
            .unwrap();

        // Should have sent KeyAgreement frame via kex_reader's own tx
        let frame = rx_frames.recv().await.unwrap();
        assert!(
            matches!(frame, Frame::KeyAgreement(_)),
            "expected KeyAgreement, got {frame:?}"
        );
    }

    #[tokio::test]
    async fn handle_check_invalid_payload_returns_decryption_failed() {
        use crate::MoshpitError;

        let (client_reader, _cw, _sr, _sw) = make_bidirectional_loopback().await;
        let (mut kex_reader, _rx_frames, _rx_events) = make_test_kex_reader(client_reader);

        let key_bytes = [1u8; 32];
        let rnk = RandomizedNonceKey::new(&AES_256_GCM_SIV, &key_bytes).unwrap();

        let nonce_bytes = [0u8; 12];
        let garbage = vec![0u8; 32]; // not a valid ciphertext

        let (tx_event_clone, _) = unbounded_channel::<KexEvent>();
        let result = kex_reader.handle_check(&rnk, nonce_bytes, garbage, &tx_event_clone);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .downcast_ref::<MoshpitError>()
                .is_some_and(|e| *e == MoshpitError::DecryptionFailed),
        );
    }

    // -----------------------------------------------------------------------
    // client_kex tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn client_kex_server_closes_immediately_returns_error() {
        let (client_reader, _client_writer, _server_reader, server_writer) =
            make_bidirectional_loopback().await;
        let (mut kex_reader, _rx_frames, _rx_events) = make_test_kex_reader(client_reader);

        // Drop server writer immediately — client reads EOF
        drop(server_writer);

        let epk = PrivateKey::generate(&X25519).unwrap();
        let result = kex_reader.client_kex(&epk).await;
        assert!(
            result.is_err(),
            "expected error when server closes immediately"
        );
    }

    #[tokio::test]
    async fn client_kex_wrong_initial_frame_returns_key_not_established() {
        use crate::MoshpitError;

        let (client_reader, _client_writer, _server_reader, mut server_writer) =
            make_bidirectional_loopback().await;
        let (mut kex_reader, _rx_frames, _rx_events) = make_test_kex_reader(client_reader);

        // Server sends wrong frame type
        server_writer.write_frame(&Frame::KexFailure).await.unwrap();
        drop(server_writer);

        let epk = PrivateKey::generate(&X25519).unwrap();
        let result = kex_reader.client_kex(&epk).await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .downcast_ref::<MoshpitError>()
                .is_some_and(|e| *e == MoshpitError::KeyNotEstablished),
        );
    }

    #[tokio::test]
    async fn client_kex_server_closes_after_peer_initialize_returns_error() {
        let (client_reader, _client_writer, _server_reader, mut server_writer) =
            make_bidirectional_loopback().await;
        let (mut kex_reader, _rx_frames, _rx_events) = make_test_kex_reader(client_reader);

        // Server sends PeerInitialize with a valid X25519 public key, then closes
        let server_epk = PrivateKey::generate(&X25519).unwrap();
        let server_pub = server_epk.compute_public_key().unwrap();
        let salt = vec![0u8; 32];
        server_writer
            .write_frame(&Frame::PeerInitialize(server_pub.as_ref().to_vec(), salt))
            .await
            .unwrap();
        drop(server_writer);

        let epk = PrivateKey::generate(&X25519).unwrap();
        let result = kex_reader.client_kex(&epk).await;
        assert!(
            result.is_err(),
            "expected error after server closes post-PeerInitialize"
        );
    }

    #[tokio::test]
    async fn client_kex_wrong_frame_after_peer_initialize_returns_key_not_established() {
        use crate::MoshpitError;

        let (client_reader, _client_writer, _server_reader, mut server_writer) =
            make_bidirectional_loopback().await;
        let (mut kex_reader, _rx_frames, _rx_events) = make_test_kex_reader(client_reader);

        let server_epk = PrivateKey::generate(&X25519).unwrap();
        let server_pub = server_epk.compute_public_key().unwrap();
        let salt = vec![0u8; 32];
        server_writer
            .write_frame(&Frame::PeerInitialize(server_pub.as_ref().to_vec(), salt))
            .await
            .unwrap();
        // Send wrong frame instead of KeyAgreement
        server_writer.write_frame(&Frame::KexFailure).await.unwrap();
        drop(server_writer);

        let epk = PrivateKey::generate(&X25519).unwrap();
        let result = kex_reader.client_kex(&epk).await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .downcast_ref::<MoshpitError>()
                .is_some_and(|e| *e == MoshpitError::KeyNotEstablished),
        );
    }

    #[tokio::test]
    async fn client_kex_happy_path_sends_all_events() {
        use uuid::Uuid;

        let (client_reader, _client_writer, _server_reader, mut server_writer) =
            make_bidirectional_loopback().await;
        // We need a separate tx/rx so we can observe the frames KexReader tries to send
        let (tx_out, mut rx_out) = unbounded_channel::<Frame>();
        let (tx_event_out, mut rx_event_out) = unbounded_channel::<KexEvent>();
        let kex_reader = super::super::KexReader::builder()
            .reader(client_reader)
            .tx(tx_out)
            .tx_event(tx_event_out)
            .build();

        let server_epk = PrivateKey::generate(&X25519).unwrap();
        let server_pub = server_epk.compute_public_key().unwrap();
        let mut salt_bytes = [0u8; 32];
        aws_lc_rs::rand::fill(&mut salt_bytes).unwrap();

        let conn_uuid = Uuid::new_v4();
        let session_uuid = Uuid::new_v4();
        let moshpits_addr: std::net::SocketAddr = "127.0.0.1:50002".parse().unwrap();

        // Spawn mock server task
        let server_handle = tokio::spawn(async move {
            // Send PeerInitialize
            server_writer
                .write_frame(&Frame::PeerInitialize(
                    server_pub.as_ref().to_vec(),
                    salt_bytes.to_vec(),
                ))
                .await
                .unwrap();
            // Drain the Check frame that client_kex sends
            drop(rx_out.recv().await);
            // Send KeyAgreement, SessionToken, MoshpitsAddr
            server_writer
                .write_frame(&Frame::KeyAgreement(UuidWrapper::new(conn_uuid)))
                .await
                .unwrap();
            server_writer
                .write_frame(&Frame::SessionToken(UuidWrapper::new(session_uuid)))
                .await
                .unwrap();
            server_writer
                .write_frame(&Frame::MoshpitsAddr(moshpits_addr))
                .await
                .unwrap();
        });

        let client_epk = PrivateKey::generate(&X25519).unwrap();
        let mut kex_reader = kex_reader;
        kex_reader.client_kex(&client_epk).await.unwrap();
        server_handle.await.unwrap();

        // Collect all events
        let mut events = Vec::new();
        while let Ok(e) = rx_event_out.try_recv() {
            events.push(e);
        }

        // Should have: KeyMaterial, HMACKeyMaterial, Uuid, SessionInfo, MoshpitsAddr
        assert_eq!(events.len(), 5, "expected 5 kex events, got: {events:?}");
        assert!(matches!(events[0], KexEvent::KeyMaterial(_)));
        assert!(matches!(events[1], KexEvent::HMACKeyMaterial(_)));
        assert!(matches!(events[2], KexEvent::Uuid(_)));
        assert!(matches!(events[3], KexEvent::SessionInfo(_, false)));
        assert!(matches!(events[4], KexEvent::MoshpitsAddr(_)));
    }
}
