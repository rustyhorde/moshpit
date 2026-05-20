// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

use std::{
    fmt::{self, Display, Formatter},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
};

use anyhow::Result;
use aws_lc_rs::{
    aead::{
        AES_128_GCM_SIV, AES_256_GCM, AES_256_GCM_SIV, CHACHA20_POLY1305, LessSafeKey, UnboundKey,
    },
    hmac::{HMAC_SHA256, HMAC_SHA512, Key},
};
use bon::Builder;
use getset::{CopyGetters, Getters};
use serde::{Deserialize, Serialize};
use socket2::SockRef;
use tokio::{
    net::{
        UdpSocket,
        tcp::{OwnedReadHalf, OwnedWriteHalf},
    },
    spawn,
    sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel},
    task::JoinHandle,
};
use tracing::{debug, error, info, trace};
use uuid::Uuid;

use crate::{
    AgentClient, ConnectionReader, ConnectionWriter, Frame, KexConfig, KexReader, KexSender,
    MoshpitError, UuidWrapper, kex::negotiate::NegotiatedAlgorithms, load_identity_key,
    load_public_key, udp::DiffMode,
};

fn fmt_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

/// The callback type for TOFU (Trust-On-First-Use) interactive host key validation.
pub type TofuFn = Arc<dyn Fn(&str, &str) -> Result<bool> + Send + Sync>;

/// Callback invoked when a known host presents a different key than pinned.
///
/// Args are `(host, old_fingerprint, new_fingerprint)` where fingerprints are
/// base64-encoded SHA256 digests (displayed as `SHA256:<fingerprint>`).
pub type HostKeyMismatchFn = Arc<dyn Fn(&str, &str, &str) -> Result<bool> + Send + Sync>;

#[derive(Clone)]
struct HostKeyCallbacks {
    tofu_fn: Option<TofuFn>,
    host_key_mismatch_fn: Option<HostKeyMismatchFn>,
}

pub(crate) mod negotiate;

/// Returns `true` if `name` matches any pattern in `patterns`.
///
/// Patterns support exact names (`LANG`) and suffix wildcards (`LC_*`).
/// A trailing `*` matches any suffix; all other characters are matched literally.
#[must_use]
pub fn env_var_matches(name: &str, patterns: &[String]) -> bool {
    patterns.iter().any(|pat| {
        if let Some(prefix) = pat.strip_suffix('*') {
            name.starts_with(prefix)
        } else {
            name == pat.as_str()
        }
    })
}
pub(crate) mod reader;
pub(crate) mod sender;

/// The key exchange events
#[derive(Clone, Debug)]
pub enum KexEvent {
    /// Negotiated algorithms — sent before key material so the runtime can
    /// construct the correct crypto primitives.
    NegotiatedAlgorithms(NegotiatedAlgorithms),
    /// AEAD key material for encrypting/decrypting UDP packets (variable size)
    KeyMaterial(Vec<u8>),
    /// HMAC key for signing UDP packets (variable size: 64 B for SHA-512, 32 B for SHA-256)
    HMACKeyMaterial(Vec<u8>),
    /// moshpit client UUID
    Uuid(Uuid),
    /// moshpits socket address
    MoshpitsAddr(SocketAddr),
    /// Session information: (stable session UUID, `is_resume` flag)
    SessionInfo(Uuid, bool),
    /// Key exchange failure
    Failure,
    /// No algorithm in common between client and server — client should exit,
    /// not retry.
    NoCommonAlgorithm,
}

/// The moshpit key exchange state
#[derive(Clone, Copy, Debug, Default)]
pub enum KexState {
    /// Awaiting the negotiated-algorithm event (arrives before key material)
    #[default]
    AwaitingNegotiatedAlgorithms,
    /// Awaiting key material for encrypting/decrypting UDP packets
    AwaitingKeyMaterial,
    /// Awaiting HMAC key for signing UDP packets
    AwaitingHMACKeyMaterial,
    /// Awaiting moshpit client UUID
    AwaitingUuid,
    /// Awaiting session token from moshpits (client mode only, between Uuid and `MoshpitsAddr`)
    AwaitingSessionToken,
    /// Awaiting moshpits socket address
    AwaitingMoshpitsAddr,
    /// Key exchange is complete
    Complete,
}

/// The moshpit key exchange state machine
#[derive(Builder, CopyGetters, Debug)]
pub struct KexStateMachine {
    /// The current key exchange state
    #[getset(get_copy = "pub")]
    #[builder(default = KexState::default())]
    state: KexState,
    rx_event: UnboundedReceiver<KexEvent>,
}

/// The moshpit key exchange result
#[derive(Clone, Debug, CopyGetters, Getters)]
pub struct Kex {
    /// AEAD key material for encrypting/decrypting UDP packets (variable size)
    #[getset(get = "pub")]
    key: Vec<u8>,
    /// HMAC key for signing UDP packets (variable size)
    #[getset(get = "pub")]
    hmac_key: Vec<u8>,
    /// moshpit client UUID (per-connection, changes on every reconnect)
    #[getset(get_copy = "pub")]
    uuid: Uuid,
    /// An optional moshpits socket address used by moshpit.
    #[getset(get_copy = "pub")]
    moshpits_addr: Option<SocketAddr>,
    /// Stable session UUID, set for client mode after `SessionToken` received.
    #[getset(get_copy = "pub")]
    session_uuid: Option<Uuid>,
    /// Whether this connection is resuming an existing session.
    #[getset(get_copy = "pub")]
    is_resume: bool,
    /// Algorithms negotiated during key exchange.
    #[getset(get = "pub")]
    negotiated_algorithms: NegotiatedAlgorithms,
}

impl Kex {
    /// Get the wrapped UUID
    #[must_use]
    pub fn uuid_wrapper(&self) -> UuidWrapper {
        UuidWrapper::new(self.uuid)
    }

    /// Build a `LessSafeKey` for UDP encryption using the negotiated AEAD algorithm.
    ///
    /// Supports all negotiated algorithms including ChaCha20-Poly1305.  Callers are
    /// responsible for generating a unique random nonce per packet (use
    /// `aws_lc_rs::rand::fill` on a `[u8; NONCE_LEN]` buffer).
    ///
    /// # Errors
    /// Returns an error if the negotiated AEAD algorithm is unknown or the key bytes are invalid.
    pub fn build_aead_key(&self) -> Result<LessSafeKey> {
        use negotiate::{
            AEAD_AES128_GCM_SIV, AEAD_AES256_GCM, AEAD_AES256_GCM_SIV, AEAD_CHACHA20_POLY1305,
        };
        let alg: &'static aws_lc_rs::aead::Algorithm =
            match self.negotiated_algorithms.aead.as_str() {
                AEAD_AES256_GCM_SIV => &AES_256_GCM_SIV,
                AEAD_AES256_GCM => &AES_256_GCM,
                AEAD_CHACHA20_POLY1305 => &CHACHA20_POLY1305,
                AEAD_AES128_GCM_SIV => &AES_128_GCM_SIV,
                _ => return Err(MoshpitError::NoCommonAlgorithm.into()),
            };
        debug!(
            aead = %self.negotiated_algorithms.aead,
            key_len = self.key.len(),
            key_hex = %fmt_hex(&self.key),
            "build_aead_key: constructing LessSafeKey"
        );
        Ok(LessSafeKey::new(UnboundKey::new(alg, &self.key)?))
    }

    /// Build an HMAC `Key` for UDP packet authentication using the negotiated MAC algorithm.
    #[must_use]
    pub fn build_hmac(&self) -> Key {
        use negotiate::MAC_HMAC_SHA256;
        if self.negotiated_algorithms.mac.as_str() == MAC_HMAC_SHA256 {
            Key::new(HMAC_SHA256, &self.hmac_key)
        } else {
            Key::new(HMAC_SHA512, &self.hmac_key)
        }
    }

    /// Returns the byte length of the MAC tag produced by the negotiated MAC algorithm.
    ///
    /// HMAC-SHA256 produces 32-byte tags; all others produce 64-byte tags.
    #[must_use]
    pub fn mac_tag_len(&self) -> usize {
        use negotiate::MAC_HMAC_SHA256;
        if self.negotiated_algorithms.mac.as_str() == MAC_HMAC_SHA256 {
            32
        } else {
            64
        }
    }
}

impl Default for Kex {
    fn default() -> Self {
        Self {
            key: Vec::new(),
            hmac_key: Vec::new(),
            uuid: Uuid::nil(),
            moshpits_addr: None,
            session_uuid: None,
            is_resume: false,
            negotiated_algorithms: NegotiatedAlgorithms::default(),
        }
    }
}

/// Extended key exchange for the moshpits side of the exchange
#[derive(Builder, Clone, Debug, CopyGetters, Getters)]
pub struct ServerKex {
    /// The user associated with the key exchange
    #[getset(get = "pub")]
    user: String,
    /// The shell associated with the key exchange
    #[getset(get = "pub")]
    shell: String,
    /// The stable session UUID assigned to this connection
    #[getset(get_copy = "pub")]
    session_uuid: Uuid,
    /// Whether this connection is resuming an existing session
    #[getset(get_copy = "pub")]
    #[builder(default)]
    is_resume: bool,
    /// UDP diff transport mode negotiated during key exchange.
    /// Set from the client's `ClientOptions` frame; defaults to `Reliable`.
    #[getset(get_copy = "pub")]
    #[builder(default)]
    diff_mode: DiffMode,
    /// Algorithms negotiated during key exchange.
    #[getset(get = "pub")]
    #[builder(default)]
    negotiated_algorithms: NegotiatedAlgorithms,
    /// Environment variable pairs received from the client via `ClientEnv`.
    /// The server applies only those matching its `accept_env` config patterns.
    #[getset(get = "pub")]
    #[builder(default)]
    client_env: Vec<(String, String)>,
    /// Additional PATH directories received from the client via `ClientEnv`.
    /// Prepended to the server's `server_path`; ignored when `path_locked = true`.
    #[getset(get = "pub")]
    #[builder(default)]
    client_extra_path: Vec<String>,
}

impl KexStateMachine {
    /// Handle key exchange events
    ///
    /// # Errors
    /// Returns an error if the key exchange state is invalid
    ///
    pub async fn handle_events(&mut self, client_mode: bool) -> Result<Kex> {
        let mut kex = Kex::default();

        while let Some(event) = self.rx_event.recv().await {
            match (self.state, event) {
                (KexState::AwaitingNegotiatedAlgorithms, KexEvent::NegotiatedAlgorithms(algos)) => {
                    kex.negotiated_algorithms = algos;
                    self.state = KexState::AwaitingKeyMaterial;
                }
                (KexState::AwaitingKeyMaterial, KexEvent::KeyMaterial(key_material)) => {
                    kex.key = key_material;
                    self.state = KexState::AwaitingHMACKeyMaterial;
                }
                (
                    KexState::AwaitingHMACKeyMaterial,
                    KexEvent::HMACKeyMaterial(hmac_key_material),
                ) => {
                    kex.hmac_key = hmac_key_material;
                    self.state = KexState::AwaitingUuid;
                }
                (KexState::AwaitingUuid, KexEvent::Uuid(uuid)) => {
                    kex.uuid = uuid;
                    if client_mode {
                        self.state = KexState::AwaitingSessionToken;
                    } else {
                        self.state = KexState::Complete;
                        break;
                    }
                }
                (
                    KexState::AwaitingSessionToken,
                    KexEvent::SessionInfo(session_uuid, is_resume),
                ) => {
                    kex.session_uuid = Some(session_uuid);
                    kex.is_resume = is_resume;
                    self.state = KexState::AwaitingMoshpitsAddr;
                }
                (KexState::AwaitingMoshpitsAddr, KexEvent::MoshpitsAddr(addr)) => {
                    self.state = KexState::Complete;
                    kex.moshpits_addr = Some(addr);
                    break;
                }
                (_, KexEvent::NoCommonAlgorithm) => {
                    return Err(MoshpitError::NoCommonAlgorithm.into());
                }
                _ => {
                    return Err(MoshpitError::InvalidKexState.into());
                }
            }
        }

        match self.state {
            KexState::Complete => Ok(kex),
            _ => Err(MoshpitError::InvalidKexState.into()),
        }
    }
}

/// The key exchange mode
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub enum KexMode {
    /// Client mode
    #[default]
    Client,
    /// Server mode
    Server(SocketAddr),
}

impl Display for KexMode {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            KexMode::Client => write!(f, "Client"),
            KexMode::Server(addr) => write!(f, "Server({addr})"),
        }
    }
}

/// Run the client side of the key exchange
///
/// # Errors
///
pub async fn run_key_exchange<T: KexConfig>(
    config: T,
    sock_read: OwnedReadHalf,
    sock_write: OwnedWriteHalf,
    passphrase_fn: impl Fn() -> Result<Option<String>>,
    tofu_fn: Option<TofuFn>,
    host_key_mismatch_fn: Option<HostKeyMismatchFn>,
) -> Result<(Kex, Arc<UdpSocket>, Option<ServerKex>)> {
    // Setup the TCP connection to the server for key exchange
    let mode = config.mode();
    let reader = ConnectionReader::builder().reader(sock_read).build();
    let writer = ConnectionWriter::builder().writer(sock_write).build();
    let (tx, rx) = unbounded_channel();
    let (tx_event, rx_event) = unbounded_channel::<KexEvent>();
    let mut kex_sm = KexStateMachine::builder().rx_event(rx_event).build();
    let kex_handle = spawn(async move { kex_sm.handle_events(mode == KexMode::Client).await });

    // Setup the TCP frame sender
    let _write_handle = spawn(async move {
        let mut sender = KexSender::builder().writer(writer).rx(rx).build();
        if let Err(e) = sender.handle_send_frames().await {
            error!("{e}");
        }
    });

    Ok(match mode {
        KexMode::Client => {
            run_client_kex(
                config,
                tx,
                tx_event,
                reader,
                kex_handle,
                passphrase_fn,
                HostKeyCallbacks {
                    tofu_fn,
                    host_key_mismatch_fn,
                },
            )
            .await?
        }
        KexMode::Server(socket_addr) => {
            let tx_c = tx.clone();
            match run_server_kex(config, socket_addr, tx, tx_event, reader, kex_handle).await {
                Ok(result) => result,
                Err(e) => {
                    let _blah = tx_c.send(Frame::KexFailure);
                    Err(e)?
                }
            }
        }
    })
}

#[cfg_attr(nightly, allow(clippy::too_many_lines))]
async fn run_client_kex<T: KexConfig>(
    config: T,
    tx: UnboundedSender<Frame>,
    tx_event: UnboundedSender<KexEvent>,
    reader: ConnectionReader,
    kex_handle: JoinHandle<Result<Kex>>,
    passphrase_fn: impl Fn() -> Result<Option<String>>,
    callbacks: HostKeyCallbacks,
) -> Result<(Kex, Arc<UdpSocket>, Option<ServerKex>)> {
    let agent_socket = config.agent_socket();

    // Resolve identity: either from a running agent or directly from key files.
    let (full_public_key_bytes, agent_fingerprint) = if let Some(ref socket) = agent_socket {
        info!("Agent socket configured — loading identity from moshpit-agent");
        let client = AgentClient::new(socket.clone());
        let ids = client.list_identities().await.map_err(|e| {
            error!("Failed to list agent identities: {e}");
            MoshpitError::KeyFileMissing
        })?;
        if ids.is_empty() {
            error!("Agent has no loaded identities — run `mpa add-key <path>` first");
            return Err(MoshpitError::KeyFileMissing.into());
        }
        let id = &ids[0];
        info!(
            "Using agent identity: {} ({})",
            id.fingerprint, id.algorithm
        );
        let pk_bytes = client.get_public_key(&id.fingerprint).await.map_err(|e| {
            error!("Failed to get public key from agent: {e}");
            MoshpitError::KeyFileMissing
        })?;
        (pk_bytes, Some(id.fingerprint.clone()))
    } else {
        let (private_key_path, public_key_path) = config.key_pair_paths()?;
        info!("Loading private key from {}", private_key_path.display());
        info!("Loading public key from {}", public_key_path.display());

        let (full_pub_bytes, public_key_bytes) = load_public_key(&public_key_path)
            .inspect_err(|e| {
                error!(
                    "Failed to load public key from {}: {e}",
                    public_key_path.display()
                );
            })
            .map_err(|_| MoshpitError::KeyFileMissing)?;
        if !private_key_path.try_exists().unwrap_or(false) {
            error!(
                "Failed to load private key from {}: file does not exist",
                private_key_path.display()
            );
            return Err(MoshpitError::KeyFileMissing.into());
        }

        let identity_key = if let Ok(identity_key) = load_identity_key(&private_key_path, None) {
            info!("Private key is unencrypted — no passphrase needed");
            identity_key
        } else {
            info!("Private key may be encrypted — invoking passphrase prompt");
            let passphrase = passphrase_fn().map_err(|e| {
                error!("Passphrase prompt failed: {e}");
                e
            })?;
            let Some(passphrase) = passphrase else {
                error!("Passphrase prompt returned no input — cannot decrypt key");
                return Err(MoshpitError::KeyCorrupt.into());
            };
            load_identity_key(&private_key_path, Some(&passphrase))
                .inspect_err(|e| error!("Private key validation failed: {e}"))
                .map_err(|_| MoshpitError::KeyCorrupt)?
        };
        if identity_key.public_key().as_slice() != public_key_bytes.as_slice() {
            error!(
                "Computed public key does not match stored public key at {}",
                public_key_path.display()
            );
            return Err(MoshpitError::KeyPairMismatch.into());
        }
        info!(
            "Private identity key ({}) verified successfully",
            identity_key.key_algorithm()
        );

        #[cfg(feature = "unstable")]
        {
            // Store algorithm and private key for later use below.
            (full_pub_bytes, None)
        }
        #[cfg(not(feature = "unstable"))]
        (full_pub_bytes, None)
    };

    // For file-based path, we need the identity_key for unstable signing.
    // Re-load it here (only in the non-agent branch that reaches this point).
    #[cfg(feature = "unstable")]
    let (client_identity_key_algorithm, client_identity_private_key) = if agent_socket.is_some() {
        // Agent holds the private key; algorithm is looked up from fingerprint.
        // The `agent_fingerprint` carries the algorithm at signing time.
        (String::new(), vec![])
    } else {
        let (private_key_path, _) = config.key_pair_paths()?;
        let identity_key = load_identity_key(&private_key_path, None).or_else(|_| {
            let passphrase = passphrase_fn()?;
            let p = passphrase.ok_or(MoshpitError::KeyCorrupt)?;
            load_identity_key(&private_key_path, Some(&p))
                .map_err(|_| anyhow::anyhow!(MoshpitError::KeyCorrupt))
        })?;
        (
            identity_key.key_algorithm().clone(),
            identity_key.private_key().clone(),
        )
    };

    // Setup the TCP frame reader
    let tx_c = tx.clone();
    let tx_event_c = tx_event.clone();
    let requested = config.resume_session_uuid();
    let server_id = config.server_id();
    let HostKeyCallbacks {
        tofu_fn,
        host_key_mismatch_fn,
    } = callbacks;

    let diff_mode = config.diff_mode();
    let client_algos = config.preferred_algorithms();
    let user = config.user().unwrap_or_default();
    let send_env_patterns = config.send_env();
    let send_env: Vec<(String, String)> = std::env::vars()
        .filter(|(k, _)| env_var_matches(k, &send_env_patterns))
        .collect();
    let send_path = config.send_path();
    let _read_handle = spawn(async move {
        #[cfg(feature = "unstable")]
        let mut frame_reader = KexReader::builder()
            .reader(reader)
            .tx(tx_c)
            .tx_event(tx_event_c)
            .maybe_requested_session_uuid(requested)
            .maybe_server_destination(server_id)
            .maybe_tofu_fn(tofu_fn)
            .maybe_host_key_mismatch_fn(host_key_mismatch_fn)
            .diff_mode(diff_mode)
            .client_algos(client_algos)
            .user(user)
            .full_public_key_bytes(full_public_key_bytes)
            .client_identity_key_algorithm(client_identity_key_algorithm)
            .client_identity_private_key(client_identity_private_key)
            .maybe_agent_socket(agent_socket)
            .maybe_agent_fingerprint(agent_fingerprint)
            .send_env(send_env)
            .send_path(send_path)
            .build();
        #[cfg(not(feature = "unstable"))]
        let mut frame_reader = KexReader::builder()
            .reader(reader)
            .tx(tx_c)
            .tx_event(tx_event_c)
            .maybe_requested_session_uuid(requested)
            .maybe_server_destination(server_id)
            .maybe_tofu_fn(tofu_fn)
            .maybe_host_key_mismatch_fn(host_key_mismatch_fn)
            .diff_mode(diff_mode)
            .client_algos(client_algos)
            .user(user)
            .full_public_key_bytes(full_public_key_bytes)
            .maybe_agent_socket(agent_socket)
            .maybe_agent_fingerprint(agent_fingerprint)
            .send_env(send_env)
            .send_path(send_path)
            .build();
        if let Err(e) = frame_reader.client_kex().await {
            error!("client_kex failed: {e}");
        }
    });

    // Send KexInit only — Initialize/ResumeRequest is sent inside client_kex() after
    // reading the server's KexInit and generating the correct ephemeral key.
    tx.send(Frame::KexInit(config.preferred_algorithms()))?;

    let kex = kex_handle.await??;

    if let Some(moshpits_addr) = kex.moshpits_addr() {
        trace!("Connecting to moshpits at {moshpits_addr}");
        // Bind to the unspecified address on port 0 so the OS assigns both the
        // outbound interface and an ephemeral port automatically.
        let bind_addr = if moshpits_addr.is_ipv6() {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
        } else {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
        };
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
        udp_listener.connect(moshpits_addr).await?;
        Ok((kex, Arc::new(udp_listener), None))
    } else {
        Err(MoshpitError::InvalidMoshpitsAddress.into())
    }
}

async fn run_server_kex<T: KexConfig>(
    config: T,
    socket_addr: SocketAddr,
    tx: UnboundedSender<Frame>,
    tx_event: UnboundedSender<KexEvent>,
    reader: ConnectionReader,
    kex_handle: JoinHandle<Result<Kex>>,
) -> Result<(Kex, Arc<UdpSocket>, Option<ServerKex>)> {
    let port_pool_opt = config.port_pool();
    let (_private_key_path, public_key_path) = config.key_pair_paths()?;
    let session_registry = config.session_registry();
    trace!(
        "Loading identity public key from {}",
        public_key_path.display()
    );

    // Setup the TCP frame reader
    let tx_c = tx.clone();
    let tx_event_c = tx_event.clone();
    let server_preferred_algos = config.preferred_algorithms();
    let mut frame_reader = KexReader::builder()
        .reader(reader)
        .tx(tx_c)
        .tx_event(tx_event_c)
        .server_preferred_algos(server_preferred_algos)
        .build();
    if let Some(port_pool) = port_pool_opt {
        let (skex, udp_arc) = frame_reader
            .server_kex(socket_addr, port_pool, &public_key_path, session_registry)
            .await?;
        Ok((kex_handle.await??, udp_arc, Some(skex)))
    } else {
        Err(anyhow::anyhow!(
            "Port pool is required for server key exchange"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn kex_state_machine_server_mode_completes_after_uuid() {
        use crate::kex::negotiate::NegotiatedAlgorithms;

        let (tx, rx) = unbounded_channel();
        let mut sm = KexStateMachine::builder().rx_event(rx).build();
        let key = vec![1u8; 32];
        let hmac_key = vec![2u8; 64];
        let uuid = Uuid::new_v4();
        tx.send(KexEvent::NegotiatedAlgorithms(
            NegotiatedAlgorithms::default(),
        ))
        .unwrap();
        tx.send(KexEvent::KeyMaterial(key.clone())).unwrap();
        tx.send(KexEvent::HMACKeyMaterial(hmac_key.clone()))
            .unwrap();
        tx.send(KexEvent::Uuid(uuid)).unwrap();
        drop(tx);
        let kex = sm.handle_events(false).await.unwrap();
        assert_eq!(kex.key().as_slice(), key.as_slice());
        assert_eq!(kex.hmac_key().as_slice(), hmac_key.as_slice());
        assert_eq!(kex.uuid(), uuid);
        assert!(kex.moshpits_addr().is_none());
        assert!(kex.session_uuid().is_none());
    }

    #[tokio::test]
    async fn kex_state_machine_client_mode_full_sequence() {
        use crate::kex::negotiate::NegotiatedAlgorithms;

        let (tx, rx) = unbounded_channel();
        let mut sm = KexStateMachine::builder().rx_event(rx).build();
        let key = vec![3u8; 32];
        let hmac_key = vec![4u8; 64];
        let uuid = Uuid::new_v4();
        let session_uuid = Uuid::new_v4();
        let addr: SocketAddr = "127.0.0.1:50001".parse().unwrap();
        tx.send(KexEvent::NegotiatedAlgorithms(
            NegotiatedAlgorithms::default(),
        ))
        .unwrap();
        tx.send(KexEvent::KeyMaterial(key.clone())).unwrap();
        tx.send(KexEvent::HMACKeyMaterial(hmac_key.clone()))
            .unwrap();
        tx.send(KexEvent::Uuid(uuid)).unwrap();
        tx.send(KexEvent::SessionInfo(session_uuid, false)).unwrap();
        tx.send(KexEvent::MoshpitsAddr(addr)).unwrap();
        let kex = sm.handle_events(true).await.unwrap();
        assert_eq!(kex.key().as_slice(), key.as_slice());
        assert_eq!(kex.hmac_key().as_slice(), hmac_key.as_slice());
        assert_eq!(kex.uuid(), uuid);
        assert_eq!(kex.session_uuid(), Some(session_uuid));
        assert_eq!(kex.moshpits_addr(), Some(addr));
        assert!(!kex.is_resume());
    }

    #[tokio::test]
    async fn kex_state_machine_wrong_event_order_returns_invalid_state() {
        let (tx, rx) = unbounded_channel();
        let mut sm = KexStateMachine::builder().rx_event(rx).build();
        // Send Uuid when state is AwaitingNegotiatedAlgorithms — wrong order
        tx.send(KexEvent::Uuid(Uuid::new_v4())).unwrap();
        drop(tx);
        let result = sm.handle_events(true).await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .downcast_ref::<MoshpitError>()
                .is_some_and(|e| *e == MoshpitError::InvalidKexState),
        );
    }

    #[tokio::test]
    async fn kex_state_machine_channel_dropped_returns_invalid_state() {
        let (tx, rx) = unbounded_channel::<KexEvent>();
        let mut sm = KexStateMachine::builder().rx_event(rx).build();
        // Drop sender immediately — recv() returns None, falls through to InvalidKexState
        drop(tx);
        let result = sm.handle_events(true).await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .downcast_ref::<MoshpitError>()
                .is_some_and(|e| *e == MoshpitError::InvalidKexState),
        );
    }

    #[test]
    fn kex_mode_display_formatting() {
        assert_eq!(format!("{}", KexMode::Client), "Client");
        let addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        assert_eq!(
            format!("{}", KexMode::Server(addr)),
            "Server(127.0.0.1:12345)"
        );
    }
}
