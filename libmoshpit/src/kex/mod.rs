// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

use std::{
    fmt::{self, Display, Formatter},
    net::SocketAddr,
    sync::Arc,
};

use anyhow::Result;
use aws_lc_rs::{
    agreement::{PrivateKey, X25519},
    cipher::AES_256_KEY_LEN,
};
use bon::Builder;
use getset::{CopyGetters, Getters};
use local_ip_address::local_ip;
use serde::{Deserialize, Serialize};
use tokio::{
    net::{
        UdpSocket,
        tcp::{OwnedReadHalf, OwnedWriteHalf},
    },
    spawn,
    sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel},
    task::JoinHandle,
};
use tracing::{error, trace};
use uuid::Uuid;

use crate::{
    ConnectionReader, ConnectionWriter, Frame, KexConfig, KexReader, KexSender, MoshpitError,
    UuidWrapper, decrypt_private_key, load_private_key, load_public_key,
};

pub(crate) mod reader;
pub(crate) mod sender;

/// The key exchange events
#[derive(Clone, Copy, Debug)]
pub enum KexEvent {
    /// Key material for encrypting/decrypting UDP packets
    KeyMaterial([u8; 32]),
    /// HMAC key for signing UDP packets
    HMACKeyMaterial([u8; 64]),
    /// moshpit client UUID
    Uuid(Uuid),
    /// moshpits socket address
    MoshpitsAddr(SocketAddr),
    /// Session information: (stable session UUID, `is_resume` flag)
    SessionInfo(Uuid, bool),
    /// Key exchange failure
    Failure,
}

/// The moshpit key exchange state
#[derive(Clone, Copy, Debug, Default)]
pub enum KexState {
    /// Awaiting key material for encrypting/decrypting UDP packets
    #[default]
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
#[derive(Clone, Copy, CopyGetters, Debug)]
pub struct Kex {
    /// AES-256-GCM-SIV key material for encrypting/decrypting UDP packets
    #[getset(get_copy = "pub")]
    key: [u8; 32],
    /// HMAC key for signing UDP packets
    #[getset(get_copy = "pub")]
    hmac_key: [u8; 64],
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
}

impl Kex {
    /// Get the wrapped UUID
    #[must_use]
    pub fn uuid_wrapper(&self) -> UuidWrapper {
        UuidWrapper::new(self.uuid)
    }
}

impl Default for Kex {
    fn default() -> Self {
        Self {
            key: [0u8; 32],
            hmac_key: [0u8; 64],
            uuid: Uuid::nil(),
            moshpits_addr: None,
            session_uuid: None,
            is_resume: false,
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
            run_client_kex(config, tx, tx_event, reader, kex_handle, passphrase_fn).await?
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

async fn run_client_kex<T: KexConfig>(
    config: T,
    tx: UnboundedSender<Frame>,
    tx_event: UnboundedSender<KexEvent>,
    reader: ConnectionReader,
    kex_handle: JoinHandle<Result<Kex>>,
    passphrase_fn: impl Fn() -> Result<Option<String>>,
) -> Result<(Kex, Arc<UdpSocket>, Option<ServerKex>)> {
    let (private_key_path, public_key_path) = config.key_pair_paths()?;
    trace!("Loading private key from {}", private_key_path.display());
    trace!("Loading public key from {}", public_key_path.display());

    // Load the moshpit public and private key
    let (unenc_key_pair_opt, enc_key_pair_opt) = load_private_key(&private_key_path)?;
    let (full_public_key_bytes, public_key_bytes) = load_public_key(&public_key_path)?;

    let (pk, my_public_key) = if let Some(enc_key_pair) = enc_key_pair_opt {
        // Get the passphrase
        if let Some(passphrase) = passphrase_fn()? {
            let salt_bytes = enc_key_pair.salt_bytes();
            let nonce_bytes = enc_key_pair.nonce_bytes();
            let mut encrypted_private_key_bytes =
                enc_key_pair.encrypted_private_key_bytes().clone();
            decrypt_private_key(
                &passphrase,
                salt_bytes,
                nonce_bytes,
                &mut encrypted_private_key_bytes,
            )?;

            let private_key = PrivateKey::from_private_key(
                &X25519,
                &encrypted_private_key_bytes[..AES_256_KEY_LEN],
            )?;
            let public_key = private_key.compute_public_key()?;

            if public_key.as_ref() != public_key_bytes.as_slice() {
                return Err(anyhow::anyhow!("Public key does not match the private key"));
            }
            (private_key, public_key)
        } else {
            return Err(anyhow::anyhow!("No valid private key found"));
        }
    } else if let Some(unenc_key_pair) = unenc_key_pair_opt {
        unenc_key_pair.take()
    } else {
        return Err(anyhow::anyhow!("No valid private key found"));
    };

    // Setup the TCP frame reader
    let tx_c = tx.clone();
    let tx_event_c = tx_event.clone();
    let requested = config.resume_session_uuid();
    let _read_handle = spawn(async move {
        let mut frame_reader = KexReader::builder()
            .reader(reader)
            .tx(tx_c)
            .tx_event(tx_event_c)
            .maybe_requested_session_uuid(requested)
            .build();
        if let Err(e) = frame_reader.client_kex(&pk).await {
            trace!("{e}");
        }
    });

    // Send the initialize or resume-request frame with our public key
    let frame = if let Some(session_uuid) = config.resume_session_uuid() {
        Frame::ResumeRequest(
            UuidWrapper::new(session_uuid),
            config.user().unwrap_or_default().as_bytes().to_vec(),
            my_public_key.as_ref().to_vec(),
            full_public_key_bytes,
        )
    } else {
        Frame::Initialize(
            config.user().unwrap_or_default().as_bytes().to_vec(),
            my_public_key.as_ref().to_vec(),
            full_public_key_bytes,
        )
    };
    tx.send(frame)?;

    let kex = kex_handle.await??;

    if let Some(moshpits_addr) = kex.moshpits_addr() {
        trace!("Connecting to moshpits at {moshpits_addr}");
        let my_local_ip = local_ip()?;
        let socket_addr = SocketAddr::new(my_local_ip, 0);
        let udp_listener = UdpSocket::bind(socket_addr).await?;
        udp_listener.connect(moshpits_addr).await?;
        let frame = Frame::MoshpitAddr(udp_listener.local_addr()?);
        tx.send(frame.clone())?;
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
    let (private_key_path, public_key_path) = config.key_pair_paths()?;
    let session_registry = config.session_registry();
    trace!("Loading private key from {}", private_key_path.display());
    trace!("Loading public key from {}", public_key_path.display());

    // Setup the TCP frame reader
    let tx_c = tx.clone();
    let tx_event_c = tx_event.clone();
    let mut frame_reader = KexReader::builder()
        .reader(reader)
        .tx(tx_c)
        .tx_event(tx_event_c)
        .build();
    if let Some(port_pool) = port_pool_opt {
        let (skex, udp_arc) = frame_reader
            .server_kex(
                socket_addr,
                port_pool,
                &private_key_path,
                &public_key_path,
                session_registry,
            )
            .await?;
        Ok((kex_handle.await??, udp_arc, Some(skex)))
    } else {
        Err(anyhow::anyhow!(
            "Port pool is required for server key exchange"
        ))
    }
}
