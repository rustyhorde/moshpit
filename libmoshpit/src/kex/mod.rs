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
    agreement::{PrivateKey, X25519},
    cipher::AES_256_KEY_LEN,
};
use bon::Builder;
use getset::CopyGetters;
use tokio::{
    net::{
        UdpSocket,
        tcp::{OwnedReadHalf, OwnedWriteHalf},
    },
    spawn,
    sync::{
        Mutex,
        mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel},
    },
    task::JoinHandle,
};
use tracing::{error, trace};
use uuid::Uuid;

use crate::{
    ConnectionReader, ConnectionWriter, Frame, KexReader, KexSender, MoshpitError, UuidWrapper,
    decrypt_private_key, load_private_key, load_public_key,
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
    /// moshpit client UUID
    #[getset(get_copy = "pub")]
    uuid: Uuid,
    /// An optional moshpits socket address used by moshpit.
    #[getset(get_copy = "pub")]
    moshpits_addr: Option<SocketAddr>,
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
        }
    }
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
                        self.state = KexState::AwaitingMoshpitsAddr;
                    } else {
                        self.state = KexState::Complete;
                        break;
                    }
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
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KexMode {
    /// Client mode
    Client,
    /// Server mode
    Server(SocketAddr),
}

/// Run the client side of the key exchange
///
/// # Errors
///
pub async fn run_key_exchange(
    mode: KexMode,
    sock_read: OwnedReadHalf,
    sock_write: OwnedWriteHalf,
    port_pool: Option<Arc<Mutex<BTreeSet<u16>>>>,
    private_key_path: PathBuf,
    public_key_path: PathBuf,
    passphrase_fn: impl Fn() -> Result<Option<String>>,
) -> Result<(Kex, Arc<UdpSocket>)> {
    // Setup the TCP connection to the server for key exchange
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
            error!("tcp frame sender error {e}");
        }
    });

    Ok(match mode {
        KexMode::Client => {
            run_client_kex(
                tx,
                tx_event,
                reader,
                kex_handle,
                private_key_path,
                public_key_path,
                passphrase_fn,
            )
            .await?
        }
        KexMode::Server(socket_addr) => {
            run_server_kex(
                socket_addr,
                port_pool,
                tx,
                tx_event,
                reader,
                kex_handle,
                private_key_path,
                public_key_path,
            )
            .await?
        }
    })
}

async fn run_client_kex(
    tx: UnboundedSender<Frame>,
    tx_event: UnboundedSender<KexEvent>,
    reader: ConnectionReader,
    kex_handle: JoinHandle<Result<Kex>>,
    private_key_path: PathBuf,
    public_key_path: PathBuf,
    passphrase_fn: impl Fn() -> Result<Option<String>>,
) -> Result<(Kex, Arc<UdpSocket>)> {
    // Load the moshpit public and private key
    let (unenc_key_pair_opt, enc_key_pair_opt) = load_private_key(&private_key_path)?;
    let public_key_bytes = load_public_key(&public_key_path)?;

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
    let _read_handle = spawn(async move {
        let mut frame_reader = KexReader::builder()
            .reader(reader)
            .tx(tx_c)
            .tx_event(tx_event_c)
            .build();
        if let Err(e) = frame_reader.client_kex(&pk).await {
            error!("tcp frame reader: {e}");
        }
    });

    // Send the initialize frame with our public key
    let frame = Frame::Initialize(my_public_key.as_ref().to_vec());
    tx.send(frame.clone())?;

    let kex = kex_handle.await??;

    if let Some(moshpits_addr) = kex.moshpits_addr() {
        trace!("Connecting to moshpits at {moshpits_addr}");
        let socket_addr = "0.0.0.0:0".parse::<SocketAddr>()?;
        let udp_listener = UdpSocket::bind(socket_addr).await?;
        udp_listener.connect(moshpits_addr).await?;
        let frame = Frame::MoshpitAddr(udp_listener.local_addr()?);
        tx.send(frame.clone())?;
        Ok((kex, Arc::new(udp_listener)))
    } else {
        Err(MoshpitError::InvalidMoshpitsAddress.into())
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_server_kex(
    socket_addr: SocketAddr,
    port_pool_opt: Option<Arc<Mutex<BTreeSet<u16>>>>,
    tx: UnboundedSender<Frame>,
    tx_event: UnboundedSender<KexEvent>,
    reader: ConnectionReader,
    kex_handle: JoinHandle<Result<Kex>>,
    private_key_path: PathBuf,
    public_key_path: PathBuf,
) -> Result<(Kex, Arc<UdpSocket>)> {
    // Setup the TCP frame reader
    let tx_c = tx.clone();
    let tx_event_c = tx_event.clone();
    let mut frame_reader = KexReader::builder()
        .reader(reader)
        .tx(tx_c)
        .tx_event(tx_event_c)
        .build();
    if let Some(port_pool) = port_pool_opt {
        let udp_arc = frame_reader
            .server_kex(socket_addr, port_pool, &private_key_path, &public_key_path)
            .await?;
        Ok((kex_handle.await??, udp_arc))
    } else {
        Err(anyhow::anyhow!(
            "Port pool is required for server key exchange"
        ))
    }
}
