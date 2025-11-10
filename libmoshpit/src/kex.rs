// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

use std::net::SocketAddr;

use anyhow::Result;
use bon::Builder;
use getset::CopyGetters;
use tokio::sync::mpsc::UnboundedReceiver;
use uuid::Uuid;

use crate::MoshpitError;

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
