// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

use anyhow::Result;
use aws_lc_rs::aead::{AES_256_GCM_SIV, RandomizedNonceKey};
use bon::Builder;
use getset::Getters;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub(crate) mod reader;
pub(crate) mod sender;

/// Controls whether the UDP transport retransmits lost diff packets or relies
/// on periodic full-screen snapshots for recovery.
///
/// `Reliable` (default): NAK-based selective retransmission with exponential
/// backoff — suited for low-loss paths where retransmit rarely fires.
///
/// `Datagram`: fire-and-forget diffs with no retransmission; the server instead
/// sends a full `ScreenStateCompressed` every 150 ms.
/// Eliminates head-of-line blocking on flaky/high-loss connections at the cost
/// of slightly higher bandwidth.  Requested by the client during key exchange
/// via [`Frame::ClientOptions`](crate::Frame); the server always supports both modes.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DiffMode {
    /// Ordered delivery with NAK-based selective retransmission (default).
    #[default]
    Reliable,
    /// Fire-and-forget diffs; periodic full-screen snapshots for recovery.
    Datagram,
}

/// UDP client data
#[derive(Builder, Debug, Getters)]
#[getset(get = "pub")]
pub struct UdpClient {
    /// Client UUID
    uuid: Uuid,
    /// Key for encrypting/decrypting UDP packets
    #[builder(with = |key: [u8; 32]| -> Result<_> { RandomizedNonceKey::new(&AES_256_GCM_SIV, &key).map_err(Into::into) })]
    rnk: RandomizedNonceKey,
}
