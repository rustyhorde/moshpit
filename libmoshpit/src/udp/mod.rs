// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

use anyhow::Result;
use aws_lc_rs::aead::{AES_256_GCM_SIV, LessSafeKey, UnboundKey};
use bon::Builder;
use getset::Getters;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub(crate) mod reader;
pub(crate) mod sender;

/// Controls the UDP transport delivery strategy for diff packets.
///
/// `Reliable` (default): NAK-based selective retransmission with exponential
/// backoff — suited for low-loss paths where retransmit rarely fires.
///
/// `Datagram`: fire-and-forget diffs with no retransmission; the server instead
/// sends a full `ScreenStateCompressed` every 150 ms.
/// Eliminates head-of-line blocking on flaky/high-loss connections at the cost
/// of slightly higher bandwidth.
///
/// `StateSync`: Mosh-style ack-based diffs. The server sends
/// `contents_diff(ack_state, current)` on every screen change; the client acks
/// each packet so the server advances its diff baseline. No NAKs, no reorder
/// buffer, and no periodic full-screen pushes — lost packets are implicitly
/// covered by the next diff from the same baseline.
///
/// All modes are requested by the client during key exchange via
/// [`Frame::ClientOptions`](crate::Frame); the server always supports all modes.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DiffMode {
    /// Ordered delivery with NAK-based selective retransmission (default).
    #[default]
    Reliable,
    /// Fire-and-forget diffs; periodic full-screen snapshots for recovery.
    Datagram,
    /// Mosh-style ack-based diffs: server computes `contents_diff(ack_state, current)` on
    /// every change; client sends `ClientAck` after rendering each packet so the server can
    /// advance its diff baseline. No reorder buffer, no NAKs, no periodic full-screen pushes
    /// except on explicit desync recovery via `RepaintRequest`.
    #[serde(rename = "statesync")]
    StateSync,
}

/// UDP client data
#[derive(Builder, Debug, Getters)]
#[getset(get = "pub")]
pub struct UdpClient {
    /// Client UUID
    uuid: Uuid,
    /// Key for encrypting/decrypting UDP packets
    #[builder(with = |key: [u8; 32]| -> Result<_> { Ok(LessSafeKey::new(UnboundKey::new(&AES_256_GCM_SIV, &key)?)) })]
    rnk: LessSafeKey,
}
