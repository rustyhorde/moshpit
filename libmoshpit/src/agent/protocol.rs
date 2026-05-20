// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

//! Request/response types for the moshpit agent Unix-socket protocol.
//!
//! The wire format is simple length-prefixed bincode-next:
//!
//! ```text
//! [u32 big-endian message length][bincode-next encoded message]
//! ```
//!
//! Private keys never cross the socket — only public keys and signatures are
//! returned from the agent.

use bincode_next::{Decode, Encode};

/// A loaded identity known to the agent.
#[derive(Clone, Debug, Decode, Encode)]
pub struct AgentIdentityInfo {
    /// Key algorithm string (e.g. `"X25519"`, `"P384"`).
    pub algorithm: String,
    /// `SHA256:<base64>` fingerprint of the public key.
    pub fingerprint: String,
    /// Optional comment (e.g. `user@host`).
    pub comment: String,
}

/// Requests sent by a client to the agent.
#[derive(Clone, Debug, Decode, Encode)]
pub enum AgentRequest {
    /// List all identities currently held in memory.
    ListIdentities,
    /// Return the full public key file bytes for the identity with the given fingerprint.
    ///
    /// The fingerprint is the `SHA256:<base64>` form without trailing comment.
    GetPublicKey(String),
    /// Sign `data` with the private key identified by `fingerprint`.
    ///
    /// Only meaningful for ML-DSA keys; ECDH identity keys don't sign.
    Sign {
        /// `SHA256:<base64>` fingerprint (without trailing comment).
        fingerprint: String,
        /// Raw bytes to sign.
        data: Vec<u8>,
    },
    /// Add an identity from `key_path`, decrypting it with `passphrase` if encrypted.
    AddIdentity {
        /// Absolute path to the private key file.
        key_path: String,
        /// Passphrase to decrypt the key; `None` for unencrypted keys.
        passphrase: Option<String>,
    },
    /// Remove the identity identified by `fingerprint`.
    RemoveIdentity(String),
    /// Remove all identities from memory.
    RemoveAllIdentities,
    /// Lock the agent: clear all keys from memory.
    Lock,
    /// Unlock the agent with a master credential (currently a passphrase string).
    Unlock(String),
}

/// Responses from the agent.
#[derive(Clone, Debug, Decode, Encode)]
pub enum AgentResponse {
    /// A list of known identities.
    Identities(Vec<AgentIdentityInfo>),
    /// The full public key file bytes for the requested identity.
    PublicKey(Vec<u8>),
    /// A signature produced by the agent.
    Signature(Vec<u8>),
    /// Generic success.
    Ok,
    /// An error message.
    Error(String),
}
