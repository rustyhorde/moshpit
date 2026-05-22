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
    /// List identities whose algorithm appears in `supported_algorithms`.
    ///
    /// Use this instead of [`AgentRequest::ListIdentities`] when the caller may not
    /// support every algorithm the agent holds (e.g. a client built without the
    /// `unstable` feature cannot use ML-DSA keys).
    ListSupportedIdentities {
        /// Algorithm strings the caller supports (e.g. `["P384", "P256", "X25519"]`).
        supported_algorithms: Vec<String>,
    },
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

#[cfg(test)]
mod tests {
    use bincode_next::{config::standard, decode_from_slice, encode_to_vec};

    use super::*;

    #[test]
    fn roundtrip_request_lock() {
        let encoded = encode_to_vec(&AgentRequest::Lock, standard()).unwrap();
        let (rt, _): (AgentRequest, _) = decode_from_slice(&encoded, standard()).unwrap();
        assert!(matches!(rt, AgentRequest::Lock));
    }

    #[test]
    fn roundtrip_request_unlock() {
        let encoded =
            encode_to_vec(AgentRequest::Unlock("secret".to_string()), standard()).unwrap();
        let (rt, _): (AgentRequest, _) = decode_from_slice(&encoded, standard()).unwrap();
        assert!(matches!(rt, AgentRequest::Unlock(ref s) if s == "secret"));
    }

    #[test]
    fn roundtrip_request_remove_all() {
        let encoded = encode_to_vec(&AgentRequest::RemoveAllIdentities, standard()).unwrap();
        let (rt, _): (AgentRequest, _) = decode_from_slice(&encoded, standard()).unwrap();
        assert!(matches!(rt, AgentRequest::RemoveAllIdentities));
    }

    #[test]
    fn roundtrip_response_ok() {
        let encoded = encode_to_vec(&AgentResponse::Ok, standard()).unwrap();
        let (rt, _): (AgentResponse, _) = decode_from_slice(&encoded, standard()).unwrap();
        assert!(matches!(rt, AgentResponse::Ok));
    }

    #[test]
    fn agent_identity_info_clone_and_debug() {
        let info = AgentIdentityInfo {
            algorithm: "P384".to_string(),
            fingerprint: "SHA256:abcd".to_string(),
            comment: "user@host".to_string(),
        };
        let cloned = info.clone();
        assert_eq!(cloned.algorithm, "P384");
        let debug_str = format!("{info:?}");
        assert!(debug_str.contains("P384"));
    }
}
