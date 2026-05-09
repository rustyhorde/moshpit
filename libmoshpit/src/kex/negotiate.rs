// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

use anyhow::Result;
use bincode_next::{Decode, Encode};

use crate::error::Error as MoshpitError;

// ── Algorithm name constants ──────────────────────────────────────────────────

/// X25519 ECDH with HKDF-SHA256 key extraction
pub const KEX_X25519_SHA256: &str = "x25519-sha256";
/// AES-256-GCM-SIV authenticated encryption
pub const AEAD_AES256_GCM_SIV: &str = "aes256-gcm-siv";
/// HMAC-SHA512 packet authentication (64-byte tag)
pub const MAC_HMAC_SHA512: &str = "hmac-sha512";
/// HKDF-SHA256 key expansion
pub const KDF_HKDF_SHA256: &str = "hkdf-sha256";

// ── Types ─────────────────────────────────────────────────────────────────────

/// Ordered list of algorithm names offered during KEX negotiation.
///
/// Each field holds algorithms in preference order (most preferred first).
/// Sent by both client and server in a [`Frame::KexInit`](crate::Frame) frame.
#[derive(Clone, Debug, Decode, Encode, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AlgorithmList {
    /// Key exchange algorithms (e.g. `"x25519-sha256"`)
    pub kex: Vec<String>,
    /// AEAD session encryption algorithms (e.g. `"aes256-gcm-siv"`)
    pub aead: Vec<String>,
    /// UDP packet MAC algorithms (e.g. `"hmac-sha512"`)
    pub mac: Vec<String>,
    /// KDF expand algorithms (e.g. `"hkdf-sha256"`)
    pub kdf: Vec<String>,
}

/// The result of [`negotiate`]: the single algorithm chosen for each category.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NegotiatedAlgorithms {
    /// Chosen key exchange algorithm
    pub kex: String,
    /// Chosen AEAD session encryption algorithm
    pub aead: String,
    /// Chosen UDP packet MAC algorithm
    pub mac: String,
    /// Chosen KDF expand algorithm
    pub kdf: String,
}

impl Default for NegotiatedAlgorithms {
    fn default() -> Self {
        Self {
            kex: KEX_X25519_SHA256.to_string(),
            aead: AEAD_AES256_GCM_SIV.to_string(),
            mac: MAC_HMAC_SHA512.to_string(),
            kdf: KDF_HKDF_SHA256.to_string(),
        }
    }
}

// ── Public functions ──────────────────────────────────────────────────────────

/// Returns the complete set of algorithms supported by this build.
///
/// Phase 1: only the current hardcoded stack is listed.  Future phases will
/// extend each `Vec` as new algorithms are added.
#[must_use]
pub fn supported_algorithms() -> AlgorithmList {
    AlgorithmList {
        kex: vec![KEX_X25519_SHA256.to_string()],
        aead: vec![AEAD_AES256_GCM_SIV.to_string()],
        mac: vec![MAC_HMAC_SHA512.to_string()],
        kdf: vec![KDF_HKDF_SHA256.to_string()],
    }
}

/// SSH-style "first match wins" algorithm negotiation.
///
/// For each category, selects the first algorithm from `client_prefs` that
/// also appears in `server_supports`.  Returns [`MoshpitError::NoCommonAlgorithm`]
/// if any category has no intersection.
///
/// # Errors
/// - [`MoshpitError::NoCommonAlgorithm`] — no common algorithm in at least one category
pub fn negotiate(
    client_prefs: &AlgorithmList,
    server_supports: &AlgorithmList,
) -> Result<NegotiatedAlgorithms> {
    let pick = |client: &[String], server: &[String]| -> Option<String> {
        client.iter().find(|a| server.contains(a)).cloned()
    };

    let kex =
        pick(&client_prefs.kex, &server_supports.kex).ok_or(MoshpitError::NoCommonAlgorithm)?;
    let aead =
        pick(&client_prefs.aead, &server_supports.aead).ok_or(MoshpitError::NoCommonAlgorithm)?;
    let mac =
        pick(&client_prefs.mac, &server_supports.mac).ok_or(MoshpitError::NoCommonAlgorithm)?;
    let kdf =
        pick(&client_prefs.kdf, &server_supports.kdf).ok_or(MoshpitError::NoCommonAlgorithm)?;

    Ok(NegotiatedAlgorithms {
        kex,
        aead,
        mac,
        kdf,
    })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn current() -> AlgorithmList {
        supported_algorithms()
    }

    #[test]
    fn negotiate_current_stack_succeeds() {
        let client = current();
        let server = current();
        let negotiated = negotiate(&client, &server).expect("should succeed with identical lists");
        assert_eq!(negotiated.kex, KEX_X25519_SHA256);
        assert_eq!(negotiated.aead, AEAD_AES256_GCM_SIV);
        assert_eq!(negotiated.mac, MAC_HMAC_SHA512);
        assert_eq!(negotiated.kdf, KDF_HKDF_SHA256);
    }

    #[test]
    fn negotiate_picks_first_common_kex() {
        let client = AlgorithmList {
            kex: vec!["future-algo".to_string(), KEX_X25519_SHA256.to_string()],
            aead: vec![AEAD_AES256_GCM_SIV.to_string()],
            mac: vec![MAC_HMAC_SHA512.to_string()],
            kdf: vec![KDF_HKDF_SHA256.to_string()],
        };
        let server = current();
        let negotiated = negotiate(&client, &server).expect("should find x25519-sha256");
        assert_eq!(negotiated.kex, KEX_X25519_SHA256);
    }

    #[test]
    fn negotiate_no_common_kex_returns_error() {
        let client = AlgorithmList {
            kex: vec!["unknown-kex".to_string()],
            aead: vec![AEAD_AES256_GCM_SIV.to_string()],
            mac: vec![MAC_HMAC_SHA512.to_string()],
            kdf: vec![KDF_HKDF_SHA256.to_string()],
        };
        let server = current();
        let err = negotiate(&client, &server).unwrap_err();
        assert!(
            err.downcast_ref::<MoshpitError>()
                .is_some_and(|e| *e == MoshpitError::NoCommonAlgorithm)
        );
    }

    #[test]
    fn negotiate_no_common_aead_returns_error() {
        let client = AlgorithmList {
            kex: vec![KEX_X25519_SHA256.to_string()],
            aead: vec!["unknown-aead".to_string()],
            mac: vec![MAC_HMAC_SHA512.to_string()],
            kdf: vec![KDF_HKDF_SHA256.to_string()],
        };
        let server = current();
        let err = negotiate(&client, &server).unwrap_err();
        assert!(
            err.downcast_ref::<MoshpitError>()
                .is_some_and(|e| *e == MoshpitError::NoCommonAlgorithm)
        );
    }

    #[test]
    fn negotiate_empty_client_list_returns_error() {
        let client = AlgorithmList {
            kex: vec![],
            aead: vec![AEAD_AES256_GCM_SIV.to_string()],
            mac: vec![MAC_HMAC_SHA512.to_string()],
            kdf: vec![KDF_HKDF_SHA256.to_string()],
        };
        let server = current();
        assert!(negotiate(&client, &server).is_err());
    }

    #[test]
    fn negotiate_preference_ordering_respected() {
        // Server supports both; client lists "future" first — but server doesn't have it.
        // Client's second choice matches.
        let client = AlgorithmList {
            kex: vec!["future-kex".to_string(), KEX_X25519_SHA256.to_string()],
            aead: vec!["future-aead".to_string(), AEAD_AES256_GCM_SIV.to_string()],
            mac: vec!["future-mac".to_string(), MAC_HMAC_SHA512.to_string()],
            kdf: vec!["future-kdf".to_string(), KDF_HKDF_SHA256.to_string()],
        };
        let server = current();
        let negotiated = negotiate(&client, &server).expect("second-choice should match");
        assert_eq!(negotiated.kex, KEX_X25519_SHA256);
        assert_eq!(negotiated.aead, AEAD_AES256_GCM_SIV);
        assert_eq!(negotiated.mac, MAC_HMAC_SHA512);
        assert_eq!(negotiated.kdf, KDF_HKDF_SHA256);
    }
}
