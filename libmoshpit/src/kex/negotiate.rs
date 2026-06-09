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
/// NIST P-384 ECDH with HKDF-SHA384 key extraction (higher security margin)
pub const KEX_P384_SHA384: &str = "p384-sha384";
/// NIST P-256 ECDH with HKDF-SHA256 (FIPS-compliant environments)
pub const KEX_P256_SHA256: &str = "p256-sha256";
/// NIST FIPS 203 ML-KEM-512 with HKDF-SHA256 key extraction
pub const KEX_ML_KEM_512_SHA256: &str = "ml-kem-512-sha256";
/// NIST FIPS 203 ML-KEM-768 with HKDF-SHA256 key extraction
pub const KEX_ML_KEM_768_SHA256: &str = "ml-kem-768-sha256";
/// NIST FIPS 203 ML-KEM-1024 with HKDF-SHA256 key extraction
pub const KEX_ML_KEM_1024_SHA256: &str = "ml-kem-1024-sha256";
/// AES-256-GCM-SIV authenticated encryption (nonce-misuse resistant)
pub const AEAD_AES256_GCM_SIV: &str = "aes256-gcm-siv";
/// AES-256-GCM authenticated encryption
pub const AEAD_AES256_GCM: &str = "aes256-gcm";
/// ChaCha20-Poly1305 authenticated encryption (fast on no-AES-NI CPUs)
pub const AEAD_CHACHA20_POLY1305: &str = "chacha20-poly1305";
/// AES-128-GCM-SIV authenticated encryption (16-byte key)
pub const AEAD_AES128_GCM_SIV: &str = "aes128-gcm-siv";
/// HMAC-SHA512 packet authentication (64-byte tag)
pub const MAC_HMAC_SHA512: &str = "hmac-sha512";
/// HMAC-SHA256 packet authentication (32-byte tag, saves 32 B/packet)
pub const MAC_HMAC_SHA256: &str = "hmac-sha256";
/// HKDF-SHA256 key expansion
pub const KDF_HKDF_SHA256: &str = "hkdf-sha256";
/// HKDF-SHA384 key expansion (natural pairing with P-384)
pub const KDF_HKDF_SHA384: &str = "hkdf-sha384";
/// HKDF-SHA512 key expansion (higher security margin)
pub const KDF_HKDF_SHA512: &str = "hkdf-sha512";

// ── Wire protocol version ──────────────────────────────────────────────────────

/// Highest wire protocol version this build speaks.
///
/// # When to bump
///
/// Increment this for **any** change to the wire format or its interpretation:
/// adding, removing, reordering, or re-typing a [`Frame`](crate::Frame) or
/// [`EncryptedFrame`](crate::EncryptedFrame) variant or its fields, or changing
/// the meaning of an existing frame.  Leave [`MIN_PROTOCOL_VERSION`] where it is
/// (do **not** raise it for a normal feature bump) so this build keeps
/// negotiating with older peers — see that constant for the retirement knob.
///
/// # Where to branch
///
/// Gate version-dependent behaviour on the value negotiated during key exchange,
/// reachable via [`Kex::protocol_version`](crate::Kex::protocol_version) (client)
/// and [`ServerKex::protocol_version`](crate::ServerKex::protocol_version)
/// (server).  Never branch on the crate version (`CARGO_PKG_VERSION`): two builds
/// with different crate versions can still share the same wire protocol, and a
/// newer build must keep speaking the older format to an older peer.
///
/// ```text
/// // Emitting or parsing a frame whose shape changed in v2:
/// if kex.protocol_version() >= 2 {
///     // v2 wire shape
/// } else {
///     // v1 fallback — keep talking to older peers
/// }
/// ```
///
/// The negotiated version is first available on [`Kex`](crate::Kex) /
/// [`ServerKex`](crate::ServerKex) once key exchange completes.  To gate the
/// format of **UDP** frames it must additionally be threaded into the UDP
/// transport (`UdpSender` / `UdpReader`), which does not receive it today; the
/// `Kex` value at session setup is the single source to pass down.
pub const PROTOCOL_VERSION: u16 = 1;

/// Lowest wire protocol version this build can implement.
///
/// This is the hard floor below which the code no longer carries the logic to
/// speak: it is the oldest version still present in `protocol_version()` branches.
///
/// # When to raise (protocol retirement)
///
/// Raise this constant **only** to permanently drop support for an old protocol —
/// for example after a security fix that makes an earlier version unsafe — and
/// delete the now-dead `< new floor` branches at the same time.  This is a
/// breaking change for peers that can only speak the retired versions.
///
/// Separately, a server **operator** can raise the *effective* floor at runtime
/// via `mps --min-protocol-version` (or `MOSHPITS_MIN_PROTOCOL_VERSION`) without
/// recompiling; that value is clamped to `[MIN_PROTOCOL_VERSION, PROTOCOL_VERSION]`
/// by [`KexConfig::protocol_support`](crate::KexConfig::protocol_support) and can
/// never drop below this constant.  See [`ProtocolSupport`] and
/// [`negotiate_protocol_version`].
pub const MIN_PROTOCOL_VERSION: u16 = 1;

/// The inclusive range of wire protocol versions an endpoint supports, advertised
/// in its [`Frame::KexInit`](crate::Frame) frame so the peer can negotiate a
/// common version.
#[derive(Clone, Copy, Debug, Decode, Encode, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProtocolSupport {
    /// Lowest version this endpoint will accept (its effective floor).
    pub min: u16,
    /// Highest version this endpoint speaks (always [`PROTOCOL_VERSION`]).
    pub max: u16,
}

/// The build-default support range: `min` is [`MIN_PROTOCOL_VERSION`] and `max`
/// is [`PROTOCOL_VERSION`].
#[must_use]
pub fn local_protocol_support() -> ProtocolSupport {
    ProtocolSupport {
        min: MIN_PROTOCOL_VERSION,
        max: PROTOCOL_VERSION,
    }
}

/// Negotiate the highest wire protocol version both peers support.
///
/// Picks `min(local.max, peer.max)` and accepts it only if it falls within both
/// endpoints' supported ranges.  The computation is symmetric: both sides reach
/// the same result from the two advertised [`ProtocolSupport`] ranges.
///
/// # Errors
/// - [`MoshpitError::IncompatibleProtocolVersion`] — the supported ranges do not overlap
pub fn negotiate_protocol_version(local: ProtocolSupport, peer: ProtocolSupport) -> Result<u16> {
    let agreed = local.max.min(peer.max);
    if agreed >= local.min && agreed >= peer.min {
        Ok(agreed)
    } else {
        Err(MoshpitError::IncompatibleProtocolVersion.into())
    }
}

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
    /// Agreed wire protocol version (see [`negotiate_protocol_version`]).
    ///
    /// [`negotiate`] sets this to [`PROTOCOL_VERSION`] as a placeholder; the key
    /// exchange readers overwrite it with the value negotiated from both peers'
    /// advertised [`ProtocolSupport`] ranges.
    pub protocol_version: u16,
}

impl Default for NegotiatedAlgorithms {
    fn default() -> Self {
        Self {
            kex: KEX_X25519_SHA256.to_string(),
            aead: AEAD_AES256_GCM_SIV.to_string(),
            mac: MAC_HMAC_SHA512.to_string(),
            kdf: KDF_HKDF_SHA256.to_string(),
            protocol_version: PROTOCOL_VERSION,
        }
    }
}

// ── Public functions ──────────────────────────────────────────────────────────

/// Returns the complete set of algorithms supported by this build, in server-default
/// preference order (strongest / most broadly compatible first).
#[must_use]
pub fn supported_algorithms() -> AlgorithmList {
    AlgorithmList {
        kex: vec![
            KEX_X25519_SHA256.to_string(),
            KEX_ML_KEM_768_SHA256.to_string(),
            KEX_ML_KEM_512_SHA256.to_string(),
            KEX_ML_KEM_1024_SHA256.to_string(),
            KEX_P384_SHA384.to_string(),
            KEX_P256_SHA256.to_string(),
        ],
        aead: vec![
            AEAD_AES256_GCM_SIV.to_string(),
            AEAD_AES256_GCM.to_string(),
            AEAD_CHACHA20_POLY1305.to_string(),
            AEAD_AES128_GCM_SIV.to_string(),
        ],
        mac: vec![MAC_HMAC_SHA512.to_string(), MAC_HMAC_SHA256.to_string()],
        kdf: vec![
            KDF_HKDF_SHA256.to_string(),
            KDF_HKDF_SHA384.to_string(),
            KDF_HKDF_SHA512.to_string(),
        ],
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
        // Placeholder; the kex readers overwrite this with the result of
        // negotiate_protocol_version() once both ProtocolSupport ranges are known.
        protocol_version: PROTOCOL_VERSION,
    })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::{
        AlgorithmList, MoshpitError, ProtocolSupport,
        AEAD_AES128_GCM_SIV, AEAD_AES256_GCM, AEAD_AES256_GCM_SIV, AEAD_CHACHA20_POLY1305,
        KDF_HKDF_SHA256, KDF_HKDF_SHA512,
        KEX_ML_KEM_512_SHA256, KEX_ML_KEM_768_SHA256, KEX_ML_KEM_1024_SHA256,
        KEX_P256_SHA256, KEX_P384_SHA384, KEX_X25519_SHA256,
        MAC_HMAC_SHA256, MAC_HMAC_SHA512,
        MIN_PROTOCOL_VERSION, PROTOCOL_VERSION,
        local_protocol_support, negotiate, negotiate_protocol_version, supported_algorithms,
    };

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
    fn negotiate_picks_ml_kem_when_preferred_and_supported() {
        let client = AlgorithmList {
            kex: vec![
                KEX_ML_KEM_768_SHA256.to_string(),
                KEX_X25519_SHA256.to_string(),
            ],
            aead: vec![AEAD_AES256_GCM_SIV.to_string()],
            mac: vec![MAC_HMAC_SHA512.to_string()],
            kdf: vec![KDF_HKDF_SHA256.to_string()],
        };
        let server = current();
        let negotiated = negotiate(&client, &server).expect("should find ml-kem-768-sha256");
        assert_eq!(negotiated.kex, KEX_ML_KEM_768_SHA256);
    }

    #[test]
    fn negotiate_falls_back_from_ml_kem_to_ecdh() {
        let client = AlgorithmList {
            kex: vec![
                KEX_ML_KEM_768_SHA256.to_string(),
                KEX_X25519_SHA256.to_string(),
            ],
            aead: vec![AEAD_AES256_GCM_SIV.to_string()],
            mac: vec![MAC_HMAC_SHA512.to_string()],
            kdf: vec![KDF_HKDF_SHA256.to_string()],
        };
        let server = AlgorithmList {
            kex: vec![KEX_X25519_SHA256.to_string()],
            aead: vec![AEAD_AES256_GCM_SIV.to_string()],
            mac: vec![MAC_HMAC_SHA512.to_string()],
            kdf: vec![KDF_HKDF_SHA256.to_string()],
        };
        let negotiated = negotiate(&client, &server).expect("should fall back to x25519");
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

    #[test]
    fn negotiate_server_preference_order_wins() {
        // Server prefers x448 over x25519; client supports both but prefers x25519.
        // When server's list is passed first (server-preferred mode), x448 wins.
        let server_prefs = AlgorithmList {
            kex: vec![KEX_P384_SHA384.to_string(), KEX_X25519_SHA256.to_string()],
            aead: vec![
                AEAD_CHACHA20_POLY1305.to_string(),
                AEAD_AES256_GCM_SIV.to_string(),
            ],
            mac: vec![MAC_HMAC_SHA256.to_string(), MAC_HMAC_SHA512.to_string()],
            kdf: vec![KDF_HKDF_SHA512.to_string(), KDF_HKDF_SHA256.to_string()],
        };
        let client_offered = AlgorithmList {
            kex: vec![KEX_X25519_SHA256.to_string(), KEX_P384_SHA384.to_string()],
            aead: vec![
                AEAD_AES256_GCM_SIV.to_string(),
                AEAD_CHACHA20_POLY1305.to_string(),
            ],
            mac: vec![MAC_HMAC_SHA512.to_string(), MAC_HMAC_SHA256.to_string()],
            kdf: vec![KDF_HKDF_SHA256.to_string(), KDF_HKDF_SHA512.to_string()],
        };
        // Server-preferred: negotiate(server_prefs, client_offered)
        let negotiated = negotiate(&server_prefs, &client_offered)
            .expect("should find common algorithms in server preference order");
        assert_eq!(negotiated.kex, KEX_P384_SHA384, "server prefers x448");
        assert_eq!(
            negotiated.aead, AEAD_CHACHA20_POLY1305,
            "server prefers chacha20"
        );
        assert_eq!(negotiated.mac, MAC_HMAC_SHA256, "server prefers sha256 mac");
        assert_eq!(
            negotiated.kdf, KDF_HKDF_SHA512,
            "server prefers hkdf-sha512"
        );
    }

    // ── protocol version negotiation ───────────────────────────────────────────

    #[test]
    fn local_protocol_support_uses_build_constants() {
        let s = local_protocol_support();
        assert_eq!(s.min, MIN_PROTOCOL_VERSION);
        assert_eq!(s.max, PROTOCOL_VERSION);
    }

    #[test]
    fn protocol_support_is_ordered_and_hashable() {
        use std::collections::{BTreeSet, HashSet};

        let lo = ProtocolSupport { min: 1, max: 1 };
        let hi = ProtocolSupport { min: 1, max: 2 };
        // Exercises the derived `Ord`/`PartialOrd`.
        assert!(lo < hi);
        let ordered: BTreeSet<ProtocolSupport> = [hi, lo].into_iter().collect();
        assert_eq!(ordered.iter().next(), Some(&lo));
        // Exercises the derived `Hash`.
        let hashed: HashSet<ProtocolSupport> = [lo, hi, lo].into_iter().collect();
        assert_eq!(hashed.len(), 2);
    }

    #[test]
    fn negotiate_protocol_version_equal_ranges() {
        let s = ProtocolSupport { min: 1, max: 3 };
        assert_eq!(negotiate_protocol_version(s, s).expect("overlap"), 3);
    }

    #[test]
    fn negotiate_protocol_version_picks_min_of_maxes() {
        let local = ProtocolSupport { min: 1, max: 3 };
        let peer = ProtocolSupport { min: 1, max: 2 };
        assert_eq!(negotiate_protocol_version(local, peer).expect("overlap"), 2);
        assert_eq!(negotiate_protocol_version(peer, local).expect("overlap"), 2);
    }

    #[test]
    fn negotiate_protocol_version_backward_compatible() {
        // A server speaking up to v3 (floor v1) still talks to a v1-only client.
        let server = ProtocolSupport { min: 1, max: 3 };
        let client = ProtocolSupport { min: 1, max: 1 };
        assert_eq!(
            negotiate_protocol_version(server, client).expect("v1 overlap"),
            1
        );
    }

    #[test]
    fn negotiate_protocol_version_no_overlap_client_too_old() {
        // Server retired v1 (floor raised to 2); a v1-only client is rejected.
        let server = ProtocolSupport { min: 2, max: 2 };
        let client = ProtocolSupport { min: 1, max: 1 };
        let err = negotiate_protocol_version(server, client).unwrap_err();
        assert!(
            err.downcast_ref::<MoshpitError>()
                .is_some_and(|e| *e == MoshpitError::IncompatibleProtocolVersion)
        );
    }

    #[test]
    fn negotiate_protocol_version_no_overlap_client_too_new() {
        // Symmetric: a client whose floor exceeds the server's max is rejected.
        let server = ProtocolSupport { min: 1, max: 1 };
        let client = ProtocolSupport { min: 2, max: 2 };
        let err = negotiate_protocol_version(server, client).unwrap_err();
        assert!(
            err.downcast_ref::<MoshpitError>()
                .is_some_and(|e| *e == MoshpitError::IncompatibleProtocolVersion)
        );
    }

    #[test]
    fn negotiate_sets_placeholder_protocol_version() {
        let n = negotiate(&current(), &current()).expect("negotiate ok");
        assert_eq!(n.protocol_version, PROTOCOL_VERSION);
    }

    #[test]
    fn supported_algorithms_contains_all_known_algorithms() {
        let algos = supported_algorithms();
        assert!(algos.kex.contains(&KEX_X25519_SHA256.to_string()));
        assert!(algos.kex.contains(&KEX_ML_KEM_512_SHA256.to_string()));
        assert!(algos.kex.contains(&KEX_ML_KEM_768_SHA256.to_string()));
        assert!(algos.kex.contains(&KEX_ML_KEM_1024_SHA256.to_string()));
        assert!(algos.kex.contains(&KEX_P384_SHA384.to_string()));
        assert!(algos.kex.contains(&KEX_P256_SHA256.to_string()));
        assert!(algos.aead.contains(&AEAD_AES256_GCM_SIV.to_string()));
        assert!(algos.aead.contains(&AEAD_AES256_GCM.to_string()));
        assert!(algos.aead.contains(&AEAD_CHACHA20_POLY1305.to_string()));
        assert!(algos.aead.contains(&AEAD_AES128_GCM_SIV.to_string()));
        assert!(algos.mac.contains(&MAC_HMAC_SHA512.to_string()));
        assert!(algos.mac.contains(&MAC_HMAC_SHA256.to_string()));
        assert!(algos.kdf.contains(&KDF_HKDF_SHA256.to_string()));
        assert!(algos.kdf.contains(&KDF_HKDF_SHA512.to_string()));
    }
}
