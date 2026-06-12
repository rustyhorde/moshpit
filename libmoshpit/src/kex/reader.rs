// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

use std::{
    collections::BTreeSet,
    fmt::{Debug, Formatter, Result as FmtResult},
    fs::{OpenOptions, create_dir_all, read_to_string, write},
    io::{BufRead, BufReader},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::Result;
use aws_lc_rs::{
    aead::{
        AES_128_GCM_SIV, AES_256_GCM, AES_256_GCM_SIV, Aad, CHACHA20_POLY1305, LessSafeKey,
        NONCE_LEN, Nonce, UnboundKey,
    },
    agreement::{
        ECDH_P256, ECDH_P384, ParsedPublicKey, PrivateKey, UnparsedPublicKey, X25519, agree,
    },
    error::Unspecified,
    hkdf::{HKDF_SHA256, HKDF_SHA384, HKDF_SHA512, Salt},
    kem::{
        Algorithm as KemAlgorithm, Ciphertext, DecapsulationKey, EncapsulationKey, ML_KEM_512,
        ML_KEM_768, ML_KEM_1024,
    },
    rand::fill,
};
#[cfg(feature = "unstable")]
use aws_lc_rs::{
    signature::UnparsedPublicKey as SignatureUnparsedPublicKey,
    unstable::signature::{
        ML_DSA_44, ML_DSA_44_SIGNING, ML_DSA_65, ML_DSA_65_SIGNING, ML_DSA_87, ML_DSA_87_SIGNING,
        PqdsaKeyPair,
    },
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use bon::Builder;
#[cfg(feature = "unstable")]
use bytes::Buf as _;
#[cfg(feature = "unstable")]
use bytes::BytesMut;
use socket2::SockRef;
use tokio::{
    net::UdpSocket,
    process::Command,
    sync::{Mutex, mpsc::UnboundedSender},
};
use tracing::{debug, error, trace};
use uuid::Uuid;

use crate::kex::HostKeyMismatchFn;
use crate::{
    ConnectionReader, Frame, KexEvent, MoshpitError, ServerKex, UuidWrapper,
    kex::TofuFn,
    kex::negotiate::{
        AEAD_AES128_GCM_SIV, AEAD_AES256_GCM, AEAD_AES256_GCM_SIV, AEAD_CHACHA20_POLY1305,
        AlgorithmList, KDF_HKDF_SHA256, KDF_HKDF_SHA384, KDF_HKDF_SHA512, KEX_ML_KEM_512_SHA256,
        KEX_ML_KEM_768_SHA256, KEX_ML_KEM_1024_SHA256, KEX_P256_SHA256, KEX_P384_SHA384,
        KEX_X25519_SHA256, MAC_HMAC_SHA256, MAC_HMAC_SHA512, NegotiatedAlgorithms, ProtocolSupport,
        local_protocol_support, negotiate, negotiate_protocol_version, supported_algorithms,
    },
    load_public_key,
    session::SessionRegistry,
    udp::DiffMode,
};
#[cfg(feature = "unstable")]
use crate::{KEY_ALGORITHM_ML_DSA_44, KEY_ALGORITHM_ML_DSA_65, KEY_ALGORITHM_ML_DSA_87};

const AEAD_KEY_INFO: &[u8] = b"AEAD KEY";
const HMAC_KEY_INFO: &[u8] = b"HMAC KEY";

fn fmt_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

enum ResolvedKexAlgorithm {
    Dh(&'static aws_lc_rs::agreement::Algorithm),
    Kem(&'static KemAlgorithm),
}

enum ClientEphemeral {
    Dh(PrivateKey),
    Kem(DecapsulationKey),
}

#[cfg(feature = "unstable")]
struct IdentityProofContext<'a> {
    client_identity_full: &'a [u8],
    user: &'a [u8],
    client_exchange: &'a [u8],
    server_exchange: &'a [u8],
    salt: &'a [u8],
    negotiated: &'a NegotiatedAlgorithms,
    public_key_path: &'a PathBuf,
}

#[cfg(feature = "unstable")]
struct IdentityTranscriptParts<'a> {
    role: &'a [u8],
    negotiated: &'a NegotiatedAlgorithms,
    user: &'a [u8],
    client_exchange: &'a [u8],
    client_identity: &'a [u8],
    server_identity: &'a [u8],
    server_exchange: &'a [u8],
    salt: &'a [u8],
}

fn resolve_kex_alg(kex: &str) -> Result<ResolvedKexAlgorithm> {
    match kex {
        KEX_X25519_SHA256 => Ok(ResolvedKexAlgorithm::Dh(&X25519)),
        KEX_P384_SHA384 => Ok(ResolvedKexAlgorithm::Dh(&ECDH_P384)),
        KEX_P256_SHA256 => Ok(ResolvedKexAlgorithm::Dh(&ECDH_P256)),
        KEX_ML_KEM_512_SHA256 => Ok(ResolvedKexAlgorithm::Kem(&ML_KEM_512)),
        KEX_ML_KEM_768_SHA256 => Ok(ResolvedKexAlgorithm::Kem(&ML_KEM_768)),
        KEX_ML_KEM_1024_SHA256 => Ok(ResolvedKexAlgorithm::Kem(&ML_KEM_1024)),
        _ => Err(MoshpitError::NoCommonAlgorithm.into()),
    }
}

fn resolve_hkdf_alg(kdf: &str) -> Result<aws_lc_rs::hkdf::Algorithm> {
    match kdf {
        KDF_HKDF_SHA256 => Ok(HKDF_SHA256),
        KDF_HKDF_SHA384 => Ok(HKDF_SHA384),
        KDF_HKDF_SHA512 => Ok(HKDF_SHA512),
        _ => Err(MoshpitError::NoCommonAlgorithm.into()),
    }
}

fn resolve_aead_alg(aead: &str) -> Result<&'static aws_lc_rs::aead::Algorithm> {
    match aead {
        AEAD_AES256_GCM_SIV => Ok(&AES_256_GCM_SIV),
        AEAD_AES256_GCM => Ok(&AES_256_GCM),
        AEAD_CHACHA20_POLY1305 => Ok(&CHACHA20_POLY1305),
        AEAD_AES128_GCM_SIV => Ok(&AES_128_GCM_SIV),
        _ => Err(MoshpitError::NoCommonAlgorithm.into()),
    }
}

fn resolve_hmac_key_type(mac: &str) -> Result<aws_lc_rs::hmac::Algorithm> {
    match mac {
        MAC_HMAC_SHA512 => Ok(HKDF_SHA512.hmac_algorithm()),
        MAC_HMAC_SHA256 => Ok(HKDF_SHA256.hmac_algorithm()),
        _ => Err(MoshpitError::NoCommonAlgorithm.into()),
    }
}

fn derive_session_keys(
    shared_secret: &[u8],
    salt_bytes: &[u8],
    negotiated: &NegotiatedAlgorithms,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let hkdf_alg = resolve_hkdf_alg(&negotiated.kdf)?;
    let aead_alg = resolve_aead_alg(&negotiated.aead)?;
    let hmac_key_type = resolve_hmac_key_type(&negotiated.mac)?;
    let salt = Salt::new(hkdf_alg, salt_bytes);
    let prk = salt.extract(shared_secret);

    let okm_aead = prk.expand(&[AEAD_KEY_INFO], aead_alg)?;
    let mut key_bytes = vec![0u8; aead_alg.key_len()];
    okm_aead.fill(&mut key_bytes)?;

    let mac_key_len = hmac_key_type.digest_algorithm().output_len();
    let okm_hmac = prk.expand(&[HMAC_KEY_INFO], hmac_key_type)?;
    let mut hmac_key_bytes = vec![0u8; mac_key_len];
    okm_hmac.fill(&mut hmac_key_bytes)?;

    Ok((key_bytes, hmac_key_bytes))
}

#[cfg(feature = "unstable")]
fn push_transcript_field(transcript: &mut Vec<u8>, label: &[u8], value: &[u8]) -> Result<()> {
    transcript.extend_from_slice(&u32::try_from(label.len())?.to_be_bytes());
    transcript.extend_from_slice(label);
    transcript.extend_from_slice(&u32::try_from(value.len())?.to_be_bytes());
    transcript.extend_from_slice(value);
    Ok(())
}

#[cfg(feature = "unstable")]
fn identity_transcript(parts: &IdentityTranscriptParts<'_>) -> Result<Vec<u8>> {
    let mut transcript = b"moshpit-identity-proof-v1".to_vec();
    push_transcript_field(&mut transcript, b"role", parts.role)?;
    push_transcript_field(&mut transcript, b"kex", parts.negotiated.kex.as_bytes())?;
    push_transcript_field(&mut transcript, b"aead", parts.negotiated.aead.as_bytes())?;
    push_transcript_field(&mut transcript, b"mac", parts.negotiated.mac.as_bytes())?;
    push_transcript_field(&mut transcript, b"kdf", parts.negotiated.kdf.as_bytes())?;
    push_transcript_field(&mut transcript, b"user", parts.user)?;
    push_transcript_field(&mut transcript, b"client-exchange", parts.client_exchange)?;
    push_transcript_field(&mut transcript, b"client-identity", parts.client_identity)?;
    push_transcript_field(&mut transcript, b"server-identity", parts.server_identity)?;
    push_transcript_field(&mut transcript, b"server-exchange", parts.server_exchange)?;
    push_transcript_field(&mut transcript, b"salt", parts.salt)?;
    Ok(transcript)
}

#[cfg(feature = "unstable")]
fn is_ml_dsa_algorithm(key_alg: &str) -> bool {
    matches!(
        key_alg,
        KEY_ALGORITHM_ML_DSA_44 | KEY_ALGORITHM_ML_DSA_65 | KEY_ALGORITHM_ML_DSA_87
    )
}

/// Parse an SSH-format ML-DSA public key blob into `(algorithm, key_bytes)`.
///
/// Splits on whitespace, base64-decodes the key part, then walks two
/// length-prefixed fields (algorithm name, public key). Exposed
/// (`#[doc(hidden)]`) so the fuzz harness can drive the base64 + length-prefix
/// parsing on arbitrary bytes; not part of the stable API.
///
/// # Errors
/// If the blob is not a valid SSH-format public key.
#[cfg(feature = "unstable")]
#[doc(hidden)]
pub fn parse_full_public_key(full_public_key: &[u8]) -> Result<(String, Vec<u8>)> {
    let pub_key_str = String::from_utf8_lossy(full_public_key);
    let pub_key_parts: Vec<&str> = pub_key_str.split_whitespace().collect();
    if pub_key_parts.len() != 3 {
        return Err(MoshpitError::InvalidKeyHeader.into());
    }
    let decoded = STANDARD.decode(pub_key_parts[1].as_bytes())?;
    let mut bytes = BytesMut::from(&decoded[..]);
    if bytes.remaining() < 4 {
        return Err(MoshpitError::InvalidKeyHeader.into());
    }
    let key_alg_len = usize::try_from(bytes.get_u32())?;
    if bytes.remaining() < key_alg_len + 4 {
        return Err(MoshpitError::InvalidKeyHeader.into());
    }
    let key_alg = bytes.split_to(key_alg_len);
    let key_alg = std::str::from_utf8(&key_alg)
        .map_err(|_| MoshpitError::InvalidKeyHeader)?
        .to_string();
    let public_key_len = usize::try_from(bytes.get_u32())?;
    if bytes.remaining() < public_key_len {
        return Err(MoshpitError::InvalidKeyHeader.into());
    }
    let public_key = bytes.split_to(public_key_len).to_vec();
    Ok((key_alg, public_key))
}

#[cfg(feature = "unstable")]
fn sign_identity_transcript(
    key_alg: &str,
    private_key: &[u8],
    transcript: &[u8],
) -> Result<Vec<u8>> {
    let signing_alg = match key_alg {
        KEY_ALGORITHM_ML_DSA_44 => &ML_DSA_44_SIGNING,
        KEY_ALGORITHM_ML_DSA_65 => &ML_DSA_65_SIGNING,
        KEY_ALGORITHM_ML_DSA_87 => &ML_DSA_87_SIGNING,
        _ => return Err(MoshpitError::InvalidKeyHeader.into()),
    };
    let key_pair = PqdsaKeyPair::from_raw_private_key(signing_alg, private_key)?;
    let mut signature = vec![0u8; signing_alg.signature_len()];
    let signature_len = key_pair.sign(transcript, &mut signature)?;
    signature.truncate(signature_len);
    Ok(signature)
}

#[cfg(feature = "unstable")]
fn verify_identity_transcript(
    key_alg: &str,
    public_key: &[u8],
    transcript: &[u8],
    signature: &[u8],
) -> Result<()> {
    let verification_alg = match key_alg {
        KEY_ALGORITHM_ML_DSA_44 => &ML_DSA_44,
        KEY_ALGORITHM_ML_DSA_65 => &ML_DSA_65,
        KEY_ALGORITHM_ML_DSA_87 => &ML_DSA_87,
        _ => return Err(MoshpitError::InvalidKeyHeader.into()),
    };
    let public_key = SignatureUnparsedPublicKey::new(verification_alg, public_key);
    public_key
        .verify(transcript, signature)
        .map_err(|_| MoshpitError::KeyNotEstablished.into())
}

/// The key exchange reader for the moshpit
#[derive(Builder)]
pub struct KexReader {
    /// The connection reader
    reader: ConnectionReader,
    /// The frame sender
    tx: UnboundedSender<Frame>,
    /// The key exchange event sender
    tx_event: UnboundedSender<KexEvent>,
    /// The session UUID the client is requesting to resume (None for fresh connections).
    requested_session_uuid: Option<Uuid>,
    /// The server destination hostname or IP
    server_destination: Option<String>,
    /// The callback for TOFU interactive prompt
    tofu_fn: Option<TofuFn>,
    /// Callback for known-host key mismatch replacement prompt.
    host_key_mismatch_fn: Option<HostKeyMismatchFn>,
    /// UDP diff transport mode requested by this client.  When `Datagram` or
    /// `StateSync`, the client sends a `Frame::ClientOptions(1)` or `(2)` before
    /// the `Check` frame so the server can enable the appropriate delivery path
    /// for this session.  Defaults to `Reliable` (no `ClientOptions` frame sent).
    #[builder(default)]
    diff_mode: DiffMode,
    /// Algorithm list offered by this client, sent via `KexInit` before `Initialize`.
    /// Defaults to [`supported_algorithms()`].
    #[builder(default = supported_algorithms())]
    client_algos: AlgorithmList,
    /// Algorithm preferences for server mode.  The server sends this list in its
    /// `KexInit` frame and negotiates using server-preference order.
    /// Defaults to [`supported_algorithms()`].
    #[builder(default = supported_algorithms())]
    server_preferred_algos: AlgorithmList,
    /// Wire protocol version range this endpoint advertises in `KexInit` and uses
    /// as the local side of version negotiation.  Set from
    /// [`KexConfig::protocol_support`](crate::config::KexConfig::protocol_support);
    /// defaults to the build range.
    #[builder(default = local_protocol_support())]
    protocol_support: ProtocolSupport,
    /// Username sent in `Initialize` frame (client mode only).
    #[builder(default)]
    user: String,
    /// Long-term identity public key bytes sent in `Initialize` for authorized-keys
    /// validation on the server (client mode only).
    #[builder(default)]
    full_public_key_bytes: Vec<u8>,
    /// Long-term identity key algorithm string (client mode only).
    #[cfg(feature = "unstable")]
    #[builder(default)]
    client_identity_key_algorithm: String,
    /// Long-term identity private key bytes for optional transcript proofs.
    #[cfg(feature = "unstable")]
    #[builder(default)]
    client_identity_private_key: Vec<u8>,
    /// Environment variable pairs to send to the server via `ClientEnv` (client mode only).
    /// Filtered from the client's environment using the `send_env` config patterns.
    #[builder(default)]
    send_env: Vec<(String, String)>,
    /// Additional PATH directories to prepend to the server's `server_path` (client mode only).
    /// Sent via the `ClientEnv` frame; ignored by the server when `path_locked = true`.
    #[builder(default)]
    send_path: Vec<String>,
    /// Agent socket path.  When set, identity-key operations (signing) are
    /// delegated to the running `mpa` agent instead of using a local private key.
    agent_socket: Option<PathBuf>,
    /// Fingerprint of the agent identity to use for signing.
    agent_fingerprint: Option<String>,
}

impl Debug for KexReader {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        let mut debug = f.debug_struct("KexReader");
        let _ = debug
            .field("reader", &self.reader)
            .field("tx", &self.tx)
            .field("tx_event", &self.tx_event)
            .field("requested_session_uuid", &self.requested_session_uuid)
            .field("server_destination", &self.server_destination)
            .field(
                "tofu_fn",
                &if self.tofu_fn.is_some() {
                    "Some(<fn>)"
                } else {
                    "None"
                },
            )
            .field(
                "host_key_mismatch_fn",
                &if self.host_key_mismatch_fn.is_some() {
                    "Some(<fn>)"
                } else {
                    "None"
                },
            )
            .field("diff_mode", &self.diff_mode)
            .field("client_algos", &self.client_algos)
            .field("server_preferred_algos", &self.server_preferred_algos)
            .field("protocol_support", &self.protocol_support)
            .field("user", &self.user)
            .field("full_public_key_bytes", &"<redacted>")
            .field("send_env", &"<redacted>")
            .field("send_path", &self.send_path);
        #[cfg(feature = "unstable")]
        let _ = debug
            .field(
                "client_identity_key_algorithm",
                &self.client_identity_key_algorithm,
            )
            .field("client_identity_private_key", &"<redacted>");
        let _ = debug
            .field("agent_socket", &self.agent_socket)
            .field("agent_fingerprint", &self.agent_fingerprint);
        debug.finish()
    }
}

impl KexReader {
    /// Perform the client side of a key exchange
    ///
    /// # Errors
    ///
    #[cfg_attr(nightly, allow(clippy::too_many_lines))]
    pub async fn client_kex(&mut self) -> Result<()> {
        trace!("client_kex: waiting for KexInit from server");
        let negotiated = match self.reader.read_frame().await? {
            Some(Frame::KexInit(server_algos, server_proto)) => {
                trace!(
                    "client_kex: KexInit received — server offered: kex={:?} aead={:?} mac={:?} kdf={:?} proto={}-{}",
                    server_algos.kex,
                    server_algos.aead,
                    server_algos.mac,
                    server_algos.kdf,
                    server_proto.min,
                    server_proto.max
                );
                // Server-preferred negotiation: first of server's list that client supports.
                let mut negotiated = match negotiate(&server_algos, &self.client_algos) {
                    Ok(n) => n,
                    Err(e) => {
                        error!(
                            "client_kex: no algorithm in common — \
                             server offered kex={:?} aead={:?} mac={:?} kdf={:?}, \
                             client supports kex={:?} aead={:?} mac={:?} kdf={:?}",
                            server_algos.kex,
                            server_algos.aead,
                            server_algos.mac,
                            server_algos.kdf,
                            self.client_algos.kex,
                            self.client_algos.aead,
                            self.client_algos.mac,
                            self.client_algos.kdf,
                        );
                        drop(self.tx_event.send(KexEvent::NoCommonAlgorithm));
                        return Err(e);
                    }
                };
                // Negotiate the wire protocol version from both advertised ranges.
                negotiated.protocol_version =
                    match negotiate_protocol_version(self.protocol_support, server_proto) {
                        Ok(v) => v,
                        Err(e) => {
                            error!(
                                "client_kex: incompatible wire protocol version — \
                                 client supports [{}, {}], server supports [{}, {}]",
                                self.protocol_support.min,
                                self.protocol_support.max,
                                server_proto.min,
                                server_proto.max,
                            );
                            drop(self.tx_event.send(KexEvent::Failure));
                            return Err(e);
                        }
                    };
                trace!(
                    "client_kex: negotiated: kex={} aead={} mac={} kdf={} proto=v{}",
                    negotiated.kex,
                    negotiated.aead,
                    negotiated.mac,
                    negotiated.kdf,
                    negotiated.protocol_version
                );
                negotiated
            }
            Some(Frame::KexFailure) => {
                error!("client_kex: server rejected key exchange (KexFailure before KexInit)");
                drop(self.tx_event.send(KexEvent::NoCommonAlgorithm));
                return Err(MoshpitError::NoCommonAlgorithm.into());
            }
            None => {
                error!("client_kex: server closed connection before sending KexInit");
                drop(self.tx_event.send(KexEvent::Failure));
                return Err(anyhow::anyhow!("Server closed connection before KexInit"));
            }
            Some(other) => {
                error!(
                    "client_kex: expected KexInit but got frame id={}",
                    other.id()
                );
                drop(self.tx_event.send(KexEvent::Failure));
                return Err(MoshpitError::KeyNotEstablished.into());
            }
        };

        // Resolve algorithms from the negotiated names before generating the EPK.
        let kex_alg = resolve_kex_alg(&negotiated.kex)?;
        let aead_alg = resolve_aead_alg(&negotiated.aead)?;
        let kex_aead_log = negotiated.aead.clone();
        let kex_mac_log = negotiated.mac.clone();

        // Emit the negotiated algorithm set so the runtime can construct the right crypto
        // primitives when it later receives KeyMaterial and HMACKeyMaterial.
        drop(
            self.tx_event
                .send(KexEvent::NegotiatedAlgorithms(negotiated.clone())),
        );

        let (client_ephemeral, epk_pub_bytes) = match kex_alg {
            ResolvedKexAlgorithm::Dh(agreement_alg) => {
                let epk = PrivateKey::generate(agreement_alg)?;
                let epk_pub = epk.compute_public_key()?;
                (ClientEphemeral::Dh(epk), epk_pub.as_ref().to_vec())
            }
            ResolvedKexAlgorithm::Kem(kem_algorithm) => {
                let decapsulation_key = DecapsulationKey::generate(kem_algorithm)?;
                let encapsulation_key = decapsulation_key.encapsulation_key()?;
                let encapsulation_key_bytes = encapsulation_key.key_bytes()?;
                (
                    ClientEphemeral::Kem(decapsulation_key),
                    encapsulation_key_bytes.as_ref().to_vec(),
                )
            }
        };

        // Send Initialize or ResumeRequest with our ephemeral public key + identity key.
        let user_bytes = self.user.as_bytes().to_vec();
        let identity_pk = self.full_public_key_bytes.clone();
        #[cfg(feature = "unstable")]
        let transcript_user = user_bytes.clone();
        #[cfg(feature = "unstable")]
        let transcript_client_exchange = epk_pub_bytes.clone();
        if let Some(session_uuid) = self.requested_session_uuid {
            self.tx.send(Frame::ResumeRequest(
                UuidWrapper::new(session_uuid),
                user_bytes,
                epk_pub_bytes.clone(),
                identity_pk,
            ))?;
        } else {
            self.tx.send(Frame::Initialize(
                user_bytes,
                epk_pub_bytes.clone(),
                identity_pk,
            ))?;
        }

        trace!("client_kex: waiting for PeerInitialize");
        match self.reader.read_frame().await? {
            Some(Frame::KexFailure) => {
                error!(
                    "client_kex: server rejected key exchange (KexFailure before PeerInitialize)"
                );
                drop(self.tx_event.send(KexEvent::NoCommonAlgorithm));
                return Err(MoshpitError::NoCommonAlgorithm.into());
            }
            None => {
                error!("client_kex: server closed connection before sending PeerInitialize");
                return Err(anyhow::anyhow!(
                    "Server closed connection during key exchange"
                ));
            }
            Some(Frame::PeerInitialize(identity_pk, ephemeral_pk, salt_bytes)) => {
                trace!(
                    "client_kex: received PeerInitialize (identity={} bytes, ephemeral={} bytes)",
                    identity_pk.len(),
                    ephemeral_pk.len()
                );

                if let Some(host) = &self.server_destination {
                    trace!("client_kex: checking known_hosts for host '{host}'");
                    match check_known_hosts(
                        host,
                        &identity_pk,
                        self.tofu_fn.as_ref(),
                        self.host_key_mismatch_fn.as_ref(),
                    ) {
                        Err(e) => {
                            error!("client_kex: known_hosts check error for '{host}': {e}");
                            drop(self.tx_event.send(KexEvent::Failure));
                            return Err(e);
                        }
                        Ok(false) => {
                            error!("client_kex: host key verification rejected for '{host}'");
                            drop(self.tx_event.send(KexEvent::Failure));
                            return Err(MoshpitError::HostKeyRejected.into());
                        }
                        Ok(true) => {
                            trace!("client_kex: host key verified for '{host}'");
                        }
                    }
                } else {
                    trace!("client_kex: no server_destination set, skipping host-key check");
                }

                #[cfg(feature = "unstable")]
                {
                    // Derive the algorithm from the public-key bytes rather than from
                    // client_identity_key_algorithm, which is empty on the agent path.
                    let effective_alg = parse_full_public_key(&self.full_public_key_bytes)
                        .map(|(alg, _)| alg)
                        .unwrap_or_default();
                    if is_ml_dsa_algorithm(&effective_alg) {
                        let transcript = identity_transcript(&IdentityTranscriptParts {
                            role: b"client",
                            negotiated: &negotiated,
                            user: &transcript_user,
                            client_exchange: &transcript_client_exchange,
                            client_identity: &self.full_public_key_bytes,
                            server_identity: &identity_pk,
                            server_exchange: &ephemeral_pk,
                            salt: &salt_bytes,
                        })?;
                        #[cfg(unix)]
                        let signature = if let (Some(socket), Some(fp)) =
                            (&self.agent_socket, &self.agent_fingerprint)
                        {
                            // Delegate signing to the agent — private key stays in agent memory.
                            crate::agent::client::AgentClient::new(socket.clone())
                                .sign(fp, &transcript)
                                .await?
                        } else {
                            sign_identity_transcript(
                                &effective_alg,
                                &self.client_identity_private_key,
                                &transcript,
                            )?
                        };
                        #[cfg(not(unix))]
                        let signature = sign_identity_transcript(
                            &effective_alg,
                            &self.client_identity_private_key,
                            &transcript,
                        )?;
                        self.tx.send(Frame::IdentityProof(signature))?;
                    }
                }

                let shared_secret = match client_ephemeral {
                    ClientEphemeral::Dh(epk) => {
                        let ResolvedKexAlgorithm::Dh(agreement_alg) =
                            resolve_kex_alg(&negotiated.kex)?
                        else {
                            return Err(MoshpitError::NoCommonAlgorithm.into());
                        };
                        let peer_public_key = UnparsedPublicKey::new(agreement_alg, &ephemeral_pk);
                        trace!("client_kex: running ECDH agree()");
                        agree(&epk, peer_public_key, Unspecified, |key_material| {
                            Ok(key_material.to_vec())
                        })?
                    }
                    ClientEphemeral::Kem(decapsulation_key) => {
                        trace!("client_kex: running ML-KEM decapsulate()");
                        decapsulation_key
                            .decapsulate(Ciphertext::from(ephemeral_pk.as_slice()))?
                            .as_ref()
                            .to_vec()
                    }
                };

                let (key_bytes, hmac_key_bytes) =
                    derive_session_keys(&shared_secret, &salt_bytes, &negotiated)?;
                debug!(
                    side = "client",
                    aead = %kex_aead_log,
                    key_len = key_bytes.len(),
                    key_hex = %fmt_hex(&key_bytes),
                    "kex: derived AEAD key"
                );
                debug!(
                    side = "client",
                    mac = %kex_mac_log,
                    hmac_key_len = hmac_key_bytes.len(),
                    hmac_key_hex = %fmt_hex(&hmac_key_bytes),
                    "kex: derived HMAC key"
                );

                self.tx_event
                    .send(KexEvent::KeyMaterial(key_bytes.clone()))
                    .map_err(|_| Unspecified)?;
                self.tx_event
                    .send(KexEvent::HMACKeyMaterial(hmac_key_bytes))
                    .map_err(|_| Unspecified)?;

                let rnk = LessSafeKey::new(UnboundKey::new(aead_alg, &key_bytes)?);
                let mut check = b"Yoda".to_vec();
                let mut nonce_bytes = [0u8; NONCE_LEN];
                fill(&mut nonce_bytes)?;
                let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes)?;
                rnk.seal_in_place_append_tag(nonce, Aad::empty(), &mut check)?;

                match self.diff_mode {
                    DiffMode::Datagram => self.tx.send(Frame::ClientOptions(1))?,
                    DiffMode::StateSync => self.tx.send(Frame::ClientOptions(2))?,
                    DiffMode::Reliable => {}
                }
                if !self.send_env.is_empty() || !self.send_path.is_empty() {
                    self.tx.send(Frame::ClientEnv(
                        self.send_env.clone(),
                        self.send_path.clone(),
                    ))?;
                }
                self.tx.send(Frame::Check(nonce_bytes, check))?;
                trace!("client_kex: key exchange secret established, Check frame sent");
            }
            Some(other) => {
                error!(
                    "client_kex: expected PeerInitialize but got frame id={}",
                    other.id()
                );
                drop(self.tx_event.send(KexEvent::Failure));
                return Err(MoshpitError::KeyNotEstablished.into());
            }
        }

        trace!("client_kex: waiting for KeyAgreement");
        match self.reader.read_frame().await? {
            Some(Frame::KeyAgreement(uuid)) => {
                trace!("client_kex: received KeyAgreement uuid={}", uuid);
                self.tx_event
                    .send(KexEvent::Uuid(*uuid.as_ref()))
                    .map_err(|_| Unspecified)?;
            }
            Some(other) => {
                error!(
                    "client_kex: expected KeyAgreement but got frame id={}",
                    other.id()
                );
                return Err(MoshpitError::KeyNotEstablished.into());
            }
            None => {
                error!("client_kex: server closed connection before sending KeyAgreement");
                return Err(anyhow::anyhow!(
                    "Server closed connection before KeyAgreement"
                ));
            }
        }

        // Receive stable session token (sent by server after KeyAgreement)
        trace!("client_kex: waiting for SessionToken");
        match self.reader.read_frame().await? {
            Some(Frame::SessionToken(session_uuid_wrapper)) => {
                let session_uuid = *session_uuid_wrapper.as_ref();
                let is_resume = self.requested_session_uuid == Some(session_uuid);
                trace!("client_kex: received SessionToken {session_uuid} (resume={is_resume})");
                self.tx_event
                    .send(KexEvent::SessionInfo(session_uuid, is_resume))
                    .map_err(|_| Unspecified)?;
            }
            Some(other) => {
                error!(
                    "client_kex: expected SessionToken but got frame id={}",
                    other.id()
                );
                return Err(MoshpitError::KeyNotEstablished.into());
            }
            None => {
                error!("client_kex: server closed connection before sending SessionToken");
                return Err(anyhow::anyhow!(
                    "Server closed connection before SessionToken"
                ));
            }
        }

        trace!("client_kex: waiting for MoshpitsAddr");
        match self.reader.read_frame().await? {
            Some(Frame::MoshpitsAddr(addr)) => {
                trace!("client_kex: received MoshpitsAddr {addr}");
                self.tx_event
                    .send(KexEvent::MoshpitsAddr(addr))
                    .map_err(|_| Unspecified)?;
            }
            Some(other) => {
                error!(
                    "client_kex: expected MoshpitsAddr but got frame id={}",
                    other.id()
                );
                return Err(MoshpitError::KeyNotEstablished.into());
            }
            None => {
                error!("client_kex: server closed connection before sending MoshpitsAddr");
                return Err(anyhow::anyhow!(
                    "Server closed connection before MoshpitsAddr"
                ));
            }
        }

        trace!("client_kex: complete");
        Ok(())
    }

    /// Perform the server side of a key exchange
    ///
    /// # Errors
    ///
    #[cfg_attr(nightly, allow(clippy::too_many_lines))]
    pub async fn server_kex(
        &mut self,
        socket_addr: SocketAddr,
        port_pool: Arc<Mutex<BTreeSet<u16>>>,
        public_key_path: &PathBuf,
        session_registry: Option<SessionRegistry>,
    ) -> Result<(ServerKex, Arc<UdpSocket>)> {
        trace!("server_kex: waiting for KexInit from client");
        let negotiated = match self.reader.read_frame().await? {
            Some(Frame::KexInit(client_algos, client_proto)) => {
                trace!(
                    "server_kex: KexInit received — client offered: kex={:?} aead={:?} mac={:?} kdf={:?} proto={}-{}",
                    client_algos.kex,
                    client_algos.aead,
                    client_algos.mac,
                    client_algos.kdf,
                    client_proto.min,
                    client_proto.max
                );
                // Advertise our own capabilities first — before any negotiation —
                // so the client always receives our KexInit and can self-diagnose a
                // mismatch precisely (we still reject below via KexFailure when the
                // ranges don't overlap).  The client needs this to pick the ephemeral
                // key algorithm before sending Initialize.
                self.tx.send(Frame::KexInit(
                    self.server_preferred_algos.clone(),
                    self.protocol_support,
                ))?;
                trace!("server_kex: sent KexInit to client");

                // Server-preferred: first of server's list that client also offered.
                let Ok(mut negotiated) = negotiate(&self.server_preferred_algos, &client_algos)
                else {
                    error!(
                        "server_kex: no algorithm in common — \
                         server preferred kex={:?} aead={:?} mac={:?} kdf={:?}, \
                         client offered kex={:?} aead={:?} mac={:?} kdf={:?}",
                        self.server_preferred_algos.kex,
                        self.server_preferred_algos.aead,
                        self.server_preferred_algos.mac,
                        self.server_preferred_algos.kdf,
                        client_algos.kex,
                        client_algos.aead,
                        client_algos.mac,
                        client_algos.kdf,
                    );
                    return Err(MoshpitError::NoCommonAlgorithm.into());
                };
                // Negotiate the wire protocol version from both advertised ranges.
                negotiated.protocol_version =
                    match negotiate_protocol_version(self.protocol_support, client_proto) {
                        Ok(v) => v,
                        Err(e) => {
                            error!(
                                "server_kex: incompatible wire protocol version — \
                                 server supports [{}, {}], client supports [{}, {}]",
                                self.protocol_support.min,
                                self.protocol_support.max,
                                client_proto.min,
                                client_proto.max,
                            );
                            return Err(e);
                        }
                    };
                trace!(
                    "server_kex: negotiated: kex={} aead={} mac={} kdf={} proto=v{}",
                    negotiated.kex,
                    negotiated.aead,
                    negotiated.mac,
                    negotiated.kdf,
                    negotiated.protocol_version
                );
                negotiated
            }
            None => {
                error!("server_kex: client closed connection before sending KexInit");
                return Err(MoshpitError::InvalidFrame.into());
            }
            Some(other) => {
                error!(
                    "server_kex: expected KexInit but got frame id={}",
                    other.id()
                );
                return Err(MoshpitError::InvalidFrame.into());
            }
        };

        trace!("server_kex: waiting for Initialize/ResumeRequest from client");
        let (rnk, user_str, shell, requested_session_uuid_opt) =
            match self.reader.read_frame().await? {
                None => {
                    error!("server_kex: client closed connection before sending Initialize");
                    return Err(MoshpitError::InvalidFrame.into());
                }
                Some(frame) => {
                    let (user, pk, fpk, req_uuid) = match frame {
                        Frame::Initialize(user, pk, fpk) => {
                            trace!("server_kex: received Initialize from client");
                            (user, pk, fpk, None)
                        }
                        Frame::ResumeRequest(session_uuid_wrapper, user, pk, fpk) => {
                            trace!(
                                "server_kex: received ResumeRequest for session {}",
                                session_uuid_wrapper
                            );
                            (user, pk, fpk, Some(*session_uuid_wrapper.as_ref()))
                        }
                        other => {
                            error!(
                                "server_kex: expected Initialize/ResumeRequest but got frame id={}",
                                other.id()
                            );
                            return Err(MoshpitError::InvalidFrame.into());
                        }
                    };
                    let user_str = String::from_utf8_lossy(&user).to_string();
                    trace!(
                        "server_kex: validating system account for user '{}'",
                        user_str
                    );
                    let (home_dir, shell) = if self.validate_user(&user_str).await? {
                        trace!(
                            "server_kex: user '{}' is valid, getting home/shell",
                            user_str
                        );
                        self.get_home_dir_shell(&user_str).await?
                    } else {
                        error!("server_kex: '{}' is not a valid system account", user_str);
                        return Err(MoshpitError::KeyNotEstablished.into());
                    };
                    trace!(
                        "server_kex: home_dir='{}', checking authorized_keys",
                        home_dir
                    );
                    if !check_authorized_keys(&home_dir, &fpk)? {
                        error!(
                            "server_kex: client pubkey not in '{home_dir}/.mp/authorized_keys' \
                             (file missing, wrong permissions, or key not added)",
                        );
                        return Err(MoshpitError::KeyNotEstablished.into());
                    }
                    trace!("server_kex: authorized_keys OK, sending NegotiatedAlgorithms event");
                    drop(
                        self.tx_event
                            .send(KexEvent::NegotiatedAlgorithms(negotiated.clone())),
                    );
                    let initialize_result = self.handle_initialize(
                        &pk,
                        &negotiated,
                        &self.tx_event.clone(),
                        public_key_path,
                    )?;
                    let rnk = initialize_result.0;
                    #[cfg(feature = "unstable")]
                    self.handle_identity_proof_if_required(IdentityProofContext {
                        client_identity_full: &fpk,
                        user: &user,
                        client_exchange: &pk,
                        server_exchange: &initialize_result.1,
                        salt: &initialize_result.2,
                        negotiated: &negotiated,
                        public_key_path,
                    })
                    .await?;
                    trace!("server_kex: PeerInitialize sent to client");
                    (rnk, user_str, shell, req_uuid)
                }
            };

        // Read the next frame: clients may send `ClientOptions` (diff mode),
        // `ClientEnv` (env/path passthrough), both in that order, or go straight
        // to `Check`.  Any other frame type is a protocol error.
        trace!("server_kex: waiting for ClientOptions, ClientEnv, or Check frame");
        let mut client_env: Vec<(String, String)> = Vec::new();
        let mut client_extra_path: Vec<String> = Vec::new();
        let negotiated_diff_mode = match self.reader.read_frame().await? {
            Some(Frame::ClientOptions(mode_byte)) => {
                let mode = match mode_byte {
                    1 => {
                        trace!("server_kex: client requested DiffMode::Datagram");
                        DiffMode::Datagram
                    }
                    2 => {
                        trace!("server_kex: client requested DiffMode::StateSync");
                        DiffMode::StateSync
                    }
                    other => {
                        trace!("server_kex: ClientOptions mode_byte={other}, using Reliable");
                        DiffMode::Reliable
                    }
                };
                // After ClientOptions, expect ClientEnv or Check
                match self.reader.read_frame().await? {
                    Some(Frame::ClientEnv(env, path)) => {
                        trace!(
                            "server_kex: received ClientEnv ({} vars, {} path entries) after ClientOptions",
                            env.len(),
                            path.len()
                        );
                        client_env = env;
                        client_extra_path = path;
                        // Now read Check
                        match self.reader.read_frame().await? {
                            Some(Frame::Check(nonce, enc)) => {
                                trace!(
                                    "server_kex: received Check frame after ClientEnv, verifying"
                                );
                                self.handle_check(&rnk, nonce, enc, &self.tx_event.clone())?;
                                trace!("server_kex: Check verified, KeyAgreement sent");
                            }
                            Some(other) => {
                                error!(
                                    "server_kex: expected Check after ClientEnv but got frame id={}",
                                    other.id()
                                );
                                return Err(MoshpitError::InvalidFrame.into());
                            }
                            None => {
                                error!("server_kex: client closed connection after ClientEnv");
                                return Err(MoshpitError::InvalidFrame.into());
                            }
                        }
                    }
                    Some(Frame::Check(nonce, enc)) => {
                        trace!("server_kex: received Check frame after ClientOptions, verifying");
                        self.handle_check(&rnk, nonce, enc, &self.tx_event.clone())?;
                        trace!("server_kex: Check verified, KeyAgreement sent");
                    }
                    Some(other) => {
                        error!(
                            "server_kex: expected ClientEnv or Check after ClientOptions but got frame id={}",
                            other.id()
                        );
                        return Err(MoshpitError::InvalidFrame.into());
                    }
                    None => {
                        error!("server_kex: client closed connection after ClientOptions");
                        return Err(MoshpitError::InvalidFrame.into());
                    }
                }
                mode
            }
            Some(Frame::ClientEnv(env, path)) => {
                trace!(
                    "server_kex: received ClientEnv ({} vars, {} path entries)",
                    env.len(),
                    path.len()
                );
                client_env = env;
                client_extra_path = path;
                // Now read Check
                match self.reader.read_frame().await? {
                    Some(Frame::Check(nonce, enc)) => {
                        trace!("server_kex: received Check frame after ClientEnv, verifying");
                        self.handle_check(&rnk, nonce, enc, &self.tx_event.clone())?;
                        trace!("server_kex: Check verified, KeyAgreement sent");
                    }
                    Some(other) => {
                        error!(
                            "server_kex: expected Check after ClientEnv but got frame id={}",
                            other.id()
                        );
                        return Err(MoshpitError::InvalidFrame.into());
                    }
                    None => {
                        error!("server_kex: client closed connection after ClientEnv");
                        return Err(MoshpitError::InvalidFrame.into());
                    }
                }
                DiffMode::Reliable
            }
            Some(Frame::Check(nonce, enc)) => {
                trace!("server_kex: received Check frame (no ClientOptions/ClientEnv), verifying");
                self.handle_check(&rnk, nonce, enc, &self.tx_event.clone())?;
                trace!("server_kex: Check verified, KeyAgreement sent");
                DiffMode::Reliable
            }
            Some(other) => {
                error!(
                    "server_kex: expected ClientOptions, ClientEnv, or Check but got frame id={}",
                    other.id()
                );
                return Err(MoshpitError::InvalidFrame.into());
            }
            None => {
                error!("server_kex: client closed connection before sending Check");
                return Err(MoshpitError::InvalidFrame.into());
            }
        };

        // Determine session UUID: reuse the requested session if user matches,
        // else create new.  Any live connection on the same session will be
        // displaced by `resolve_session` when it cancels the old conn_token.
        let (session_uuid, is_resume) = match (requested_session_uuid_opt, &session_registry) {
            (Some(req_uuid), Some(registry)) => {
                let reg = registry.lock().await;
                if let Some(stored_user) = reg.get(&req_uuid) {
                    if *stored_user == user_str {
                        (req_uuid, true)
                    } else {
                        (Uuid::new_v4(), false)
                    }
                } else {
                    (Uuid::new_v4(), false)
                }
            }
            _ => (Uuid::new_v4(), false),
        };

        // Register new sessions in the lightweight registry
        if !is_resume && let Some(ref registry) = session_registry {
            let mut reg = registry.lock().await;
            drop(reg.insert(session_uuid, user_str.clone()));
        }

        // Inform the client of its stable session UUID
        self.tx
            .send(Frame::SessionToken(UuidWrapper::new(session_uuid)))?;

        let udp_arc = self.handle_udp_setup(socket_addr, port_pool).await?;

        let skex = ServerKex::builder()
            .user(user_str)
            .shell(shell)
            .session_uuid(session_uuid)
            .is_resume(is_resume)
            .diff_mode(negotiated_diff_mode)
            .negotiated_algorithms(negotiated)
            .client_env(client_env)
            .client_extra_path(client_extra_path)
            .build();

        Ok((skex, udp_arc))
    }

    #[cfg(feature = "unstable")]
    async fn handle_identity_proof_if_required(
        &mut self,
        context: IdentityProofContext<'_>,
    ) -> Result<()> {
        let (key_alg, public_key) = parse_full_public_key(context.client_identity_full)?;
        if !is_ml_dsa_algorithm(&key_alg) {
            return Ok(());
        }

        let signature = match self.reader.read_frame().await? {
            Some(Frame::IdentityProof(signature)) => signature,
            Some(other) => {
                error!(
                    "server_kex: expected IdentityProof for ML-DSA key but got frame id={}",
                    other.id()
                );
                return Err(MoshpitError::KeyNotEstablished.into());
            }
            None => {
                error!("server_kex: client closed before sending ML-DSA IdentityProof");
                return Err(MoshpitError::KeyNotEstablished.into());
            }
        };
        let (_, server_identity_public) = load_public_key(context.public_key_path)?;
        let transcript = identity_transcript(&IdentityTranscriptParts {
            role: b"client",
            negotiated: context.negotiated,
            user: context.user,
            client_exchange: context.client_exchange,
            client_identity: context.client_identity_full,
            server_identity: &server_identity_public,
            server_exchange: context.server_exchange,
            salt: context.salt,
        })?;
        verify_identity_transcript(&key_alg, &public_key, &transcript, &signature)
    }

    fn handle_initialize(
        &mut self,
        pk: &[u8],
        negotiated: &NegotiatedAlgorithms,
        tx_event: &UnboundedSender<KexEvent>,
        public_key_path: &PathBuf,
    ) -> Result<(LessSafeKey, Vec<u8>, Vec<u8>)> {
        let kex_alg = resolve_kex_alg(&negotiated.kex)?;
        let aead_alg = resolve_aead_alg(&negotiated.aead)?;
        let kex_aead_log = negotiated.aead.clone();
        let kex_mac_log = negotiated.mac.clone();

        // Load only the server's identity public key bytes for host authentication
        let (_, identity_pub_key_bytes) = load_public_key(public_key_path)?;

        // Generate a (non-secret) salt value
        let mut salt_bytes = [0u8; 32];
        fill(&mut salt_bytes)?;

        let (server_ephemeral_or_ciphertext, shared_secret) = match kex_alg {
            ResolvedKexAlgorithm::Dh(agreement_alg) => {
                let ephemeral_priv = PrivateKey::generate(agreement_alg)?;
                let ephemeral_pub = ephemeral_priv.compute_public_key()?;
                let unparsed_public_key = UnparsedPublicKey::new(agreement_alg, pk);
                let parsed_public_key = ParsedPublicKey::try_from(&unparsed_public_key)?;
                let shared_secret = agree(
                    &ephemeral_priv,
                    parsed_public_key,
                    Unspecified,
                    |key_material| Ok(key_material.to_vec()),
                )?;
                (ephemeral_pub.as_ref().to_vec(), shared_secret)
            }
            ResolvedKexAlgorithm::Kem(kem_algorithm) => {
                let encapsulation_key = EncapsulationKey::new(kem_algorithm, pk)?;
                let (ciphertext, shared_secret) = encapsulation_key.encapsulate()?;
                (
                    ciphertext.as_ref().to_vec(),
                    shared_secret.as_ref().to_vec(),
                )
            }
        };

        // Send the server's identity public key, ephemeral public key or KEM ciphertext,
        // and salt back to the client.
        let peer_initialize = Frame::PeerInitialize(
            identity_pub_key_bytes,
            server_ephemeral_or_ciphertext.clone(),
            salt_bytes.to_vec(),
        );
        self.tx.send(peer_initialize)?;

        let (key_bytes, hmac_key_bytes) =
            derive_session_keys(&shared_secret, &salt_bytes, negotiated)?;
        debug!(
            side = "server",
            aead = %kex_aead_log,
            key_len = key_bytes.len(),
            key_hex = %fmt_hex(&key_bytes),
            "kex: derived AEAD key"
        );
        debug!(
            side = "server",
            mac = %kex_mac_log,
            hmac_key_len = hmac_key_bytes.len(),
            hmac_key_hex = %fmt_hex(&hmac_key_bytes),
            "kex: derived HMAC key"
        );

        tx_event
            .send(KexEvent::KeyMaterial(key_bytes.clone()))
            .map_err(|_| Unspecified)?;
        tx_event
            .send(KexEvent::HMACKeyMaterial(hmac_key_bytes))
            .map_err(|_| Unspecified)?;
        let rnk = LessSafeKey::new(UnboundKey::new(aead_alg, &key_bytes)?);
        Ok((rnk, server_ephemeral_or_ciphertext, salt_bytes.to_vec()))
    }

    fn handle_check(
        &mut self,
        rnk: &LessSafeKey,
        nonce_bytes: [u8; 12],
        mut check_bytes: Vec<u8>,
        tx_event: &UnboundedSender<KexEvent>,
    ) -> Result<()> {
        let nonce = Nonce::from(&nonce_bytes);
        let decrypted_data = rnk
            .open_in_place(nonce, Aad::empty(), &mut check_bytes)
            .map_err(|_| MoshpitError::DecryptionFailed)?;
        if decrypted_data == b"Yoda" {
            let id = Uuid::new_v4();
            tx_event.send(KexEvent::Uuid(id)).map_err(|_| Unspecified)?;
            self.tx.send(Frame::KeyAgreement(UuidWrapper::new(id)))?;
        } else {
            error!("Check frame verification failed");
            return Err(MoshpitError::DecryptionFailed.into());
        }
        Ok(())
    }

    async fn handle_udp_setup(
        &mut self,
        socket_addr: SocketAddr,
        port_pool: Arc<Mutex<BTreeSet<u16>>>,
    ) -> Result<Arc<UdpSocket>> {
        // Bind to all interfaces so we can receive from the client regardless of
        // NAT, multi-homing, or routing asymmetry.
        let unspecified = match socket_addr {
            SocketAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            SocketAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        };

        // Snapshot pool candidates without holding the lock during async bind attempts
        // so concurrent connections do not block each other.
        let candidates: Vec<u16> = {
            let port_p = port_pool.lock().await;
            port_p.iter().copied().collect()
        };

        // Try ports in ascending order; use the first one the OS accepts.
        let mut bound: Option<(u16, UdpSocket)> = None;
        for port in candidates {
            let bind_addr = SocketAddr::new(unspecified, port);
            trace!("trying moshpits UDP bind at {bind_addr}");
            match UdpSocket::bind(bind_addr).await {
                Ok(sock) => {
                    bound = Some((port, sock));
                    break;
                }
                Err(e) => {
                    trace!("port {port} unavailable: {e}");
                }
            }
        }

        let (next_port, udp_listener) = bound.ok_or_else(|| {
            anyhow::anyhow!("no available UDP port in pool (50000–59999 exhausted)")
        })?;

        // Remove the successfully-bound port from the pool.
        {
            let mut port_p = port_pool.lock().await;
            let _ = port_p.remove(&next_port);
        }

        // Advertise after confirming the bind succeeded — avoids pointing the
        // client at a port that subsequently fails to open.
        let udp_addr_for_client = SocketAddr::new(socket_addr.ip(), next_port);
        trace!("advertising moshpits UDP socket at {udp_addr_for_client}");
        self.tx.send(Frame::MoshpitsAddr(udp_addr_for_client))?;

        let sock = SockRef::from(&udp_listener);
        drop(sock.set_recv_buffer_size(4 * 1024 * 1024));
        drop(sock.set_send_buffer_size(4 * 1024 * 1024));
        // DSCP Expedited Forwarding (EF, DSCP 46 = TOS byte 0xB8): give terminal
        // traffic priority on QoS-aware networks.  Silently ignored on platforms
        // where the socket option is unavailable.
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        if socket_addr.is_ipv4() {
            drop(sock.set_tos_v4(0xB8));
        } else {
            drop(sock.set_tclass_v6(0xB8));
        }
        Ok(Arc::new(udp_listener))
    }

    #[cfg(target_os = "linux")]
    async fn validate_user(&self, user: &str) -> Result<bool> {
        let mut is_valid_user = Command::new("id");
        let _ = is_valid_user.arg(user);
        let output = is_valid_user
            .output()
            .await
            .map_err(|_e| MoshpitError::KeyNotEstablished)?;
        Ok(output.status.success())
    }

    #[cfg(target_os = "macos")]
    async fn validate_user(&self, user: &str) -> Result<bool> {
        let mut is_valid_user = Command::new("dscl");
        let _ = is_valid_user.args([".", "-read", format!("/Users/{user}").as_str()]);
        let output = is_valid_user
            .output()
            .await
            .map_err(|_e| MoshpitError::KeyNotEstablished)?;
        Ok(output.status.success())
    }

    #[cfg(target_os = "windows")]
    async fn validate_user(&self, user: &str) -> Result<bool> {
        let mut is_valid_user = Command::new("net");
        let _ = is_valid_user.args(["user", user]);
        let output = is_valid_user
            .output()
            .await
            .map_err(|_e| MoshpitError::KeyNotEstablished)?;
        Ok(output.status.success())
    }

    #[cfg(target_os = "linux")]
    async fn get_home_dir_shell(&self, user: &str) -> Result<(String, String)> {
        let mut cmd = Command::new("getent");
        let _ = cmd.args(["passwd", user]);
        let output = cmd
            .output()
            .await
            .map_err(|_e| MoshpitError::KeyNotEstablished)?;
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let parts: Vec<&str> = stdout.split(':').collect();
            if parts.len() >= 7 {
                let home_dir = parts[5].to_string();
                let shell = parts[6].trim().to_string();
                return Ok((home_dir, shell));
            }
        }
        Err(MoshpitError::KeyNotEstablished.into())
    }

    #[cfg(target_os = "macos")]
    async fn get_home_dir_shell(&self, user: &str) -> Result<(String, String)> {
        let mut cmd = Command::new("dscl");
        let _ = cmd.args([
            ".",
            "-read",
            format!("/Users/{user}").as_str(),
            "NFSHomeDirectory",
            "UserShell",
        ]);
        let output = cmd
            .output()
            .await
            .map_err(|_e| MoshpitError::KeyNotEstablished)?;
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let mut home_dir = String::new();
            let mut shell = String::new();
            for line in stdout.lines() {
                if let Some(stripped) = line.strip_prefix("NFSHomeDirectory:") {
                    home_dir = stripped.trim().to_string();
                } else if let Some(stripped) = line.strip_prefix("UserShell:") {
                    shell = stripped.trim().to_string();
                }
            }
            return Ok((home_dir, shell));
        }
        Err(MoshpitError::KeyNotEstablished.into())
    }

    #[cfg(target_os = "windows")]
    async fn get_home_dir_shell(&self, user: &str) -> Result<(String, String)> {
        let mut cmd = Command::new("net");
        let _ = cmd.args(["user", user]);
        let output = cmd
            .output()
            .await
            .map_err(|_e| MoshpitError::KeyNotEstablished)?;
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let mut home_dir = String::new();
            for line in stdout.lines() {
                if line.to_lowercase().starts_with("home directory") {
                    home_dir = line[14..].trim().to_string();
                    break;
                }
            }
            if home_dir.is_empty() {
                home_dir = format!("C:\\Users\\{user}");
            }
            return Ok((home_dir, String::from("cmd.exe")));
        }
        Err(MoshpitError::KeyNotEstablished.into())
    }
}

fn check_authorized_keys(home_dir: &str, fpk: &[u8]) -> Result<bool> {
    let moshpit_path = PathBuf::from(home_dir).join(".mp");
    let authorized_keys_path = moshpit_path.join("authorized_keys");
    if check_permissions(&moshpit_path, &authorized_keys_path)? {
        let authorized_keys_file = OpenOptions::new()
            .read(true)
            .open(&authorized_keys_path)
            .map_err(|_e| MoshpitError::KeyNotEstablished)?;
        let buffered_reader = BufReader::new(authorized_keys_file);
        let fpk_str = String::from_utf8_lossy(fpk);

        for line in buffered_reader.lines().map_while(Result::ok) {
            if line == fpk_str {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

#[cfg_attr(windows, allow(clippy::unnecessary_wraps))]
fn check_permissions(moshpit_path: &Path, authorized_keys_path: &Path) -> Result<bool> {
    #[cfg(target_family = "unix")]
    {
        use std::os::unix::fs::MetadataExt;

        let moshpit_metadata = moshpit_path.metadata()?;
        let authorized_keys_metadata = authorized_keys_path.metadata()?;

        // Check that .mp directory has mode 0o700 (rwx------ = 0o40700 with S_IFDIR bit)
        // We mask with 0o777 to get just the permission bits
        let dir_perms = moshpit_metadata.mode() & 0o777;
        if dir_perms != 0o700 {
            return Ok(false);
        }

        // Check that authorized_keys file is owned by the user and not writable by others
        let file_perms = authorized_keys_metadata.mode() & 0o777;
        if file_perms != 0o600 {
            return Ok(false);
        }
    }
    #[cfg(target_os = "windows")]
    {
        if !windows_only_owner_has_access(moshpit_path)
            || !windows_only_owner_has_access(authorized_keys_path)
        {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Verify that every `ACCESS_ALLOWED` ACE on `path` belongs to the file owner
/// or the SYSTEM account, which is the Windows equivalent of `mode 0o700/0o600`.
#[cfg(target_os = "windows")]
fn windows_only_owner_has_access(path: &Path) -> bool {
    use std::os::windows::ffi::OsStrExt;
    use windows::{
        Win32::Foundation::{HLOCAL, LocalFree},
        Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT},
        Win32::Security::{
            ACCESS_ALLOWED_ACE, ACL, ACL_SIZE_INFORMATION, AclSizeInformation, CreateWellKnownSid,
            DACL_SECURITY_INFORMATION, EqualSid, GetAce, GetAclInformation,
            OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, WinLocalSystemSid,
        },
        core::PCWSTR,
    };

    let wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut p_dacl: *mut ACL = std::ptr::null_mut();
    let mut p_owner = PSID(std::ptr::null_mut());
    let mut p_sd = PSECURITY_DESCRIPTOR(std::ptr::null_mut());

    // Retrieve the DACL and owner SID for the path.
    let err = unsafe {
        GetNamedSecurityInfoW(
            PCWSTR(wide.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION,
            Some(&raw mut p_owner),
            None,
            Some(&raw mut p_dacl),
            None,
            &raw mut p_sd,
        )
    };
    if err.0 != 0 {
        return false;
    }

    // Build the SYSTEM SID; SYSTEM is permitted to have access on Windows.
    let mut system_sid_buf = [0u8; 68];
    let mut system_sid_size: u32 = 68;
    let system_sid = PSID(system_sid_buf.as_mut_ptr().cast());
    let ok = unsafe {
        CreateWellKnownSid(
            WinLocalSystemSid,
            None,
            Some(system_sid),
            &raw mut system_sid_size,
        )
    };
    if ok.is_err() {
        unsafe {
            let _ = LocalFree(Some(HLOCAL(p_sd.0)));
        }
        return false;
    }

    let result = if p_dacl.is_null() {
        // A null DACL grants unrestricted access to everyone — not secure.
        false
    } else {
        let mut acl_info = ACL_SIZE_INFORMATION::default();
        let ok = unsafe {
            GetAclInformation(
                p_dacl,
                std::ptr::addr_of_mut!(acl_info).cast::<core::ffi::c_void>(),
                u32::try_from(size_of::<ACL_SIZE_INFORMATION>())
                    .expect("ACL_SIZE_INFORMATION fits in u32"),
                AclSizeInformation,
            )
        };
        if ok.is_err() {
            unsafe {
                let _ = LocalFree(Some(HLOCAL(p_sd.0)));
            }
            return false;
        }

        let mut secure = true;
        for i in 0..acl_info.AceCount {
            let mut p_ace: *mut core::ffi::c_void = std::ptr::null_mut();
            if unsafe { GetAce(p_dacl, i, &raw mut p_ace) }.is_ok() {
                let ace = unsafe { &*(p_ace as *const ACCESS_ALLOWED_ACE) };
                // AceType 0 == ACCESS_ALLOWED_ACE_TYPE; deny ACEs for others are fine.
                if ace.Header.AceType == 0u8 {
                    let ace_sid = PSID(std::ptr::addr_of!(ace.SidStart) as *mut core::ffi::c_void);
                    let is_owner = unsafe { EqualSid(ace_sid, p_owner) }.is_ok();
                    let is_system = unsafe { EqualSid(ace_sid, system_sid) }.is_ok();
                    if !is_owner && !is_system {
                        secure = false;
                        break;
                    }
                }
            }
        }
        secure
    };

    unsafe {
        let _ = LocalFree(Some(HLOCAL(p_sd.0)));
    }
    result
}

fn check_known_hosts(
    host: &str,
    pk: &[u8],
    tofu_fn: Option<&TofuFn>,
    mismatch_fn: Option<&HostKeyMismatchFn>,
) -> Result<bool> {
    use aws_lc_rs::digest::{SHA256, digest};

    let home = dirs2::home_dir().ok_or_else(|| anyhow::anyhow!("No home directory found"))?;
    let known_hosts_path = home.join(".mp").join("known_hosts");
    let pk_b64 = STANDARD.encode(pk);

    if known_hosts_path.exists() {
        let content = read_to_string(&known_hosts_path)?;
        for line in content.lines() {
            let mut parts = line.split_whitespace();
            if let (Some(h), Some(k)) = (parts.next(), parts.next())
                && h == host
            {
                if k == pk_b64 {
                    return Ok(true);
                }
                let old_fingerprint = key_fingerprint_from_b64(k);
                let new_fingerprint = STANDARD.encode(digest(&SHA256, pk));
                error!("HOST KEY VERIFICATION FAILED for {host}!");
                if let Some(prompt_replace) = mismatch_fn
                    && prompt_replace(host, &old_fingerprint, &new_fingerprint)?
                {
                    replace_known_host_key(host, &pk_b64)?;
                    return Ok(true);
                }
                return Ok(false);
            }
        }
    }

    // Not found, do TOFU
    if let Some(tofu) = tofu_fn {
        let fingerprint = STANDARD.encode(digest(&SHA256, pk));
        if tofu(host, &fingerprint)? {
            // Save it
            use std::io::Write;
            if let Some(parent) = known_hosts_path.parent() {
                create_dir_all(parent)?;
            }
            let mut file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&known_hosts_path)?;
            writeln!(file, "{host} {pk_b64}")?;
            Ok(true)
        } else {
            Ok(false)
        }
    } else {
        error!("Unknown host {host}, no TOFU callback provided");
        Ok(false)
    }
}

fn key_fingerprint_from_b64(key_b64: &str) -> String {
    use aws_lc_rs::digest::{SHA256, digest};

    let key_bytes = STANDARD
        .decode(key_b64.as_bytes())
        .unwrap_or_else(|_| key_b64.as_bytes().to_vec());
    STANDARD.encode(digest(&SHA256, &key_bytes))
}

fn replace_known_host_key(host: &str, new_pk_b64: &str) -> Result<()> {
    let home = dirs2::home_dir().ok_or_else(|| anyhow::anyhow!("No home directory found"))?;
    let known_hosts_path = home.join(".mp").join("known_hosts");
    if let Some(parent) = known_hosts_path.parent() {
        create_dir_all(parent)?;
    }

    let mut replaced = false;
    let mut out_lines: Vec<String> = Vec::new();

    if known_hosts_path.exists() {
        let content = read_to_string(&known_hosts_path)?;
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                out_lines.push(line.to_string());
                continue;
            }
            let mut parts = line.split_whitespace();
            if let Some(existing_host) = parts.next()
                && existing_host == host
            {
                if !replaced {
                    out_lines.push(format!("{host} {new_pk_b64}"));
                    replaced = true;
                }
                continue;
            }
            out_lines.push(line.to_string());
        }
    }

    if !replaced {
        out_lines.push(format!("{host} {new_pk_b64}"));
    }

    let mut updated = out_lines.join("\n");
    if !updated.is_empty() {
        updated.push('\n');
    }
    write(known_hosts_path, updated)?;
    Ok(())
}

#[cfg(test)]
#[cfg(unix)]
#[allow(unsafe_code)]
mod tests {
    use std::{
        env::set_var,
        fs::{DirBuilder, File, OpenOptions, create_dir_all, read_to_string},
        io::Write,
        iter::from_fn,
        net::SocketAddr,
        os::unix::fs::{DirBuilderExt, OpenOptionsExt},
        path::PathBuf,
        sync::{Arc, Mutex, OnceLock},
    };

    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use tempfile::TempDir;
    use tokio::spawn;
    use tokio::sync::mpsc::UnboundedReceiver;

    use aws_lc_rs::aead::Nonce;
    use aws_lc_rs::kem::{
        Ciphertext, DecapsulationKey, EncapsulationKey, ML_KEM_512, ML_KEM_768, ML_KEM_1024,
    };

    use super::{check_authorized_keys, check_known_hosts, derive_session_keys};
    use crate::kex::negotiate::{
        AEAD_AES256_GCM_SIV, KDF_HKDF_SHA256, KEX_ML_KEM_512_SHA256, KEX_ML_KEM_768_SHA256,
        KEX_ML_KEM_1024_SHA256, MAC_HMAC_SHA512, NegotiatedAlgorithms,
    };
    use crate::kex::{HostKeyMismatchFn, TofuFn};

    /// Tests that mutate the `HOME` environment variable must hold this lock
    /// to prevent races with concurrently-running tests in the same process.
    fn home_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(Mutex::default)
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /// Write a `.mp/known_hosts` file inside `dir` with `host <pk_b64>` line.
    fn write_known_hosts(dir: &TempDir, host: &str, pk: &[u8]) {
        let mp = dir.path().join(".mp");
        create_dir_all(&mp).expect("create .mp dir");
        let kh = mp.join("known_hosts");
        let mut f = File::create(kh).expect("create known_hosts file");
        writeln!(f, "{host} {}", STANDARD.encode(pk)).expect("write known_hosts entry");
    }

    /// Write a `.mp/authorized_keys` file with the given bytes as content and
    /// apply the supplied `mode` bits.
    fn write_authorized_keys(dir: &TempDir, content: &[u8], mode: u32) {
        let mp = dir.path().join(".mp");
        DirBuilder::new()
            .mode(0o700)
            .create(&mp)
            .expect("create .mp dir with 0o700");
        let ak = mp.join("authorized_keys");
        let mut f = OpenOptions::new()
            .create(true)
            .write(true)
            .mode(mode)
            .open(ak)
            .expect("create authorized_keys file");
        f.write_all(content).expect("write authorized_keys content");
    }

    #[test]
    fn ml_kem_round_trip_derives_same_session_keys() {
        for (alg, name) in [
            (&ML_KEM_512, KEX_ML_KEM_512_SHA256),
            (&ML_KEM_768, KEX_ML_KEM_768_SHA256),
            (&ML_KEM_1024, KEX_ML_KEM_1024_SHA256),
        ] {
            let decapsulation_key =
                DecapsulationKey::generate(alg).expect("test ML-KEM key generation");
            let encapsulation_key_bytes = decapsulation_key
                .encapsulation_key()
                .expect("encapsulation key from decapsulation key")
                .key_bytes()
                .expect("encapsulation key bytes");
            let encapsulation_key = EncapsulationKey::new(alg, encapsulation_key_bytes.as_ref())
                .expect("encapsulation key from bytes");
            let (ciphertext, server_secret) = encapsulation_key.encapsulate().expect("encapsulate");
            let client_secret = decapsulation_key
                .decapsulate(Ciphertext::from(ciphertext.as_ref()))
                .expect("decapsulate");
            assert_eq!(server_secret.as_ref(), client_secret.as_ref());

            let negotiated = NegotiatedAlgorithms {
                kex: name.to_string(),
                aead: AEAD_AES256_GCM_SIV.to_string(),
                mac: MAC_HMAC_SHA512.to_string(),
                kdf: KDF_HKDF_SHA256.to_string(),
                ..NegotiatedAlgorithms::default()
            };
            let salt = [7u8; 32];
            let server_keys = derive_session_keys(server_secret.as_ref(), &salt, &negotiated)
                .expect("derive server session keys");
            let client_keys = derive_session_keys(client_secret.as_ref(), &salt, &negotiated)
                .expect("derive client session keys");
            assert_eq!(server_keys, client_keys);
            assert_eq!(server_keys.0.len(), 32);
            assert_eq!(server_keys.1.len(), 64);
        }
    }

    #[test]
    fn ml_kem_rejects_mismatched_or_malformed_inputs() {
        let decapsulation_key =
            DecapsulationKey::generate(&ML_KEM_512).expect("test ML-KEM-512 key generation");
        let encapsulation_key_bytes = decapsulation_key
            .encapsulation_key()
            .expect("encapsulation key from decapsulation key")
            .key_bytes()
            .expect("encapsulation key bytes");
        assert!(EncapsulationKey::new(&ML_KEM_768, encapsulation_key_bytes.as_ref()).is_err());

        let encapsulation_key =
            EncapsulationKey::new(&ML_KEM_512, encapsulation_key_bytes.as_ref())
                .expect("encapsulation key from bytes");
        let (ciphertext, _) = encapsulation_key.encapsulate().expect("encapsulate");
        let truncated = &ciphertext.as_ref()[..ciphertext.as_ref().len() - 1];
        assert!(
            decapsulation_key
                .decapsulate(Ciphertext::from(truncated))
                .is_err()
        );
    }

    #[cfg(feature = "unstable")]
    #[test]
    fn ml_dsa_identity_transcript_signature_verifies() {
        use aws_lc_rs::{
            encoding::AsRawBytes as _, signature::KeyPair as _, unstable::signature::PqdsaKeyPair,
        };

        let key_pair = PqdsaKeyPair::generate(&aws_lc_rs::unstable::signature::ML_DSA_44_SIGNING)
            .expect("test ML-DSA-44 key generation");
        let private_key = key_pair
            .private_key()
            .as_raw_bytes()
            .expect("private key bytes");
        let public_key = key_pair.public_key().as_ref();
        let negotiated = NegotiatedAlgorithms {
            kex: KEX_ML_KEM_768_SHA256.to_string(),
            aead: AEAD_AES256_GCM_SIV.to_string(),
            mac: MAC_HMAC_SHA512.to_string(),
            kdf: KDF_HKDF_SHA256.to_string(),
            ..NegotiatedAlgorithms::default()
        };
        let transcript = super::identity_transcript(&super::IdentityTranscriptParts {
            role: b"client",
            negotiated: &negotiated,
            user: b"alice",
            client_exchange: b"client-exchange",
            client_identity: b"client-identity",
            server_identity: b"server-identity",
            server_exchange: b"server-exchange",
            salt: b"salt",
        })
        .expect("build identity transcript");
        let signature = super::sign_identity_transcript(
            crate::KEY_ALGORITHM_ML_DSA_44,
            private_key.as_ref(),
            &transcript,
        )
        .expect("sign identity transcript");
        super::verify_identity_transcript(
            crate::KEY_ALGORITHM_ML_DSA_44,
            public_key,
            &transcript,
            &signature,
        )
        .expect("verify identity transcript");
    }

    // -----------------------------------------------------------------------
    // check_known_hosts tests
    // -----------------------------------------------------------------------

    /// A key that exactly matches the pinned entry is accepted.
    #[test]
    fn check_known_hosts_match() {
        let _guard = home_lock().lock().expect("home mutex not poisoned");
        let dir = TempDir::new().expect("temp dir creation");
        let pk = b"server-public-key-bytes";
        let host = "192.0.2.1";
        write_known_hosts(&dir, host, pk);
        // Point HOME at the temp dir so check_known_hosts finds our file.
        // SAFETY: test-only; serialized via home_lock.
        unsafe { set_var("HOME", dir.path()) };
        let result = check_known_hosts(host, pk, None, None).expect("check_known_hosts");
        assert!(result, "matching key should be accepted");
    }

    /// A different key for a known host is a MITM — must be rejected.
    #[test]
    fn check_known_hosts_mismatch() {
        let _guard = home_lock().lock().expect("home mutex not poisoned");
        let dir = TempDir::new().expect("temp dir creation");
        let pinned_pk = b"real-server-key";
        let attacker_pk = b"mitm-attacker-key";
        let host = "192.0.2.2";
        write_known_hosts(&dir, host, pinned_pk);
        // SAFETY: test-only; serialized via home_lock.
        unsafe { set_var("HOME", dir.path()) };
        let result = check_known_hosts(host, attacker_pk, None, None).expect("check_known_hosts");
        assert!(!result, "mismatched host key must be rejected");
    }

    /// A mismatched key can be explicitly accepted and replaced by callback.
    #[test]
    fn check_known_hosts_mismatch_replace_accept() {
        let _guard = home_lock().lock().expect("home mutex not poisoned");
        let dir = TempDir::new().expect("temp dir creation");
        let old_pk = b"old-server-key";
        let new_pk = b"new-server-key";
        let host = "192.0.2.20";
        write_known_hosts(&dir, host, old_pk);
        // SAFETY: test-only; serialized via home_lock.
        unsafe { set_var("HOME", dir.path()) };

        let mismatch_fn: HostKeyMismatchFn = Arc::new(|_h, _old_fp, _new_fp| Ok(true));
        let result =
            check_known_hosts(host, new_pk, None, Some(&mismatch_fn)).expect("check_known_hosts");
        assert!(result, "accepted replacement should return true");

        let content = read_to_string(dir.path().join(".mp").join("known_hosts"))
            .expect("read known_hosts file");
        assert!(content.contains(host));
        assert!(content.contains(&STANDARD.encode(new_pk)));
        assert!(!content.contains(&STANDARD.encode(old_pk)));
    }

    /// A mismatched key rejected by callback must keep existing `known_hosts` entry.
    #[test]
    fn check_known_hosts_mismatch_replace_reject_keeps_old_key() {
        let _guard = home_lock().lock().expect("home mutex not poisoned");
        let dir = TempDir::new().expect("temp dir creation");
        let old_pk = b"old-server-key";
        let new_pk = b"new-server-key";
        let host = "192.0.2.21";
        write_known_hosts(&dir, host, old_pk);
        // SAFETY: test-only; serialized via home_lock.
        unsafe { set_var("HOME", dir.path()) };

        let mismatch_fn: HostKeyMismatchFn = Arc::new(|_h, _old_fp, _new_fp| Ok(false));
        let result =
            check_known_hosts(host, new_pk, None, Some(&mismatch_fn)).expect("check_known_hosts");
        assert!(!result, "rejected replacement should return false");

        let content = read_to_string(dir.path().join(".mp").join("known_hosts"))
            .expect("read known_hosts file");
        assert!(content.contains(host));
        assert!(content.contains(&STANDARD.encode(old_pk)));
        assert!(!content.contains(&STANDARD.encode(new_pk)));
    }

    /// Invalid base64 `known_hosts` values still produce a deterministic fingerprint.
    #[test]
    fn key_fingerprint_from_b64_handles_invalid_input() {
        let fp = super::key_fingerprint_from_b64("not-base64-@@@");
        assert!(!fp.is_empty());
    }

    /// Unknown host + TOFU callback that returns `true` → accepted and saved.
    #[test]
    fn check_known_hosts_tofu_accept() {
        let _guard = home_lock().lock().expect("home mutex not poisoned");
        let dir = TempDir::new().expect("temp dir creation");
        let pk = b"brand-new-server-key";
        let host = "192.0.2.3";
        // No existing known_hosts file; just ensure the .mp dir exists.
        create_dir_all(dir.path().join(".mp")).expect("create .mp dir");
        // SAFETY: test-only; serialized via home_lock.
        unsafe { set_var("HOME", dir.path()) };
        let tofu_fn: TofuFn = Arc::new(|_host, _fp| Ok(true));
        let result = check_known_hosts(host, pk, Some(&tofu_fn), None).expect("check_known_hosts");
        assert!(result, "TOFU accept should return true");
        // Key should now be persisted.
        let kh_content = read_to_string(dir.path().join(".mp").join("known_hosts"))
            .expect("read known_hosts file");
        assert!(
            kh_content.contains(host),
            "host should be saved to known_hosts"
        );
    }

    /// Unknown host + TOFU callback that returns `false` → rejected.
    #[test]
    fn check_known_hosts_tofu_reject() {
        let _guard = home_lock().lock().expect("home mutex not poisoned");
        let dir = TempDir::new().expect("temp dir creation");
        let pk = b"unknown-server-key";
        let host = "192.0.2.4";
        create_dir_all(dir.path().join(".mp")).expect("create .mp dir");
        // SAFETY: test-only; serialized via home_lock.
        unsafe { set_var("HOME", dir.path()) };
        let tofu_fn: TofuFn = Arc::new(|_host, _fp| Ok(false));
        let result = check_known_hosts(host, pk, Some(&tofu_fn), None).expect("check_known_hosts");
        assert!(!result, "TOFU reject should return false");
    }

    /// Unknown host with no TOFU callback → rejected (fail closed).
    #[test]
    fn check_known_hosts_no_tofu() {
        let _guard = home_lock().lock().expect("home mutex not poisoned");
        let dir = TempDir::new().expect("temp dir creation");
        let pk = b"some-server-key";
        let host = "192.0.2.5";
        create_dir_all(dir.path().join(".mp")).expect("create .mp dir");
        // SAFETY: test-only; serialized via home_lock.
        unsafe { set_var("HOME", dir.path()) };
        let result = check_known_hosts(host, pk, None, None).expect("check_known_hosts");
        assert!(!result, "no TOFU callback must fail closed");
    }

    // -----------------------------------------------------------------------
    // check_authorized_keys tests
    // -----------------------------------------------------------------------

    /// Key present in `authorized_keys` with correct permissions → accepted.
    #[test]
    fn check_authorized_keys_match() {
        let dir = TempDir::new().expect("temp dir creation");
        let key_bytes = b"my-full-public-key-bytes";
        write_authorized_keys(&dir, key_bytes, 0o600);
        let home_str = dir.path().to_str().expect("test path is valid UTF-8");
        let result = check_authorized_keys(home_str, key_bytes).expect("check_authorized_keys");
        assert!(result, "matching key in authorized_keys should be accepted");
    }

    /// Key NOT present in `authorized_keys` → rejected.
    #[test]
    fn check_authorized_keys_mismatch() {
        let dir = TempDir::new().expect("temp dir creation");
        let stored_key = b"stored-key";
        let presented_key = b"different-key";
        write_authorized_keys(&dir, stored_key, 0o600);
        let home_str = dir.path().to_str().expect("test path is valid UTF-8");
        let result = check_authorized_keys(home_str, presented_key).expect("check_authorized_keys");
        assert!(!result, "key not in authorized_keys should be rejected");
    }

    /// `authorized_keys` with 0o644 permissions (group/world-readable) → rejected.
    #[test]
    fn check_authorized_keys_bad_perms() {
        let dir = TempDir::new().expect("temp dir creation");
        let key_bytes = b"my-full-public-key-bytes";
        write_authorized_keys(&dir, key_bytes, 0o644);
        let home_str = dir.path().to_str().expect("test path is valid UTF-8");
        let result = check_authorized_keys(home_str, key_bytes).expect("check_authorized_keys");
        assert!(
            !result,
            "world-readable authorized_keys must be rejected (permission check)"
        );
    }

    // -----------------------------------------------------------------------
    // Algorithm resolution helper tests
    // -----------------------------------------------------------------------

    #[test]
    fn resolve_kex_alg_dh_algorithms_succeed() {
        use crate::kex::negotiate::{KEX_P256_SHA256, KEX_P384_SHA384, KEX_X25519_SHA256};
        for kex in [KEX_X25519_SHA256, KEX_P384_SHA384, KEX_P256_SHA256] {
            let result = super::resolve_kex_alg(kex);
            assert!(result.is_ok(), "{kex} should resolve OK");
            assert!(
                matches!(
                    result.expect("resolve kex alg"),
                    super::ResolvedKexAlgorithm::Dh(_)
                ),
                "{kex} should map to a DH algorithm"
            );
        }
    }

    #[test]
    fn resolve_kex_alg_kem_algorithms_succeed() {
        for kex in [
            KEX_ML_KEM_512_SHA256,
            KEX_ML_KEM_768_SHA256,
            KEX_ML_KEM_1024_SHA256,
        ] {
            let result = super::resolve_kex_alg(kex);
            assert!(result.is_ok(), "{kex} should resolve OK");
            assert!(
                matches!(
                    result.expect("resolve kex alg"),
                    super::ResolvedKexAlgorithm::Kem(_)
                ),
                "{kex} should map to a KEM algorithm"
            );
        }
    }

    #[test]
    fn resolve_hkdf_alg_all_supported_succeed() {
        use crate::kex::negotiate::{KDF_HKDF_SHA384, KDF_HKDF_SHA512};
        for kdf in [KDF_HKDF_SHA256, KDF_HKDF_SHA384, KDF_HKDF_SHA512] {
            assert!(
                super::resolve_hkdf_alg(kdf).is_ok(),
                "{kdf} should resolve OK"
            );
        }
        assert!(
            super::resolve_hkdf_alg("unknown-kdf").is_err(),
            "unknown KDF must return an error"
        );
    }

    #[test]
    fn resolve_aead_alg_all_supported_succeed() {
        use crate::kex::negotiate::{AEAD_AES128_GCM_SIV, AEAD_AES256_GCM, AEAD_CHACHA20_POLY1305};
        for aead in [
            AEAD_AES256_GCM_SIV,
            AEAD_AES256_GCM,
            AEAD_CHACHA20_POLY1305,
            AEAD_AES128_GCM_SIV,
        ] {
            assert!(
                super::resolve_aead_alg(aead).is_ok(),
                "{aead} should resolve OK"
            );
        }
        assert!(
            super::resolve_aead_alg("unknown-aead").is_err(),
            "unknown AEAD must return an error"
        );
    }

    #[test]
    fn resolve_hmac_key_type_all_supported_succeed() {
        use crate::kex::negotiate::MAC_HMAC_SHA256;
        for mac in [MAC_HMAC_SHA512, MAC_HMAC_SHA256] {
            assert!(
                super::resolve_hmac_key_type(mac).is_ok(),
                "{mac} should resolve OK"
            );
        }
        assert!(
            super::resolve_hmac_key_type("unknown-mac").is_err(),
            "unknown MAC must return an error"
        );
    }

    // -----------------------------------------------------------------------
    // Helpers for KexReader / client_kex / handle_check / handle_udp_setup tests
    // -----------------------------------------------------------------------

    use std::collections::BTreeSet;
    use std::sync::Arc as StdArc;

    use aws_lc_rs::{
        aead::{AES_256_GCM_SIV, Aad, LessSafeKey, NONCE_LEN, UnboundKey},
        agreement::{PrivateKey, X25519},
        rand::fill,
    };
    use tokio::sync::Mutex as TokioMutex;
    use tokio::{
        net::{TcpListener, TcpStream, UdpSocket},
        sync::mpsc::unbounded_channel,
    };

    use crate::{
        ConnectionReader, ConnectionWriter, Frame, KexEvent, UuidWrapper, supported_algorithms,
    };

    /// Create two connected TCP stream pairs.
    /// Returns `(client_reader, client_writer, server_reader, server_writer)`.
    async fn make_bidirectional_loopback() -> (
        ConnectionReader,
        ConnectionWriter,
        ConnectionReader,
        ConnectionWriter,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test TCP listener");
        let addr = listener.local_addr().expect("listener local addr");
        let (server_stream, client_stream) = tokio::join!(
            async {
                listener
                    .accept()
                    .await
                    .map(|(s, _)| s)
                    .expect("accept connection")
            },
            TcpStream::connect(addr),
        );
        let client_stream = client_stream.expect("connect to test listener");
        let (server_r, server_w) = server_stream.into_split();
        let (client_r, client_w) = client_stream.into_split();
        (
            ConnectionReader::builder().reader(client_r).build(),
            ConnectionWriter::builder().writer(client_w).build(),
            ConnectionReader::builder().reader(server_r).build(),
            ConnectionWriter::builder().writer(server_w).build(),
        )
    }

    /// Build a `KexReader` around `reader` and return channel receivers
    /// so tests can observe outbound frames and events.
    fn make_test_kex_reader(
        reader: ConnectionReader,
    ) -> (
        super::super::KexReader,
        UnboundedReceiver<Frame>,
        UnboundedReceiver<KexEvent>,
    ) {
        let (tx, rx_frames) = unbounded_channel::<Frame>();
        let (tx_event, rx_events) = unbounded_channel::<KexEvent>();
        let kex_reader = super::super::KexReader::builder()
            .reader(reader)
            .tx(tx)
            .tx_event(tx_event)
            .build();
        (kex_reader, rx_frames, rx_events)
    }

    // -----------------------------------------------------------------------
    // handle_udp_setup tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn handle_udp_setup_uses_first_available_port() -> anyhow::Result<()> {
        let (client_reader, _client_writer, _server_reader, _server_writer) =
            make_bidirectional_loopback().await;
        let (mut kex_reader, mut rx_frames, _rx_events) = make_test_kex_reader(client_reader);

        // Ask the OS for a free port so the test doesn't conflict with a running
        // moshpit server that may already hold a port in the 50000–59999 range.
        let free_port = {
            let probe = UdpSocket::bind("0.0.0.0:0").await?;
            probe.local_addr()?.port()
            // probe drops here, releasing the port before handle_udp_setup re-binds it
        };

        let mut pool = BTreeSet::new();
        let _ = pool.insert(free_port);
        let port_pool = StdArc::new(TokioMutex::new(pool));
        let socket_addr: SocketAddr = "127.0.0.1:9000".parse().expect("hardcoded test address");

        let udp_arc = kex_reader.handle_udp_setup(socket_addr, port_pool).await?;

        let frame = rx_frames.recv().await.expect("receive MoshpitsAddr frame");
        let advertised_port = match frame {
            Frame::MoshpitsAddr(a) => a.port(),
            other => panic!("expected MoshpitsAddr, got {other:?}"),
        };
        assert_eq!(advertised_port, free_port);
        assert!(udp_arc.local_addr().is_ok());
        Ok(())
    }

    #[tokio::test]
    async fn handle_udp_setup_empty_pool_returns_error() {
        let (client_reader, _client_writer, _server_reader, _server_writer) =
            make_bidirectional_loopback().await;
        let (mut kex_reader, _rx_frames, _rx_events) = make_test_kex_reader(client_reader);

        let pool: BTreeSet<u16> = BTreeSet::new();
        let port_pool = StdArc::new(TokioMutex::new(pool));
        let socket_addr: SocketAddr = "127.0.0.1:9000".parse().expect("hardcoded test address");

        let result = kex_reader.handle_udp_setup(socket_addr, port_pool).await;
        assert!(result.is_err(), "expected error when pool is empty");
    }

    #[tokio::test]
    async fn handle_udp_setup_skips_in_use_port() {
        let (client_reader, _client_writer, _server_reader, _server_writer) =
            make_bidirectional_loopback().await;
        let (mut kex_reader, mut rx_frames, _rx_events) = make_test_kex_reader(client_reader);

        // Get two OS-assigned free ports.
        let sock_a = UdpSocket::bind("0.0.0.0:0")
            .await
            .expect("bind test UDP socket a");
        let sock_b = UdpSocket::bind("0.0.0.0:0")
            .await
            .expect("bind test UDP socket b");
        let port_a = sock_a.local_addr().expect("socket a local addr").port();
        let port_b = sock_b.local_addr().expect("socket b local addr").port();

        // Ensure the lower-numbered port (tried first by BTreeSet iteration) stays
        // occupied; drop the higher-numbered socket so handle_udp_setup can bind it.
        let (occupied_port, occupied_sock, free_port) = if port_a < port_b {
            drop(sock_b);
            (port_a, sock_a, port_b)
        } else {
            drop(sock_a);
            (port_b, sock_b, port_a)
        };

        let mut pool = BTreeSet::new();
        let _ = pool.insert(occupied_port);
        let _ = pool.insert(free_port);
        let port_pool = StdArc::new(TokioMutex::new(pool));
        let socket_addr: SocketAddr = "127.0.0.1:9000".parse().expect("hardcoded test address");

        // occupied_sock is still alive — occupied_port is held at the OS level.
        let udp_arc = kex_reader
            .handle_udp_setup(socket_addr, port_pool.clone())
            .await
            .expect("handle_udp_setup with one free port");
        drop(occupied_sock); // explicit: ensure it outlives handle_udp_setup

        let frame = rx_frames.recv().await.expect("receive MoshpitsAddr frame");
        let advertised_port = match frame {
            Frame::MoshpitsAddr(a) => a.port(),
            other => panic!("expected MoshpitsAddr, got {other:?}"),
        };
        assert_eq!(
            advertised_port, free_port,
            "should have skipped the in-use port"
        );
        assert!(udp_arc.local_addr().is_ok());
        // The occupied port was never successfully bound — it must remain in the pool.
        assert!(
            port_pool.lock().await.contains(&occupied_port),
            "in-use port should remain in pool"
        );
    }

    // -----------------------------------------------------------------------
    // handle_check tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn handle_check_valid_yoda_payload_succeeds() {
        let (client_reader, _cw, _sr, _sw) = make_bidirectional_loopback().await;
        let (mut kex_reader, mut rx_frames, _rx_events) = make_test_kex_reader(client_reader);

        let key_bytes = [1u8; 32];
        let rnk = LessSafeKey::new(
            UnboundKey::new(&AES_256_GCM_SIV, &key_bytes).expect("test AES-256-GCM-SIV key setup"),
        );

        // Encrypt "Yoda" the same way client_kex does
        let mut plaintext = b"Yoda".to_vec();
        let mut nonce_bytes = [0u8; NONCE_LEN];
        fill(&mut nonce_bytes).expect("fill nonce bytes");
        let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes).expect("create nonce");
        rnk.seal_in_place_append_tag(nonce, Aad::empty(), &mut plaintext)
            .expect("seal in place");

        let (tx_event_clone, _rx_event_clone) = unbounded_channel::<KexEvent>();
        kex_reader
            .handle_check(&rnk, nonce_bytes, plaintext, &tx_event_clone)
            .expect("handle_check with valid Yoda payload");

        // Should have sent KeyAgreement frame via kex_reader's own tx
        let frame = rx_frames.recv().await.expect("receive KeyAgreement frame");
        assert!(
            matches!(frame, Frame::KeyAgreement(_)),
            "expected KeyAgreement, got {frame:?}"
        );
    }

    #[tokio::test]
    async fn handle_check_invalid_payload_returns_decryption_failed() {
        use crate::MoshpitError;

        let (client_reader, _cw, _sr, _sw) = make_bidirectional_loopback().await;
        let (mut kex_reader, _rx_frames, _rx_events) = make_test_kex_reader(client_reader);

        let key_bytes = [1u8; 32];
        let rnk = LessSafeKey::new(
            UnboundKey::new(&AES_256_GCM_SIV, &key_bytes).expect("test AES-256-GCM-SIV key setup"),
        );

        let nonce_bytes = [0u8; NONCE_LEN];
        let garbage = vec![0u8; 32]; // not a valid ciphertext

        let (tx_event_clone, _) = unbounded_channel::<KexEvent>();
        let result = kex_reader.handle_check(&rnk, nonce_bytes, garbage, &tx_event_clone);
        assert!(result.is_err());
        assert!(
            result
                .expect_err("expected decryption error")
                .downcast_ref::<MoshpitError>()
                .is_some_and(|e| *e == MoshpitError::DecryptionFailed),
        );
    }

    // -----------------------------------------------------------------------
    // client_kex tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn client_kex_server_closes_immediately_returns_error() {
        let (client_reader, _client_writer, _server_reader, server_writer) =
            make_bidirectional_loopback().await;
        let (mut kex_reader, _rx_frames, _rx_events) = make_test_kex_reader(client_reader);

        // Drop server writer immediately — client reads EOF
        drop(server_writer);

        let result = kex_reader.client_kex().await;
        assert!(
            result.is_err(),
            "expected error when server closes immediately"
        );
    }

    #[tokio::test]
    async fn client_kex_kex_failure_before_kex_init_returns_no_common_algorithm() {
        use crate::MoshpitError;

        let (client_reader, _client_writer, _server_reader, mut server_writer) =
            make_bidirectional_loopback().await;
        let (mut kex_reader, _rx_frames, _rx_events) = make_test_kex_reader(client_reader);

        // Server rejects immediately with KexFailure (e.g. no common algorithm)
        server_writer
            .write_frame(&Frame::KexFailure)
            .await
            .expect("write KexFailure frame");
        drop(server_writer);

        let result = kex_reader.client_kex().await;
        assert!(result.is_err());
        assert!(
            result
                .expect_err("expected NoCommonAlgorithm error")
                .downcast_ref::<MoshpitError>()
                .is_some_and(|e| *e == MoshpitError::NoCommonAlgorithm),
        );
    }

    #[tokio::test]
    async fn client_kex_unexpected_initial_frame_returns_key_not_established() {
        use crate::MoshpitError;

        let (client_reader, _client_writer, _server_reader, mut server_writer) =
            make_bidirectional_loopback().await;
        let (mut kex_reader, _rx_frames, _rx_events) = make_test_kex_reader(client_reader);

        // Server sends a non-KexInit, non-KexFailure frame — truly unexpected
        server_writer
            .write_frame(&Frame::KeyAgreement(UuidWrapper::new(uuid::Uuid::nil())))
            .await
            .expect("write unexpected KeyAgreement frame");
        drop(server_writer);

        let result = kex_reader.client_kex().await;
        assert!(result.is_err());
        assert!(
            result
                .expect_err("expected KeyNotEstablished error")
                .downcast_ref::<MoshpitError>()
                .is_some_and(|e| *e == MoshpitError::KeyNotEstablished),
        );
    }

    #[tokio::test]
    async fn client_kex_server_closes_after_peer_initialize_returns_error() {
        let (client_reader, _client_writer, _server_reader, mut server_writer) =
            make_bidirectional_loopback().await;
        let (mut kex_reader, _rx_frames, _rx_events) = make_test_kex_reader(client_reader);

        // Server sends KexInit then PeerInitialize with a valid X25519 public key, then closes
        let server_epk = PrivateKey::generate(&X25519).expect("generate test X25519 key");
        let server_epk_pub = server_epk.compute_public_key().expect("compute public key");
        let identity_key = vec![0u8; 32]; // fixed identity bytes (not used for ECDH)
        let salt = vec![0u8; 32];
        server_writer
            .write_frame(&Frame::KexInit(
                supported_algorithms(),
                crate::kex::negotiate::local_protocol_support(),
            ))
            .await
            .expect("write KexInit frame");
        server_writer
            .write_frame(&Frame::PeerInitialize(
                identity_key,
                server_epk_pub.as_ref().to_vec(),
                salt,
            ))
            .await
            .expect("write PeerInitialize frame");
        drop(server_writer);

        let result = kex_reader.client_kex().await;
        assert!(
            result.is_err(),
            "expected error after server closes post-PeerInitialize"
        );
    }

    #[tokio::test]
    async fn client_kex_wrong_frame_after_peer_initialize_returns_key_not_established() {
        use crate::MoshpitError;

        let (client_reader, _client_writer, _server_reader, mut server_writer) =
            make_bidirectional_loopback().await;
        let (mut kex_reader, _rx_frames, _rx_events) = make_test_kex_reader(client_reader);

        let server_epk = PrivateKey::generate(&X25519).expect("generate test X25519 key");
        let server_epk_pub = server_epk.compute_public_key().expect("compute public key");
        let identity_key = vec![0u8; 32];
        let salt = vec![0u8; 32];
        server_writer
            .write_frame(&Frame::KexInit(
                supported_algorithms(),
                crate::kex::negotiate::local_protocol_support(),
            ))
            .await
            .expect("write KexInit frame");
        server_writer
            .write_frame(&Frame::PeerInitialize(
                identity_key,
                server_epk_pub.as_ref().to_vec(),
                salt,
            ))
            .await
            .expect("write PeerInitialize frame");
        // Send wrong frame instead of KeyAgreement
        server_writer
            .write_frame(&Frame::KexFailure)
            .await
            .expect("write KexFailure frame");
        drop(server_writer);

        let result = kex_reader.client_kex().await;
        assert!(result.is_err());
        assert!(
            result
                .expect_err("expected KeyNotEstablished error")
                .downcast_ref::<MoshpitError>()
                .is_some_and(|e| *e == MoshpitError::KeyNotEstablished),
        );
    }

    #[tokio::test]
    async fn client_kex_incompatible_protocol_version_fails() {
        use crate::MoshpitError;
        use crate::kex::negotiate::ProtocolSupport;

        let (client_reader, _client_writer, _server_reader, mut server_writer) =
            make_bidirectional_loopback().await;
        let (mut kex_reader, _rx_frames, mut rx_events) = make_test_kex_reader(client_reader);

        // Server advertises a protocol range that does not overlap the client's
        // default support (`{min:1, max:1}`), so version negotiation must fail
        // even though the algorithm lists agree.
        server_writer
            .write_frame(&Frame::KexInit(
                supported_algorithms(),
                ProtocolSupport { min: 2, max: 2 },
            ))
            .await
            .expect("write KexInit frame");
        drop(server_writer);

        let result = kex_reader.client_kex().await;
        assert!(
            result
                .expect_err("expected IncompatibleProtocolVersion error")
                .downcast_ref::<MoshpitError>()
                .is_some_and(|e| *e == MoshpitError::IncompatibleProtocolVersion),
        );
        // A Failure event is emitted so the state machine can tear the session down.
        assert!(
            from_fn(|| rx_events.try_recv().ok()).any(|e| matches!(e, KexEvent::Failure)),
            "expected a KexEvent::Failure to be sent",
        );
    }

    #[tokio::test]
    async fn server_kex_incompatible_protocol_version_fails() {
        use crate::MoshpitError;
        use crate::kex::negotiate::ProtocolSupport;

        // The server-side reader reads from the server end of the loopback while
        // the client end writes the KexInit.
        let (_client_reader, mut client_writer, server_reader, _server_writer) =
            make_bidirectional_loopback().await;
        // `_rx_frames` must stay bound: server_kex sends its own KexInit on this
        // channel before negotiating, and a dropped receiver would fail that send
        // first, masking the version error we are testing for.
        let (mut kex_reader, _rx_frames, _rx_events) = make_test_kex_reader(server_reader);

        // Client advertises a protocol range disjoint from the server's default.
        client_writer
            .write_frame(&Frame::KexInit(
                supported_algorithms(),
                ProtocolSupport { min: 2, max: 2 },
            ))
            .await
            .expect("write KexInit frame");
        drop(client_writer);

        let mut pool = BTreeSet::new();
        let _ = pool.insert(50123u16);
        let port_pool = StdArc::new(TokioMutex::new(pool));
        let socket_addr: SocketAddr = "127.0.0.1:9000".parse().expect("hardcoded test address");
        // The version error returns before the public key file is read, so this
        // path never has to exist.
        let dummy_pubkey = PathBuf::from("/nonexistent/pubkey");

        let result = kex_reader
            .server_kex(socket_addr, port_pool, &dummy_pubkey, None)
            .await;
        assert!(
            result
                .expect_err("expected IncompatibleProtocolVersion error")
                .downcast_ref::<MoshpitError>()
                .is_some_and(|e| *e == MoshpitError::IncompatibleProtocolVersion),
        );
    }

    #[tokio::test]
    async fn client_kex_happy_path_sends_all_events() {
        use uuid::Uuid;

        let (client_reader, _client_writer, _server_reader, mut server_writer) =
            make_bidirectional_loopback().await;
        // We need a separate tx/rx so we can observe the frames KexReader tries to send
        let (tx_out, mut rx_out) = unbounded_channel::<Frame>();
        let (tx_event_out, mut rx_event_out) = unbounded_channel::<KexEvent>();
        let kex_reader = super::super::KexReader::builder()
            .reader(client_reader)
            .tx(tx_out)
            .tx_event(tx_event_out)
            .build();

        let server_epk = PrivateKey::generate(&X25519).expect("generate test X25519 key");
        let server_epk_pub = server_epk.compute_public_key().expect("compute public key");
        let identity_key = vec![0u8; 32]; // fixed identity bytes (not used for ECDH)
        let mut salt_bytes = [0u8; 32];
        fill(&mut salt_bytes).expect("fill salt bytes");

        let conn_uuid = Uuid::new_v4();
        let session_uuid = Uuid::new_v4();
        let moshpits_addr: SocketAddr = "127.0.0.1:50002".parse().expect("hardcoded test address");

        // Spawn mock server task
        let server_handle = spawn(async move {
            // 1. Send KexInit so client can negotiate and generate its ephemeral key.
            server_writer
                .write_frame(&Frame::KexInit(
                    supported_algorithms(),
                    crate::kex::negotiate::local_protocol_support(),
                ))
                .await
                .expect("write KexInit frame");
            // 2. Drain the Initialize frame that client_kex sends after negotiation.
            drop(rx_out.recv().await);
            // 3. Send PeerInitialize with the server's identity key, ephemeral key, and salt.
            server_writer
                .write_frame(&Frame::PeerInitialize(
                    identity_key,
                    server_epk_pub.as_ref().to_vec(),
                    salt_bytes.to_vec(),
                ))
                .await
                .expect("write PeerInitialize frame");
            // 4. Drain the Check frame that client_kex sends after ECDH.
            drop(rx_out.recv().await);
            // 5. Send KeyAgreement, SessionToken, MoshpitsAddr.
            server_writer
                .write_frame(&Frame::KeyAgreement(UuidWrapper::new(conn_uuid)))
                .await
                .expect("write KeyAgreement frame");
            server_writer
                .write_frame(&Frame::SessionToken(UuidWrapper::new(session_uuid)))
                .await
                .expect("write SessionToken frame");
            server_writer
                .write_frame(&Frame::MoshpitsAddr(moshpits_addr))
                .await
                .expect("write MoshpitsAddr frame");
        });

        let mut kex_reader = kex_reader;
        kex_reader
            .client_kex()
            .await
            .expect("client_kex happy path");
        server_handle.await.expect("server task panicked");

        // Collect all events
        let mut events = Vec::new();
        while let Ok(e) = rx_event_out.try_recv() {
            events.push(e);
        }

        // Should have: NegotiatedAlgorithms, KeyMaterial, HMACKeyMaterial, Uuid, SessionInfo, MoshpitsAddr
        assert_eq!(events.len(), 6, "expected 6 kex events, got: {events:?}");
        assert!(matches!(events[0], KexEvent::NegotiatedAlgorithms(_)));
        assert!(matches!(events[1], KexEvent::KeyMaterial(_)));
        assert!(matches!(events[2], KexEvent::HMACKeyMaterial(_)));
        assert!(matches!(events[3], KexEvent::Uuid(_)));
        assert!(matches!(events[4], KexEvent::SessionInfo(_, false)));
        assert!(matches!(events[5], KexEvent::MoshpitsAddr(_)));
    }

    #[tokio::test]
    async fn client_kex_server_closes_before_session_token_returns_error() {
        let (client_reader, _client_writer, _server_reader, mut server_writer) =
            make_bidirectional_loopback().await;
        let (mut kex_reader, _rx_frames, _rx_events) = make_test_kex_reader(client_reader);

        let server_epk = PrivateKey::generate(&X25519).expect("generate test X25519 key");
        let server_epk_pub = server_epk.compute_public_key().expect("compute public key");
        let identity_key = vec![0u8; 32];
        let salt = vec![0u8; 32];
        server_writer
            .write_frame(&Frame::KexInit(
                supported_algorithms(),
                crate::kex::negotiate::local_protocol_support(),
            ))
            .await
            .expect("write KexInit frame");
        server_writer
            .write_frame(&Frame::PeerInitialize(
                identity_key,
                server_epk_pub.as_ref().to_vec(),
                salt,
            ))
            .await
            .expect("write PeerInitialize frame");
        server_writer
            .write_frame(&Frame::KeyAgreement(UuidWrapper::new(uuid::Uuid::new_v4())))
            .await
            .expect("write KeyAgreement frame");
        // Close without sending SessionToken
        drop(server_writer);

        let result = kex_reader.client_kex().await;
        assert!(
            result.is_err(),
            "expected error when server closes before SessionToken"
        );
    }

    #[tokio::test]
    async fn client_kex_server_closes_before_moshpits_addr_returns_error() {
        let (client_reader, _client_writer, _server_reader, mut server_writer) =
            make_bidirectional_loopback().await;
        let (mut kex_reader, _rx_frames, _rx_events) = make_test_kex_reader(client_reader);

        let server_epk = PrivateKey::generate(&X25519).expect("generate test X25519 key");
        let server_epk_pub = server_epk.compute_public_key().expect("compute public key");
        let identity_key = vec![0u8; 32];
        let salt = vec![0u8; 32];
        server_writer
            .write_frame(&Frame::KexInit(
                supported_algorithms(),
                crate::kex::negotiate::local_protocol_support(),
            ))
            .await
            .expect("write KexInit frame");
        server_writer
            .write_frame(&Frame::PeerInitialize(
                identity_key,
                server_epk_pub.as_ref().to_vec(),
                salt,
            ))
            .await
            .expect("write PeerInitialize frame");
        server_writer
            .write_frame(&Frame::KeyAgreement(UuidWrapper::new(uuid::Uuid::new_v4())))
            .await
            .expect("write KeyAgreement frame");
        server_writer
            .write_frame(&Frame::SessionToken(UuidWrapper::new(uuid::Uuid::new_v4())))
            .await
            .expect("write SessionToken frame");
        // Close without sending MoshpitsAddr
        drop(server_writer);

        let result = kex_reader.client_kex().await;
        assert!(
            result.is_err(),
            "expected error when server closes before MoshpitsAddr"
        );
    }

    #[tokio::test]
    async fn client_kex_wrong_frame_instead_of_session_token_returns_key_not_established() {
        use crate::MoshpitError;

        let (client_reader, _client_writer, _server_reader, mut server_writer) =
            make_bidirectional_loopback().await;
        let (mut kex_reader, _rx_frames, _rx_events) = make_test_kex_reader(client_reader);

        let server_epk = PrivateKey::generate(&X25519).expect("generate test X25519 key");
        let server_epk_pub = server_epk.compute_public_key().expect("compute public key");
        let identity_key = vec![0u8; 32];
        let salt = vec![0u8; 32];
        server_writer
            .write_frame(&Frame::KexInit(
                supported_algorithms(),
                crate::kex::negotiate::local_protocol_support(),
            ))
            .await
            .expect("write KexInit frame");
        server_writer
            .write_frame(&Frame::PeerInitialize(
                identity_key,
                server_epk_pub.as_ref().to_vec(),
                salt,
            ))
            .await
            .expect("write PeerInitialize frame");
        server_writer
            .write_frame(&Frame::KeyAgreement(UuidWrapper::new(uuid::Uuid::new_v4())))
            .await
            .expect("write KeyAgreement frame");
        // Send wrong frame instead of SessionToken
        server_writer
            .write_frame(&Frame::KexFailure)
            .await
            .expect("write KexFailure frame");
        drop(server_writer);

        let result = kex_reader.client_kex().await;
        assert!(result.is_err());
        assert!(
            result
                .expect_err("expected KeyNotEstablished error")
                .downcast_ref::<MoshpitError>()
                .is_some_and(|e| *e == MoshpitError::KeyNotEstablished),
            "expected KeyNotEstablished error"
        );
    }

    // -----------------------------------------------------------------------
    // resolve_kex_alg tests
    // -----------------------------------------------------------------------

    #[test]
    fn resolve_kex_alg_all_known_variants() {
        use super::resolve_kex_alg;
        use crate::kex::negotiate::{
            KEX_ML_KEM_512_SHA256, KEX_ML_KEM_768_SHA256, KEX_ML_KEM_1024_SHA256, KEX_P256_SHA256,
            KEX_P384_SHA384, KEX_X25519_SHA256,
        };
        assert!(resolve_kex_alg(KEX_X25519_SHA256).is_ok());
        assert!(resolve_kex_alg(KEX_P384_SHA384).is_ok());
        assert!(resolve_kex_alg(KEX_P256_SHA256).is_ok());
        assert!(resolve_kex_alg(KEX_ML_KEM_512_SHA256).is_ok());
        assert!(resolve_kex_alg(KEX_ML_KEM_768_SHA256).is_ok());
        assert!(resolve_kex_alg(KEX_ML_KEM_1024_SHA256).is_ok());
    }

    #[test]
    fn resolve_kex_alg_unknown_returns_error() {
        assert!(super::resolve_kex_alg("bogus-kex-alg").is_err());
    }

    // -----------------------------------------------------------------------
    // unstable feature (ML-DSA) tests
    // -----------------------------------------------------------------------

    #[cfg(feature = "unstable")]
    #[test]
    fn ml_dsa_sign_verify_ml_dsa_65_and_87() {
        use aws_lc_rs::{
            encoding::AsRawBytes as _,
            signature::KeyPair as _,
            unstable::signature::{ML_DSA_65_SIGNING, ML_DSA_87_SIGNING, PqdsaKeyPair},
        };

        let negotiated = NegotiatedAlgorithms {
            kex: KEX_ML_KEM_768_SHA256.to_string(),
            aead: AEAD_AES256_GCM_SIV.to_string(),
            mac: MAC_HMAC_SHA512.to_string(),
            kdf: KDF_HKDF_SHA256.to_string(),
            ..NegotiatedAlgorithms::default()
        };

        for (signing_alg, alg_str) in [
            (&ML_DSA_65_SIGNING, crate::KEY_ALGORITHM_ML_DSA_65),
            (&ML_DSA_87_SIGNING, crate::KEY_ALGORITHM_ML_DSA_87),
        ] {
            let key_pair = PqdsaKeyPair::generate(signing_alg).expect("generate test ML-DSA key");
            let private_key = key_pair
                .private_key()
                .as_raw_bytes()
                .expect("private key bytes");
            let public_key = key_pair.public_key().as_ref().to_vec();
            let transcript = super::identity_transcript(&super::IdentityTranscriptParts {
                role: b"client",
                negotiated: &negotiated,
                user: b"alice",
                client_exchange: b"client-exchange",
                client_identity: b"client-identity",
                server_identity: b"server-identity",
                server_exchange: b"server-exchange",
                salt: b"salt",
            })
            .expect("build identity transcript");
            let signature =
                super::sign_identity_transcript(alg_str, private_key.as_ref(), &transcript)
                    .expect("sign identity transcript");
            super::verify_identity_transcript(alg_str, &public_key, &transcript, &signature)
                .expect("verify identity transcript");
        }
    }

    #[cfg(feature = "unstable")]
    #[test]
    fn is_ml_dsa_algorithm_returns_true_for_ml_dsa() {
        assert!(super::is_ml_dsa_algorithm(crate::KEY_ALGORITHM_ML_DSA_44));
        assert!(super::is_ml_dsa_algorithm(crate::KEY_ALGORITHM_ML_DSA_65));
        assert!(super::is_ml_dsa_algorithm(crate::KEY_ALGORITHM_ML_DSA_87));
    }

    #[cfg(feature = "unstable")]
    #[test]
    fn is_ml_dsa_algorithm_returns_false_for_ecdh() {
        assert!(!super::is_ml_dsa_algorithm("X25519"));
        assert!(!super::is_ml_dsa_algorithm("P384"));
        assert!(!super::is_ml_dsa_algorithm("unknown"));
    }

    #[cfg(feature = "unstable")]
    #[test]
    fn parse_full_public_key_valid() {
        let alg = b"X25519";
        let pubkey = [0xABu8; 32];
        let mut payload = Vec::new();
        payload.extend_from_slice(
            &u32::try_from(alg.len())
                .expect("alg length fits in u32")
                .to_be_bytes(),
        );
        payload.extend_from_slice(alg);
        payload.extend_from_slice(
            &u32::try_from(pubkey.len())
                .expect("pubkey length fits in u32")
                .to_be_bytes(),
        );
        payload.extend_from_slice(&pubkey);
        let b64 = STANDARD.encode(&payload);
        let full_key = format!("moshpit {b64} user@host").into_bytes();
        let (key_alg, key_bytes) =
            super::parse_full_public_key(&full_key).expect("parse full public key");
        assert_eq!(key_alg, "X25519");
        assert_eq!(key_bytes, pubkey);
    }

    #[cfg(feature = "unstable")]
    #[test]
    fn parse_full_public_key_wrong_part_count() {
        let result = super::parse_full_public_key(b"moshpit only-two-parts");
        assert!(result.is_err());
    }

    #[cfg(feature = "unstable")]
    #[test]
    fn parse_full_public_key_truncated_payload() {
        let b64 = STANDARD.encode(b"abc");
        let full_key = format!("moshpit {b64} user@host").into_bytes();
        let result = super::parse_full_public_key(&full_key);
        assert!(result.is_err());
    }

    #[cfg(feature = "unstable")]
    #[test]
    fn sign_identity_transcript_unknown_alg_errors() {
        let result = super::sign_identity_transcript("X25519", &[], &[]);
        assert!(result.is_err());
    }

    #[cfg(feature = "unstable")]
    #[test]
    fn verify_identity_transcript_unknown_alg_errors() {
        let result = super::verify_identity_transcript("X25519", &[], &[], &[]);
        assert!(result.is_err());
    }
}
