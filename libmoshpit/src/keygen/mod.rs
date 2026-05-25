// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

//! Key generation, loading, encryption, and fingerprinting for identity key pairs.

use std::{
    fs::File,
    io::{BufWriter, Read, Write},
    path::PathBuf,
};

use anyhow::{Error, Result};
use argon2::{Argon2, PasswordHasher, password_hash::phc::SaltString};
use aws_lc_rs::{
    aead::{AES_256_GCM_SIV, Aad, Nonce, RandomizedNonceKey},
    agreement::{ECDH_P256, ECDH_P384, PrivateKey, PublicKey, X25519},
    cipher::AES_256_KEY_LEN,
    digest::SHA512_OUTPUT_LEN,
    encoding::{AsBigEndian as _, Curve25519SeedBin, EcPrivateKeyBin},
    hkdf::{HKDF_SHA512, Salt},
    rand::fill,
};
#[cfg(feature = "unstable")]
use aws_lc_rs::{
    encoding::AsRawBytes as _,
    signature::KeyPair as _,
    unstable::signature::{
        ML_DSA_44_SIGNING, ML_DSA_65_SIGNING, ML_DSA_87_SIGNING, PqdsaKeyPair,
        PqdsaSigningAlgorithm,
    },
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use bytes::{Buf as _, BytesMut};
use getset::Getters;
use whoami::{hostname, username};

use crate::{KexMode, MoshpitError};

pub(crate) mod pk;

const KEY_HEADER: &[u8] = b"moshpit-key-v1";
/// The key algorithm string for X25519 (Curve25519) ECDH keys.
pub const KEY_ALGORITHM_X25519: &str = "X25519";
/// The key algorithm string for ECDH P-384 keys.
pub const KEY_ALGORITHM_P384: &str = "P384";
/// The key algorithm string for ECDH P-256 keys.
pub const KEY_ALGORITHM_P256: &str = "P256";
/// The experimental key algorithm string for ML-DSA-44 identity keys.
#[cfg(feature = "unstable")]
pub const KEY_ALGORITHM_ML_DSA_44: &str = "ML-DSA-44";
/// The experimental key algorithm string for ML-DSA-65 identity keys.
#[cfg(feature = "unstable")]
pub const KEY_ALGORITHM_ML_DSA_65: &str = "ML-DSA-65";
/// The experimental key algorithm string for ML-DSA-87 identity keys.
#[cfg(feature = "unstable")]
pub const KEY_ALGORITHM_ML_DSA_87: &str = "ML-DSA-87";

/// Returns a numeric strength rank for a key algorithm (higher = stronger).
///
/// Used by the client to select the strongest available identity from the agent
/// when multiple keys are loaded. Unknown algorithms rank lowest (0).
#[cfg(unix)]
pub(crate) fn algorithm_strength_rank(alg: &str) -> u8 {
    match alg {
        "ML-DSA-87" => 6,
        "ML-DSA-65" => 5,
        "ML-DSA-44" => 4,
        KEY_ALGORITHM_P384 => 3,
        KEY_ALGORITHM_P256 => 2,
        KEY_ALGORITHM_X25519 => 1,
        _ => 0,
    }
}

/// Identity key algorithms supported by this build of libmoshpit.
///
/// Passed to [`crate::agent::client::AgentClient::list_supported_identities`] so the
/// agent returns only keys this client can actually use.
#[cfg(all(unix, not(feature = "unstable")))]
pub(crate) const SUPPORTED_IDENTITY_ALGORITHMS: &[&str] =
    &[KEY_ALGORITHM_X25519, KEY_ALGORITHM_P256, KEY_ALGORITHM_P384];

/// Identity key algorithms supported by this build of libmoshpit (unstable variant).
#[cfg(all(unix, feature = "unstable"))]
pub(crate) const SUPPORTED_IDENTITY_ALGORITHMS: &[&str] = &[
    KEY_ALGORITHM_X25519,
    KEY_ALGORITHM_P256,
    KEY_ALGORITHM_P384,
    KEY_ALGORITHM_ML_DSA_44,
    KEY_ALGORITHM_ML_DSA_65,
    KEY_ALGORITHM_ML_DSA_87,
];

const NONE_CIPHER: &str = "none";
const NONE_KDF: &str = "none";
const KEY_CIPHER: &str = "aes-256-gcm-siv";
const HKDF_INFO: &[&[u8]] = &[b"moshpit HKDF"];

#[cfg(feature = "unstable")]
fn resolve_pqdsa_signing_alg(key_alg: &str) -> Option<&'static PqdsaSigningAlgorithm> {
    match key_alg {
        KEY_ALGORITHM_ML_DSA_44 => Some(&ML_DSA_44_SIGNING),
        KEY_ALGORITHM_ML_DSA_65 => Some(&ML_DSA_65_SIGNING),
        KEY_ALGORITHM_ML_DSA_87 => Some(&ML_DSA_87_SIGNING),
        _ => None,
    }
}

#[cfg(feature = "unstable")]
fn is_pqdsa_key_algorithm(key_alg: &str) -> bool {
    resolve_pqdsa_signing_alg(key_alg).is_some()
}

#[cfg(not(feature = "unstable"))]
fn is_pqdsa_key_algorithm(_key_alg: &str) -> bool {
    false
}

fn is_supported_key_algorithm(key_alg: &str) -> bool {
    matches!(
        key_alg,
        KEY_ALGORITHM_X25519 | KEY_ALGORITHM_P384 | KEY_ALGORITHM_P256
    ) || is_pqdsa_key_algorithm(key_alg)
}

/// The AEAD cipher algorithms supported by moshpit key generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AEADCipher {
    /// Unencrypted private key.
    None,
    /// AES-256-GCM-SIV encrypted private key.
    Aes256GcmSiv,
}

impl AEADCipher {
    /// Returns the string representation of the AEAD cipher algorithm.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            AEADCipher::None => NONE_CIPHER,
            AEADCipher::Aes256GcmSiv => KEY_CIPHER,
        }
    }

    /// Return the byte representation of the AEAD cipher algorithm.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.as_str().as_bytes()
    }
}

impl TryFrom<&str> for AEADCipher {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self> {
        TryFrom::try_from(value.as_bytes())
    }
}

impl TryFrom<&[u8]> for AEADCipher {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self> {
        match value {
            b"none" => Ok(AEADCipher::None),
            b"aes-256-gcm-siv" => Ok(AEADCipher::Aes256GcmSiv),
            _ => Err(MoshpitError::UnsupportedAeadCipher.into()),
        }
    }
}

/// A moshpit unencrypted key pair consisting of a private and public key.
#[derive(Debug, Getters)]
#[getset(get = "pub")]
pub struct UnencryptedKeyPair {
    /// The private key half of the key pair.
    private_key: PrivateKey,
    /// The public key half of the key pair.
    public_key: PublicKey,
}

impl UnencryptedKeyPair {
    /// Get the Private/Public key pair.
    #[must_use]
    pub fn take(self) -> (PrivateKey, PublicKey) {
        (self.private_key, self.public_key)
    }
}

/// A moshpit encrypted key pair.  A password is
/// required to decrypt the private key.
#[derive(Debug, Getters)]
#[getset(get = "pub")]
pub struct EncryptedKeyPair {
    /// The Argon2 KDF hahh.  Used to verify a passphrase before decryption.
    kdf: String,
    /// The public key half of the key pair.
    public_key: Vec<u8>,
    /// The key algorithm string stored in the key file.
    key_algorithm: String,
    /// The HMAC salt bytes used to extend the passphrase into key material.
    salt_bytes: Vec<u8>,
    /// The nonce bytes used for AEAD encryption/decryption.
    nonce_bytes: Vec<u8>,
    /// The encrypted private key bytes.
    encrypted_private_key_bytes: Vec<u8>,
}

/// Algorithm-aware identity key material loaded from a moshpit private key file.
#[derive(Debug, Getters)]
#[getset(get = "pub")]
pub struct IdentityKeyPair {
    /// The key algorithm string stored in the key file.
    key_algorithm: String,
    /// The public key half of the key pair.
    public_key: Vec<u8>,
    /// The private key bytes after decryption, if encrypted.
    private_key: Vec<u8>,
}

/// A moshpit key pair consisting of a private and public key.
#[derive(Debug, Getters)]
#[getset(get = "pub")]
pub struct KeyPair {
    /// The encoded private key bytes.
    private_key: String,
    /// The encoded public key bytes.
    public_key: String,
    /// The public key bytes.
    public_key_bytes: Vec<u8>,
}

impl KeyPair {
    /// Returns the default private key path and public key extension
    /// for use in key generation.
    ///
    /// # Errors
    /// If the home directory cannot be determined, an error is returned.
    ///
    pub fn default_key_path_ext(mode: KexMode, key_alg: &str) -> Result<(PathBuf, &'static str)> {
        let base_dir = dirs2::home_dir().ok_or(MoshpitError::HomeDir)?.join(".mp");
        let stem = key_alg.to_lowercase().replace('-', "_");
        Ok(match mode {
            KexMode::Client => (base_dir.join(format!("id_{stem}")), "pub"),
            KexMode::Server(_socket_addr) => (base_dir.join(format!("mps_host_{stem}_key")), "pub"),
        })
    }

    /// Generates a new moshpit key pair, optionally protected by a passphrase.
    ///
    /// The public key format is the following bytes encoded in base64:
    /// ```text
    /// <key algorithm length (kal)> (   4 bytes)
    /// <key algorithm>              ( kal bytes)
    /// <public key length (pbkl)>   (   4 bytes)
    /// <public key>                 (pbkl bytes)
    /// ```
    ///
    /// ```text
    /// 00000000  00 00 00 06 58 32 35 35  31 39 00 00 00 20 e7 62  |....X25519... .b|
    /// 00000010  70 bd fd 53 e7 23 ef 22  c5 c5 1b 82 01 d9 10 2b  |p..S.#.".......+|
    /// 00000020  88 7c ae 33 2b 72 f9 55  61 96 98 05 ed 14        |.|.3+r.Ua.....|
    /// ```
    ///
    /// The private key format is the following bytes encoded in base64:
    ///
    /// **Unencrypted private key:**
    /// ```text
    /// <magic header (moshpit-key-v1)> (  14 bytes)
    /// <cipher length (cl)>            (   4 bytes)
    /// <cipher>                        (  cl bytes)
    /// <kdf length (kdl)>              (   4 bytes)
    /// <kdf>                           ( kdl bytes)
    /// <key algorithm length (kal)>    (   4 bytes)
    /// <key algorithm>                 ( kal bytes)
    /// <public key length (pbkl)>      (   4 bytes)
    /// <public key>                    (pbkl bytes)
    /// <private key length (pvkl)>     (   4 bytes)
    /// <private key>                   (pvkl bytes)
    /// ```
    ///
    /// ```text
    /// 00000000  6d 6f 73 68 70 69 74 2d  6b 65 79 2d 76 31 00 00  |moshpit-key-v1..|
    /// 00000010  00 04 6e 6f 6e 65 00 00  00 04 6e 6f 6e 65 00 00  |..none....none..|
    /// 00000020  00 06 58 32 35 35 31 39  00 00 00 20 3e 92 69 30  |..X25519... >.i0|
    /// 00000030  c1 b9 95 e3 09 ba b2 66  84 71 0c 1d 1d f7 c6 6b  |.......f.q.....k|
    /// 00000040  ed 49 6a 0d 66 f3 7e 92  76 1e 09 7d 00 00 00 20  |.Ij.f.~.v..}... |
    /// 00000050  0f 6f 52 ac 2f d5 13 07  64 6e 96 7c c8 de dd ec  |.oR./...dn.|....|
    /// 00000060  4f 03 4b af b9 81 77 00  85 27 a9 01 48 b6 d5 8e  |O.K...w..'..H...|
    /// ```
    ///
    /// **Encrypted private key:**
    /// ```text
    /// <magic header (moshpit-key-v1)>       (  14 bytes)
    /// <cipher length (cl)>                  (   4 bytes)
    /// <cipher>                              (  cl bytes)
    /// <kdf length (kdl)>                    (   4 bytes)
    /// <kdf>                                 ( kdl bytes)
    /// <key algorithm length (kal)>          (   4 bytes)
    /// <key algorithm>                       ( kal bytes)
    /// <public key length (pbkl)>            (   4 bytes)
    /// <public key>                          (pbkl bytes)
    /// <hkdf salt length (hsl)>              (   4 bytes)
    /// <hkdf salt>                           ( hsl bytes)
    /// <nonce length (nl)>                   (   4 bytes)
    /// <nonce>                               (  nl bytes)
    /// <encrypted private key length (epkl)> (   4 bytes)
    /// <encrypted private key>               (epkl bytes)
    /// ```
    ///
    /// ```text
    /// 00000000  6d 6f 73 68 70 69 74 2d  6b 65 79 2d 76 31 00 00  |moshpit-key-v1..|
    /// 00000010  00 0f 61 65 73 2d 32 35  36 2d 67 63 6d 2d 73 69  |..aes-256-gcm-si|
    /// 00000020  76 00 00 00 61 24 61 72  67 6f 6e 32 69 64 24 76  |v...a$argon2id$v|
    /// 00000030  3d 31 39 24 6d 3d 31 39  34 35 36 2c 74 3d 32 2c  |=19$m=19456,t=2,|
    /// 00000040  70 3d 31 24 72 56 53 6c  73 4b 6a 44 45 56 70 4a  |p=1$rVSlsKjDEVpJ|
    /// 00000050  7a 4c 6d 71 79 54 45 34  75 67 24 69 42 78 6c 50  |zLmqyTE4ug$iBxlP|
    /// 00000060  36 59 45 66 79 56 30 59  69 68 53 4a 6d 58 6e 31  |6YEfyV0YihSJmXn1|
    /// 00000070  63 34 55 63 6d 33 4e 50  4b 4a 7a 51 54 75 54 6d  |c4Ucm3NPKJzQTuTm|
    /// 00000080  75 57 58 64 50 77 00 00  00 06 58 32 35 35 31 39  |uWXdPw....X25519|
    /// 00000090  00 00 00 20 e7 62 70 bd  fd 53 e7 23 ef 22 c5 c5  |... .bp..S.#."..|
    /// 000000a0  1b 82 01 d9 10 2b 88 7c  ae 33 2b 72 f9 55 61 96  |.....+.|.3+r.Ua.|
    /// 000000b0  98 05 ed 14 00 00 00 40  6d 03 02 2f 5a a5 cf 07  |.......@m../Z...|
    /// 000000c0  96 ee b5 c9 37 28 bf e2  05 68 7d 06 f3 7d 9b dc  |....7(...h}..}..|
    /// 000000d0  40 46 64 b3 4a 9a f9 bf  b6 a8 3b b6 64 0a 70 82  |@Fd.J.....;.d.p.|
    /// 000000e0  b3 bd 40 1a 4b a0 98 49  3f 4b fe 9e 5d ab 46 f6  |..@.K..I?K..].F.|
    /// 000000f0  43 bd cc 5b 8d e1 ae b9  00 00 00 0c 26 84 7d 32  |C..[........&.}2|
    /// 00000100  4e 23 8b a3 01 98 f2 17  00 00 00 30 43 f4 a2 d6  |N#.........0C...|
    /// 00000110  e4 8a d5 50 ef e1 d2 7e  dd 71 17 f2 a7 e4 72 fa  |...P...~.q....r.|
    /// 00000120  08 bd 41 63 7e f1 3f a6  7b ac 91 ae 32 c1 c7 40  |..Ac~.?.{...2..@|
    /// 00000130  44 d7 c0 1c 2b 25 ff aa  d5 d2 01 e7              |D...+%......|
    /// ```
    ///
    /// # Errors
    /// If key generation or encryption fails, an error is returned.
    ///
    pub fn generate_key_pair(
        passphrase_opt: Option<&String>,
        mode: KexMode,
        key_alg: &str,
    ) -> Result<Self> {
        if matches!(mode, KexMode::Client) && passphrase_opt.is_none_or(String::is_empty) {
            return Err(anyhow::anyhow!(
                "A non-empty passphrase is required to protect the private key"
            ));
        }

        #[cfg(feature = "unstable")]
        if let Some(alg) = resolve_pqdsa_signing_alg(key_alg) {
            let key_pair = PqdsaKeyPair::generate(alg)?;
            let public_key = key_pair.public_key().as_ref();
            let private_key = key_pair.private_key().as_raw_bytes()?;
            let (public_key_bytes, public_key_encoded) = generate_public_key(key_alg, public_key)?;
            let mut priv_key_bytes = private_key.as_ref().to_vec();
            let private_key_encoded =
                generate_private_key(&mut priv_key_bytes, public_key, passphrase_opt, key_alg)?;

            return Ok(KeyPair {
                private_key: private_key_encoded,
                public_key: public_key_encoded,
                public_key_bytes,
            });
        }

        // Map key_alg string to the aws-lc-rs agreement Algorithm
        let alg = match key_alg {
            KEY_ALGORITHM_X25519 => &X25519,
            KEY_ALGORITHM_P384 => &ECDH_P384,
            KEY_ALGORITHM_P256 => &ECDH_P256,
            _ => return Err(anyhow::anyhow!("Unknown key algorithm: {key_alg}")),
        };

        // Generate the ECDH key pair using the selected algorithm
        let priv_key = PrivateKey::generate(alg)?;
        let public_key = priv_key.compute_public_key()?;

        // Setup the encoded public key
        let (public_key_bytes, public_key_encoded) =
            generate_public_key(key_alg, public_key.as_ref())?;

        // Setup the encoded private key — extract raw bytes based on algorithm family
        let mut priv_key_bytes = if key_alg == KEY_ALGORITHM_X25519 {
            let bytes: Curve25519SeedBin<'_> = priv_key.as_be_bytes()?;
            bytes.as_ref().to_vec()
        } else {
            let bytes: EcPrivateKeyBin<'_> = priv_key.as_be_bytes()?;
            bytes.as_ref().to_vec()
        };
        let private_key_encoded = generate_private_key(
            &mut priv_key_bytes,
            public_key.as_ref(),
            passphrase_opt,
            key_alg,
        )?;

        Ok(KeyPair {
            private_key: private_key_encoded,
            public_key: public_key_encoded,
            public_key_bytes,
        })
    }

    /// Write the private key to the provided writer.
    ///
    /// # Errors
    /// If the hostname or username cannot be determined, an error is returned.
    /// If the write operation fails, an error is returned.
    ///
    pub fn write_private_key<T>(&self, writer: &mut T) -> Result<()>
    where
        T: Write,
    {
        let mut buf_writer = BufWriter::new(writer);
        buf_writer.write_all(self.private_key.as_bytes())?;
        Ok(())
    }

    /// Write the public key to the provided writer.
    ///
    /// # Errors
    /// If the hostname or username cannot be determined, an error is returned.
    /// If the write operation fails, an error is returned.
    ///
    pub fn write_public_key<T>(&self, writer: &mut T) -> Result<()>
    where
        T: Write,
    {
        let mut pub_buf_writer = BufWriter::new(writer);
        pub_buf_writer.write_all(b"moshpit ")?;
        pub_buf_writer.write_all(self.public_key.as_bytes())?;
        let username = username().unwrap_or("unknown-user".to_string());
        let hostname = hostname().unwrap_or("unknown-host".to_string());
        pub_buf_writer.write_all(format!(" {username}@{hostname}").as_bytes())?;
        Ok(())
    }

    /// Get the public key fingerprint for this key pair.
    ///
    /// # Errors
    /// If the hostname or username cannot be determined, an error is returned.
    ///
    pub fn fingerprint(&self) -> Result<String> {
        pk::fingerprint(&self.public_key_bytes)
    }

    /// Get the randomart image for this key pair.
    #[must_use]
    pub fn randomart(&self) -> String {
        pk::randomart(&self.public_key_bytes)
    }
}

fn add_key_alg(key: &mut Vec<u8>, alg: &str) -> Result<()> {
    key.extend_from_slice(&as_be_bytes(alg.len())?);
    key.extend_from_slice(alg.as_bytes());
    Ok(())
}

fn add_cipher_and_kdf(key: &mut Vec<u8>, cipher: &str, kdf: &str) -> Result<()> {
    key.extend_from_slice(&as_be_bytes(cipher.len())?);
    key.extend_from_slice(cipher.as_bytes());
    key.extend_from_slice(&as_be_bytes(kdf.len())?);
    key.extend_from_slice(kdf.as_bytes());
    Ok(())
}

fn generate_public_key(alg: &str, public_key: &[u8]) -> Result<(Vec<u8>, String)> {
    let mut public_key_bytes = vec![];
    add_key_alg(&mut public_key_bytes, alg)?;
    public_key_bytes.extend_from_slice(&as_be_bytes(public_key.len())?);
    public_key_bytes.extend_from_slice(public_key);
    let encoded = STANDARD.encode(&public_key_bytes);
    Ok((public_key_bytes, encoded))
}

fn generate_private_key(
    private_key: &mut Vec<u8>,
    public_key: &[u8],
    passphrase_opt: Option<&String>,
    alg: &str,
) -> Result<String> {
    let mut private_key_bytes = vec![];

    // Add the moshpit key header to the private key
    private_key_bytes.extend_from_slice(KEY_HEADER);

    // Generate the passphrase hash if a passphrase is provided with Argon2
    let passphrase_hash_opt = generate_passphrase_hash(passphrase_opt);

    if let Some((passphrase, passphrase_hash)) = passphrase_opt.zip(passphrase_hash_opt) {
        setup_encrypted_private_key(
            &mut private_key_bytes,
            private_key,
            public_key,
            passphrase,
            &passphrase_hash,
            alg,
        )?;
    } else {
        setup_unencrypted_private_key(&mut private_key_bytes, private_key, public_key, alg)?;
    }
    Ok(STANDARD.encode(&private_key_bytes))
}

fn setup_encrypted_private_key(
    private_key_bytes: &mut Vec<u8>,
    private_key: &mut Vec<u8>,
    public_key: &[u8],
    passphrase: &str,
    passphrase_hash: &str,
    alg: &str,
) -> Result<()> {
    add_cipher_and_kdf(private_key_bytes, KEY_CIPHER, passphrase_hash)?;
    add_key_alg(private_key_bytes, alg)?;
    private_key_bytes.extend_from_slice(&as_be_bytes(public_key.len())?);
    private_key_bytes.extend_from_slice(public_key);

    encrypt_private_key(private_key_bytes, private_key, passphrase)
}

fn setup_unencrypted_private_key(
    private_key_bytes: &mut Vec<u8>,
    private_key: &[u8],
    public_key: &[u8],
    alg: &str,
) -> Result<()> {
    add_cipher_and_kdf(private_key_bytes, NONE_CIPHER, NONE_KDF)?;
    add_key_alg(private_key_bytes, alg)?;
    private_key_bytes.extend_from_slice(&as_be_bytes(public_key.len())?);
    private_key_bytes.extend_from_slice(public_key);
    private_key_bytes.extend_from_slice(&as_be_bytes(private_key.len())?);
    private_key_bytes.extend_from_slice(private_key);
    Ok(())
}

fn generate_passphrase_hash(passphrase_opt: Option<&String>) -> Option<String> {
    passphrase_opt.and_then(|passphrase| {
        let salt = SaltString::generate();
        let argon2 = Argon2::default();
        argon2
            .hash_password_with_salt(passphrase.as_bytes(), salt.as_bytes())
            .ok()
            .map(|h| h.to_string())
    })
}

fn encrypt_private_key(
    private_key_bytes: &mut Vec<u8>,
    private_key: &mut Vec<u8>,
    passphrase: &str,
) -> Result<()> {
    use zeroize::Zeroize;
    // Encrypt the private key bytes with the passphrase
    let key_bytes = passphrase.as_bytes();

    // Extend the passphrase to 32 bytes (256 bits) for AES-256-GCM-SIV with HKDF_SHA512
    let mut salt_bytes = [0u8; SHA512_OUTPUT_LEN];
    fill(&mut salt_bytes)?;
    let salt = Salt::new(HKDF_SHA512, &salt_bytes);
    let pseudo_random_key = salt.extract(key_bytes);
    let okm_aes = pseudo_random_key.expand(HKDF_INFO, &AES_256_GCM_SIV)?;
    let mut derived_key = [0u8; AES_256_KEY_LEN];
    okm_aes.fill(&mut derived_key)?;

    // Encrypt the private key in place with an empty tag
    let rnk = RandomizedNonceKey::new(&AES_256_GCM_SIV, &derived_key)?;
    derived_key.zeroize();
    let nonce = rnk.seal_in_place_append_tag(Aad::empty(), private_key)?;
    let nonce_bytes = nonce.as_ref();

    // Append the HKDF salt, nonce, and encrypted private key bytes to the output
    private_key_bytes.extend_from_slice(&as_be_bytes(salt_bytes.len())?);
    private_key_bytes.extend_from_slice(&salt_bytes);
    private_key_bytes.extend_from_slice(&as_be_bytes(nonce_bytes.len())?);
    private_key_bytes.extend_from_slice(nonce_bytes);
    private_key_bytes.extend_from_slice(&as_be_bytes(private_key.len())?);
    private_key_bytes.extend_from_slice(private_key);

    Ok(())
}

/// Decrypts the provided encrypted private key bytes in place using the
///
/// # Errors
/// If decryption fails, an error is returned.
///
pub fn decrypt_private_key(
    passphrase: &str,
    salt_bytes: &[u8],
    nonce_bytes: &[u8],
    encrypted_private_key_bytes: &mut [u8],
) -> Result<()> {
    let _plaintext_len = decrypt_private_key_in_place(
        passphrase,
        salt_bytes,
        nonce_bytes,
        encrypted_private_key_bytes,
    )?;
    Ok(())
}

fn decrypt_private_key_to_vec(
    passphrase: &str,
    salt_bytes: &[u8],
    nonce_bytes: &[u8],
    encrypted_private_key_bytes: &[u8],
) -> Result<Vec<u8>> {
    let mut private_key = encrypted_private_key_bytes.to_vec();
    let plaintext_len =
        decrypt_private_key_in_place(passphrase, salt_bytes, nonce_bytes, &mut private_key)?;
    private_key.truncate(plaintext_len);
    Ok(private_key)
}

fn decrypt_private_key_in_place(
    passphrase: &str,
    salt_bytes: &[u8],
    nonce_bytes: &[u8],
    encrypted_private_key_bytes: &mut [u8],
) -> Result<usize> {
    use zeroize::Zeroize;
    // Encrypt the private key bytes with the passphrase
    let key_bytes = passphrase.as_bytes();

    // Extend the passphrase to 32 bytes (256 bits) for AES-256-GCM-SIV with HKDF_SHA512
    let salt = Salt::new(HKDF_SHA512, salt_bytes);
    let pseudo_random_key = salt.extract(key_bytes);
    let okm_aes = pseudo_random_key.expand(HKDF_INFO, &AES_256_GCM_SIV)?;
    let mut derived_key = [0u8; AES_256_KEY_LEN];
    okm_aes.fill(&mut derived_key)?;

    // Decrypt the private key in place with an empty tag
    let rnk = RandomizedNonceKey::new(&AES_256_GCM_SIV, &derived_key)?;
    derived_key.zeroize();
    let nonce = Nonce::try_assume_unique_for_key(nonce_bytes)?;
    let plaintext = rnk.open_in_place(nonce, Aad::empty(), encrypted_private_key_bytes)?;
    Ok(plaintext.len())
}

fn as_be_bytes(value: usize) -> Result<[u8; 4]> {
    Ok(u32::try_from(value)?.to_be_bytes())
}

/// Load a moshpit public key from the provided public key path.
///
/// # Errors
///
/// If the public key cannot be read or is invalid, an error is returned.
///
pub fn load_public_key(pub_key_path: &PathBuf) -> Result<(Vec<u8>, Vec<u8>)> {
    // Read the file contents into a buffer
    let mut buffered_reader = File::open(pub_key_path)?;
    let mut file_bytes = vec![];
    let _len = buffered_reader.read_to_end(&mut file_bytes)?;

    let pub_key_str = String::from_utf8_lossy(&file_bytes);
    let pub_key_parts: Vec<&str> = pub_key_str.split_whitespace().collect();
    if pub_key_parts.len() != 3 {
        return Err(MoshpitError::InvalidKeyHeader.into());
    }

    let pub_key_part = pub_key_parts[1].as_bytes();

    // Attempt the base64 decode the input
    let decoded = STANDARD.decode(pub_key_part)?;

    // Parse the public key file
    let mut public_key_bytes = BytesMut::from(&decoded[..]);
    let key_alg = get_val_by_len(&mut public_key_bytes)?;
    let key_alg_str = std::str::from_utf8(&key_alg).map_err(|_| MoshpitError::InvalidKeyHeader)?;
    if !is_supported_key_algorithm(key_alg_str) {
        return Err(MoshpitError::InvalidKeyHeader.into());
    }
    let pub_key_bytes = get_val_by_len(&mut public_key_bytes)?;

    Ok((file_bytes, pub_key_bytes.to_vec()))
}

/// Load a moshpit key pair from the provided private key path.
///
/// # Errors
/// If the private key cannot be read or is invalid, an error is returned.
///
pub fn load_private_key(
    priv_key_path: &PathBuf,
) -> Result<(Option<UnencryptedKeyPair>, Option<EncryptedKeyPair>)> {
    // Read the file contents into a buffer
    let mut buffered_reader = File::open(priv_key_path)?;
    let mut file_bytes = vec![];
    let _len = buffered_reader.read_to_end(&mut file_bytes)?;

    // Attempt the base64 decode the input
    let decoded = STANDARD.decode(&file_bytes)?;

    // Parse the private key file
    let mut private_key_bytes = BytesMut::from(&decoded[..]);
    let magic_key = private_key_bytes.split_to(KEY_HEADER.len());
    let magic_key_bytes = magic_key.freeze();
    if &magic_key_bytes[..] != KEY_HEADER {
        return Err(MoshpitError::InvalidKeyHeader.into());
    }
    let cipher = get_val_by_len(&mut private_key_bytes)?;
    let kdf = get_val_by_len(&mut private_key_bytes)?;
    let key_alg = get_val_by_len(&mut private_key_bytes)?;
    let key_alg_str = std::str::from_utf8(&key_alg).map_err(|_| MoshpitError::InvalidKeyHeader)?;
    let agreement_alg: &aws_lc_rs::agreement::Algorithm = match key_alg_str {
        KEY_ALGORITHM_X25519 => &X25519,
        KEY_ALGORITHM_P384 => &ECDH_P384,
        KEY_ALGORITHM_P256 => &ECDH_P256,
        _ => return Err(MoshpitError::InvalidKeyHeader.into()),
    };

    if cipher == NONE_CIPHER.as_bytes() && kdf == NONE_KDF.as_bytes() {
        let pub_key_bytes = get_val_by_len(&mut private_key_bytes)?;
        let priv_key_bytes = get_val_by_len(&mut private_key_bytes)?;

        let private_key = PrivateKey::from_private_key(agreement_alg, &priv_key_bytes)?;
        let public_key = private_key.compute_public_key()?;
        if public_key.as_ref() != pub_key_bytes.as_ref() {
            return Err(MoshpitError::PublicKeyMismatch.into());
        }
        let unencrypted_key_pair = UnencryptedKeyPair {
            private_key,
            public_key,
        };
        Ok((Some(unencrypted_key_pair), None))
    } else {
        let pub_key_bytes = get_val_by_len(&mut private_key_bytes)?;
        let salt_bytes = get_val_by_len(&mut private_key_bytes)?;
        let nonce_bytes = get_val_by_len(&mut private_key_bytes)?;
        let encrypted_priv_key_bytes = get_val_by_len(&mut private_key_bytes)?;

        let encrypted_key_pair = EncryptedKeyPair {
            kdf: String::from_utf8_lossy(&kdf).to_string(),
            public_key: pub_key_bytes.to_vec(),
            key_algorithm: key_alg_str.to_string(),
            salt_bytes: salt_bytes.to_vec(),
            nonce_bytes: nonce_bytes.to_vec(),
            encrypted_private_key_bytes: encrypted_priv_key_bytes.to_vec(),
        };
        Ok((None, Some(encrypted_key_pair)))
    }
}

/// Load and validate identity key material, decrypting it with `passphrase` when needed.
///
/// # Errors
/// If the key file is missing, malformed, encrypted without a passphrase, or the
/// public/private halves do not match.
pub fn load_identity_key(
    priv_key_path: &PathBuf,
    passphrase: Option<&str>,
) -> Result<IdentityKeyPair> {
    let mut buffered_reader = File::open(priv_key_path)?;
    let mut file_bytes = vec![];
    let _len = buffered_reader.read_to_end(&mut file_bytes)?;
    let decoded = STANDARD.decode(&file_bytes)?;

    let mut private_key_bytes = BytesMut::from(&decoded[..]);
    let magic_key = private_key_bytes.split_to(KEY_HEADER.len());
    let magic_key_bytes = magic_key.freeze();
    if &magic_key_bytes[..] != KEY_HEADER {
        return Err(MoshpitError::InvalidKeyHeader.into());
    }
    let cipher = get_val_by_len(&mut private_key_bytes)?;
    let kdf = get_val_by_len(&mut private_key_bytes)?;
    let key_alg = get_val_by_len(&mut private_key_bytes)?;
    let key_alg_str = std::str::from_utf8(&key_alg).map_err(|_| MoshpitError::InvalidKeyHeader)?;
    if !is_supported_key_algorithm(key_alg_str) {
        return Err(MoshpitError::InvalidKeyHeader.into());
    }
    let public_key = get_val_by_len(&mut private_key_bytes)?.to_vec();

    let private_key = if cipher == NONE_CIPHER.as_bytes() && kdf == NONE_KDF.as_bytes() {
        get_val_by_len(&mut private_key_bytes)?.to_vec()
    } else {
        let salt_bytes = get_val_by_len(&mut private_key_bytes)?;
        let nonce_bytes = get_val_by_len(&mut private_key_bytes)?;
        let encrypted_priv_key_bytes = get_val_by_len(&mut private_key_bytes)?;
        let passphrase = passphrase.ok_or(MoshpitError::KeyCorrupt)?;
        decrypt_private_key_to_vec(
            passphrase,
            &salt_bytes,
            &nonce_bytes,
            &encrypted_priv_key_bytes,
        )?
    };

    validate_identity_key_pair(key_alg_str, &public_key, &private_key)?;
    Ok(IdentityKeyPair {
        key_algorithm: key_alg_str.to_string(),
        public_key,
        private_key,
    })
}

/// Validate decrypted identity key material against the public key stored in the key file.
///
/// # Errors
/// If the key algorithm is unsupported or the public/private halves do not match.
pub fn validate_identity_key_pair(
    key_alg: &str,
    public_key: &[u8],
    private_key: &[u8],
) -> Result<()> {
    let agreement_alg: Option<&aws_lc_rs::agreement::Algorithm> = match key_alg {
        KEY_ALGORITHM_X25519 => Some(&X25519),
        KEY_ALGORITHM_P384 => Some(&ECDH_P384),
        KEY_ALGORITHM_P256 => Some(&ECDH_P256),
        _ => None,
    };
    if let Some(agreement_alg) = agreement_alg {
        let private_key = PrivateKey::from_private_key(agreement_alg, private_key)?;
        let computed_public_key = private_key.compute_public_key()?;
        if computed_public_key.as_ref() == public_key {
            return Ok(());
        }
        return Err(MoshpitError::PublicKeyMismatch.into());
    }

    #[cfg(feature = "unstable")]
    if let Some(signing_alg) = resolve_pqdsa_signing_alg(key_alg) {
        let key_pair = PqdsaKeyPair::from_raw_private_key(signing_alg, private_key)?;
        if key_pair.public_key().as_ref() == public_key {
            return Ok(());
        }
        return Err(MoshpitError::PublicKeyMismatch.into());
    }

    Err(MoshpitError::InvalidKeyHeader.into())
}

fn get_val_by_len(bytes: &mut BytesMut) -> Result<BytesMut> {
    let len_bytes = usize::try_from(bytes.get_u32())?;
    let val_bytes = bytes.split_to(len_bytes);
    Ok(val_bytes)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use anyhow::Result;
    use argon2::{Argon2, PasswordHash, PasswordVerifier as _};
    use base64::Engine;

    use super::{
        decrypt_private_key, load_identity_key, load_private_key, validate_identity_key_pair,
    };

    // SHA256:wyKn0zB58msvX/02OmeJfcKRauGoQ2lMhdD/cKcrS6A= jozias@CachyOS
    //
    // +-[X25519 SHA256]-+
    //|^O*=*o       ..oo|
    //|Xo..++        = o|
    //| + . ..      + BE|
    //|    o  ..     * *|
    //|   . . .S. +   +.|
    //|  .     o + ...++|
    //| .     . .   .+=X|
    //|  o . o       o=B|
    //|   +.o..     . oo|
    //+----[SHA256]-----+
    //
    // SHA256:QjvDiq17SSkBEX7XarpkwP9boipvmghbO5djkhCZzyw= jozias@CachyOS
    //
    // +-[X25519 SHA256]-+
    // |^OO+*o           |
    // |+= .o+       .   |
    // |.o.. o.     . .  |
    // |.+=o. ..   .   o |
    // | oO..o  S .     o|
    // | *+=. .    .  E .|
    // |**=o .    o    . |
    // |*B= + .  . .     |
    // |O++*.. .o.       |
    // +----[SHA256]-----+
    //
    #[test]
    fn test_load_private_key_unenc() -> Result<()> {
        let priv_key_path = PathBuf::from("tests/keys/id_x25519_test");
        let (unencrypted_key_pair_opt, encrypted_key_pair_opt) = load_private_key(&priv_key_path)?;
        assert!(unencrypted_key_pair_opt.is_some());
        assert!(encrypted_key_pair_opt.is_none());
        let unencrypted_key_pair = unencrypted_key_pair_opt
            .ok_or_else(|| anyhow::anyhow!("expected unencrypted key pair"))?;
        let public_key_bytes = unencrypted_key_pair.public_key.as_ref();
        let expected_public_key_bytes = vec![
            0x38, 0x43, 0x92, 0xD7, 0x3E, 0xEA, 0x2F, 0x77, 0x6B, 0x45, 0x7B, 0x99, 0xFD, 0xD6,
            0x9D, 0x5B, 0x11, 0xF2, 0x3E, 0x8D, 0xB7, 0x13, 0x0B, 0xF7, 0x54, 0xF0, 0xC8, 0x49,
            0x93, 0xD4, 0xF5, 0x5B,
        ];
        assert_eq!(public_key_bytes, expected_public_key_bytes.as_slice());
        Ok(())
    }

    #[test]
    fn test_load_private_key_enc() -> Result<()> {
        let priv_key_path = PathBuf::from("tests/keys/id_x25519_test_enc");
        let (unencrypted_key_pair_opt, encrypted_key_pair_opt) = load_private_key(&priv_key_path)?;
        assert!(unencrypted_key_pair_opt.is_none());
        assert!(encrypted_key_pair_opt.is_some());
        let encrypted_key_pair =
            encrypted_key_pair_opt.ok_or_else(|| anyhow::anyhow!("expected encrypted key pair"))?;
        assert!(encrypted_key_pair.kdf.starts_with("$argon2id$"));
        let public_key_bytes = encrypted_key_pair.public_key.as_slice();
        let expected_public_key_bytes = vec![
            0x45, 0xDA, 0x9E, 0xCC, 0x73, 0xE8, 0x69, 0xE1, 0x98, 0xAF, 0xD9, 0x57, 0xD0, 0xAA,
            0xA4, 0x2D, 0xA9, 0x52, 0xD0, 0x9C, 0xE3, 0x7B, 0x0A, 0x93, 0xEA, 0x9D, 0xDF, 0x6F,
            0x4D, 0x54, 0x3F, 0x2F,
        ];
        assert_eq!(public_key_bytes, expected_public_key_bytes.as_slice());
        let parsed_hash = PasswordHash::new(&encrypted_key_pair.kdf)?;
        let argon2 = Argon2::default();
        assert!(argon2.verify_password(b"test", &parsed_hash).is_ok());

        let salt_bytes = encrypted_key_pair.salt_bytes.as_slice();
        let nonce_bytes = encrypted_key_pair.nonce_bytes.as_slice();
        let encrypted_private_key_bytes = encrypted_key_pair.encrypted_private_key_bytes.clone();
        let mut decrypted_bytes = encrypted_key_pair.encrypted_private_key_bytes.clone();

        let decrypt_res =
            decrypt_private_key("test", salt_bytes, nonce_bytes, &mut decrypted_bytes);
        assert!(decrypt_res.is_ok());
        assert_ne!(encrypted_private_key_bytes, decrypted_bytes);
        Ok(())
    }

    #[test]
    fn test_generate_key_pair_unencrypted() -> Result<()> {
        let key_pair = super::KeyPair::generate_key_pair(
            None,
            super::KexMode::Server("0.0.0.0:0".parse().expect("hardcoded address")),
            super::KEY_ALGORITHM_X25519,
        )?;
        let mut priv_key_bytes = vec![];
        key_pair.write_private_key(&mut priv_key_bytes)?;

        // Verify it can be loaded as unencrypted
        let decoded = base64::engine::general_purpose::STANDARD.decode(&priv_key_bytes)?;
        let mut buf = bytes::BytesMut::from(&decoded[..]);
        let header = buf.split_to(super::KEY_HEADER.len());
        assert_eq!(&header[..], super::KEY_HEADER);

        let cipher = super::get_val_by_len(&mut buf)?;
        let kdf = super::get_val_by_len(&mut buf)?;
        assert_eq!(&cipher[..], super::NONE_CIPHER.as_bytes());
        assert_eq!(&kdf[..], super::NONE_KDF.as_bytes());

        Ok(())
    }

    #[cfg(feature = "unstable")]
    #[test]
    fn test_generate_and_load_ml_dsa_identity_key() -> Result<()> {
        for key_alg in [
            super::KEY_ALGORITHM_ML_DSA_44,
            super::KEY_ALGORITHM_ML_DSA_65,
            super::KEY_ALGORITHM_ML_DSA_87,
        ] {
            let key_pair = super::KeyPair::generate_key_pair(
                None,
                super::KexMode::Server("0.0.0.0:0".parse().expect("hardcoded address")),
                key_alg,
            )?;
            let dir = tempfile::TempDir::new()?;
            let key_path = dir.path().join("id_mldsa");
            let mut private_key = std::fs::File::create(&key_path)?;
            key_pair.write_private_key(&mut private_key)?;

            let loaded = load_identity_key(&key_path, None)?;
            assert_eq!(loaded.key_algorithm(), key_alg);
            assert!(!key_pair.public_key_bytes().is_empty());
            assert!(!loaded.public_key().is_empty());
            assert!(!loaded.private_key().is_empty());
        }
        Ok(())
    }

    #[test]
    fn test_load_identity_key_unenc_x25519() {
        let path = PathBuf::from("tests/keys/id_x25519_test");
        let key = load_identity_key(&path, None).expect("load unencrypted key");
        assert_eq!(key.key_algorithm(), super::KEY_ALGORITHM_X25519);
        let expected = vec![
            0x38, 0x43, 0x92, 0xD7, 0x3E, 0xEA, 0x2F, 0x77, 0x6B, 0x45, 0x7B, 0x99, 0xFD, 0xD6,
            0x9D, 0x5B, 0x11, 0xF2, 0x3E, 0x8D, 0xB7, 0x13, 0x0B, 0xF7, 0x54, 0xF0, 0xC8, 0x49,
            0x93, 0xD4, 0xF5, 0x5B,
        ];
        assert_eq!(key.public_key(), &expected);
        assert!(!key.private_key().is_empty());
    }

    #[test]
    fn test_load_identity_key_enc_x25519() {
        let path = PathBuf::from("tests/keys/id_x25519_test_enc");
        let key = load_identity_key(&path, Some("test")).expect("load encrypted key");
        assert_eq!(key.key_algorithm(), super::KEY_ALGORITHM_X25519);
        let expected = vec![
            0x45, 0xDA, 0x9E, 0xCC, 0x73, 0xE8, 0x69, 0xE1, 0x98, 0xAF, 0xD9, 0x57, 0xD0, 0xAA,
            0xA4, 0x2D, 0xA9, 0x52, 0xD0, 0x9C, 0xE3, 0x7B, 0x0A, 0x93, 0xEA, 0x9D, 0xDF, 0x6F,
            0x4D, 0x54, 0x3F, 0x2F,
        ];
        assert_eq!(key.public_key(), &expected);
        assert!(!key.private_key().is_empty());
    }

    #[test]
    fn test_load_identity_key_enc_wrong_passphrase() {
        let path = PathBuf::from("tests/keys/id_x25519_test_enc");
        assert!(load_identity_key(&path, Some("wrong")).is_err());
    }

    #[test]
    fn test_load_identity_key_enc_no_passphrase() {
        let path = PathBuf::from("tests/keys/id_x25519_test_enc");
        assert!(load_identity_key(&path, None).is_err());
    }

    #[test]
    fn test_load_identity_key_invalid_header() -> Result<()> {
        let dir = tempfile::TempDir::new()?;
        let path = dir.path().join("bad_key");
        let garbage =
            base64::engine::general_purpose::STANDARD.encode(b"wrong-header-for-testing-purposes");
        std::fs::write(&path, garbage)?;
        assert!(load_identity_key(&path, None).is_err());
        Ok(())
    }

    #[test]
    fn test_validate_identity_key_pair_mismatch() -> Result<()> {
        let key = load_identity_key(&PathBuf::from("tests/keys/id_x25519_test"), None)?;
        let wrong_pub = vec![0u8; 32];
        assert!(
            validate_identity_key_pair(key.key_algorithm(), &wrong_pub, key.private_key()).is_err()
        );
        Ok(())
    }

    #[test]
    fn test_validate_identity_key_pair_unsupported_alg() {
        assert!(validate_identity_key_pair("bogus-alg", &[0u8; 32], &[0u8; 32]).is_err());
    }

    #[test]
    fn test_generate_key_pair_p384() -> Result<()> {
        let key_pair = super::KeyPair::generate_key_pair(
            None,
            super::KexMode::Server("0.0.0.0:0".parse().expect("hardcoded address")),
            super::KEY_ALGORITHM_P384,
        )?;
        let dir = tempfile::TempDir::new()?;
        let path = dir.path().join("id_p384");
        let mut f = std::fs::File::create(&path)?;
        key_pair.write_private_key(&mut f)?;
        drop(f);
        let loaded = load_identity_key(&path, None)?;
        assert_eq!(loaded.key_algorithm(), super::KEY_ALGORITHM_P384);
        validate_identity_key_pair(
            super::KEY_ALGORITHM_P384,
            loaded.public_key(),
            loaded.private_key(),
        )?;
        Ok(())
    }

    #[test]
    fn test_generate_key_pair_p256() -> Result<()> {
        let key_pair = super::KeyPair::generate_key_pair(
            None,
            super::KexMode::Server("0.0.0.0:0".parse().expect("hardcoded address")),
            super::KEY_ALGORITHM_P256,
        )?;
        let dir = tempfile::TempDir::new()?;
        let path = dir.path().join("id_p256");
        let mut f = std::fs::File::create(&path)?;
        key_pair.write_private_key(&mut f)?;
        drop(f);
        let loaded = load_identity_key(&path, None)?;
        assert_eq!(loaded.key_algorithm(), super::KEY_ALGORITHM_P256);
        validate_identity_key_pair(
            super::KEY_ALGORITHM_P256,
            loaded.public_key(),
            loaded.private_key(),
        )?;
        Ok(())
    }

    #[test]
    fn test_generate_key_pair_client_requires_passphrase() {
        assert!(
            super::KeyPair::generate_key_pair(
                None,
                super::KexMode::Client,
                super::KEY_ALGORITHM_X25519,
            )
            .is_err()
        );
    }

    #[test]
    fn test_generate_key_pair_unknown_algorithm() {
        assert!(
            super::KeyPair::generate_key_pair(
                None,
                super::KexMode::Server("0.0.0.0:0".parse().expect("hardcoded address")),
                "unknown-alg",
            )
            .is_err()
        );
    }

    #[test]
    fn test_generate_key_pair_encrypted_x25519() -> Result<()> {
        let passphrase = "my-test-passphrase".to_string();
        let key_pair = super::KeyPair::generate_key_pair(
            Some(&passphrase),
            super::KexMode::Server("0.0.0.0:0".parse().expect("hardcoded address")),
            super::KEY_ALGORITHM_X25519,
        )?;
        let dir = tempfile::TempDir::new()?;
        let path = dir.path().join("id_x25519_enc");
        let mut f = std::fs::File::create(&path)?;
        key_pair.write_private_key(&mut f)?;
        drop(f);
        let loaded = load_identity_key(&path, Some(&passphrase))?;
        assert_eq!(loaded.key_algorithm(), super::KEY_ALGORITHM_X25519);
        assert_eq!(loaded.public_key().len(), 32);
        validate_identity_key_pair(
            super::KEY_ALGORITHM_X25519,
            loaded.public_key(),
            loaded.private_key(),
        )?;
        Ok(())
    }

    #[cfg(feature = "unstable")]
    #[test]
    fn test_load_identity_key_enc_ml_dsa() -> Result<()> {
        let passphrase = "ml-dsa-passphrase".to_string();
        let key_pair = super::KeyPair::generate_key_pair(
            Some(&passphrase),
            super::KexMode::Server("0.0.0.0:0".parse().expect("hardcoded address")),
            super::KEY_ALGORITHM_ML_DSA_44,
        )?;
        let dir = tempfile::TempDir::new()?;
        let path = dir.path().join("id_mldsa_enc");
        let mut f = std::fs::File::create(&path)?;
        key_pair.write_private_key(&mut f)?;
        drop(f);
        let loaded = load_identity_key(&path, Some(&passphrase))?;
        assert_eq!(loaded.key_algorithm(), super::KEY_ALGORITHM_ML_DSA_44);
        assert!(!loaded.public_key().is_empty());
        assert!(!loaded.private_key().is_empty());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn algorithm_strength_rank_ordering() {
        use super::algorithm_strength_rank;
        // Stronger algorithms rank higher.
        assert!(algorithm_strength_rank("P384") > algorithm_strength_rank("P256"));
        assert!(algorithm_strength_rank("P256") > algorithm_strength_rank("X25519"));
        assert!(algorithm_strength_rank("ML-DSA-87") > algorithm_strength_rank("ML-DSA-65"));
        assert!(algorithm_strength_rank("ML-DSA-65") > algorithm_strength_rank("ML-DSA-44"));
        assert!(algorithm_strength_rank("ML-DSA-44") > algorithm_strength_rank("P384"));
        // Unknown algorithms rank lowest.
        assert_eq!(algorithm_strength_rank("unknown"), 0);
        assert!(algorithm_strength_rank("X25519") > algorithm_strength_rank("unknown"));
    }
}
