// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

//! Encrypted vault for storing key paths and their passphrases.
//!
//! The vault file uses the same crypto stack as moshpit private keys:
//! Argon2id → HKDF-SHA512 → AES-256-GCM-SIV.
//!
//! On-disk format:
//! ```text
//! b"moshpit-vault-v1"   (16 bytes, magic header)
//! [u32 len][cipher]     "aes-256-gcm-siv" or "none"
//! [u32 len][kdf]        argon2id PHC hash string or "none"
//! [u32 len][salt]       64 bytes of random salt
//! [u32 len][nonce]      12 bytes of random nonce
//! [u32 len][ciphertext] AES-256-GCM-SIV encrypted bincode-next payload
//! ```
//!
//! The plaintext payload is a bincode-next-serialised `Vec<VaultEntry>`.

use std::{
    fs::{File, OpenOptions},
    io::{Read as _, Write as _},
    path::{Path, PathBuf},
    str::from_utf8,
};

#[cfg(target_family = "unix")]
use std::os::unix::fs::OpenOptionsExt as _;

use anyhow::{Result, anyhow};
use argon2::{
    Argon2, PasswordHash, PasswordHasher as _, PasswordVerifier as _,
    password_hash::phc::SaltString,
};
use aws_lc_rs::{
    aead::{AES_256_GCM_SIV, Aad, LessSafeKey, Nonce, RandomizedNonceKey, UnboundKey},
    hkdf::{HKDF_SHA512, Salt},
    rand::fill,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use bincode_next::{Decode, Encode, config::standard, decode_from_slice, encode_to_vec};
use bytes::{Buf as _, BytesMut};
use zeroize::{Zeroize, ZeroizeOnDrop};

const VAULT_HEADER: &[u8] = b"moshpit-vault-v1";
const VAULT_CIPHER: &str = "aes-256-gcm-siv";
const VAULT_NONE_CIPHER: &str = "none";
const VAULT_NONE_KDF: &str = "none";
const HKDF_INFO: &[u8] = b"moshpit-vault HKDF";

/// A single entry in the vault: a key path and its passphrase.
#[derive(Clone, Debug, Decode, Encode, Zeroize, ZeroizeOnDrop)]
pub(crate) struct VaultEntry {
    /// Absolute path to the private key file.
    pub(crate) key_path: String,
    /// Passphrase used to decrypt the key; empty string for unencrypted keys.
    pub(crate) passphrase: String,
}

/// The in-memory representation of the decrypted vault.
#[derive(Clone, Debug, Default)]
pub(crate) struct Vault {
    entries: Vec<VaultEntry>,
}

impl Drop for Vault {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl Vault {
    fn zeroize(&mut self) {
        for entry in &mut self.entries {
            entry.zeroize();
        }
        self.entries.clear();
    }

    /// Create an empty vault.
    #[must_use]
    pub(crate) fn new() -> Self {
        Self::default()
    }

    #[cfg(test)]
    fn remove(&mut self, key_path: &str) {
        self.entries.retain(|e| e.key_path != key_path);
    }

    /// Add or update an entry.
    pub(crate) fn upsert(&mut self, key_path: String, passphrase: String) {
        if let Some(e) = self.entries.iter_mut().find(|e| e.key_path == key_path) {
            e.passphrase.zeroize();
            e.passphrase = passphrase;
        } else {
            self.entries.push(VaultEntry {
                key_path,
                passphrase,
            });
        }
    }

    /// Return a reference to all entries.
    #[must_use]
    pub(crate) fn entries(&self) -> &[VaultEntry] {
        &self.entries
    }

    /// Encrypt and write this vault to `path` using `passphrase` as the master key.
    pub(crate) fn save_encrypted(&self, path: &Path, passphrase: &str) -> Result<()> {
        let payload = encode_to_vec(&self.entries, standard())?;

        // Derive master key: Argon2id hash → HKDF-SHA512 → 32 bytes for AES-256-GCM-SIV
        let mut salt_bytes = [0u8; 64];
        fill(&mut salt_bytes)?;
        let argon2_salt = SaltString::generate();
        let argon2 = Argon2::default();
        let hash = argon2
            .hash_password_with_salt(passphrase.as_bytes(), argon2_salt.as_bytes())
            .map_err(|e| anyhow!("argon2 hashing: {e}"))?
            .to_string();

        let prk = Salt::new(HKDF_SHA512, &salt_bytes).extract(passphrase.as_bytes());
        let mut key_bytes = [0u8; 32];
        prk.expand(&[HKDF_INFO], &AES_256_GCM_SIV)?
            .fill(&mut key_bytes)?;

        let nonce_key = RandomizedNonceKey::new(&AES_256_GCM_SIV, &key_bytes)?;
        let mut nonce_bytes = [0u8; 12];
        let ciphertext = {
            let mut in_out = payload.clone();
            let nonce = nonce_key.seal_in_place_append_tag(Aad::empty(), &mut in_out)?;
            nonce_bytes.copy_from_slice(nonce.as_ref());
            in_out
        };

        let mut out = VAULT_HEADER.to_vec();
        write_lv(&mut out, VAULT_CIPHER.as_bytes())?;
        write_lv(&mut out, hash.as_bytes())?;
        write_lv(&mut out, &salt_bytes)?;
        write_lv(&mut out, &nonce_bytes)?;
        write_lv(&mut out, &ciphertext)?;

        let encoded = STANDARD.encode(&out);

        let mut file = {
            #[cfg(target_family = "unix")]
            {
                OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .mode(0o600)
                    .open(path)?
            }
            #[cfg(not(target_family = "unix"))]
            {
                OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .open(path)?
            }
        };
        file.write_all(encoded.as_bytes())?;
        Ok(())
    }

    /// Load and decrypt a vault from `path` using `passphrase`.
    pub(crate) fn load_encrypted(path: &Path, passphrase: &str) -> Result<Self> {
        let mut file = File::open(path)?;
        let mut encoded = String::new();
        let _n = file.read_to_string(&mut encoded)?;

        let raw = STANDARD.decode(encoded.trim())?;
        let mut buf = BytesMut::from(&raw[..]);

        let header = buf.split_to(VAULT_HEADER.len());
        if header.as_ref() != VAULT_HEADER {
            return Err(anyhow!("invalid vault header"));
        }

        let cipher = read_lv(&mut buf)?;
        let cipher_str = from_utf8(&cipher).map_err(|_| anyhow!("invalid vault cipher"))?;
        let kdf = read_lv(&mut buf)?;
        let kdf_str = from_utf8(&kdf).map_err(|_| anyhow!("invalid vault kdf"))?;

        if cipher_str == VAULT_NONE_CIPHER && kdf_str == VAULT_NONE_KDF {
            let payload = read_lv(&mut buf)?;
            let (entries, _) = decode_from_slice::<Vec<VaultEntry>, _>(&payload, standard())?;
            return Ok(Self { entries });
        }

        if cipher_str != VAULT_CIPHER {
            return Err(anyhow!("unsupported vault cipher: {cipher_str}"));
        }

        // Verify passphrase via Argon2
        let hash_str = from_utf8(&kdf).map_err(|_| anyhow!("invalid kdf string"))?;
        let parsed =
            PasswordHash::new(hash_str).map_err(|e| anyhow!("invalid argon2 hash: {e}"))?;
        Argon2::default()
            .verify_password(passphrase.as_bytes(), &parsed)
            .map_err(|_| anyhow!("incorrect master passphrase"))?;

        let salt_bytes = read_lv(&mut buf)?;
        let nonce_bytes = read_lv(&mut buf)?;
        let mut ciphertext = read_lv(&mut buf)?.to_vec();

        let prk = Salt::new(HKDF_SHA512, &salt_bytes).extract(passphrase.as_bytes());
        let mut key_bytes = [0u8; 32];
        prk.expand(&[HKDF_INFO], &AES_256_GCM_SIV)?
            .fill(&mut key_bytes)?;
        let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes)?;
        let unbound = UnboundKey::new(&AES_256_GCM_SIV, &key_bytes)?;
        let key = LessSafeKey::new(unbound);
        let plaintext = key
            .open_in_place(nonce, Aad::empty(), &mut ciphertext)
            .map_err(|_| anyhow!("vault decryption failed"))?;

        let (entries, _) = decode_from_slice::<Vec<VaultEntry>, _>(plaintext, standard())?;
        Ok(Self { entries })
    }

    /// Write a vault without encryption (for unencrypted agent setups).
    pub(crate) fn save_plaintext(&self, path: &Path) -> Result<()> {
        let payload = encode_to_vec(&self.entries, standard())?;
        let mut out = VAULT_HEADER.to_vec();
        write_lv(&mut out, VAULT_NONE_CIPHER.as_bytes())?;
        write_lv(&mut out, VAULT_NONE_KDF.as_bytes())?;
        write_lv(&mut out, &payload)?;
        let encoded = STANDARD.encode(&out);

        let mut file = {
            #[cfg(target_family = "unix")]
            {
                OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .mode(0o600)
                    .open(path)?
            }
            #[cfg(not(target_family = "unix"))]
            {
                OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .open(path)?
            }
        };
        file.write_all(encoded.as_bytes())?;
        Ok(())
    }
}

fn write_lv(out: &mut Vec<u8>, data: &[u8]) -> Result<()> {
    let len = u32::try_from(data.len()).map_err(|_| anyhow!("vault field exceeds 4 GiB limit"))?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(data);
    Ok(())
}

fn read_lv(buf: &mut BytesMut) -> Result<BytesMut> {
    if buf.remaining() < 4 {
        return Err(anyhow!("vault truncated reading length"));
    }
    let len = usize::try_from(buf.get_u32())?;
    if buf.remaining() < len {
        return Err(anyhow!("vault truncated reading value"));
    }
    Ok(buf.split_to(len))
}

/// Default vault path: `~/.mp/agent-vault`.
pub(crate) fn default_vault_path() -> Option<PathBuf> {
    dirs2::home_dir().map(|h| h.join(".mp").join("agent-vault"))
}

#[cfg(test)]
mod tests {
    use std::fs::write;

    use anyhow::Result;
    use base64::engine::general_purpose::STANDARD;
    use bytes::BytesMut;

    use super::{VAULT_HEADER, Vault, default_vault_path, read_lv, write_lv};

    #[test]
    fn vault_upsert_and_entries() {
        let mut v = Vault::new();
        v.upsert("/tmp/key1".into(), "pass1".into());
        v.upsert("/tmp/key2".into(), "pass2".into());
        assert_eq!(v.entries().len(), 2);
        v.upsert("/tmp/key1".into(), "newpass".into());
        assert_eq!(v.entries().len(), 2);
        assert_eq!(v.entries()[0].passphrase, "newpass");
    }

    #[test]
    fn vault_remove() {
        let mut v = Vault::new();
        v.upsert("/tmp/key1".into(), "pass1".into());
        v.upsert("/tmp/key2".into(), "pass2".into());
        v.remove("/tmp/key1");
        assert_eq!(v.entries().len(), 1);
        assert_eq!(v.entries()[0].key_path, "/tmp/key2");
    }

    #[test]
    fn vault_roundtrip_encrypted() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("vault");

        let mut v = Vault::new();
        v.upsert("/tmp/key".into(), "secret".into());
        v.save_encrypted(&path, "master").expect("save encrypted");

        let loaded = Vault::load_encrypted(&path, "master").expect("load encrypted");
        assert_eq!(loaded.entries().len(), 1);
        assert_eq!(loaded.entries()[0].key_path, "/tmp/key");
        assert_eq!(loaded.entries()[0].passphrase, "secret");
    }

    #[test]
    fn vault_wrong_passphrase() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("vault");

        let mut v = Vault::new();
        v.upsert("/tmp/key".into(), "secret".into());
        v.save_encrypted(&path, "master").expect("save encrypted");

        let result = Vault::load_encrypted(&path, "wrong");
        assert!(result.is_err());
    }

    #[test]
    fn vault_roundtrip_plaintext() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("vault");

        let mut v = Vault::new();
        v.upsert("/tmp/k".into(), "pp".into());
        v.save_plaintext(&path).expect("save plaintext");

        let loaded = Vault::load_encrypted(&path, "ignored").expect("load plaintext");
        assert_eq!(loaded.entries()[0].key_path, "/tmp/k");
    }

    #[test]
    fn vault_default_path_is_some() {
        assert!(default_vault_path().is_some());
    }

    #[test]
    fn vault_load_invalid_header() {
        use base64::Engine as _;
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("vault");
        let garbage = STANDARD.encode(b"not-a-valid-vault");
        write(&path, garbage.as_bytes()).expect("write test file");
        let result = Vault::load_encrypted(&path, "any");
        assert!(
            result
                .expect_err("expected load error on invalid header")
                .to_string()
                .contains("invalid vault header")
        );
    }

    #[test]
    fn vault_load_unsupported_cipher() -> Result<()> {
        use base64::Engine as _;
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("vault");
        let mut out = VAULT_HEADER.to_vec();
        write_lv(&mut out, b"unknown-cipher")?;
        write_lv(&mut out, b"none")?;
        let encoded = STANDARD.encode(&out);
        write(&path, encoded.as_bytes()).expect("write test file");
        let result = Vault::load_encrypted(&path, "any");
        assert!(
            result
                .expect_err("expected load error on unknown cipher")
                .to_string()
                .contains("unsupported vault cipher")
        );
        Ok(())
    }

    #[test]
    fn read_lv_truncated_length_field() {
        // Buffer with only 2 bytes — too short to read a u32 length
        let mut buf = BytesMut::from(&[0x00u8, 0x01][..]);
        let result = read_lv(&mut buf);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("truncated reading length")
        );
    }

    #[test]
    fn read_lv_truncated_value_field() {
        // Buffer says value is 100 bytes but only has 2 bytes after the length
        let mut out = Vec::new();
        out.extend_from_slice(&100u32.to_be_bytes());
        out.extend_from_slice(&[0xAAu8, 0xBB]);
        let mut buf = BytesMut::from(&out[..]);
        let result = read_lv(&mut buf);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("truncated reading value")
        );
    }
}
