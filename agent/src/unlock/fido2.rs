// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

//! FIDO2 / passkey / hardware security key unlock backend.
//!
//! Derives the vault master passphrase from the HMAC-secret extension of a
//! FIDO2 authenticator (`YubiKey`, etc.).  A random 32-byte salt and the
//! credential ID are stored alongside the vault in
//! `{vault_path}.fido2`; the hardware token computes a deterministic
//! HMAC-SHA256 over the salt using an internal device secret.  The 32-byte
//! output is base64-encoded and used as the vault master passphrase.
//!
//! No secret material is stored on disk.  Without the physical token the
//! passphrase cannot be reproduced.
//!
//! # Protocol
//!
//! **Enrollment** (state file absent):
//! 1. Enumerate connected FIDO2 devices and open the first found.
//! 2. Call `fido_dev_make_cred` with `FIDO_EXT_HMAC_SECRET` to create a
//!    non-resident ES256 credential.
//! 3. Persist the returned credential ID and a fresh random 32-byte salt to
//!    `{vault_path}.fido2` (bincode-next encoded, mode 0o600).
//! 4. Immediately run an assertion to derive and return the passphrase.
//!
//! **Assertion** (state file present):
//! 1. Load credential ID and salt from `{vault_path}.fido2`.
//! 2. Call `fido_dev_get_assert` with `FIDO_EXT_HMAC_SECRET` and the salt.
//! 3. Base64-encode the 32-byte HMAC-secret output → vault master passphrase.

#![allow(unsafe_code)]

use std::{
    ffi::{CStr, c_int},
    fs,
    io::Write as _,
    path::{Path, PathBuf},
    ptr::null,
    slice::from_raw_parts,
    sync::LazyLock,
};

#[cfg(target_family = "unix")]
use std::{fs::OpenOptions, os::unix::fs::OpenOptionsExt as _};

#[cfg(not(target_family = "unix"))]
use std::fs::File;

use anyhow::{Result, anyhow};
use aws_lc_rs::{digest, rand::fill};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use bincode_next::{Decode, Encode, config::standard, decode_from_slice, encode_to_vec};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::UnlockBackend;

// ── Inline libfido2 FFI ───────────────────────────────────────────────────────

/// Raw bindings to the subset of `<fido.h>` required for HMAC-secret assertion.
#[allow(
    non_camel_case_types,
    dead_code,
    unreachable_pub,
    clippy::upper_case_acronyms
)]
mod sys {
    use std::ffi::{c_char, c_int};

    // Opaque C types.
    pub enum fido_dev_t {}
    pub enum fido_dev_info_t {}
    pub enum fido_cred_t {}
    pub enum fido_assert_t {}

    // Error codes.
    pub const FIDO_OK: c_int = 0;

    // Extension flags.
    pub const FIDO_EXT_HMAC_SECRET: c_int = 0x01;

    // COSE algorithm identifiers.
    pub const COSE_ES256: c_int = -7;

    // fido_opt_t values.
    pub const FIDO_OPT_OMIT: c_int = 0;
    pub const FIDO_OPT_FALSE: c_int = 1;
    pub const FIDO_OPT_TRUE: c_int = 2;

    unsafe extern "C" {
        // Library initialisation.
        pub fn fido_init(flags: c_int);

        // Device info / enumeration.
        pub fn fido_dev_info_new(n: usize) -> *mut fido_dev_info_t;
        pub fn fido_dev_info_free(di: *mut *mut fido_dev_info_t, n: usize);
        pub fn fido_dev_info_manifest(
            di: *mut fido_dev_info_t,
            ilen: usize,
            olen: *mut usize,
        ) -> c_int;
        pub fn fido_dev_info_ptr(di: *const fido_dev_info_t, idx: usize) -> *const fido_dev_info_t;
        pub fn fido_dev_info_path(di: *const fido_dev_info_t) -> *const c_char;

        // Device lifecycle.
        pub fn fido_dev_new() -> *mut fido_dev_t;
        pub fn fido_dev_free(dev: *mut *mut fido_dev_t);
        pub fn fido_dev_open(dev: *mut fido_dev_t, path: *const c_char) -> c_int;
        pub fn fido_dev_close(dev: *mut fido_dev_t) -> c_int;

        // Credential.
        pub fn fido_cred_new() -> *mut fido_cred_t;
        pub fn fido_cred_free(cred: *mut *mut fido_cred_t);
        pub fn fido_cred_set_type(cred: *mut fido_cred_t, cose_alg: c_int) -> c_int;
        pub fn fido_cred_set_rp(
            cred: *mut fido_cred_t,
            id: *const c_char,
            name: *const c_char,
        ) -> c_int;
        pub fn fido_cred_set_user(
            cred: *mut fido_cred_t,
            id: *const u8,
            id_len: usize,
            name: *const c_char,
            display_name: *const c_char,
            icon: *const c_char,
        ) -> c_int;
        pub fn fido_cred_set_clientdata_hash(
            cred: *mut fido_cred_t,
            hash: *const u8,
            hash_len: usize,
        ) -> c_int;
        pub fn fido_cred_set_extensions(cred: *mut fido_cred_t, extensions: c_int) -> c_int;
        pub fn fido_cred_set_rk(cred: *mut fido_cred_t, rk: c_int) -> c_int;
        pub fn fido_dev_make_cred(
            dev: *mut fido_dev_t,
            cred: *mut fido_cred_t,
            pin: *const c_char,
        ) -> c_int;
        pub fn fido_cred_id_ptr(cred: *const fido_cred_t) -> *const u8;
        pub fn fido_cred_id_len(cred: *const fido_cred_t) -> usize;

        // Assertion.
        pub fn fido_assert_new() -> *mut fido_assert_t;
        pub fn fido_assert_free(assert: *mut *mut fido_assert_t);
        pub fn fido_assert_set_rp(assert: *mut fido_assert_t, id: *const c_char) -> c_int;
        pub fn fido_assert_set_clientdata_hash(
            assert: *mut fido_assert_t,
            hash: *const u8,
            hash_len: usize,
        ) -> c_int;
        pub fn fido_assert_allow_cred(
            assert: *mut fido_assert_t,
            cred_id: *const u8,
            cred_id_len: usize,
        ) -> c_int;
        pub fn fido_assert_set_extensions(assert: *mut fido_assert_t, extensions: c_int) -> c_int;
        pub fn fido_assert_set_hmac_salt(
            assert: *mut fido_assert_t,
            salt: *const u8,
            salt_len: usize,
        ) -> c_int;
        pub fn fido_assert_set_up(assert: *mut fido_assert_t, up: c_int) -> c_int;
        pub fn fido_dev_get_assert(
            dev: *mut fido_dev_t,
            assert: *mut fido_assert_t,
            pin: *const c_char,
        ) -> c_int;
        pub fn fido_assert_hmac_secret_ptr(assert: *const fido_assert_t, idx: usize) -> *const u8;
        pub fn fido_assert_hmac_secret_len(assert: *const fido_assert_t, idx: usize) -> usize;

        // Error description.
        pub fn fido_strerr(n: c_int) -> *const c_char;
    }
}

// ── Library initialisation (once) ────────────────────────────────────────────

static FIDO_INIT: LazyLock<()> = LazyLock::new(|| {
    unsafe { sys::fido_init(0) };
});

fn ensure_fido_init() {
    let () = *LazyLock::force(&FIDO_INIT);
}

// ── Fixed clientdata hashes (computed once; the security comes from the HW) ──

static ENROLL_CD_HASH: LazyLock<[u8; 32]> = LazyLock::new(|| {
    digest::digest(&digest::SHA256, b"moshpit-agent-fido2-enroll-v1")
        .as_ref()
        .try_into()
        .expect("SHA-256 output is always 32 bytes")
});

static ASSERT_CD_HASH: LazyLock<[u8; 32]> = LazyLock::new(|| {
    digest::digest(&digest::SHA256, b"moshpit-agent-fido2-assert-v1")
        .as_ref()
        .try_into()
        .expect("SHA-256 output is always 32 bytes")
});

// ── RAII wrappers ─────────────────────────────────────────────────────────────

struct DevInfo {
    ptr: *mut sys::fido_dev_info_t,
    n: usize,
}

impl DevInfo {
    fn new(n: usize) -> Option<Self> {
        let ptr = unsafe { sys::fido_dev_info_new(n) };
        if ptr.is_null() {
            None
        } else {
            Some(Self { ptr, n })
        }
    }

    fn manifest(&mut self) -> Result<usize> {
        let mut olen = 0usize;
        let rc = unsafe { sys::fido_dev_info_manifest(self.ptr, self.n, &raw mut olen) };
        fido_check(rc)?;
        Ok(olen)
    }

    fn path(&self, idx: usize) -> Option<&CStr> {
        unsafe {
            let entry = sys::fido_dev_info_ptr(self.ptr, idx);
            if entry.is_null() {
                return None;
            }
            let p = sys::fido_dev_info_path(entry);
            if p.is_null() {
                None
            } else {
                Some(CStr::from_ptr(p))
            }
        }
    }
}

impl Drop for DevInfo {
    fn drop(&mut self) {
        unsafe { sys::fido_dev_info_free(&raw mut self.ptr, self.n) };
    }
}

struct Dev {
    ptr: *mut sys::fido_dev_t,
}

impl Dev {
    fn open(path: &CStr) -> Result<Self> {
        let ptr = unsafe { sys::fido_dev_new() };
        if ptr.is_null() {
            return Err(anyhow!("fido2: fido_dev_new returned null (OOM)"));
        }
        let rc = unsafe { sys::fido_dev_open(ptr, path.as_ptr()) };
        if rc != sys::FIDO_OK {
            let mut p = ptr;
            unsafe { sys::fido_dev_free(&raw mut p) };
            return Err(anyhow!("fido2: fido_dev_open: {}", fido_err_str(rc)));
        }
        Ok(Self { ptr })
    }
}

impl Drop for Dev {
    fn drop(&mut self) {
        unsafe {
            let _ = sys::fido_dev_close(self.ptr);
            sys::fido_dev_free(&raw mut self.ptr);
        }
    }
}

struct Cred {
    ptr: *mut sys::fido_cred_t,
}

impl Cred {
    fn new() -> Result<Self> {
        let ptr = unsafe { sys::fido_cred_new() };
        if ptr.is_null() {
            Err(anyhow!("fido2: fido_cred_new returned null (OOM)"))
        } else {
            Ok(Self { ptr })
        }
    }
}

impl Drop for Cred {
    fn drop(&mut self) {
        unsafe { sys::fido_cred_free(&raw mut self.ptr) };
    }
}

struct Assert {
    ptr: *mut sys::fido_assert_t,
}

impl Assert {
    fn new() -> Result<Self> {
        let ptr = unsafe { sys::fido_assert_new() };
        if ptr.is_null() {
            Err(anyhow!("fido2: fido_assert_new returned null (OOM)"))
        } else {
            Ok(Self { ptr })
        }
    }
}

impl Drop for Assert {
    fn drop(&mut self) {
        unsafe { sys::fido_assert_free(&raw mut self.ptr) };
    }
}

// ── Error helpers ─────────────────────────────────────────────────────────────

fn fido_err_str(rc: c_int) -> String {
    unsafe {
        let p = sys::fido_strerr(rc);
        if p.is_null() {
            format!("error code {rc}")
        } else {
            CStr::from_ptr(p).to_string_lossy().into_owned()
        }
    }
}

fn fido_check(rc: c_int) -> Result<()> {
    if rc == sys::FIDO_OK {
        Ok(())
    } else {
        Err(anyhow!("fido2: {}", fido_err_str(rc)))
    }
}

// ── Persistent FIDO2 state ────────────────────────────────────────────────────

/// On-disk state stored alongside the vault.  Neither field is secret.
#[derive(Encode, Decode, Zeroize, ZeroizeOnDrop)]
struct Fido2State {
    /// Credential ID returned by `fido_dev_make_cred`.
    credential_id: Vec<u8>,
    /// Random 32-byte salt sent to the device as the HMAC-secret input.
    salt: [u8; 32],
}

impl Fido2State {
    fn generate(credential_id: Vec<u8>) -> Result<Self> {
        let mut salt = [0u8; 32];
        fill(&mut salt).map_err(|_| anyhow!("fido2: failed to generate random salt"))?;
        Ok(Self {
            credential_id,
            salt,
        })
    }

    fn load(path: &Path) -> Result<Self> {
        let bytes = fs::read(path)
            .map_err(|e| anyhow!("fido2: failed to read state file {}: {e}", path.display()))?;
        let (state, _) = decode_from_slice::<Self, _>(&bytes, standard())
            .map_err(|e| anyhow!("fido2: failed to decode state file: {e}"))?;
        Ok(state)
    }

    fn save(&self, path: &Path) -> Result<()> {
        let bytes =
            encode_to_vec(self, standard()).map_err(|e| anyhow!("fido2: encode error: {e}"))?;

        #[cfg(target_family = "unix")]
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| anyhow!("fido2: failed to create state file {}: {e}", path.display()))?;

        #[cfg(not(target_family = "unix"))]
        let mut file = File::create(path)
            .map_err(|e| anyhow!("fido2: failed to create state file {}: {e}", path.display()))?;

        file.write_all(&bytes)
            .map_err(|e| anyhow!("fido2: failed to write state file: {e}"))
    }
}

// ── Device helpers ────────────────────────────────────────────────────────────

const MAX_DEVS: usize = 16;

fn open_first_device() -> Result<Dev> {
    ensure_fido_init();

    let mut di = DevInfo::new(MAX_DEVS)
        .ok_or_else(|| anyhow!("fido2: fido_dev_info_new returned null (OOM)"))?;
    let n = di.manifest()?;
    if n == 0 {
        return Err(anyhow!(
            "no FIDO2 device found; insert your security key and try again"
        ));
    }
    let path = di
        .path(0)
        .ok_or_else(|| anyhow!("fido2: could not read device path at index 0"))?;
    Dev::open(path)
}

// ── Enrollment ────────────────────────────────────────────────────────────────

fn enroll(dev: &Dev) -> Result<Fido2State> {
    const USER_ID: &[u8] = b"moshpit-agent-user";
    let cred = Cred::new()?;

    fido_check(unsafe { sys::fido_cred_set_type(cred.ptr, sys::COSE_ES256) })?;
    fido_check(unsafe {
        sys::fido_cred_set_rp(
            cred.ptr,
            c"moshpit-agent".as_ptr(),
            c"Moshpit Agent".as_ptr(),
        )
    })?;
    fido_check(unsafe {
        sys::fido_cred_set_user(
            cred.ptr,
            USER_ID.as_ptr(),
            USER_ID.len(),
            c"moshpit-agent".as_ptr(),
            c"Moshpit Agent".as_ptr(),
            null(),
        )
    })?;

    let hash = &*ENROLL_CD_HASH;
    fido_check(unsafe { sys::fido_cred_set_clientdata_hash(cred.ptr, hash.as_ptr(), hash.len()) })?;
    fido_check(unsafe { sys::fido_cred_set_extensions(cred.ptr, sys::FIDO_EXT_HMAC_SECRET) })?;
    // Non-resident credential — do not store on the device.
    fido_check(unsafe { sys::fido_cred_set_rk(cred.ptr, sys::FIDO_OPT_FALSE) })?;

    eprintln!("Touch your FIDO2 security key to enroll with moshpit-agent...");
    fido_check(unsafe { sys::fido_dev_make_cred(dev.ptr, cred.ptr, null()) })?;

    let id_ptr = unsafe { sys::fido_cred_id_ptr(cred.ptr) };
    let id_len = unsafe { sys::fido_cred_id_len(cred.ptr) };
    if id_ptr.is_null() || id_len == 0 {
        return Err(anyhow!("fido2: credential ID is empty after make_cred"));
    }
    let credential_id = unsafe { from_raw_parts(id_ptr, id_len) }.to_vec();

    Fido2State::generate(credential_id)
}

// ── Assertion (HMAC-secret retrieval) ────────────────────────────────────────

fn hmac_secret(dev: &Dev, state: &Fido2State) -> Result<[u8; 32]> {
    let assert = Assert::new()?;

    fido_check(unsafe { sys::fido_assert_set_rp(assert.ptr, c"moshpit-agent".as_ptr()) })?;

    let hash = &*ASSERT_CD_HASH;
    fido_check(unsafe {
        sys::fido_assert_set_clientdata_hash(assert.ptr, hash.as_ptr(), hash.len())
    })?;

    fido_check(unsafe {
        sys::fido_assert_allow_cred(
            assert.ptr,
            state.credential_id.as_ptr(),
            state.credential_id.len(),
        )
    })?;

    fido_check(unsafe { sys::fido_assert_set_extensions(assert.ptr, sys::FIDO_EXT_HMAC_SECRET) })?;
    fido_check(unsafe {
        sys::fido_assert_set_hmac_salt(assert.ptr, state.salt.as_ptr(), state.salt.len())
    })?;
    // Require user presence (button touch).
    fido_check(unsafe { sys::fido_assert_set_up(assert.ptr, sys::FIDO_OPT_TRUE) })?;

    eprintln!("Touch your FIDO2 security key to unlock...");
    fido_check(unsafe { sys::fido_dev_get_assert(dev.ptr, assert.ptr, null()) })?;

    let hmac_ptr = unsafe { sys::fido_assert_hmac_secret_ptr(assert.ptr, 0) };
    let hmac_len = unsafe { sys::fido_assert_hmac_secret_len(assert.ptr, 0) };

    if hmac_ptr.is_null() || hmac_len == 0 {
        return Err(anyhow!("fido2: HMAC-secret is empty in assertion response"));
    }
    if hmac_len != 32 {
        return Err(anyhow!(
            "fido2: unexpected HMAC-secret length {hmac_len} (expected 32)"
        ));
    }

    Ok(unsafe { from_raw_parts(hmac_ptr, hmac_len) }
        .try_into()
        .expect("length is 32"))
}

// ── Backend ───────────────────────────────────────────────────────────────────

/// Derives the vault passphrase from a FIDO2 hardware security key via the
/// HMAC-secret extension.
pub(crate) struct Fido2Backend {
    /// Path to the on-disk state file (`{vault_path}.fido2`).
    pub(crate) state_path: PathBuf,
}

impl UnlockBackend for Fido2Backend {
    fn retrieve_passphrase(&self) -> Result<String> {
        let dev = open_first_device()?;

        let state = if self.state_path.exists() {
            Fido2State::load(&self.state_path)?
        } else {
            let s = enroll(&dev)?;
            s.save(&self.state_path)?;
            s
        };

        let secret = hmac_secret(&dev, &state)?;
        Ok(STANDARD.encode(secret))
    }

    fn name(&self) -> &'static str {
        "fido2"
    }
}
