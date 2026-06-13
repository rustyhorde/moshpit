// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

//! Fuzz target for the **post-decryption** `EncryptedFrame` decode path.
//!
//! `fuzz_encframe` builds its AEAD/HMAC keys from all-zero material, so every
//! random input fails HMAC verification and returns `Err` *before* any
//! ciphertext is decrypted or any `EncryptedFrame` is bincode-decoded. That
//! leaves the variant-dispatch deserialization — `decode_from_slice` over the
//! plaintext at `encframe.rs` — effectively unfuzzed.
//!
//! This target closes that gap: it holds a *real* fixed AEAD key and HMAC key
//! and seals fuzzer-controlled `inner` bytes into a well-formed packet, so a
//! valid packet is produced every run and the fuzzer-controlled bytes flow
//! directly into the bincode decoder (exercising length-prefix limits, variant
//! tags, and nested `Vec`/tuple decoding) just as a malicious server's payload
//! would after it authenticated.
//!
//! Invariants verified:
//! - No panic regardless of the inner plaintext bytes.

#![no_main]

use std::io::Cursor;
use std::sync::Once;

use aws_lc_rs::{
    aead::{AES_256_GCM_SIV, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey},
    hmac::{HMAC_SHA512, Key, sign},
};
use libfuzzer_sys::fuzz_target;
use libmoshpit::EncryptedFrame;
use uuid::Uuid;

static HOOK: Once = Once::new();

/// Replace libfuzzer-sys's abort-on-panic hook with a non-aborting one.
///
/// `EncryptedFrame::parse` deliberately contains decoder panics via the
/// `catch_unwind` in `frames::decode_frame` (a workaround for a bincode-next
/// `Vec<integer>` underflow bug). libfuzzer-sys installs a panic hook that
/// aborts the process at panic-*initiation*, which would defeat that
/// `catch_unwind` and report the contained panic as a crash. Swapping in a
/// non-aborting hook lets the production guard do its job; any panic that
/// escapes `catch_unwind` is still reported as a crash by the libfuzzer
/// driver's outer `catch_unwind` backstop.
fn allow_contained_panics() {
    HOOK.call_once(|| {
        let _ = std::panic::take_hook();
        std::panic::set_hook(Box::new(|info| {
            eprintln!("[fuzz] contained (caught) panic: {info}");
        }));
    });
}

/// Seal `inner` into a well-formed UDP packet under the fixed keys, mirroring
/// `UdpSender`'s wire format:
/// `[nonce (12)] [seq (8)] [hmac_tag (64)] [length (8)] [id || inner || aead_tag]`.
fn build_packet(rnk: &LessSafeKey, hmac: &Key, id: Uuid, inner: &[u8]) -> Option<Vec<u8>> {
    let seq: u64 = 0;
    let aad = Aad::from(seq.to_be_bytes());
    let mut encrypted_part = id.as_bytes().to_vec();
    encrypted_part.extend_from_slice(inner);
    // A fixed nonce is fine: each run uses a fresh, independent key context and
    // we never reuse it for a second distinct message.
    let nonce = Nonce::try_assume_unique_for_key(&[0u8; NONCE_LEN]).ok()?;
    rnk.seal_in_place_append_tag(nonce, aad, &mut encrypted_part)
        .ok()?;

    let seq_bytes = seq.to_be_bytes();
    let mut to_sign = seq_bytes.to_vec();
    to_sign.extend_from_slice(&encrypted_part);
    let tag = sign(hmac, &to_sign);

    let mut packet = vec![0u8; NONCE_LEN];
    packet.extend_from_slice(&seq_bytes);
    packet.extend_from_slice(tag.as_ref());
    packet.extend_from_slice(&encrypted_part.len().to_be_bytes());
    packet.extend_from_slice(&encrypted_part);
    Some(packet)
}

fuzz_target!(|data: &[u8]| {
    allow_contained_panics();

    let Ok(unbound) = UnboundKey::new(&AES_256_GCM_SIV, &[1u8; 32]) else {
        return;
    };
    let rnk = LessSafeKey::new(unbound);
    let hmac = Key::new(HMAC_SHA512, &[2u8; 64]);
    let id = Uuid::nil();

    let Some(packet) = build_packet(&rnk, &hmac, id, data) else {
        return;
    };
    let mut cursor = Cursor::new(packet.as_slice());
    // HMAC + AEAD now succeed by construction, so this drives the bincode
    // decode of `data`. All outcomes (Ok/Err) are fine; only panics fail.
    let _ = EncryptedFrame::parse(&mut cursor, id, &hmac, &rnk, 64);
});
