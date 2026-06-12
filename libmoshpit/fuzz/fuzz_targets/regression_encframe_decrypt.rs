// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

//! Regression tests for `fuzz_encframe_decrypt` crashes.
//!
//! Per the cargo-fuzz documentation, each crash is embedded here as a
//! `&[u8]` constant so that `cargo test` permanently guards against
//! regressions without requiring a nightly fuzzer run.
//!
//! To add a new crash:
//! 1. Extract the bytes from the artifact zip downloaded from CI.
//! 2. Run `xxd -i crash-<hash>` (or `hexdump -C`) to get the byte values.
//! 3. Add a new test function following the pattern below.
//! 4. Commit the raw crash file to `fuzz/artifacts/fuzz_encframe_decrypt/crash-<hash>`
//!    so `cargo +nightly fuzz run fuzz_encframe_decrypt` also replays it automatically.

use std::io::Cursor;

use aws_lc_rs::{
    aead::{AES_256_GCM_SIV, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey},
    hmac::{HMAC_SHA512, Key, sign},
};
use libmoshpit::EncryptedFrame;
use uuid::Uuid;

fn build_packet(rnk: &LessSafeKey, hmac: &Key, id: Uuid, inner: &[u8]) -> Option<Vec<u8>> {
    let seq: u64 = 0;
    let aad = Aad::from(seq.to_be_bytes());
    let mut encrypted_part = id.as_bytes().to_vec();
    encrypted_part.extend_from_slice(inner);
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

/// Helper that mirrors the fuzz target body exactly.
///
/// Any panic inside this function is a confirmed bug: the fuzzer found inner
/// plaintext bytes that panic the post-decryption `EncryptedFrame` decode.
fn run_fuzz_encframe_decrypt(data: &[u8]) {
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
    let _ = EncryptedFrame::parse(&mut cursor, id, &hmac, &rnk, 64);
}

#[test]
fn regression_empty() {
    run_fuzz_encframe_decrypt(&[]);
}

#[test]
fn regression_huge_length_prefix() {
    // Variant tag 0 (Bytes) followed by a UUID and a Vec whose length prefix
    // claims an enormous size: the decode limit must reject it, not OOM/panic.
    run_fuzz_encframe_decrypt(&[0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
}

#[test]
fn regression_unknown_variant_tag() {
    // A variant tag well past the 14 defined variants must decode-error cleanly.
    run_fuzz_encframe_decrypt(&[0xff]);
    run_fuzz_encframe_decrypt(&[0x7f, 0x00, 0x00]);
}

#[test]
fn regression_nak_vec_u64_varint_underflow() {
    // Found by fuzz_encframe_decrypt: EncryptedFrame::Nak(Vec<u64>) (variant 2)
    // with a single element encoded via the 0xfd (253) "u64 follows" varint
    // marker makes bincode-next 3.0.0-rc.15 compute `len * 8 - consumed` and
    // panic with "attempt to subtract with overflow". The catch_unwind guard in
    // `frames::decode_frame` must turn this into a clean Err, not a panic.
    run_fuzz_encframe_decrypt(&[2, 1, 253, 0, 0, 1, 0, 0, 0, 0, 0]);
}
