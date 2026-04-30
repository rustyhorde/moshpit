// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

//! Regression tests for `fuzz_encframe` crashes.
//!
//! Per the cargo-fuzz documentation, each crash is embedded here as a
//! `&[u8]` constant so that `cargo test` permanently guards against
//! regressions without requiring a nightly fuzzer run.
//!
//! To add a new crash:
//! 1. Extract the bytes from the artifact zip downloaded from CI.
//! 2. Run `xxd -i crash-<hash>` (or `hexdump -C`) to get the byte values.
//! 3. Add a new test function following the pattern in `regression_crash_6720028039`.
//! 4. Commit the raw crash file to `fuzz/artifacts/fuzz_encframe/crash-<hash>`
//!    so `cargo +nightly fuzz run fuzz_encframe` also replays it automatically.

use std::io::Cursor;

use aws_lc_rs::{
    aead::{AES_256_GCM_SIV, RandomizedNonceKey},
    hmac::{HMAC_SHA512, Key},
};
use libmoshpit::EncryptedFrame;
use uuid::Uuid;

/// Helper that mirrors the fuzz target body exactly.
///
/// Any panic inside this function is a confirmed bug: the fuzzer found an
/// input that causes an unwrap/unreachable/index-out-of-bounds in the parser.
fn run_fuzz_encframe(data: &[u8]) {
    let Ok(rnk) = RandomizedNonceKey::new(&AES_256_GCM_SIV, &[0u8; 32]) else {
        return;
    };
    let hmac = Key::new(HMAC_SHA512, &[0u8; 64]);
    let id = Uuid::nil();
    let mut cursor = Cursor::new(data);
    // All outcomes (Ok or Err) are acceptable; only panics are failures.
    let _ = EncryptedFrame::parse(&mut cursor, id, &hmac, &rnk);
}

#[test]
fn regression_empty() {
    run_fuzz_encframe(&[]);
}
