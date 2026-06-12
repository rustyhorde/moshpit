// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

//! Regression tests for `fuzz_pubkey_parse` crashes.
//!
//! Per the cargo-fuzz documentation, each crash is embedded here as a
//! `&[u8]` constant so that `cargo test` permanently guards against
//! regressions without requiring a nightly fuzzer run.
//!
//! These tests are only meaningful with libmoshpit's `unstable` feature
//! enabled (run `cargo test --features unstable`); otherwise they compile to
//! an empty body.
//!
//! To add a new crash:
//! 1. Extract the bytes from the artifact zip downloaded from CI.
//! 2. Run `xxd -i crash-<hash>` (or `hexdump -C`) to get the byte values.
//! 3. Add a new test function following the pattern below.
//! 4. Commit the raw crash file to `fuzz/artifacts/fuzz_pubkey_parse/crash-<hash>`
//!    so `cargo +nightly fuzz run fuzz_pubkey_parse` also replays it automatically.

/// Helper that mirrors the fuzz target body exactly.
///
/// Any panic inside this function is a confirmed bug: the fuzzer found an
/// input that panics the SSH-format public-key parser.
#[cfg(feature = "unstable")]
fn run_fuzz_pubkey_parse(data: &[u8]) {
    let _ = libmoshpit::parse_full_public_key(data);
}

#[cfg(not(feature = "unstable"))]
fn run_fuzz_pubkey_parse(_data: &[u8]) {}

#[test]
fn regression_empty() {
    run_fuzz_pubkey_parse(&[]);
}

#[test]
fn regression_not_three_parts() {
    run_fuzz_pubkey_parse(b"only-one");
    run_fuzz_pubkey_parse(b"two parts");
    run_fuzz_pubkey_parse(b"a b c d");
}

#[test]
fn regression_bad_base64_middle() {
    // Three whitespace parts but the middle is not valid base64.
    run_fuzz_pubkey_parse(b"ssh-mldsa !!!notbase64!!! comment");
}

#[test]
fn regression_truncated_length_prefixes() {
    use base64::{Engine, engine::general_purpose::STANDARD};
    // Valid base64 whose decoded bytes have a truncated/overrunning length
    // prefix: must error, not panic.
    let short = STANDARD.encode([0x00, 0x00, 0x00]);
    let overrun = STANDARD.encode([0x00, 0x00, 0x00, 0x10]);
    run_fuzz_pubkey_parse(format!("ssh-mldsa {short} comment").as_bytes());
    run_fuzz_pubkey_parse(format!("ssh-mldsa {overrun} comment").as_bytes());
}
