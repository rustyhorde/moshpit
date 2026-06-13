// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

//! Regression tests for `fuzz_keyfile` crashes.
//!
//! Per the cargo-fuzz documentation, each crash is embedded here as a
//! `&[u8]` constant so that `cargo test` permanently guards against
//! regressions without requiring a nightly fuzzer run.
//!
//! To add a new crash:
//! 1. Extract the bytes from the artifact zip downloaded from CI.
//! 2. Run `xxd -i crash-<hash>` (or `hexdump -C`) to get the byte values.
//! 3. Add a new test function following the pattern below.
//! 4. Commit the raw crash file to `fuzz/artifacts/fuzz_keyfile/crash-<hash>`
//!    so `cargo +nightly fuzz run fuzz_keyfile` also replays it automatically.

use base64::{Engine, engine::general_purpose::STANDARD};
use libmoshpit::{parse_private_key_bytes, parse_public_key_bytes};

/// Helper that mirrors the fuzz target body exactly.
///
/// Any panic inside this function is a confirmed bug: the fuzzer found an
/// input that causes an unwrap/index-out-of-bounds in the key-file parser.
fn run_fuzz_keyfile(data: &[u8]) {
    let Some((selector, rest)) = data.split_first() else {
        return;
    };
    if selector & 1 == 0 {
        let _ = parse_public_key_bytes(rest.to_vec());
    } else {
        let _ = parse_private_key_bytes(rest);
    }
}

#[test]
fn regression_empty() {
    run_fuzz_keyfile(&[]);
    run_fuzz_keyfile(&[0]);
    run_fuzz_keyfile(&[1]);
}

#[test]
fn regression_public_truncated_length_prefix() {
    // "ssh-x25519 <base64> comment" where the base64 decodes to fewer than the
    // 4 bytes a length prefix needs: get_val_by_len must error, not panic.
    let blob = STANDARD.encode([0x00, 0x00, 0x01]);
    let line = format!("ssh-x25519 {blob} comment");
    let mut data = vec![0u8]; // selector → public
    data.extend_from_slice(line.as_bytes());
    run_fuzz_keyfile(&data);
}

#[test]
fn regression_public_overrunning_length() {
    // Length prefix claims 0x10 bytes that do not follow.
    let blob = STANDARD.encode([0x00, 0x00, 0x00, 0x10]);
    let line = format!("ssh-x25519 {blob} comment");
    let mut data = vec![0u8];
    data.extend_from_slice(line.as_bytes());
    run_fuzz_keyfile(&data);
}

#[test]
fn regression_private_short_magic_header() {
    // base64 payload shorter than the magic header: split_to must not panic.
    let blob = STANDARD.encode([0x00, 0x01, 0x02]);
    let mut data = vec![1u8]; // selector → private
    data.extend_from_slice(blob.as_bytes());
    run_fuzz_keyfile(&data);
}
