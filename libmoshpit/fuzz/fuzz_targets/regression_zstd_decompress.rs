// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

//! Regression tests for `fuzz_zstd_decompress` crashes.
//!
//! Each crash is embedded here as a `&[u8]` constant so that `cargo test`
//! permanently guards against regressions without requiring a nightly fuzzer
//! run.
//!
//! To add a new crash:
//! 1. Extract the bytes from the artifact zip downloaded from CI.
//! 2. Run `xxd -i crash-<hash>` (or `hexdump -C`) to get the byte values.
//! 3. Add a new test function following the pattern below.
//! 4. Commit the raw crash file to `fuzz/artifacts/fuzz_zstd_decompress/crash-<hash>`
//!    so `cargo +nightly fuzz run fuzz_zstd_decompress` also replays it.

use libmoshpit::decode_all_capped;

/// Mirrors the fuzz target body exactly. Any panic here is a confirmed bug.
fn run_fuzz_zstd_decompress(data: &[u8]) {
    let _ = decode_all_capped(data);
}

#[test]
fn regression_empty() {
    run_fuzz_zstd_decompress(&[]);
}

#[test]
fn regression_zstd_magic_only() {
    // The zstd magic number with no frame body must error cleanly, not panic.
    run_fuzz_zstd_decompress(&[0x28, 0xb5, 0x2f, 0xfd]);
}

#[test]
fn regression_garbage() {
    run_fuzz_zstd_decompress(&[0xff; 64]);
}

#[test]
fn regression_high_ratio_stays_capped() {
    // A small stream that decompresses to a large run of zeros must come back
    // either as an `Ok` payload bounded by the 16 MiB cap or an over-cap `Err` —
    // never an OOM or a panic.
    let bomb =
        zstd::encode_all(vec![0u8; 4 * 1024 * 1024].as_slice(), 19).expect("encode test payload");
    match run_capped(&bomb) {
        Ok(out) => assert!(out.len() <= 16 * 1024 * 1024),
        Err(_) => {}
    }
}

/// Like `run_fuzz_zstd_decompress` but returns the result so the cap can be
/// asserted on.
fn run_capped(data: &[u8]) -> std::io::Result<Vec<u8>> {
    decode_all_capped(data)
}
