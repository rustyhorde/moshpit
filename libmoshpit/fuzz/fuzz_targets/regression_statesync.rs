// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

//! Regression tests for `fuzz_statesync` crashes.
//!
//! Each crash is embedded here as a `&[u8]` constant so that `cargo test`
//! permanently guards against regressions without requiring a nightly fuzzer
//! run. The op encoding consumed by `fuzz_statesync_drive` is:
//!  - `0x00 <u16 len> <payload>`                              → full-state push
//!  - `0x01 <u64 base> <u64 diff> <u16 len> <payload>`        → `StateSyncDiff`
//!  - `0x02 <u16 seq> <u16 total> <u16 len> <payload>`        → `StateChunk`
//!
//! To add a new crash:
//! 1. Extract the bytes from the artifact zip downloaded from CI.
//! 2. Run `xxd -i crash-<hash>` (or `hexdump -C`) to get the byte values.
//! 3. Add a new test function following the pattern below.
//! 4. Commit the raw crash file to `fuzz/artifacts/fuzz_statesync/crash-<hash>`
//!    so `cargo +nightly fuzz run fuzz_statesync` also replays it.

use libmoshpit::fuzz_statesync_drive;

/// Mirrors the fuzz target body exactly. Any panic here is a confirmed bug.
fn run_fuzz_statesync(data: &[u8]) {
    fuzz_statesync_drive(data);
}

#[test]
fn regression_empty() {
    run_fuzz_statesync(&[]);
}

#[test]
fn regression_diff_before_full_state() {
    // A diff (selector 0x01) arriving before any full state must trigger a
    // repaint request and discard, not apply to a blank screen or panic.
    // base_id=0, diff_id=1, empty compressed blob.
    run_fuzz_statesync(&[
        0x01, 0, 0, 0, 0, 0, 0, 0, 0, // base_id = 0
        0, 0, 0, 0, 0, 0, 0, 1, // diff_id = 1
        0, 0, // compressed len = 0
    ]);
}

#[test]
fn regression_chunk_total_zero() {
    // A first chunk (seq=0) declaring total=0 then nothing else: the
    // reassembly bookkeeping must not underflow or index out of bounds.
    run_fuzz_statesync(&[
        0x02, 0, 0, // seq = 0
        0, 0, // total = 0
        0, 0, // data len = 0
    ]);
}

#[test]
fn regression_out_of_order_chunk() {
    // A chunk with seq != 0 and no prior assembly: must discard and request a
    // repaint, never panic.
    run_fuzz_statesync(&[
        0x02, 0, 5, // seq = 5
        0, 9, // total = 9
        0, 0, // data len = 0
    ]);
}

#[test]
fn regression_garbage_zstd_in_diff() {
    // Full state to seed the baseline, then a diff whose compressed payload is
    // not a valid zstd stream: the decompress error must be swallowed cleanly.
    run_fuzz_statesync(&[
        0x00, 0, 1, b'x', // full state, 1 byte payload
        0x01, 0, 0, 0, 0, 0, 0, 0, 0, // base_id = 0 (matches initial ack)
        0, 0, 0, 0, 0, 0, 0, 1, // diff_id = 1
        0, 4, 0xff, 0xff, 0xff, 0xff, // 4 bytes of non-zstd garbage
    ]);
}
