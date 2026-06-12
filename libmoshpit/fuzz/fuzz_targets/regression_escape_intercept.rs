// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

//! Regression tests for `fuzz_escape_intercept` crashes.
//!
//! Per the cargo-fuzz documentation, each crash is embedded here as a
//! `&[u8]` constant so that `cargo test` permanently guards against
//! regressions without requiring a nightly fuzzer run.
//!
//! To add a new crash:
//! 1. Extract the bytes from the artifact zip downloaded from CI.
//! 2. Run `xxd -i crash-<hash>` (or `hexdump -C`) to get the byte values.
//! 3. Add a new test function following the pattern below.
//! 4. Commit the raw crash file to `fuzz/artifacts/fuzz_escape_intercept/crash-<hash>`
//!    so `cargo +nightly fuzz run fuzz_escape_intercept` also replays it automatically.

use std::sync::{Arc, Mutex};

use libmoshpit::{Emulator, intercept_queries_core};

/// Helper that mirrors the fuzz target body exactly.
///
/// Any panic inside this function is a confirmed bug: the fuzzer found an
/// input that causes an unwrap/unreachable/index-out-of-bounds in the
/// hand-rolled CSI/OSC parser.
fn run_fuzz_escape_intercept(data: &[u8]) {
    let emulator = Arc::new(Mutex::new(Emulator::new(24, 80)));
    let (passthrough, responses) =
        intercept_queries_core(data, "rgb:d0d0/d0d0/d0d0", "rgb:1c1c/1c1c/1c1c", &emulator);
    assert!(passthrough.len() <= data.len() * 2);
    for resp in responses {
        assert!(!resp.is_empty());
    }
}

#[test]
fn regression_empty() {
    run_fuzz_escape_intercept(&[]);
}

#[test]
fn regression_truncated_csi() {
    // ESC [ with no terminator: must not slice out of bounds.
    run_fuzz_escape_intercept(b"\x1b[");
    run_fuzz_escape_intercept(b"\x1b[?");
    run_fuzz_escape_intercept(b"\x1b[6");
}

#[test]
fn regression_truncated_osc() {
    // ESC ] with no terminator, and a dangling ESC at end of an OSC body.
    run_fuzz_escape_intercept(b"\x1b]10;?");
    run_fuzz_escape_intercept(b"\x1b]10;?\x1b");
}

#[test]
fn regression_lone_escape_at_end() {
    run_fuzz_escape_intercept(b"abc\x1b");
}
