// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

//! Fuzz target for `parse_full_public_key` (ML-DSA, `unstable` feature).
//!
//! During key exchange a peer's SSH-format public key blob is split on
//! whitespace, base64-decoded, and walked as two length-prefixed fields. The
//! blob is attacker-controlled, so the parser must reject any malformed input
//! with an `Err` rather than panicking on a bad length prefix or slice bound.
//!
//! `parse_full_public_key` only exists behind libmoshpit's `unstable` feature.
//! Build/run with `--features unstable` to exercise it; otherwise this target
//! is a no-op so the fuzz crate still builds on the default feature set.
//!
//! Invariants verified:
//! - No panic regardless of input.

#![no_main]

use libfuzzer_sys::fuzz_target;

#[cfg(feature = "unstable")]
fuzz_target!(|data: &[u8]| {
    // All outcomes (Ok or Err) are acceptable; only panics are failures.
    let _ = libmoshpit::parse_full_public_key(data);
});

#[cfg(not(feature = "unstable"))]
fuzz_target!(|_data: &[u8]| {
    // `parse_full_public_key` is gated behind libmoshpit's `unstable` feature;
    // without it there is nothing to fuzz here.
});
