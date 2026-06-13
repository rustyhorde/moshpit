// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

//! Fuzz target for moshpit key-file parsing.
//!
//! `parse_public_key_bytes` / `parse_private_key_bytes` are the `File::open`
//! cores of `load_public_key` / `load_private_key`. They base64-decode the
//! file and walk a length-prefixed binary layout via `get_val_by_len`, which
//! previously could panic on a truncated length prefix or an overrunning
//! length. A malformed key file (a peer's public key, a `known_hosts` entry, a
//! downloaded key) must therefore be rejected with an `Err`, never a panic.
//!
//! The first input byte selects which parser to drive so a single corpus
//! exercises both the public and private layouts.
//!
//! Invariants verified:
//! - No panic regardless of input.

#![no_main]

use libfuzzer_sys::fuzz_target;
use libmoshpit::{parse_private_key_bytes, parse_public_key_bytes};

fuzz_target!(|data: &[u8]| {
    let Some((selector, rest)) = data.split_first() else {
        return;
    };
    // All outcomes (Ok or Err) are acceptable; only panics are failures.
    if selector & 1 == 0 {
        let _ = parse_public_key_bytes(rest.to_vec());
    } else {
        let _ = parse_private_key_bytes(rest);
    }
});
