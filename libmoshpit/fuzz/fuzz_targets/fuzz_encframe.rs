// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

//! Fuzz target for the UDP `EncryptedFrame` parser.
//!
//! Invariants verified:
//! - No panic regardless of input.
//! - HMAC failures are always expected for random inputs (not a bug).
//! - `FrameTooLarge` is the only expected structured length-gate error.

#![no_main]

use std::io::Cursor;

use aws_lc_rs::{
    aead::{AES_256_GCM_SIV, RandomizedNonceKey},
    hmac::{HMAC_SHA512, Key},
};
use libfuzzer_sys::fuzz_target;
use libmoshpit::EncryptedFrame;
use uuid::Uuid;

fuzz_target!(|data: &[u8]| {
    // Use a fixed zero key; HMAC/AEAD failures are expected and not bugs.
    let Ok(rnk) = RandomizedNonceKey::new(&AES_256_GCM_SIV, &[0u8; 32]) else {
        return;
    };
    let hmac = Key::new(HMAC_SHA512, &[0u8; 64]);
    let id = Uuid::nil();

    let mut cursor = Cursor::new(data);
    match EncryptedFrame::parse(&mut cursor, id, &hmac, &rnk) {
        Ok(Some(_)) => {
            // Parsed a valid frame — no panic, that's success (very unlikely
            // with random data given the HMAC gate, but theoretically possible).
        }
        Ok(None) => {
            // Insufficient data — expected for most random inputs.
        }
        Err(_e) => {
            // Structured errors (FrameTooLarge, HMAC failure, AEAD failure,
            // decode errors) are all acceptable. No panics allowed.
        }
    }
});
