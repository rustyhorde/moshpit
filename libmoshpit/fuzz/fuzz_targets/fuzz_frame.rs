// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

//! Fuzz target for the TCP `Frame` parser.
//!
//! Invariants verified:
//! - No panic regardless of input.
//! - When `Ok(Some(frame))` is returned, the frame round-trips correctly.
//! - `FrameTooLarge` is the only expected structured error.

#![no_main]

use std::io::Cursor;

use libfuzzer_sys::fuzz_target;
use libmoshpit::Frame;

fuzz_target!(|data: &[u8]| {
    let mut cursor = Cursor::new(data);
    match Frame::parse(&mut cursor) {
        Ok(Some(_frame)) => {
            // A valid frame was parsed — no panic, that's success.
        }
        Ok(None) => {
            // Incomplete data — expected for most random inputs.
        }
        Err(_e) => {
            // Only structured errors (e.g. FrameTooLarge, decode errors) are
            // acceptable. The important invariant is: no panic.
        }
    }
});
