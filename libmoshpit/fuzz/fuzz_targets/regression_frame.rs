// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

//! Regression tests for `fuzz_frame` crashes.

use libmoshpit::Frame;
use std::io::Cursor;

/// Helper that mirrors the fuzz target body exactly.
fn run_fuzz_frame(data: &[u8]) {
    let mut cursor = Cursor::new(data);
    let _ = Frame::parse(&mut cursor);
}

#[test]
fn regression_empty() {
    run_fuzz_frame(&[]);
}

/// Regression test for the crash found in CI run 25139587977 / artifact 6720028039.
/// This was identified as an OOM issue in Frame::parse.
#[test]
fn regression_crash_6720028039() {
    const CRASH: &[u8] = &[
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0xfc, 0x10, 0x10, 0xff,
        0xf7, 0x00, 0x3d, 0x00, 0x25, 0x00, 0x20, 0x70, 0xb2,
    ];
    run_fuzz_frame(CRASH);
}

/// Regression test for crash artifact `crash-ff8e016881278559e9754b0116854ad9f5d0df33`.
/// The frame decoded to a `ResumeRequest` whose leading `UuidWrapper` string field
/// held non-ASCII multi-byte UTF-8; `Uuid::parse_str`'s error path sliced the string
/// on a non-char boundary and panicked. Fixed by switching to `Uuid::try_parse`.
#[test]
fn regression_crash_ff8e0168() {
    const CRASH: &[u8] = &[
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1d, 0x07, 0x19, 0x7b, 0x31, 0x36, 0x31,
        0x35, 0x02, 0x00, 0x00, 0x00, 0x38, 0x39, 0x00, 0x26, 0x07, 0x19, 0x7b, 0x30, 0x30, 0x30,
        0x30, 0x02, 0xdf, 0x84, 0x3b, 0x7d, 0x83, 0x31,
    ];
    run_fuzz_frame(CRASH);
}
