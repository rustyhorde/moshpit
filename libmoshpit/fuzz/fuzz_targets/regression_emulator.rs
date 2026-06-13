// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

//! Regression tests for `fuzz_emulator` crashes.
//!
//! Per the cargo-fuzz documentation, each crash is embedded here as a
//! `&[u8]` constant so that `cargo test` permanently guards against
//! regressions without requiring a nightly fuzzer run.
//!
//! To add a new crash:
//! 1. Extract the bytes from the artifact zip downloaded from CI.
//! 2. Run `xxd -i crash-<hash>` (or `hexdump -C`) to get the byte values.
//! 3. Add a new test function following the pattern below.
//! 4. Commit the raw crash file to `fuzz/artifacts/fuzz_emulator/crash-<hash>`
//!    so `cargo +nightly fuzz run fuzz_emulator` also replays it automatically.

use std::sync::{Arc, Mutex};

use libmoshpit::{DisplayPreference, Emulator, PredictionEngine, Renderer, render_server_update};

const ROWS: u16 = 24;
const COLS: u16 = 80;

/// Helper that mirrors the fuzz target body exactly.
///
/// Any panic inside this function is a confirmed bug in moshpit's use of the
/// terminal-emulation pipeline.
fn run_fuzz_emulator(data: &[u8]) {
    let mut server = Emulator::new(ROWS, COLS);
    server.process(data);
    let screen_state = server.screen().contents_formatted();

    let client = Arc::new(Mutex::new(Emulator::new(ROWS, COLS)));
    {
        let mut emu = client
            .lock()
            .expect("fresh emulator mutex is never poisoned");
        emu.process(&screen_state);
        let _ = emu.screen().contents_formatted();
    }

    let prediction = Arc::new(Mutex::new(PredictionEngine::new(
        DisplayPreference::Adaptive,
    )));
    let renderer = Arc::new(Mutex::new(Renderer::new(ROWS, COLS)));
    let _ = render_server_update(&client, &prediction, &renderer, true);
}

#[test]
fn regression_empty() {
    run_fuzz_emulator(&[]);
}

#[test]
fn regression_escape_heavy() {
    // A grab-bag of CSI/OSC/SGR/cursor-movement sequences that stress the
    // screen-state serialization and diff paths.
    run_fuzz_emulator(b"\x1b[2J\x1b[H\x1b[1;31mred\x1b[0m\x1b[10;10Hxy\x1b]0;title\x07");
    run_fuzz_emulator(b"\x1b[999;999H\x1b[38;2;1;2;3mtruecolor\x1b[J");
}

#[test]
fn regression_wide_and_control_chars() {
    // Wide chars, combining marks, and raw control bytes.
    run_fuzz_emulator("日本語\u{0301}\t\r\n\x08\x07".as_bytes());
}
