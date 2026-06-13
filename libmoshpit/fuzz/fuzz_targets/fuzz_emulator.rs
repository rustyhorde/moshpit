// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

//! Fuzz target for the terminal-emulation ingest pipeline.
//!
//! The server feeds raw PTY bytes from a possibly-malicious shell into a vt100
//! emulator and serializes the result with `contents_formatted()`; the client
//! feeds that serialized state back into its own emulator and renders diffs.
//! `vt100` is third-party, but moshpit's *use* of it — serializing screen
//! state, round-tripping it through a second emulator, and rendering server
//! updates with prediction overlays — is unfuzzed.
//!
//! This target drives that whole client/server ingest path on arbitrary bytes:
//! 1. `Emulator::process` (server side, attacker-controlled PTY bytes).
//! 2. `screen().contents_formatted()` — the `ScreenState` payload.
//! 3. Feed that payload into a second emulator (the client's `ScreenState`
//!    handling) and serialize again.
//! 4. `render_server_update` — the diff + prediction-overlay render path.
//!
//! Invariants verified:
//! - No panic regardless of input.

#![no_main]

use std::sync::{Arc, Mutex};

use libfuzzer_sys::fuzz_target;
use libmoshpit::{DisplayPreference, Emulator, PredictionEngine, Renderer, render_server_update};

const ROWS: u16 = 24;
const COLS: u16 = 80;

fuzz_target!(|data: &[u8]| {
    // Server side: feed attacker-controlled PTY bytes into the emulator.
    let mut server = Emulator::new(ROWS, COLS);
    server.process(data);
    let screen_state = server.screen().contents_formatted();

    // Client side: apply the serialized ScreenState into a fresh emulator, just
    // as the client does on an `EncryptedFrame::ScreenState` / decompressed
    // `ScreenStateCompressed`, then re-serialize it.
    let client = Arc::new(Mutex::new(Emulator::new(ROWS, COLS)));
    {
        let mut emu = client
            .lock()
            .expect("fresh emulator mutex is never poisoned");
        emu.process(&screen_state);
        let _ = emu.screen().contents_formatted();
    }

    // Render path: exercise the diff + prediction overlay render the client runs
    // on every server update.
    let prediction = Arc::new(Mutex::new(PredictionEngine::new(
        DisplayPreference::Adaptive,
    )));
    let renderer = Arc::new(Mutex::new(Renderer::new(ROWS, COLS)));
    let _ = render_server_update(&client, &prediction, &renderer, true);
});
