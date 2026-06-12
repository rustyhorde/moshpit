// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

//! Fuzz target for the client-side terminal escape-sequence interceptor.
//!
//! `intercept_queries_core` is the hand-rolled CSI/OSC parser that runs on the
//! client against raw PTY bytes streamed from the server — the most
//! attacker-controlled, highest-volume input in the system. Unlike the bincode
//! frame parsers it does manual cursor arithmetic and slicing, so it is exactly
//! the kind of code where an out-of-bounds slice or overflow panic could hide.
//!
//! Invariants verified:
//! - No panic regardless of input.
//! - Every returned response payload is non-empty (canned responses only).

#![no_main]

use std::sync::{Arc, Mutex};

use libfuzzer_sys::fuzz_target;
use libmoshpit::{Emulator, intercept_queries_core};

fuzz_target!(|data: &[u8]| {
    // A non-trivial screen size so the DSR/XTWINOPS branches read realistic
    // cursor/size values. The emulator is only read, never mutated, by the
    // interceptor.
    let emulator = Arc::new(Mutex::new(Emulator::new(24, 80)));

    let (passthrough, responses) =
        intercept_queries_core(data, "rgb:d0d0/d0d0/d0d0", "rgb:1c1c/1c1c/1c1c", &emulator);

    // The interceptor never invents passthrough bytes out of nothing: output is
    // bounded by input (VT/FF expand 1→2, so allow a 2x ceiling).
    assert!(passthrough.len() <= data.len() * 2);

    // Canned query responses are always non-empty.
    for resp in responses {
        assert!(!resp.is_empty());
    }
});
