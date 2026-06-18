// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

//! Fuzz target for the client-side `StateSync` application pipeline.
//!
//! The newer StateSync diff-delivery mode (commit b177951) added the
//! `StateSyncDiff` / `StateChunk` / `ClientAck` frames and a client module,
//! `udp::statesync::StateSyncClient`, that:
//!  - decompresses incoming zstd diff/chunk payloads (the 16 MiB-capped
//!    decompression-bomb guard, [`decode_all_capped`]),
//!  - reassembles multi-part full-state pushes from `StateChunk` frames using
//!    hand-rolled `seq`/`total` bookkeeping, and
//!  - applies diffs against an ack baseline via a temporary `vt100::Parser`.
//!
//! `fuzz_encframe_decrypt` already covers decoding these frames off the wire,
//! but stops at the decode boundary — nothing exercised what happens *after*.
//! This target drives `fuzz_statesync_drive`, which replays a fuzzer-derived
//! sequence of full-state / diff / chunk operations against one
//! `StateSyncClient`, so cross-call reassembly state and the decompression cap
//! are stressed with attacker-controlled bytes.
//!
//! Invariants verified:
//! - No panic regardless of the op sequence (out-of-order chunks, mismatched
//!   `total`, diffs before any full state, malformed/oversized zstd, etc.).

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    libmoshpit::fuzz_statesync_drive(data);
});
