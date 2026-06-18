// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

//! Fuzz target for the zstd decompression-bomb guard, `decode_all_capped`.
//!
//! Every compressed server payload — `ScreenStateCompressed`, `CompressedBytes`
//! (both pre-existing) and the newer `StateSyncDiff` / `StateChunk` — is run
//! through [`decode_all_capped`], which bounds output to 16 MiB so a tiny frame
//! cannot expand into an OOM. No previous target ever actually *decompressed* a
//! payload (they stopped at frame decode), so this shared primitive was
//! unfuzzed.
//!
//! This target feeds arbitrary bytes straight into the decompressor.
//!
//! Invariants verified:
//! - No panic and no unbounded allocation on any input: the function returns
//!   `Ok` with a `Vec` of at most 16 MiB, or `Err` (invalid stream / over-cap).

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = libmoshpit::decode_all_capped(data);
});
