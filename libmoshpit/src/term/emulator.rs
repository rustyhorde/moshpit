// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

use std::fmt;

/// A VT100/VT220 terminal emulator that tracks screen state.
///
/// Wraps `vt100::Parser` and exposes the minimal surface needed by the
/// prediction engine and renderer: feed bytes in, read the current screen
/// state out, and resize on SIGWINCH.
pub struct Emulator {
    parser: vt100::Parser,
}

impl fmt::Debug for Emulator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (rows, cols) = self.parser.screen().size();
        f.debug_struct("Emulator")
            .field("rows", &rows)
            .field("cols", &cols)
            .finish_non_exhaustive()
    }
}

impl Emulator {
    /// Create a new emulator with the given initial terminal dimensions.
    #[must_use]
    pub fn new(rows: u16, cols: u16) -> Self {
        Self {
            parser: vt100::Parser::new(rows, cols, 0),
        }
    }

    /// Feed raw bytes from the server into the emulator.
    pub fn process(&mut self, bytes: &[u8]) {
        self.parser.process(bytes);
    }

    /// Resize the emulator's screen (call on SIGWINCH).
    pub fn set_size(&mut self, rows: u16, cols: u16) {
        self.parser.screen_mut().set_size(rows, cols);
    }

    /// Replace the emulator's parser with an authoritative one.
    ///
    /// Used to resync the client emulator to a full-screen snapshot or a
    /// reconstructed `StateSync` state so that the emulator remains the single
    /// source of truth the renderer and prediction engine read from.  The
    /// caller is responsible for building `parser` with the correct dimensions
    /// and alternate-screen state.
    pub fn replace_parser(&mut self, parser: vt100::Parser) {
        self.parser = parser;
    }

    /// Returns the current screen state.
    #[must_use]
    pub fn screen(&self) -> &vt100::Screen {
        self.parser.screen()
    }

    /// Returns a reference to the underlying parser (needed for `contents_diff`).
    #[must_use]
    pub fn parser(&self) -> &vt100::Parser {
        &self.parser
    }

    /// Returns a mutable reference to the underlying parser.
    pub fn parser_mut(&mut self) -> &mut vt100::Parser {
        &mut self.parser
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_size_updates_screen_dimensions() {
        let mut emu = Emulator::new(24, 80);
        assert_eq!(emu.screen().size(), (24, 80));
        emu.set_size(30, 100);
        assert_eq!(emu.screen().size(), (30, 100));
    }

    #[test]
    fn emulator_new_initial_size() {
        let emu = Emulator::new(24, 80);
        assert_eq!(emu.screen().size(), (24, 80));
    }

    #[test]
    fn emulator_process_bytes_moves_cursor() {
        let mut emu = Emulator::new(24, 80);
        emu.process(b"hello");
        assert_eq!(emu.screen().cursor_position(), (0, 5));
    }

    #[test]
    fn replace_parser_swaps_in_authoritative_state() {
        let mut emu = Emulator::new(24, 80);
        emu.process(b"stale");
        let mut fresh = vt100::Parser::new(24, 80, 0);
        fresh.process(b"fresh");
        emu.replace_parser(fresh);
        assert_eq!(
            emu.screen().cell(0, 0).map(vt100::Cell::contents),
            Some("f")
        );
        assert_eq!(emu.screen().cursor_position(), (0, 5));
    }

    #[test]
    fn emulator_debug_format_contains_struct_name() {
        let emu = Emulator::new(24, 80);
        let s = format!("{emu:?}");
        assert!(s.contains("Emulator"));
    }
}
