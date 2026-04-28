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
        self.parser.set_size(rows, cols);
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
