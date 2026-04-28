// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

//! Differential terminal renderer.
//!
//! Converts the output of the terminal emulator ([`vt100::Screen`]) plus any
//! prediction overlays into the minimal sequence of ANSI escape codes needed
//! to update the user's physical terminal from its last known state.
//!
//! # Strategy
//!
//! `vt100::Screen` exposes `contents_diff(prev: &vt100::Screen) -> Vec<u8>`
//! which returns the bytes that transition a terminal showing `prev` to one
//! showing `self`.  We use this as the baseline differential and then apply
//! prediction overlays on top as a second pass:
//!
//! 1. `diff = current_screen.contents_diff(prev_screen)` – bring the physical
//!    terminal up to date with the server-driven screen.
//! 2. For each active overlay cell: `CSI row;col H` + SGR + character.
//! 3. Restore the cursor to the predicted (or real) cursor position.
//!
//! We maintain a `vt100::Parser` that is advanced with every rendered output
//! so that subsequent diffs are always computed against what is actually shown
//! on the user's screen (real content + overlays).

use std::fmt;

use super::prediction::{OverlayCell, OverlayCursor};

/// A stateful differential renderer.
pub struct Renderer {
    /// Tracks what the user's physical terminal currently looks like.
    displayed: vt100::Parser,
    /// True after the first render — before that we must do a full refresh.
    initialized: bool,
}

impl fmt::Debug for Renderer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Renderer")
            .field("initialized", &self.initialized)
            .finish_non_exhaustive()
    }
}

impl Renderer {
    /// Create a new renderer with the given initial terminal dimensions.
    #[must_use]
    pub fn new(rows: u16, cols: u16) -> Self {
        Self {
            displayed: vt100::Parser::new(rows, cols, 0),
            initialized: false,
        }
    }

    /// Resize the renderer's view of the physical terminal.
    pub fn set_size(&mut self, rows: u16, cols: u16) {
        // Resizing forces a full refresh on the next render.
        self.displayed.set_size(rows, cols);
        self.initialized = false;
    }

    /// Produce the bytes to send to stdout that will bring the user's terminal
    /// from its current state to `screen` with `overlays` applied on top.
    ///
    /// Internally advances the "displayed" parser so the next call computes a
    /// correct differential.
    ///
    /// * `screen` – the current server-driven screen state.
    /// * `overlays` – predicted cells to paint on top of the real screen.
    /// * `cursor` – the predicted cursor position (overrides real cursor if
    ///   `Some`).
    #[must_use]
    pub fn render(
        &mut self,
        screen: &vt100::Screen,
        overlays: &[OverlayCell],
        cursor: Option<OverlayCursor>,
    ) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::with_capacity(4096);

        // ── 1. diff the real screen against what we last displayed ───────
        if self.initialized {
            let diff = screen.contents_diff(self.displayed.screen());
            out.extend_from_slice(&diff);
        } else {
            // First render or after resize: full refresh.
            out.extend_from_slice(&screen.contents_formatted());
            self.initialized = true;
        }

        // ── 2. paint overlay cells ───────────────────────────────────────
        if !overlays.is_empty() {
            // Save cursor position before painting overlays.
            out.extend_from_slice(b"\x1b[s");

            for cell in overlays {
                // Move to cell position (1-based).
                write_to_vec(
                    &mut out,
                    format_args!("\x1b[{};{}H", cell.row + 1, cell.col + 1),
                );
                if cell.flagged {
                    // Underline on
                    out.extend_from_slice(b"\x1b[4m");
                }
                // Write the predicted character.
                let mut char_buf = [0u8; 4];
                let s = cell.ch.encode_utf8(&mut char_buf);
                out.extend_from_slice(s.as_bytes());
                if cell.flagged {
                    // Reset underline
                    out.extend_from_slice(b"\x1b[24m");
                }
            }
        }

        // ── 3. position the cursor ───────────────────────────────────────
        let (cur_row, cur_col) = if let Some(oc) = cursor {
            (oc.row, oc.col)
        } else {
            screen.cursor_position()
        };
        write_to_vec(
            &mut out,
            format_args!("\x1b[{};{}H", cur_row + 1, cur_col + 1),
        );

        // Restore SGR to default in case overlays left state dirty.
        if !overlays.is_empty() {
            out.extend_from_slice(b"\x1b[m");
            // We saved cursor before overlays; re-position explicitly above instead.
        }

        // ── 4. advance the "displayed" parser ────────────────────────────
        // Process all bytes we just emitted so the next diff is correct.
        self.displayed.process(&out);

        out
    }

    /// Force a complete screen redraw on the next call to [`Renderer::render`].
    pub fn invalidate(&mut self) {
        self.initialized = false;
    }
}

/// Emit the ANSI sequences for `overlays` and `cursor` without touching any
/// renderer state.  Used by the stdin forwarder to preview predicted keystrokes
/// on top of whatever is currently displayed — without modifying the
/// differential-render baseline.
#[must_use]
pub fn paint_overlays_to_ansi(overlays: &[OverlayCell], cursor: Option<OverlayCursor>) -> Vec<u8> {
    if overlays.is_empty() && cursor.is_none() {
        return Vec::new();
    }

    let mut out: Vec<u8> = Vec::with_capacity(256);

    if !overlays.is_empty() {
        out.extend_from_slice(b"\x1b[s"); // save cursor
        for cell in overlays {
            write_to_vec(
                &mut out,
                format_args!("\x1b[{};{}H", cell.row + 1, cell.col + 1),
            );
            if cell.flagged {
                out.extend_from_slice(b"\x1b[4m");
            }
            let mut char_buf = [0u8; 4];
            let s = cell.ch.encode_utf8(&mut char_buf);
            out.extend_from_slice(s.as_bytes());
            if cell.flagged {
                out.extend_from_slice(b"\x1b[24m");
            }
        }
        out.extend_from_slice(b"\x1b[m"); // reset SGR
        out.extend_from_slice(b"\x1b[u"); // restore cursor to pre-paint position
    }

    if let Some(oc) = cursor {
        write_to_vec(
            &mut out,
            format_args!("\x1b[{};{}H", oc.row + 1, oc.col + 1),
        );
    }

    out
}

// Helper: write a `fmt::Arguments` into a `Vec<u8>` without allocation.
fn write_to_vec(buf: &mut Vec<u8>, args: fmt::Arguments<'_>) {
    use std::io::Write as _;
    drop(buf.write_fmt(args));
}
