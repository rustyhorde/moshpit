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
        self.displayed.screen_mut().set_size(rows, cols);
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
        let new_alt = screen.alternate_screen();
        let old_alt = self.displayed.screen().alternate_screen();

        // Emit the alt-screen transition before any content so the terminal is in the
        // correct buffer before the diff / full-refresh bytes are applied.
        if new_alt && !old_alt {
            out.extend_from_slice(b"\x1b[?1049h");
        } else if !new_alt && old_alt {
            out.extend_from_slice(b"\x1b[?1049l");
        }

        if self.initialized {
            let diff = screen.contents_diff(self.displayed.screen());
            out.extend_from_slice(&diff);
        } else {
            // First render or after resize/invalidate: full refresh.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_size_resets_renderer_and_updates_dimensions() {
        let mut renderer = Renderer::new(24, 80);
        // Force initialized state by rendering once.
        let mut parser = vt100::Parser::new(24, 80, 0);
        parser.process(b"hello");
        drop(renderer.render(parser.screen(), &[], None));
        assert!(renderer.initialized);

        // set_size should clear initialized so next render is a full refresh.
        renderer.set_size(30, 100);
        assert!(!renderer.initialized);
    }

    #[test]
    fn renderer_new_is_not_initialized() {
        let r = Renderer::new(24, 80);
        assert!(!r.initialized);
    }

    #[test]
    fn renderer_first_render_sets_initialized() {
        let mut r = Renderer::new(24, 80);
        let parser = vt100::Parser::new(24, 80, 0);
        let out = r.render(parser.screen(), &[], None);
        assert!(r.initialized);
        assert!(!out.is_empty());
    }

    #[test]
    fn renderer_invalidate_clears_initialized() {
        let mut r = Renderer::new(24, 80);
        let parser = vt100::Parser::new(24, 80, 0);
        drop(r.render(parser.screen(), &[], None));
        assert!(r.initialized);
        r.invalidate();
        assert!(!r.initialized);
    }

    #[test]
    fn paint_overlays_to_ansi_empty_returns_empty() {
        let out = paint_overlays_to_ansi(&[], None);
        assert!(out.is_empty());
    }

    #[test]
    fn paint_overlays_to_ansi_with_cell_contains_escape_sequences() {
        use super::super::prediction::OverlayCell;
        let cells = vec![OverlayCell {
            row: 0,
            col: 0,
            ch: 'a',
            flagged: false,
        }];
        let out = paint_overlays_to_ansi(&cells, None);
        let s = String::from_utf8_lossy(&out);
        assert!(s.contains("\x1b[s"));
        assert!(s.contains("\x1b[1;1H"));
        assert!(s.contains('a'));
        assert!(s.contains("\x1b[u"));
    }

    // ── Phase 3: extended renderer tests ──────────────────────────────────────

    #[test]
    fn render_with_content_produces_nonempty_output() {
        let mut r = Renderer::new(24, 80);
        let mut parser = vt100::Parser::new(24, 80, 0);
        parser.process(b"hello");
        let out = r.render(parser.screen(), &[], None);
        assert!(!out.is_empty());
        let s = String::from_utf8_lossy(&out);
        assert!(s.contains("hello"));
    }

    #[test]
    fn render_second_call_with_no_change_produces_minimal_output() {
        let mut r = Renderer::new(24, 80);
        let mut parser = vt100::Parser::new(24, 80, 0);
        parser.process(b"hello");
        // First render (full refresh)
        let first = r.render(parser.screen(), &[], None);
        assert!(!first.is_empty());
        // Second render without changes: only cursor positioning
        let second = r.render(parser.screen(), &[], None);
        // Should be much shorter than the first (just cursor move, no cell redraws)
        assert!(
            second.len() < first.len(),
            "second render with no changes should be smaller"
        );
    }

    #[test]
    fn render_with_overlay_cell_contains_overlay_character() {
        use super::super::prediction::OverlayCell;
        let mut r = Renderer::new(24, 80);
        let parser = vt100::Parser::new(24, 80, 0);
        let overlays = vec![OverlayCell {
            row: 0,
            col: 0,
            ch: 'Z',
            flagged: false,
        }];
        let out = r.render(parser.screen(), &overlays, None);
        let s = String::from_utf8_lossy(&out);
        assert!(
            s.contains('Z'),
            "overlay character 'Z' must appear in output"
        );
    }

    #[test]
    fn render_with_flagged_overlay_contains_underline_sequence() {
        use super::super::prediction::OverlayCell;
        let mut r = Renderer::new(24, 80);
        let parser = vt100::Parser::new(24, 80, 0);
        let overlays = vec![OverlayCell {
            row: 2,
            col: 5,
            ch: 'F',
            flagged: true,
        }];
        let out = r.render(parser.screen(), &overlays, None);
        let s = String::from_utf8_lossy(&out);
        // Underline on: ESC[4m, underline off: ESC[24m
        assert!(
            s.contains("\x1b[4m"),
            "flagged overlay must include underline-on sequence"
        );
        assert!(
            s.contains("\x1b[24m"),
            "flagged overlay must include underline-off sequence"
        );
        assert!(s.contains('F'));
    }

    #[test]
    fn render_with_cursor_override_positions_cursor_at_override() {
        use super::super::prediction::OverlayCursor;
        let mut r = Renderer::new(24, 80);
        let parser = vt100::Parser::new(24, 80, 0);
        let cursor_override = Some(OverlayCursor { row: 5, col: 10 });
        let out = r.render(parser.screen(), &[], cursor_override);
        let s = String::from_utf8_lossy(&out);
        // Cursor should be positioned at row+1=6, col+1=11 (1-based)
        assert!(
            s.contains("\x1b[6;11H"),
            "cursor override must position cursor at (6,11): {s:?}"
        );
    }

    #[test]
    fn paint_overlays_to_ansi_with_cursor_positions_cursor() {
        use super::super::prediction::OverlayCursor;
        let out = paint_overlays_to_ansi(&[], Some(OverlayCursor { row: 3, col: 7 }));
        let s = String::from_utf8_lossy(&out);
        assert!(
            s.contains("\x1b[4;8H"),
            "cursor overlay must produce ESC[4;8H: {s:?}"
        );
    }

    #[test]
    fn render_emits_alt_screen_enter_on_transition() {
        let mut r = Renderer::new(24, 80);
        // First render to initialise (main screen).
        let mut p1 = vt100::Parser::new(24, 80, 0);
        p1.process(b"hello");
        drop(r.render(p1.screen(), &[], None));

        // Switch to alt-screen.
        let mut p2 = vt100::Parser::new(24, 80, 0);
        p2.process(b"\x1b[?1049h");
        let out = r.render(p2.screen(), &[], None);
        let s = String::from_utf8_lossy(&out);
        assert!(
            s.contains("\x1b[?1049h"),
            "alt-screen enter must appear in output when transitioning to alt-screen: {s:?}"
        );
    }

    #[test]
    fn render_emits_alt_screen_exit_on_transition() {
        let mut r = Renderer::new(24, 80);
        // Start in alt-screen.
        let mut p1 = vt100::Parser::new(24, 80, 0);
        p1.process(b"\x1b[?1049h");
        drop(r.render(p1.screen(), &[], None));

        // Switch back to main screen.
        let mut p2 = vt100::Parser::new(24, 80, 0);
        p2.process(b"\x1b[?1049h\x1b[?1049l");
        let out = r.render(p2.screen(), &[], None);
        let s = String::from_utf8_lossy(&out);
        assert!(
            s.contains("\x1b[?1049l"),
            "alt-screen exit must appear in output when transitioning to main screen: {s:?}"
        );
    }

    #[test]
    fn render_size_change_triggers_full_refresh() {
        let mut r = Renderer::new(24, 80);
        let mut parser = vt100::Parser::new(24, 80, 0);
        parser.process(b"hello");
        // First render to initialise
        let first = r.render(parser.screen(), &[], None);
        assert!(!first.is_empty());
        // Change size
        r.set_size(30, 100);
        assert!(!r.initialized);
        // Next render should be a full refresh (larger output)
        let mut parser2 = vt100::Parser::new(30, 100, 0);
        parser2.process(b"world");
        let after_resize = r.render(parser2.screen(), &[], None);
        assert!(r.initialized);
        assert!(!after_resize.is_empty());
    }
}
