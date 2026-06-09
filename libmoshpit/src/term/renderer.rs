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
//! showing `self`, including the final cursor position, SGR attributes and
//! cursor visibility.  Rather than diffing the server screen and then painting
//! predictions on top as a separate pass, we build a single *target*
//! framebuffer — the server screen with prediction overlays merged in as real
//! cells and the cursor placed at its final position — and diff that:
//!
//! 1. `frame = server_screen + predicted cells + final cursor` (a scratch
//!    [`vt100::Parser`]).
//! 2. `diff = frame.contents_diff(displayed)` – a fully self-contained update.
//!
//! Because predictions are first-class cells in `frame`, a prediction that is
//! later culled simply disappears from the next `frame`, and the diff repaints
//! the real cell automatically — no stale glyph can be left behind.
//!
//! We maintain a `vt100::Parser` (`displayed`) that is advanced with exactly
//! the bytes we emit, so subsequent diffs are always computed against what is
//! actually shown on the user's screen.

use std::{
    fmt,
    sync::{Arc, Mutex},
};

use super::emulator::Emulator;
use super::prediction::{OverlayCell, OverlayCursor, PredictionEngine};

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
        let new_alt = screen.alternate_screen();
        let old_alt = self.displayed.screen().alternate_screen();
        // An alt-screen buffer swap discards the previous buffer's contents, so
        // a diff against `displayed` would be meaningless — force a full repaint.
        let alt_changed = new_alt != old_alt;

        // ── 1. build the target framebuffer (server screen + predictions) ──
        let (rows, cols) = screen.size();
        let mut frame = vt100::Parser::new(rows, cols, 0);
        frame.process(&screen.contents_formatted());

        // Merge predicted cells as real content so the diff treats them as
        // first-class cells (and self-heals when they are later culled).
        if !overlays.is_empty() {
            let mut paint: Vec<u8> = Vec::with_capacity(overlays.len() * 12);
            for cell in overlays {
                write_to_vec(
                    &mut paint,
                    format_args!("\x1b[{};{}H", cell.row + 1, cell.col + 1),
                );
                if cell.flagged {
                    paint.extend_from_slice(b"\x1b[4m");
                }
                let mut char_buf = [0u8; 4];
                paint.extend_from_slice(cell.ch.encode_utf8(&mut char_buf).as_bytes());
                if cell.flagged {
                    paint.extend_from_slice(b"\x1b[24m");
                }
            }
            frame.process(&paint);
        }

        // Place the cursor at its final resting position (predicted or real)
        // inside the frame so the diff carries the correct cursor move.
        let (cur_row, cur_col) = if let Some(oc) = cursor {
            (oc.row, oc.col)
        } else {
            screen.cursor_position()
        };
        let mut mv: Vec<u8> = Vec::with_capacity(12);
        write_to_vec(
            &mut mv,
            format_args!("\x1b[{};{}H", cur_row + 1, cur_col + 1),
        );
        frame.process(&mv);

        // ── 2. emit the update ────────────────────────────────────────────
        let mut out: Vec<u8> = Vec::with_capacity(4096);
        // Emit the alt-screen transition first so the terminal is in the
        // correct buffer before the content bytes are applied.
        if new_alt && !old_alt {
            out.extend_from_slice(b"\x1b[?1049h");
        } else if !new_alt && old_alt {
            out.extend_from_slice(b"\x1b[?1049l");
        }

        if self.initialized && !alt_changed {
            // Native scrollback: if the new frame is simply the displayed screen
            // scrolled up by N rows, emit a *real* scroll so the rows that fall
            // off the top enter the user's terminal scrollback (mosh-style),
            // instead of repainting them away.  Only on the main screen — the
            // alternate buffer has no scrollback.  We advance `displayed` by the
            // scroll bytes *before* diffing so the differential is computed
            // against the post-scroll baseline.
            if !new_alt
                && let Some(n) =
                    detect_scroll_up(self.displayed.screen(), frame.screen(), rows, cols)
            {
                let mut scroll: Vec<u8> = Vec::with_capacity(8 + usize::from(n));
                // Park the cursor at the bottom-left, then line-feed N times.  The
                // renderer is the sole writer and never sets a scroll region on the
                // physical terminal, so these scroll the full screen.
                write_to_vec(&mut scroll, format_args!("\x1b[{rows};1H"));
                scroll.resize(scroll.len() + usize::from(n), b'\n');
                self.displayed.process(&scroll);
                out.extend_from_slice(&scroll);
            }
            let diff = frame.screen().contents_diff(self.displayed.screen());
            self.displayed.process(&diff);
            out.extend_from_slice(&diff);
        } else {
            // First render, post-resize/invalidate, or an alt-screen swap.
            let full = frame.screen().contents_formatted();
            self.displayed.process(&out);
            self.displayed.process(&full);
            out.extend_from_slice(&full);
            self.initialized = true;
        }

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

/// Render a single clean update to the terminal after the server has changed
/// the emulator's screen state.
///
/// Reconciles outstanding predictions against the new screen (`cull` +
/// `apply`) and renders the result through the shared [`Renderer`], so the
/// renderer remains the sole writer to the terminal and its `displayed`
/// baseline stays exact.  Pass `with_predictions = false` to skip the
/// prediction work entirely (e.g. in alternate-screen mode where a full-screen
/// app owns the display).
///
/// Locks are always acquired in the order **emulator → prediction → renderer**
/// to match [`render_prediction_update`] and avoid deadlocks.
///
/// # Panics
/// Never panics; poisoned mutexes are recovered via [`std::sync::PoisonError`].
#[must_use]
pub fn render_server_update(
    emulator: &Arc<Mutex<Emulator>>,
    prediction: &Arc<Mutex<PredictionEngine>>,
    renderer: &Arc<Mutex<Renderer>>,
    with_predictions: bool,
) -> Vec<u8> {
    let emu = emulator
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let screen = emu.screen();
    let (overlays, cursor) = if with_predictions {
        let mut pred = prediction
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        pred.cull(screen);
        pred.apply(screen)
    } else {
        (Vec::new(), None)
    };
    let mut rend = renderer
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    rend.render(screen, &overlays, cursor)
}

/// Render a single clean update reflecting a locally-predicted keystroke.
///
/// Feeds each byte of `new_bytes` to the prediction engine, then renders the
/// emulator's current screen with the resulting overlays through the shared
/// [`Renderer`].  Unlike [`render_server_update`] this does **not** cull, since
/// no new server data has arrived — it only adds the just-typed prediction.
///
/// Locks are always acquired in the order **emulator → prediction → renderer**.
///
/// # Panics
/// Never panics; poisoned mutexes are recovered via [`std::sync::PoisonError`].
#[must_use]
pub fn render_prediction_update(
    emulator: &Arc<Mutex<Emulator>>,
    prediction: &Arc<Mutex<PredictionEngine>>,
    renderer: &Arc<Mutex<Renderer>>,
    new_bytes: &[u8],
) -> Vec<u8> {
    let emu = emulator
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let screen = emu.screen();
    let (overlays, cursor) = {
        let mut pred = prediction
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for &byte in new_bytes {
            pred.new_user_byte(byte, screen);
        }
        pred.apply(screen)
    };
    let mut rend = renderer
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    rend.render(screen, &overlays, cursor)
}

// Helper: write a `fmt::Arguments` into a `Vec<u8>` without allocation.
fn write_to_vec(buf: &mut Vec<u8>, args: fmt::Arguments<'_>) {
    use std::io::Write as _;
    drop(buf.write_fmt(args));
}

/// Detect whether `frame` is `prev` scrolled up by N rows (`1..rows`), returning
/// the smallest such N.
///
/// A real (whole-screen) scroll appears as one of two clean shapes, depending on
/// whether the streamed output ended with a trailing newline:
///
/// * **A — new content on the bottom row** (no trailing newline): the entire
///   overlap shifts exactly, `frame[i] == prev[i + n]` for all `i in 0..rows-n`,
///   and the freshly-revealed content sits in the bottom `n` rows.
/// * **B — blank bottom row** (trailing newline parks the cursor on a fresh
///   bottom line): the upper region `frame[i] == prev[i + n]` for
///   `i in 0..rows-1-n` shifts exactly, the new lines sit just above, and the
///   bottom row is blank.
///
/// Both require at least one matched row to be non-blank (so a blank/cleared
/// screen never reads as a scroll). Comparison is on rendered text only — any
/// attribute (colour) drift in the revealed region is healed by the subsequent
/// `contents_diff`.
///
/// Anything that is *not* a clean whole-screen scroll returns `None` and falls
/// back to a plain repaint. In particular a scroll-region shift with a pinned,
/// non-blank last line (e.g. an `apt` fancy progress bar) matches neither shape:
/// shape A breaks on the pinned row, shape B requires that row to be blank.
fn detect_scroll_up(
    prev: &vt100::Screen,
    frame: &vt100::Screen,
    rows: u16,
    cols: u16,
) -> Option<u16> {
    if rows < 2 {
        return None;
    }
    let row_text = |s: &vt100::Screen, r: u16| s.contents_between(r, 0, r, cols);
    let prev_rows: Vec<String> = (0..rows).map(|r| row_text(prev, r)).collect();
    let frame_rows: Vec<String> = (0..rows).map(|r| row_text(frame, r)).collect();
    let is_blank = |s: &str| s.trim_end().is_empty();

    // No vertical movement at all (including a fully unchanged screen) — never
    // emit a scroll, or a uniform screen would read as a 1-row shift.
    if prev_rows == frame_rows {
        return None;
    }

    let shifted = |n: u16, len: u16| -> bool {
        let n = usize::from(n);
        let len = usize::from(len);
        (0..len).all(|i| frame_rows[i] == prev_rows[i + n])
            && (0..len).any(|i| !is_blank(&frame_rows[i]))
    };

    // Shape A: the whole overlap shifts cleanly (new content on the bottom rows).
    for n in 1..rows {
        if shifted(n, rows - n) {
            return Some(n);
        }
    }
    // Shape B: upper region shifts and the bottom row is blank (trailing newline).
    if is_blank(&frame_rows[usize::from(rows - 1)]) {
        for n in 1..rows - 1 {
            if shifted(n, rows - 1 - n) {
                return Some(n);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::{
        Emulator, PredictionEngine, Renderer, detect_scroll_up, paint_overlays_to_ansi,
        render_prediction_update, render_server_update,
    };

    // Drive a real emulator + renderer and feed every emitted byte into a model
    // terminal that *has* a scrollback buffer, so tests can assert on whether
    // rows scrolled off into the user's local scrollback.
    struct Harness {
        emu: Emulator,
        renderer: Renderer,
        term: vt100::Parser,
    }

    impl Harness {
        fn new(rows: u16, cols: u16) -> Self {
            Self {
                emu: Emulator::new(rows, cols),
                renderer: Renderer::new(rows, cols),
                term: vt100::Parser::new(rows, cols, 1000),
            }
        }

        // Feed server bytes through emulator + renderer into the model terminal.
        fn feed(&mut self, bytes: &[u8]) {
            self.emu.process(bytes);
            let out = self.renderer.render(self.emu.screen(), &[], None);
            self.term.process(&out);
        }

        // How many rows currently sit in the model terminal's scrollback.
        fn scrollback_depth(&mut self) -> usize {
            self.term.screen_mut().set_scrollback(usize::MAX);
            let depth = self.term.screen().scrollback();
            self.term.screen_mut().set_scrollback(0);
            depth
        }

        fn term_row(&self, r: u16) -> String {
            self.term.screen().contents_between(r, 0, r, 80)
        }
    }

    #[test]
    fn detect_scroll_up_recognizes_clean_shift() {
        let mut prev = vt100::Parser::new(4, 80, 0);
        prev.process(b"\x1b[1;1Haaa\r\nbbb\r\nccc\r\nddd");
        let mut frame = vt100::Parser::new(4, 80, 0);
        // Same content shifted up by two rows.
        frame.process(b"\x1b[1;1Hccc\r\nddd\r\neee\r\nfff");
        assert_eq!(
            detect_scroll_up(prev.screen(), frame.screen(), 4, 80),
            Some(2)
        );
    }

    #[test]
    fn detect_scroll_up_ignores_unchanged_and_blank() {
        // Unchanged screen — never a scroll.
        let mut a = vt100::Parser::new(4, 80, 0);
        a.process(b"\x1b[1;1Haaa\r\nbbb\r\nccc\r\nddd");
        let mut b = vt100::Parser::new(4, 80, 0);
        b.process(b"\x1b[1;1Haaa\r\nbbb\r\nccc\r\nddd");
        assert_eq!(detect_scroll_up(a.screen(), b.screen(), 4, 80), None);

        // Blank → blank, and blank-overlap shifts, are not scrolls.
        let blank = vt100::Parser::new(4, 80, 0);
        let mut one = vt100::Parser::new(4, 80, 0);
        one.process(b"\x1b[4;1Hxxx");
        assert_eq!(detect_scroll_up(blank.screen(), one.screen(), 4, 80), None);
    }

    #[test]
    fn native_scroll_pushes_rows_into_local_scrollback() {
        let mut h = Harness::new(24, 80);
        // Fill the screen, then stream more lines so the screen scrolls.
        for i in 0..24 {
            h.feed(format!("line{i:02}\r\n").as_bytes());
        }
        let before = h.scrollback_depth();
        for i in 24..40 {
            h.feed(format!("line{i:02}\r\n").as_bytes());
        }
        let after = h.scrollback_depth();
        assert!(
            after > before,
            "scrolled-off lines must enter local scrollback (before={before}, after={after})"
        );
        // The most recent line is visible near the bottom; an earlier streamed
        // line now lives in scrollback rather than being repainted away.
        assert!(
            (0..24).any(|r| h.term_row(r).starts_with("line39")),
            "latest line must be on screen"
        );
    }

    #[test]
    fn scrolled_off_line_is_retrievable_from_local_scrollback() {
        let mut h = Harness::new(24, 80);
        for i in 0..40 {
            h.feed(format!("line{i:02}\r\n").as_bytes());
        }
        // Scroll the model terminal all the way back; an early line that left the
        // visible screen must now be reachable in the local scrollback buffer.
        h.term.screen_mut().set_scrollback(usize::MAX);
        let reachable = (0..24).any(|r| h.term.screen().contents_between(r, 0, r, 80) == "line00");
        h.term.screen_mut().set_scrollback(0);
        assert!(
            reachable,
            "an early scrolled-off line must live in the terminal's scrollback"
        );
    }

    #[test]
    fn batched_multi_line_scroll_is_detected_in_one_render() {
        let mut h = Harness::new(6, 80);
        // Fill the 6-row screen.
        h.feed(b"\x1b[1;1Hr0\r\nr1\r\nr2\r\nr3\r\nr4\r\nr5");
        let before = h.scrollback_depth();
        // One render that scrolls the 6-row screen by four rows at once: the
        // leading "\r\n" scrolls once, then r6/r7/r8 each scroll on their trailing
        // newline (r0..r3 leave the screen). The renderer must push all four in a
        // single real scroll.
        h.feed(b"\r\nr6\r\nr7\r\nr8\r\n");
        let after = h.scrollback_depth();
        assert_eq!(after, before + 4, "a 4-row batch scroll must push 4 rows");
        assert_eq!(h.term_row(4).trim_end(), "r8");
    }

    #[test]
    fn single_linefeed_scroll_is_detected() {
        let mut h = Harness::new(4, 80);
        h.feed(b"\x1b[1;1Ha\r\nb\r\nc\r\nd");
        let before = h.scrollback_depth();
        // One more line feed scrolls the 4-row screen by exactly one row.
        h.feed(b"\r\ne");
        let after = h.scrollback_depth();
        assert_eq!(
            after,
            before + 1,
            "a one-row scroll must push exactly one row"
        );
        assert_eq!(h.term_row(3).trim_end(), "e");
    }

    #[test]
    fn apt_fancy_progress_does_not_scroll_local_scrollback() {
        let mut h = Harness::new(24, 80);
        // Reserve the last line, then stream log lines + redraw a pinned bar.
        h.feed(b"\x1b[2J\x1b[H\x1b[1;23r\x1b[1;1H");
        for (i, pct) in [(1u32, "20%"), (2, "40%"), (3, "60%"), (4, "80%")] {
            let frame = format!(
                "Unpacking pkg{i:02}...\r\n\x1b7\x1b[24;1H\x1b[42m[bar] {pct}\x1b[0m\x1b[K\x1b8"
            );
            h.feed(frame.as_bytes());
        }
        assert_eq!(
            h.scrollback_depth(),
            0,
            "a scroll-region progress bar must not spill into local scrollback"
        );
        assert!(
            h.term_row(23).contains("80%"),
            "the progress bar stays pinned to the last row"
        );
    }

    #[test]
    fn alt_screen_scroll_does_not_touch_scrollback() {
        let mut h = Harness::new(24, 80);
        // Enter the alternate screen and scroll within it.
        h.feed(b"\x1b[?1049h\x1b[1;1H");
        for i in 0..40 {
            h.feed(format!("alt{i:02}\r\n").as_bytes());
        }
        assert_eq!(
            h.scrollback_depth(),
            0,
            "the alternate screen has no scrollback; never emit a real scroll there"
        );
    }

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

    // A stand-in for the user's physical terminal: feed it every byte the
    // renderer emits and inspect the resulting screen state.  This mirrors the
    // renderer's internal `displayed` parser and lets tests assert on *visual*
    // outcomes instead of brittle escape-sequence substrings.
    fn apply(term: &mut vt100::Parser, bytes: &[u8]) {
        term.process(bytes);
    }

    #[test]
    fn render_with_overlay_cell_paints_overlay_character() {
        use super::super::prediction::OverlayCell;
        let mut r = Renderer::new(24, 80);
        let mut term = vt100::Parser::new(24, 80, 0);
        let parser = vt100::Parser::new(24, 80, 0);
        let overlays = vec![OverlayCell {
            row: 0,
            col: 0,
            ch: 'Z',
            flagged: false,
        }];
        apply(&mut term, &r.render(parser.screen(), &overlays, None));
        assert_eq!(
            term.screen().cell(0, 0).map(vt100::Cell::contents),
            Some("Z"),
            "overlay character 'Z' must be painted at (0,0)"
        );
    }

    #[test]
    fn render_with_flagged_overlay_underlines_the_cell() {
        use super::super::prediction::OverlayCell;
        let mut r = Renderer::new(24, 80);
        let mut term = vt100::Parser::new(24, 80, 0);
        let parser = vt100::Parser::new(24, 80, 0);
        let overlays = vec![OverlayCell {
            row: 2,
            col: 5,
            ch: 'F',
            flagged: true,
        }];
        apply(&mut term, &r.render(parser.screen(), &overlays, None));
        let cell = term.screen().cell(2, 5).expect("cell exists");
        assert_eq!(cell.contents(), "F");
        assert!(cell.underline(), "flagged overlay cell must be underlined");
    }

    #[test]
    fn render_with_cursor_override_positions_cursor_at_override() {
        use super::super::prediction::OverlayCursor;
        let mut r = Renderer::new(24, 80);
        let mut term = vt100::Parser::new(24, 80, 0);
        let parser = vt100::Parser::new(24, 80, 0);
        let cursor_override = Some(OverlayCursor { row: 5, col: 10 });
        apply(&mut term, &r.render(parser.screen(), &[], cursor_override));
        assert_eq!(
            term.screen().cursor_position(),
            (5, 10),
            "cursor override must place the cursor at (5,10)"
        );
    }

    #[test]
    fn render_culled_prediction_self_heals() {
        use super::super::prediction::OverlayCell;
        // The server screen shows 'a' at (0,0).
        let mut server = vt100::Parser::new(24, 80, 0);
        server.process(b"a");

        let mut r = Renderer::new(24, 80);
        let mut term = vt100::Parser::new(24, 80, 0);

        // Frame 1: a prediction overlays 'X' over the real 'a'.
        let overlay = vec![OverlayCell {
            row: 0,
            col: 0,
            ch: 'X',
            flagged: false,
        }];
        apply(&mut term, &r.render(server.screen(), &overlay, None));
        assert_eq!(
            term.screen().cell(0, 0).map(vt100::Cell::contents),
            Some("X"),
            "prediction must be visible in frame 1"
        );

        // Frame 2: the prediction is culled (no overlays) — the real cell must
        // be repainted with no leftover predicted glyph.
        apply(&mut term, &r.render(server.screen(), &[], None));
        assert_eq!(
            term.screen().cell(0, 0).map(vt100::Cell::contents),
            Some("a"),
            "culled prediction must self-heal back to the real cell"
        );
    }

    #[test]
    fn render_no_sgr_bleed_after_flagged_overlay() {
        use super::super::prediction::OverlayCell;
        // Plain (non-underlined) server text "hi" at (0,0)-(0,1).
        let mut server = vt100::Parser::new(24, 80, 0);
        server.process(b"hi");

        let mut r = Renderer::new(24, 80);
        let mut term = vt100::Parser::new(24, 80, 0);

        // A flagged (underlined) prediction at (0,5) must not leave underline
        // state bleeding onto the plain server cells.
        let overlay = vec![OverlayCell {
            row: 0,
            col: 5,
            ch: 'P',
            flagged: true,
        }];
        apply(&mut term, &r.render(server.screen(), &overlay, None));
        assert!(
            !term.screen().cell(0, 0).expect("cell").underline(),
            "plain server cell must not inherit the overlay's underline"
        );
        assert!(
            term.screen().cell(0, 5).expect("cell").underline(),
            "flagged overlay cell should be underlined"
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

    use super::super::prediction::DisplayPreference;

    /// The shared `(emulator, prediction, renderer)` trio the free-function
    /// renderers operate on.
    type RenderTrio = (
        Arc<Mutex<Emulator>>,
        Arc<Mutex<PredictionEngine>>,
        Arc<Mutex<Renderer>>,
    );

    // Build the render trio with a blank 24×80 screen.
    fn render_trio() -> RenderTrio {
        (
            Arc::new(Mutex::new(Emulator::new(24, 80))),
            Arc::new(Mutex::new(PredictionEngine::new(DisplayPreference::Always))),
            Arc::new(Mutex::new(Renderer::new(24, 80))),
        )
    }

    #[test]
    fn render_server_update_paints_emulator_screen() {
        let (emulator, prediction, renderer) = render_trio();
        emulator.lock().unwrap().process(b"server text");
        let mut term = vt100::Parser::new(24, 80, 0);
        apply(
            &mut term,
            &render_server_update(&emulator, &prediction, &renderer, true),
        );
        assert_eq!(
            term.screen().cell(0, 0).map(vt100::Cell::contents),
            Some("s"),
            "server screen content must be rendered to the terminal"
        );
    }

    #[test]
    fn render_server_update_culls_stale_predictions() {
        let (emulator, prediction, renderer) = render_trio();
        // The emulator already shows 'a' at (0,0); register a prediction that
        // the server screen contradicts so cull must discard it.
        emulator.lock().unwrap().process(b"a");
        {
            let emu = emulator.lock().unwrap();
            let mut pred = prediction.lock().unwrap();
            pred.new_user_byte(b'Z', emu.screen());
        }
        let mut term = vt100::Parser::new(24, 80, 0);
        apply(
            &mut term,
            &render_server_update(&emulator, &prediction, &renderer, true),
        );
        assert_eq!(
            term.screen().cell(0, 0).map(vt100::Cell::contents),
            Some("a"),
            "a prediction the server screen contradicts must be culled, leaving the real cell"
        );
    }

    #[test]
    fn render_server_update_without_predictions_skips_overlays() {
        let (emulator, prediction, renderer) = render_trio();
        emulator.lock().unwrap().process(b"hello");
        // Stash a prediction that would change the display if applied.
        {
            let emu = emulator.lock().unwrap();
            let mut pred = prediction.lock().unwrap();
            pred.new_user_byte(b'X', emu.screen());
        }
        let mut term = vt100::Parser::new(24, 80, 0);
        // with_predictions = false must ignore the pending prediction entirely.
        apply(
            &mut term,
            &render_server_update(&emulator, &prediction, &renderer, false),
        );
        assert_eq!(
            term.screen().cell(0, 0).map(vt100::Cell::contents),
            Some("h"),
            "with_predictions=false must render only the raw server screen"
        );
    }

    #[test]
    fn render_prediction_update_paints_keystroke_once_confirmed() {
        let (emulator, prediction, renderer) = render_trio();
        // Prime the prediction engine with the terminal dimensions so the first
        // confirming cull doesn't reset everything.
        {
            let emu = emulator.lock().unwrap();
            prediction.lock().unwrap().cull(emu.screen());
        }
        let mut term = vt100::Parser::new(24, 80, 0);

        // Type 'k' at (0,0): a fresh prediction is tentative and not yet shown.
        apply(
            &mut term,
            &render_prediction_update(&emulator, &prediction, &renderer, b"k"),
        );
        assert_eq!(
            term.screen().cell(0, 0).map(vt100::Cell::contents),
            Some(""),
            "a fresh (tentative) prediction must not be painted yet"
        );

        // A server update advances the real cursor to the predicted column
        // (0,1) without echoing the keystroke yet — this confirms the epoch.
        emulator.lock().unwrap().process(b"\x1b[1;2H");
        apply(
            &mut term,
            &render_server_update(&emulator, &prediction, &renderer, true),
        );
        assert_eq!(
            term.screen().cell(0, 0).map(vt100::Cell::contents),
            Some("k"),
            "once the epoch is confirmed the predicted keystroke must be painted"
        );
    }

    #[test]
    fn render_prediction_update_does_not_cull_between_keystrokes() {
        let (emulator, prediction, renderer) = render_trio();
        {
            let emu = emulator.lock().unwrap();
            prediction.lock().unwrap().cull(emu.screen());
        }
        let mut term = vt100::Parser::new(24, 80, 0);

        // Two predicted bytes in sequence; neither call culls, so both
        // predictions survive to be confirmed together.
        apply(
            &mut term,
            &render_prediction_update(&emulator, &prediction, &renderer, b"a"),
        );
        apply(
            &mut term,
            &render_prediction_update(&emulator, &prediction, &renderer, b"b"),
        );

        // Confirm both predictions: real cursor advances to (0,2).
        emulator.lock().unwrap().process(b"\x1b[1;3H");
        apply(
            &mut term,
            &render_server_update(&emulator, &prediction, &renderer, true),
        );
        assert_eq!(
            term.screen().cell(0, 0).map(vt100::Cell::contents),
            Some("a"),
            "first prediction must survive the second keystroke"
        );
        assert_eq!(
            term.screen().cell(0, 1).map(vt100::Cell::contents),
            Some("b"),
            "second prediction must be appended alongside the first"
        );
    }
}
