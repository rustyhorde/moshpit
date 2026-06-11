// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

//! Client-side predictive local echo, modelled on Mosh's `PredictionEngine`
//! and `OverlayManager` (terminaloverlay.h / terminaloverlay.cc).
//!
//! # How it works
//!
//! When the user types a key the prediction engine *speculatively* records
//! what the terminal screen should look like after that keystroke is echoed,
//! without touching the real screen yet.  These speculative records are called
//! *overlays*.  When the server later sends back bytes that confirm the
//! prediction (i.e. the screen now matches what we predicted), the overlay is
//! confirmed and removed.  If the server contradicts a prediction the overlay
//! is invalidated and discarded.
//!
//! Predictions are gated on measured round-trip time so that they are only
//! shown when they actually improve perceived latency:
//!
//! | `DisplayPreference` | Behaviour |
//! |---------------------|-----------|
//! | `Adaptive` (default)| Show when SRTT > 30 ms or an unconfirmed prediction is older than 250 ms |
//! | `Always`            | Always show |
//! | `Never`             | Disable (raw passthrough) |
//!
//! Predictions that remain unconfirmed for >5 s are *flagged* with an
//! underline so the user knows the display may be stale.

use std::time::Instant;

use serde::{Deserialize, Serialize};

/// How aggressively to display local-echo predictions.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DisplayPreference {
    /// Show predictions only when the link is slow (RTT > 30 ms) or a
    /// prediction glitch is detected.
    #[default]
    Adaptive,
    /// Always show predictions immediately.
    Always,
    /// Never show predictions; behave like a raw passthrough.
    Never,
}

// ── timing thresholds (milliseconds) ────────────────────────────────────────
/// Below this SRTT, suppress adaptive predictions (link is fast enough).
const SRTT_TRIGGER_LOW_MS: u64 = 20;
/// Above this SRTT, show adaptive predictions.
const SRTT_TRIGGER_HIGH_MS: u64 = 30;
/// Below this SRTT, stop underlining predictions.
const FLAG_TRIGGER_LOW_MS: u64 = 50;
/// Above this SRTT, start underlining predictions.
const FLAG_TRIGGER_HIGH_MS: u64 = 80;
/// A prediction outstanding longer than this (ms) triggers the glitch counter.
const GLITCH_THRESHOLD_MS: u64 = 250;
/// Consecutive non-glitch confirmations needed to clear the glitch trigger.
const GLITCH_REPAIR_COUNT: u32 = 10;
/// Minimum interval (ms) between non-glitch confirmations that count toward repair.
const GLITCH_REPAIR_INTERVAL_MS: u64 = 150;
/// A prediction outstanding longer than this (ms) is underlined unconditionally.
const GLITCH_FLAG_THRESHOLD_MS: u64 = 5_000;

// ── overlay types ────────────────────────────────────────────────────────────

/// A single speculative cell on the local screen.
#[derive(Clone, Debug)]
pub(crate) struct ConditionalOverlayCell {
    /// Screen column (0-based).
    pub(crate) col: u16,
    /// The character we predict will appear here.
    pub(crate) replacement: char,
    /// True when we don't know what will appear (e.g. after ESC).
    #[allow(dead_code)]
    pub(crate) unknown: bool,
    /// Contents that were already on screen when we predicted.
    pub(crate) original: String,
    /// The prediction is only shown once `confirmed_epoch >= tentative_until_epoch`.
    pub(crate) tentative_until_epoch: u64,
    /// The frame number after which the prediction expires if unconfirmed.
    #[allow(dead_code)]
    pub(crate) expiration_frame: u64,
    /// Wall-clock time when this prediction was recorded.
    pub(crate) prediction_time: Instant,
    /// Whether the overlay is active.
    pub(crate) active: bool,
}

impl ConditionalOverlayCell {
    fn new(col: u16, replacement: char, tentative_until_epoch: u64) -> Self {
        Self {
            col,
            replacement,
            unknown: false,
            original: String::new(),
            tentative_until_epoch,
            expiration_frame: u64::MAX,
            prediction_time: Instant::now(),
            active: true,
        }
    }

    /// Returns `true` if the prediction is still tentative (unconfirmed epoch).
    fn tentative(&self, confirmed_epoch: u64) -> bool {
        self.tentative_until_epoch > confirmed_epoch
    }

    /// Returns `true` if this prediction has been outstanding long enough to
    /// warrant an underline ("flagging").
    fn is_flagged(&self) -> bool {
        self.prediction_time.elapsed().as_millis() > u128::from(GLITCH_FLAG_THRESHOLD_MS)
    }
}

/// A row of speculative cell overlays.
#[derive(Clone, Debug)]
pub(crate) struct ConditionalOverlayRow {
    /// Screen row (0-based).
    pub(crate) row: u16,
    pub(crate) cells: Vec<ConditionalOverlayCell>,
}

impl ConditionalOverlayRow {
    fn new(row: u16) -> Self {
        Self {
            row,
            cells: Vec::new(),
        }
    }

    /// Return the cell overlay for `col`, inserting a blank one if absent.
    fn cell_mut(&mut self, col: u16, tentative_epoch: u64) -> &mut ConditionalOverlayCell {
        if let Some(pos) = self.cells.iter().position(|c| c.col == col) {
            return &mut self.cells[pos];
        }
        self.cells
            .push(ConditionalOverlayCell::new(col, ' ', tentative_epoch));
        self.cells.last_mut().expect("vec is empty after push")
    }
}

/// A speculative cursor position overlay.
#[derive(Clone, Debug)]
pub(crate) struct ConditionalCursorMove {
    pub(crate) row: u16,
    pub(crate) col: u16,
    pub(crate) tentative_until_epoch: u64,
    pub(crate) prediction_time: Instant,
}

impl ConditionalCursorMove {
    fn new(row: u16, col: u16, tentative_until_epoch: u64) -> Self {
        Self {
            row,
            col,
            tentative_until_epoch,
            prediction_time: Instant::now(),
        }
    }

    fn tentative(&self, confirmed_epoch: u64) -> bool {
        self.tentative_until_epoch > confirmed_epoch
    }
}

// ── a single rendered prediction overlay ────────────────────────────────────

/// A cell to be painted on top of the real screen when rendering.
#[derive(Clone, Copy, Debug)]
pub struct OverlayCell {
    /// Screen row (0-based).
    pub row: u16,
    /// Screen column (0-based).
    pub col: u16,
    /// The character to display.
    pub ch: char,
    /// If `true`, render with an underline to signal an unconfirmed prediction.
    pub flagged: bool,
}

/// Predicted cursor position to be applied after rendering overlay cells.
#[derive(Clone, Copy, Debug)]
pub struct OverlayCursor {
    /// Screen row (0-based).
    pub row: u16,
    /// Screen column (0-based).
    pub col: u16,
}

// ── main engine ─────────────────────────────────────────────────────────────

/// Local-echo prediction engine.
#[derive(Debug)]
pub struct PredictionEngine {
    overlay_rows: Vec<ConditionalOverlayRow>,
    cursors: Vec<ConditionalCursorMove>,

    /// Current prediction epoch.  Incremented on `become_tentative()`.
    prediction_epoch: u64,
    /// Highest epoch for which a prediction has been confirmed by the server.
    confirmed_epoch: u64,

    /// Whether predictions are currently underlined on the display.
    flagging: bool,
    /// Whether the measured RTT has crossed the high threshold.
    srtt_trigger: bool,
    /// Counts how many predictions have been outstanding > `GLITCH_THRESHOLD_MS`.
    glitch_trigger: u32,

    /// Smoothed RTT in milliseconds (set by the caller from UDP ACK timing).
    send_interval_ms: u64,

    /// The last byte the user typed (used for multi-byte key detection).
    last_byte: u8,

    /// Consecutive "quick" confirmations (< `GLITCH_THRESHOLD_MS`) seen since
    /// last glitch — used to decay the glitch counter.
    glitch_repair_count: u32,
    last_quick_confirmation: Instant,

    display_preference: DisplayPreference,

    /// Last known terminal dimensions; used to detect resize and reset state.
    last_rows: u16,
    last_cols: u16,
}

impl PredictionEngine {
    /// Create a new engine with the given display preference.
    #[must_use]
    pub fn new(display_preference: DisplayPreference) -> Self {
        Self {
            overlay_rows: Vec::new(),
            cursors: Vec::new(),
            prediction_epoch: 1,
            confirmed_epoch: 0,
            flagging: false,
            srtt_trigger: false,
            glitch_trigger: 0,
            send_interval_ms: 0,
            last_byte: 0,
            glitch_repair_count: 0,
            last_quick_confirmation: Instant::now(),
            display_preference,
            last_rows: 0,
            last_cols: 0,
        }
    }

    /// Update the measured RTT; may change whether predictions are shown.
    pub fn set_send_interval(&mut self, ms: u64) {
        self.send_interval_ms = ms;
        match ms {
            ms if ms > FLAG_TRIGGER_HIGH_MS => self.flagging = true,
            ms if ms <= FLAG_TRIGGER_LOW_MS => self.flagging = false,
            _ => {}
        }
        match ms {
            ms if ms > SRTT_TRIGGER_HIGH_MS => self.srtt_trigger = true,
            ms if ms <= SRTT_TRIGGER_LOW_MS => self.srtt_trigger = false,
            _ => {}
        }
    }

    /// Returns `true` when prediction overlays should be shown.
    #[must_use]
    pub fn is_active(&self) -> bool {
        match self.display_preference {
            DisplayPreference::Never => false,
            DisplayPreference::Always => true,
            DisplayPreference::Adaptive => self.srtt_trigger || self.glitch_trigger > 0,
        }
    }

    // ── row / cursor helpers ─────────────────────────────────────────────

    fn get_or_make_row(&mut self, row: u16) -> &mut ConditionalOverlayRow {
        if let Some(pos) = self.overlay_rows.iter().position(|r| r.row == row) {
            return &mut self.overlay_rows[pos];
        }
        self.overlay_rows.push(ConditionalOverlayRow::new(row));
        self.overlay_rows
            .last_mut()
            .expect("vec is empty after push")
    }

    fn cursor(&self) -> Option<&ConditionalCursorMove> {
        self.cursors.last()
    }

    /// Predicted cursor (row, col), or `None` if no active cursor prediction.
    #[must_use]
    pub fn predicted_cursor(&self) -> Option<OverlayCursor> {
        self.cursors.last().map(|c| OverlayCursor {
            row: c.row,
            col: c.col,
        })
    }

    // ── epoch management ─────────────────────────────────────────────────

    /// Start a new tentative epoch.  New predictions will not be shown until
    /// at least one is confirmed by the server.
    fn become_tentative(&mut self) {
        self.prediction_epoch += 1;
    }

    /// Handle a carriage return (CR, `\r`) from user input.
    ///
    /// Moves the predicted cursor to column 0.  If the cursor is already on
    /// the last row, scroll cannot be predicted: instead every cell on that
    /// row is tentatively predicted blank (matching what the terminal will show
    /// after the scroll) and the cursor stays on the last row.  Otherwise the
    /// cursor moves down one row.
    ///
    /// Mirrors mosh's `PredictionEngine::newline_carriage_return`.
    fn newline_carriage_return(&mut self, screen_cursor: (u16, u16), rows: u16, cols: u16) {
        let (pred_row, _) = self.cursor().map_or(screen_cursor, |c| (c.row, c.col));
        let epoch = self.prediction_epoch;

        if pred_row + 1 >= rows {
            // On the last row: we cannot predict what happens after a scroll,
            // so predict all cells on this row as blank and keep the cursor at
            // (last_row, 0).  The blank predictions will be confirmed or killed
            // quickly once the server sends the new prompt.
            let row_entry = self.get_or_make_row(pred_row);
            for col in 0..cols {
                let cell = row_entry.cell_mut(col, epoch);
                cell.replacement = ' ';
                cell.active = true;
                cell.tentative_until_epoch = epoch;
                cell.prediction_time = Instant::now();
            }
            self.push_cursor(pred_row, 0, epoch);
        } else {
            self.push_cursor(pred_row + 1, 0, epoch);
        }
    }

    fn kill_epoch(&mut self, epoch: u64, screen: &vt100::Screen) {
        // Remove cursor predictions from that epoch
        self.cursors
            .retain(|c| c.tentative_until_epoch != epoch + 1);
        // Remove cell predictions from that epoch
        for row in &mut self.overlay_rows {
            row.cells.retain(|c| c.tentative_until_epoch != epoch + 1);
        }
        self.overlay_rows.retain(|r| !r.cells.is_empty());

        // Roll back the confirmed epoch if necessary
        if self.confirmed_epoch > epoch {
            self.confirmed_epoch = epoch;
        }
        let _ = screen; // may be used for future validity checks
    }

    // ── public API ───────────────────────────────────────────────────────

    /// Record a speculative prediction for a newly typed byte.
    ///
    /// `screen` is the current terminal state (before the server has echoed
    /// the keystroke).
    pub fn new_user_byte(&mut self, byte: u8, screen: &vt100::Screen) {
        let (rows, cols) = screen.size();
        if rows == 0 || cols == 0 {
            return;
        }
        let (cursor_row, cursor_col) = screen.cursor_position();

        // Determine predicted cursor start position (use our last cursor
        // prediction if one exists, otherwise use the real cursor).
        let (pred_row, pred_col) = self
            .cursor()
            .map_or((cursor_row, cursor_col), |c| (c.row, c.col));

        match byte {
            // ── printable ASCII ──────────────────────────────────────────
            0x20..=0x7e => {
                // Predict the character appearing at the current cursor.
                let epoch = self.prediction_epoch;
                let original = screen
                    .cell(pred_row, pred_col)
                    .map(vt100::Cell::contents)
                    .unwrap_or_default()
                    .to_owned();

                let row_entry = self.get_or_make_row(pred_row);
                let cell = row_entry.cell_mut(pred_col, epoch);
                cell.replacement = byte as char;
                cell.original = original;
                cell.active = true;
                cell.tentative_until_epoch = epoch;
                cell.prediction_time = Instant::now();

                // Advance the predicted cursor.
                if pred_col + 1 < cols {
                    self.push_cursor(pred_row, pred_col + 1, epoch);
                } else {
                    // Prediction at the last column is ambiguous (emacs wraps,
                    // shells may not).  Match mosh: become tentative and move
                    // the cursor prediction to the start of the next line.
                    self.become_tentative();
                    self.newline_carriage_return((cursor_row, cursor_col), rows, cols);
                }
            }

            // ── backspace (0x7f DEL or 0x08 BS) ─────────────────────────
            0x7f | 0x08 => {
                if pred_col == 0 {
                    self.become_tentative();
                    return;
                }
                let new_col = pred_col - 1;
                // Predict a space at the previous position.
                let epoch = self.prediction_epoch;
                let original = screen
                    .cell(pred_row, new_col)
                    .map(vt100::Cell::contents)
                    .unwrap_or_default()
                    .to_owned();
                let row_entry = self.get_or_make_row(pred_row);
                let cell = row_entry.cell_mut(new_col, epoch);
                cell.replacement = ' ';
                cell.original = original;
                cell.active = true;
                cell.tentative_until_epoch = epoch;
                cell.prediction_time = Instant::now();

                self.push_cursor(pred_row, new_col, epoch);
            }

            // ── left arrow (ESC [ D) ─────────────────────────────────────
            0x1b if self.last_byte == b'[' => {
                // We only get here if last_byte was '['; not reliable without a
                // full input parser, so treat as tentative.
                self.become_tentative();
            }

            // ── carriage return: move predicted cursor to next line ───────
            // Match mosh exactly: become_tentative() then newline_carriage_return().
            // This moves the cursor prediction to (row+1, 0), or for the last
            // row predicts a blank row so that post-scroll overlay cells are
            // correct regardless of whether the terminal scrolled.
            b'\r' => {
                self.become_tentative();
                self.newline_carriage_return((cursor_row, cursor_col), rows, cols);
            }

            // ── newline / ESC / other control characters ─────────────────
            b'\n' | 0x00..=0x1f | 0x80..=0xff => {
                self.become_tentative();
            }
        }

        self.last_byte = byte;
    }

    fn push_cursor(&mut self, row: u16, col: u16, epoch: u64) {
        self.cursors
            .push(ConditionalCursorMove::new(row, col, epoch));
        // Keep the list bounded.
        if self.cursors.len() > 128 {
            let _ = self.cursors.remove(0);
        }
    }

    /// Reconcile pending predictions against the current server-driven screen.
    ///
    /// Confirms predictions that match and invalidates those that don't.
    /// Call this after every batch of bytes received from the server.
    pub fn cull(&mut self, screen: &vt100::Screen) {
        // ── terminal resize → full reset (mirrors mosh) ──────────────────
        let (rows, cols) = screen.size();
        if rows != self.last_rows || cols != self.last_cols {
            self.last_rows = rows;
            self.last_cols = cols;
            self.reset();
            return;
        }

        // ── cursor confirmation ──────────────────────────────────────────
        let (real_row, real_col) = screen.cursor_position();

        // Walk forward through cursor predictions; confirm the last one that
        // matches the current cursor position.
        let mut confirmed_cursor_epoch: Option<u64> = None;
        for cursor in &self.cursors {
            if cursor.row == real_row && cursor.col == real_col {
                confirmed_cursor_epoch = Some(cursor.tentative_until_epoch);
            }
        }
        if let Some(epoch) = confirmed_cursor_epoch
            && epoch > self.confirmed_epoch
        {
            self.confirmed_epoch = epoch;
            // Timing-based glitch tracking
            self.update_glitch_tracking();
        }

        // ── cell confirmation ────────────────────────────────────────────
        let mut epochs_to_kill: Vec<u64> = Vec::new();
        self.overlay_rows.retain_mut(|row_entry| {
            row_entry.cells.retain_mut(|cell| {
                if !cell.active {
                    return false;
                }
                // Don't evaluate tentative cells yet.
                if cell.tentative(self.confirmed_epoch) {
                    return true;
                }
                // Compare to actual screen content.
                let actual = screen
                    .cell(row_entry.row, cell.col)
                    .map(vt100::Cell::contents)
                    .unwrap_or_default();
                let predicted = cell.replacement.to_string();

                if actual == predicted {
                    // Confirmed!  Remove the overlay — the real screen already
                    // shows what we predicted.
                    false
                } else if actual == cell.original {
                    // Server still shows the pre-prediction content.  This cell is
                    // already non-tentative, so its epoch has been confirmed.  If a
                    // *strictly later* epoch has been confirmed, the server has
                    // processed past this keystroke without ever echoing it (e.g. a
                    // no-echo password field committed on Enter) → drop the prediction
                    // so it never flashes.  If only this cell's own epoch is confirmed,
                    // the echo may still be in flight — keep waiting.
                    self.confirmed_epoch <= cell.tentative_until_epoch
                } else {
                    // Server shows something different from both the prediction
                    // and the pre-prediction content → invalidate this epoch.
                    epochs_to_kill.push(cell.tentative_until_epoch.saturating_sub(1));
                    false
                }
            });
            !row_entry.cells.is_empty()
        });
        for epoch in epochs_to_kill {
            self.kill_epoch(epoch, screen);
        }

        // ── cursor validity check (mirrors mosh) ────────────────────────
        // If the most-recent cursor prediction has been confirmed by the epoch
        // counter but does NOT match the real cursor position, the prediction
        // state is stale (e.g. the shell rewrote the prompt).  Reset
        // everything, exactly as mosh does when cursor validity ==
        // IncorrectOrExpired.
        if let Some(cursor) = self.cursors.last()
            && !cursor.tentative(self.confirmed_epoch)
            && (cursor.row != real_row || cursor.col != real_col)
        {
            self.reset();
            return;
        }

        // Prune confirmed cursor predictions.
        self.cursors.retain(|c| !c.tentative(self.confirmed_epoch));
    }

    fn update_glitch_tracking(&mut self) {
        // Check how long the most-recently-confirmed prediction was outstanding
        // by looking at the oldest surviving cursor prediction time.
        let outstanding_ms = self
            .cursors
            .first()
            .map_or(0u128, |c| c.prediction_time.elapsed().as_millis());

        if outstanding_ms > u128::from(GLITCH_THRESHOLD_MS) {
            self.glitch_trigger = self.glitch_trigger.saturating_add(1);
            self.glitch_repair_count = 0;
        } else {
            // Possibly decay the glitch trigger.
            let since_last = self.last_quick_confirmation.elapsed().as_millis();
            if since_last >= u128::from(GLITCH_REPAIR_INTERVAL_MS) {
                self.last_quick_confirmation = Instant::now();
                self.glitch_repair_count += 1;
                if self.glitch_repair_count >= GLITCH_REPAIR_COUNT {
                    self.glitch_trigger = self.glitch_trigger.saturating_sub(1);
                    self.glitch_repair_count = 0;
                }
            }
        }
    }

    /// Produce the list of overlay cells to paint on top of the server screen,
    /// plus the predicted cursor position (if any).
    ///
    /// Returns `(Vec<OverlayCell>, Option<OverlayCursor>)`.
    #[must_use]
    pub fn apply(&self, screen: &vt100::Screen) -> (Vec<OverlayCell>, Option<OverlayCursor>) {
        if !self.is_active() {
            return (Vec::new(), None);
        }

        let mut cells = Vec::new();
        for row_entry in &self.overlay_rows {
            for cell in &row_entry.cells {
                if !cell.active {
                    continue;
                }
                if cell.tentative(self.confirmed_epoch) {
                    continue;
                }
                // Only paint if the cell is still different from the real screen.
                let actual = screen
                    .cell(row_entry.row, cell.col)
                    .map(vt100::Cell::contents)
                    .unwrap_or_default();
                if actual == cell.replacement.to_string() {
                    continue;
                }
                cells.push(OverlayCell {
                    row: row_entry.row,
                    col: cell.col,
                    ch: cell.replacement,
                    flagged: self.flagging || cell.is_flagged(),
                });
            }
        }

        let cursor = self.cursors.last().and_then(|c| {
            if c.tentative(self.confirmed_epoch) {
                None
            } else {
                Some(OverlayCursor {
                    row: c.row,
                    col: c.col,
                })
            }
        });

        (cells, cursor)
    }

    /// Reset all prediction state (e.g. on session reconnect).
    pub fn reset(&mut self) {
        self.overlay_rows.clear();
        self.cursors.clear();
        self.prediction_epoch = 1;
        self.confirmed_epoch = 0;
        self.glitch_trigger = 0;
        self.glitch_repair_count = 0;
        self.last_byte = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::{DisplayPreference, PredictionEngine};

    fn make_screen(rows: u16, cols: u16, content: &[u8]) -> vt100::Parser {
        let mut p = vt100::Parser::new(rows, cols, 0);
        if !content.is_empty() {
            p.process(content);
        }
        p
    }

    /// Printable ASCII branch: `Cell::contents()` result (`.to_owned()`) is stored in
    /// `cell.original` and must be a valid `String`.
    #[test]
    fn new_user_byte_printable_stores_original_as_string() -> anyhow::Result<()> {
        let mut engine = PredictionEngine::new(DisplayPreference::Always);
        // Write 'X' at (0,0), then home the cursor back to (0,0) so the
        // prediction lands on the cell that contains 'X'.
        let parser = make_screen(24, 80, b"X\x1b[H");
        let screen = parser.screen();
        assert_eq!(screen.cursor_position(), (0, 0));

        // Type 'a' — should predict 'a' at (0,0) and store original = "X".
        engine.new_user_byte(b'a', screen);

        let row = engine
            .overlay_rows
            .iter()
            .find(|r| r.row == 0)
            .ok_or_else(|| anyhow::anyhow!("no overlay row for row 0"))?;
        let cell = row
            .cells
            .iter()
            .find(|c| c.col == 0)
            .ok_or_else(|| anyhow::anyhow!("no overlay cell for col 0"))?;
        assert_eq!(cell.replacement, 'a');
        assert_eq!(cell.original, "X");
        Ok(())
    }

    /// Backspace branch: `Cell::contents()` result (`.to_owned()`) is stored in
    /// `cell.original` for the cell being blanked.
    #[test]
    fn new_user_byte_backspace_stores_original_as_string() -> anyhow::Result<()> {
        let mut engine = PredictionEngine::new(DisplayPreference::Always);
        // Write 'X' at (0,0) and home the cursor to (0,0).
        let parser = make_screen(24, 80, b"X\x1b[H");
        let screen = parser.screen();
        assert_eq!(screen.cursor_position(), (0, 0));

        // Type 'a': predicted cursor advances to (0,1).
        engine.new_user_byte(b'a', screen);

        // Backspace: predicted cursor is at (0,1), so new_col = 0.
        // original = screen.cell(0, 0) = "X".
        engine.new_user_byte(0x7f, screen);

        let row = engine
            .overlay_rows
            .iter()
            .find(|r| r.row == 0)
            .ok_or_else(|| anyhow::anyhow!("no overlay row for row 0"))?;
        let cell = row
            .cells
            .iter()
            .find(|c| c.col == 0 && c.replacement == ' ')
            .ok_or_else(|| anyhow::anyhow!("no overlay cell for backspace at col 0"))?;
        assert_eq!(cell.original, "X");
        Ok(())
    }

    #[test]
    fn display_preference_default_is_adaptive() {
        assert_eq!(DisplayPreference::default(), DisplayPreference::Adaptive);
    }

    #[test]
    fn is_active_always_returns_true() {
        let engine = PredictionEngine::new(DisplayPreference::Always);
        assert!(engine.is_active());
    }

    #[test]
    fn is_active_never_returns_false() {
        let engine = PredictionEngine::new(DisplayPreference::Never);
        assert!(!engine.is_active());
    }

    #[test]
    fn set_send_interval_above_high_threshold_activates_srtt_trigger() {
        let mut engine = PredictionEngine::new(DisplayPreference::Adaptive);
        assert!(!engine.is_active());
        engine.set_send_interval(31); // > SRTT_TRIGGER_HIGH_MS=30
        assert!(engine.is_active());
    }

    #[test]
    fn apply_never_returns_empty() {
        let engine = PredictionEngine::new(DisplayPreference::Never);
        let parser = make_screen(24, 80, b"");
        let (cells, cursor) = engine.apply(parser.screen());
        assert!(cells.is_empty());
        assert!(cursor.is_none());
    }

    // ── Phase 2: extended PredictionEngine branch tests ────────────────────────

    #[test]
    fn apply_always_with_prediction_returns_overlay() {
        let mut engine = PredictionEngine::new(DisplayPreference::Always);
        let parser_blank = make_screen(24, 80, b"");
        // Prime the engine so cull knows the terminal dimensions
        // (last_rows/last_cols default to 0; without priming the first cull resets everything).
        engine.cull(parser_blank.screen());
        // Cursor starts at (0,0); after typing 'z' the predicted cursor is at (0,1)
        engine.new_user_byte(b'z', parser_blank.screen());
        // Confirm the prediction by culling with a same-size screen whose cursor is at (0,1).
        // ESC[1;2H positions cursor at row 0, col 1 (0-based)
        let parser_cursor_at_1 = make_screen(24, 80, b"\x1b[1;2H");
        engine.cull(parser_cursor_at_1.screen());
        // Now apply against the blank screen — 'z' cell must appear in the overlay
        let (cells, _cursor) = engine.apply(parser_blank.screen());
        assert!(
            !cells.is_empty(),
            "expected at least one overlay cell after typing 'z'"
        );
        let z_cell = cells.iter().find(|c| c.ch == 'z');
        assert!(z_cell.is_some(), "expected 'z' overlay cell");
    }

    #[test]
    fn apply_always_cursor_overlay_present() {
        let mut engine = PredictionEngine::new(DisplayPreference::Always);
        let parser_blank = make_screen(24, 80, b"");
        // Prime dimensions
        engine.cull(parser_blank.screen());
        engine.new_user_byte(b'a', parser_blank.screen());
        // Confirm prediction: cursor at predicted position (0,1)
        let parser_cursor_at_1 = make_screen(24, 80, b"\x1b[1;2H");
        engine.cull(parser_cursor_at_1.screen());
        let (_cells, cursor) = engine.apply(parser_blank.screen());
        assert!(
            cursor.is_some(),
            "expected cursor overlay after typing a key"
        );
    }

    #[test]
    fn reset_clears_all_overlays() {
        let mut engine = PredictionEngine::new(DisplayPreference::Always);
        let parser = make_screen(24, 80, b"");
        engine.new_user_byte(b'a', parser.screen());
        engine.new_user_byte(b'b', parser.screen());
        engine.reset();
        let (cells, cursor) = engine.apply(parser.screen());
        assert!(cells.is_empty(), "reset must clear all cell overlays");
        assert!(cursor.is_none(), "reset must clear cursor overlay");
    }

    #[test]
    fn cull_confirmed_prediction_removed() {
        let mut engine = PredictionEngine::new(DisplayPreference::Always);
        let parser_before = make_screen(24, 80, b"");
        // Prime engine dimensions first (avoids spurious resize-reset on first cull)
        engine.cull(parser_before.screen());
        // Screen is blank; predict 'a' at (0,0). After typing, cursor will be at (0,1).
        engine.new_user_byte(b'a', parser_before.screen());
        // Cull with a screen that shows 'a' at (0,0) and cursor at (0,1).
        // vt100: after processing b"a" cursor is at (0,1).
        let parser_after = make_screen(24, 80, b"a");
        engine.cull(parser_after.screen());
        // Confirmed 'a' cell must be removed from the overlay
        let (cells, _) = engine.apply(parser_after.screen());
        let a_cell = cells.iter().find(|c| c.ch == 'a');
        assert!(
            a_cell.is_none(),
            "confirmed prediction for 'a' must be culled"
        );
    }

    /// Regression: typing into a no-echo (password) field and pressing Enter must
    /// not flash the typed characters.  The keystrokes are predicted in epoch 1 but
    /// never echoed; pressing Enter advances the confirmed epoch (the cursor moves to
    /// the next line), which retroactively makes the epoch-1 cells non-tentative.
    /// They must be dropped — not painted — because a strictly later epoch is confirmed.
    #[test]
    fn enter_does_not_flash_unechoed_password_predictions() {
        let mut engine = PredictionEngine::new(DisplayPreference::Always);
        let blank = make_screen(24, 80, b"");
        // Prime dimensions so the first real cull doesn't reset everything.
        engine.cull(blank.screen());

        // Type a "password" at (0,0). No intervening cull → the server never echoes,
        // so confirmed_epoch stays 0 and these epoch-1 cells stay tentative/hidden.
        for &b in b"secret" {
            engine.new_user_byte(b, blank.screen());
        }
        // Press Enter: become_tentative() (→ epoch 2) and predict the cursor at (1,0).
        engine.new_user_byte(b'\r', blank.screen());

        // Server response to Enter: row 0 still blank (password never echoed), cursor
        // moved to (1,0) — confirming the epoch-2 newline cursor prediction.
        let after_enter = make_screen(24, 80, b"\x1b[2;1H");
        assert_eq!(after_enter.screen().cursor_position(), (1, 0));
        engine.cull(after_enter.screen());

        // The password characters must never appear in the overlay.
        let (cells, _cursor) = engine.apply(after_enter.screen());
        assert!(
            cells.is_empty(),
            "no-echo password predictions must not flash after Enter, got: {cells:?}"
        );
    }

    /// Guard against over-culling: when only a prediction's *own* epoch is confirmed
    /// (normal in-flight typing where the server echoes one char at a time), later
    /// same-epoch predictions whose echo hasn't arrived yet must be kept and shown.
    #[test]
    fn inflight_prediction_survives_same_epoch_confirmation() {
        let mut engine = PredictionEngine::new(DisplayPreference::Always);
        let blank = make_screen(24, 80, b"");
        engine.cull(blank.screen());

        // Type "ab" — both in epoch 1; predicted cursors at (0,1) then (0,2).
        engine.new_user_byte(b'a', blank.screen());
        engine.new_user_byte(b'b', blank.screen());

        // Server screen confirms epoch 1 via the *final* cursor at (0,2) (so the
        // cursor-validity check doesn't reset), shows 'a' echoed, but leaves (0,1)
        // still blank — i.e. the 'b' echo is genuinely still in flight.
        let inflight = make_screen(24, 80, b"a\x1b[1;3H");
        assert_eq!(inflight.screen().cursor_position(), (0, 2));
        engine.cull(inflight.screen());

        // 'b' shares the confirmed epoch (1 <= 1) → it must still be shown, not culled.
        let (cells, _cursor) = engine.apply(inflight.screen());
        assert!(
            cells.iter().any(|c| c.ch == 'b'),
            "in-flight same-epoch prediction 'b' must survive, got: {cells:?}"
        );
    }

    #[test]
    fn new_user_byte_esc_marks_unknown() {
        let mut engine = PredictionEngine::new(DisplayPreference::Always);
        let parser = make_screen(24, 80, b"");
        // ESC should trigger the unknown/escape branch in new_user_byte
        engine.new_user_byte(0x1b, parser.screen());
        // After ESC the engine resets (no active predictions visible)
        let (cells, _cursor) = engine.apply(parser.screen());
        assert!(cells.is_empty(), "ESC should clear/reset predictions");
    }

    #[test]
    fn set_send_interval_below_low_threshold_deactivates_adaptive() {
        let mut engine = PredictionEngine::new(DisplayPreference::Adaptive);
        // Activate first
        engine.set_send_interval(31);
        assert!(engine.is_active());
        // Then drop below low threshold
        engine.set_send_interval(10); // < SRTT_TRIGGER_LOW_MS=20
        assert!(!engine.is_active());
    }

    #[test]
    fn is_active_adaptive_starts_inactive() {
        let engine = PredictionEngine::new(DisplayPreference::Adaptive);
        assert!(
            !engine.is_active(),
            "adaptive must start inactive (no RTT data)"
        );
    }
}
