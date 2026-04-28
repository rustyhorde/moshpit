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
        self.cells.last_mut().unwrap()
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
        self.overlay_rows.last_mut().unwrap()
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
                    .unwrap_or_default();

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
                    .unwrap_or_default();
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
                    // Server hasn't processed our keystroke yet — keep waiting.
                    true
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
