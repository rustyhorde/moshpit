// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

//! Transport-agnostic client state for Mosh-style `StateSync` diff delivery.
//!
//! [`StateSyncClient`] holds the per-session ack baseline and `StateChunk`
//! reassembly buffer, and applies incoming `ScreenStateCompressed` /
//! `StateSyncDiff` / `StateChunk` frames to the shared emulator + renderer.  It
//! is used by [`TcpTransportReader`](crate::TcpTransportReader); the UDP reader
//! carries equivalent inline logic in its receive loop.

use std::{
    mem::take,
    sync::{PoisonError, atomic::Ordering},
};

use tokio::sync::mpsc::Sender;
use tracing::{error, warn};

use crate::{
    EncryptedFrame, render_server_update,
    udp::reader::{ClientRenderCtx, apply_full_state_rendering, decode_all_capped},
};

/// Number of consecutive `base_id` mismatches before the client gives up on
/// incremental diffs and requests a fresh full-state push.
const STATESYNC_MISMATCH_LIMIT: u32 = 3;

/// Client-side `StateSync` bookkeeping shared across data-channel transports.
#[derive(Debug, Default)]
pub(crate) struct StateSyncClient {
    /// `contents_formatted()` snapshot of the client's screen at the point the
    /// last full-state push or `StateSyncDiff` was applied.  Empty before any
    /// state is applied.
    ack_state: Vec<u8>,
    /// `diff_id` of the last successfully applied state.  Zero before any diff
    /// is applied; used to validate incoming `base_id` fields.
    ack_state_seq: u64,
    /// Consecutive `StateSyncDiff` frames discarded due to `base_id` mismatch.
    statesync_mismatch_count: u32,
    /// True once the first complete full-state push has been processed.  Guards
    /// diffs from being applied to a blank initial screen.
    initial_state_received: bool,
    /// Total chunk count for the in-progress `StateChunk` assembly.  Zero = idle.
    pending_chunk_total: u16,
    /// Next expected `seq` value for the in-progress `StateChunk` assembly.
    pending_chunk_seq: u16,
    /// Accumulated payload bytes from the in-progress `StateChunk` assembly.
    pending_chunk_data: Vec<u8>,
}

impl StateSyncClient {
    /// Apply a full-state push (`ScreenState` / `ScreenStateCompressed` payload),
    /// render it, and seed the ack baseline so subsequent diffs apply cleanly.
    ///
    /// Returns the repaint bytes to send to stdout (empty if nothing changed).
    pub(crate) fn apply_full_state(&mut self, payload: &[u8], ctx: &ClientRenderCtx) -> Vec<u8> {
        let repaint = apply_full_state_rendering(
            payload,
            ctx.emulator(),
            ctx.prediction(),
            ctx.renderer(),
            ctx.in_alt_screen(),
        );
        // `apply_full_state_rendering` has replaced the emulator's parser with the
        // reconstructed screen, so read the baseline straight back from it.
        let (mut ack, is_alt) = {
            let emu = ctx
                .emulator()
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            let screen = emu.screen();
            (screen.contents_formatted(), screen.alternate_screen())
        };
        if is_alt {
            let mut prefixed = b"\x1b[?1049h".to_vec();
            prefixed.extend_from_slice(&ack);
            ack = prefixed;
        }
        self.ack_state = ack;
        self.ack_state_seq = 0;
        self.statesync_mismatch_count = 0;
        self.initial_state_received = true;
        repaint
    }

    /// Apply a `StateSyncDiff` frame against the current ack baseline.
    ///
    /// On a matching `base_id` the diff is applied, rendered, the baseline
    /// advanced to `diff_id`, and a [`EncryptedFrame::ClientAck`] sent via
    /// `nak_out_tx`.  A mismatch (or a diff that arrives before any full state)
    /// triggers a [`EncryptedFrame::RepaintRequest`].
    pub(crate) async fn apply_diff(
        &mut self,
        base_id: u64,
        diff_id: u64,
        compressed: &[u8],
        ctx: &ClientRenderCtx,
        nak_out_tx: Option<&Sender<EncryptedFrame>>,
    ) {
        if !self.initial_state_received {
            // Full state not yet received — discard and trigger a push.
            if let Some(tx) = nak_out_tx {
                drop(tx.try_send(EncryptedFrame::RepaintRequest));
            }
            return;
        }
        if base_id != self.ack_state_seq {
            self.statesync_mismatch_count += 1;
            if self.statesync_mismatch_count >= STATESYNC_MISMATCH_LIMIT {
                self.statesync_mismatch_count = 0;
                if let Some(tx) = nak_out_tx
                    && let Err(e) = tx.try_send(EncryptedFrame::RepaintRequest)
                {
                    warn!("Failed to send StateSync desync RepaintRequest: {e}");
                }
            }
            return;
        }
        self.statesync_mismatch_count = 0;
        let diff_bytes = match decode_all_capped(compressed) {
            Ok(bytes) => bytes,
            Err(e) => {
                error!("Failed to decompress StateSyncDiff: {e}");
                return;
            }
        };
        let (rows, cols) = {
            let emu = ctx
                .emulator()
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            emu.screen().size()
        };
        let mut tmp = vt100::Parser::new(rows, cols, 0);
        if !self.ack_state.is_empty() {
            tmp.process(&self.ack_state);
        }
        tmp.process(&diff_bytes);
        let is_alt = tmp.screen().alternate_screen();
        ctx.in_alt_screen().store(is_alt, Ordering::Relaxed);
        let mut new_ack = tmp.screen().contents_formatted();
        if is_alt {
            let mut prefixed = b"\x1b[?1049h".to_vec();
            prefixed.extend_from_slice(&new_ack);
            new_ack = prefixed;
        }
        self.ack_state = new_ack;
        self.ack_state_seq = diff_id;
        // Resync the authoritative emulator to the new state so the prediction
        // engine and local echo stay aligned, then render a single clean update.
        {
            let mut emu = ctx
                .emulator()
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            emu.replace_parser(tmp);
        }
        let repaint =
            render_server_update(ctx.emulator(), ctx.prediction(), ctx.renderer(), !is_alt);
        if !repaint.is_empty()
            && let Err(e) = ctx.stdout_tx().send(repaint).await
        {
            error!("Error sending StateSyncDiff to stdout channel: {e}");
        }
        if let Some(tx) = nak_out_tx
            && let Err(e) = tx.try_send(EncryptedFrame::ClientAck(diff_id))
        {
            warn!("Failed to send ClientAck: {e}");
        }
    }

    /// Process one `StateChunk` frame, accumulating in order.  When the assembly
    /// completes it is decompressed and applied as a full-state push.
    /// Out-of-order or stale chunks discard the assembly and request a repaint.
    pub(crate) async fn apply_chunk(
        &mut self,
        seq: u16,
        total: u16,
        data: Vec<u8>,
        ctx: &ClientRenderCtx,
        nak_out_tx: Option<&Sender<EncryptedFrame>>,
    ) {
        if seq == 0 {
            self.pending_chunk_total = total;
            self.pending_chunk_seq = 0;
            self.pending_chunk_data = data;
        } else if seq == self.pending_chunk_seq && total == self.pending_chunk_total {
            self.pending_chunk_data.extend_from_slice(&data);
        } else {
            // Out-of-order or stale chunk — discard assembly and request a fresh push.
            self.pending_chunk_total = 0;
            self.pending_chunk_seq = 0;
            self.pending_chunk_data.clear();
            if let Some(tx) = nak_out_tx {
                drop(tx.try_send(EncryptedFrame::RepaintRequest));
            }
            return;
        }
        self.pending_chunk_seq += 1;
        if self.pending_chunk_seq != self.pending_chunk_total {
            return;
        }
        // Assembly complete — process as a full-state push.
        let payload_compressed = take(&mut self.pending_chunk_data);
        self.pending_chunk_seq = 0;
        self.pending_chunk_total = 0;
        match decode_all_capped(payload_compressed.as_slice()) {
            Ok(payload) => {
                let repaint = self.apply_full_state(&payload, ctx);
                if !repaint.is_empty()
                    && let Err(e) = ctx.stdout_tx().send(repaint).await
                {
                    error!("Error sending StateChunk repaint to stdout channel: {e}");
                }
            }
            Err(e) => {
                error!("Failed to decompress StateChunk assembly: {e}");
            }
        }
    }
}
