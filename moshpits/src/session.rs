// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
};

use libmoshpit::{EncryptedFrame, TerminalMessage};
use tokio::sync::{Mutex, mpsc::Sender};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

/// Maximum bytes kept in the per-session scrollback ring buffer (64 KiB).
pub(crate) const SCROLLBACK_CAPACITY: usize = 65_536;

/// Replaceable output handle for a session.
#[derive(Debug)]
pub(crate) struct SessionOutputHandle {
    /// Per-connection UUID used to tag outbound [`EncryptedFrame::Bytes`] datagrams.
    pub kex_uuid: Uuid,
    /// Channel to the live [`crate::UdpSender`].  Set to `None` when the client has
    /// disconnected and the PTY is running headless.
    pub tx: Option<Sender<EncryptedFrame>>,
    /// Cancellation token for the current connection's UDP tasks.  Cancelled on resume
    /// to shut down the stale reader/sender pair.
    pub conn_token: Option<CancellationToken>,
    /// UDP port allocated for the current connection, returned to the pool when the PTY
    /// session ends.
    pub udp_port: Option<u16>,
}

/// Full state for one live PTY session.
#[derive(Debug)]
pub(crate) struct SessionRecord {
    /// Forward keyboard / resize events from the connected client into this channel.
    pub term_tx: Sender<TerminalMessage>,
    /// Shared, replaceable output handle – updated on every reconnect.
    pub output_handle: Arc<Mutex<SessionOutputHandle>>,
    /// Ring buffer of raw PTY output bytes for scrollback replay on reconnect.
    pub scrollback: Arc<Mutex<VecDeque<u8>>>,
}

/// Full session registry: maps stable session UUID → [`SessionRecord`].
pub(crate) type FullSessionRegistry = Arc<Mutex<HashMap<Uuid, SessionRecord>>>;

/// Create a new, empty [`FullSessionRegistry`].
pub(crate) fn new_full_registry() -> FullSessionRegistry {
    Arc::new(Mutex::new(HashMap::new()))
}
