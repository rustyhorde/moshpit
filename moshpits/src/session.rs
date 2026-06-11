// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

use std::{
    collections::{HashMap, VecDeque},
    fmt,
    sync::Arc,
    sync::atomic::{AtomicBool, AtomicU64, AtomicUsize},
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
    /// Data channel to the live [`crate::UdpSender`] (PTY diffs, screen state).
    /// Set to `None` when the client has disconnected and the PTY is running headless.
    pub data_tx: Option<Sender<EncryptedFrame>>,
    /// Control channel to the live [`crate::UdpSender`] (Keepalive, Shutdown).
    /// Polled before the data channel inside `UdpSender` to prevent HOL-blocking.
    pub control_tx: Option<Sender<EncryptedFrame>>,
    /// Cancellation token for the current connection's UDP tasks.  Cancelled on resume
    /// to shut down the stale reader/sender pair.
    pub conn_token: Option<CancellationToken>,
    /// UDP port allocated for the current connection, returned to the pool when the PTY
    /// session ends.
    pub udp_port: Option<u16>,
}

/// Full state for one live PTY session.
pub(crate) struct SessionRecord {
    /// Forward keyboard / resize events from the connected client into this channel.
    pub term_tx: Sender<TerminalMessage>,
    /// Shared, replaceable output handle – updated on every reconnect.
    pub output_handle: Arc<Mutex<SessionOutputHandle>>,
    /// Ring buffer of raw PTY output bytes for scrollback replay on reconnect.
    pub scrollback: Arc<Mutex<VecDeque<u8>>>,
    /// Server-side vt100 emulator tracking current PTY screen state.
    /// Fed by the PTY reader thread; queried on reconnect and by the periodic
    /// screen-state sync task to produce [`libmoshpit::EncryptedFrame::ScreenState`] frames.
    pub server_emulator: Arc<Mutex<vt100::Parser>>,
    /// Counter tracking when the screen state has changed (e.g. PTY output or resize).
    /// Used by the screen-sync task to skip expensive re-rendering when idle.
    pub dirty_counter: Arc<AtomicU64>,
    /// Set to `true` by `spawn_pty_reader` whenever a diff chunk is forwarded to the
    /// client. Atomically swapped to `false` by the screen-sync task each tick to
    /// suppress redundant snapshots while the diff stream is actively delivering content.
    pub diff_in_flight: Arc<AtomicBool>,
    /// Current effective maximum PTY-chunk payload size (bytes) used by `spawn_pty_reader`
    /// when splitting large PTY reads into UDP datagrams.  Starts at the conservative
    /// baseline (`MAX_UDP_PAYLOAD` = 1200 B) and is updated upward by the MTU probe
    /// watchdog when the path proves it can handle larger datagrams without loss.
    /// Stored in `SessionRecord` so reconnects reuse the already-probed value.
    pub effective_mtu: Arc<AtomicUsize>,
}

impl fmt::Debug for SessionRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionRecord")
            .field("output_handle", &self.output_handle)
            .field("scrollback", &self.scrollback)
            .finish_non_exhaustive()
    }
}

/// Full session registry: maps stable session UUID → [`SessionRecord`].
pub(crate) type FullSessionRegistry = Arc<Mutex<HashMap<Uuid, SessionRecord>>>;

/// Create a new, empty [`FullSessionRegistry`].
pub(crate) fn new_full_registry() -> FullSessionRegistry {
    Arc::new(Mutex::new(HashMap::new()))
}

#[cfg(test)]
mod test {
    use std::{
        collections::VecDeque,
        sync::Arc,
        sync::atomic::{AtomicBool, AtomicU64, AtomicUsize},
    };

    use libmoshpit::{EncryptedFrame, TerminalMessage};
    use tokio::sync::{
        Mutex,
        mpsc::{Sender, channel},
    };
    use uuid::Uuid;

    use super::{SCROLLBACK_CAPACITY, SessionOutputHandle, SessionRecord, new_full_registry};

    #[test]
    fn scrollback_capacity_is_64kib() {
        assert_eq!(SCROLLBACK_CAPACITY, 65_536);
    }

    #[tokio::test]
    async fn new_full_registry_is_empty() {
        let registry = new_full_registry();
        assert!(registry.lock().await.is_empty());
    }

    #[test]
    fn session_output_handle_debug() {
        let handle = SessionOutputHandle {
            kex_uuid: Uuid::nil(),
            data_tx: None::<Sender<EncryptedFrame>>,
            control_tx: None::<Sender<EncryptedFrame>>,
            conn_token: None,
            udp_port: None,
        };
        let s = format!("{handle:?}");
        assert!(s.contains("SessionOutputHandle"));
        assert!(s.contains("kex_uuid"));
    }

    #[tokio::test]
    async fn session_record_debug() {
        let (term_tx, _term_rx) = channel::<TerminalMessage>(1);
        let (data_tx, _data_rx) = channel::<EncryptedFrame>(1);
        let (_ctrl_tx, _ctrl_rx) = channel::<EncryptedFrame>(1);
        let output_handle = Arc::new(Mutex::new(SessionOutputHandle {
            kex_uuid: Uuid::nil(),
            data_tx: Some(data_tx),
            control_tx: None,
            conn_token: None,
            udp_port: None,
        }));
        let scrollback = Arc::new(Mutex::new(VecDeque::<u8>::new()));
        let server_emulator = Arc::new(Mutex::new(vt100::Parser::new(24, 80, 0)));
        let dirty_counter = Arc::new(AtomicU64::new(1));
        let diff_in_flight = Arc::new(AtomicBool::new(false));
        let effective_mtu = Arc::new(AtomicUsize::new(1200));
        let record = SessionRecord {
            term_tx,
            output_handle,
            scrollback,
            server_emulator,
            dirty_counter,
            diff_in_flight,
            effective_mtu,
        };
        let s = format!("{record:?}");
        assert!(s.contains("SessionRecord"));
        assert!(s.contains("output_handle"));
    }
}
