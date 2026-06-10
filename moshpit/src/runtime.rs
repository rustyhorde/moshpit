// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

use std::{
    ffi::OsString,
    fs::{DirBuilder, OpenOptions},
    io::{Read as _, Write as _, stdin, stdout},
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[cfg(target_family = "unix")]
use std::os::unix::fs::DirBuilderExt;

use anyhow::{Context as _, Result, bail};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use dialoguer::{Confirm, Password};
use libmoshpit::{
    DiffMode, DisplayPreference, Emulator, EncryptedFrame, FileLayer, KEY_ALGORITHM_X25519, Kex,
    KexConfig as _, KexMode, KeyPair, MoshpitError, PredictionEngine, Renderer, UdpReader,
    UdpSender, UuidWrapper, config_file_path, init_tracing, load, paint_overlays_to_ansi,
    parse_server_destination, render_prediction_update, run_key_exchange,
};
use terminal_size::terminal_size;
#[cfg(unix)]
use tokio::signal::unix::{SignalKind, signal};
use tokio::{
    net::{TcpStream, UdpSocket},
    select, spawn,
    sync::{
        Mutex,
        mpsc::{Receiver, Sender, channel},
    },
    time,
};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, trace, warn};
use uuid::Uuid;

use crate::{
    cli::{Cli, Commands},
    config::Config,
    effective,
};

#[cfg_attr(coverage_nightly, coverage(off))]
pub(crate) async fn run<I, T>(args: Option<I>) -> Result<()>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    // Collect the command line once so we can both parse the typed `Cli` and
    // recover the raw `ArgMatches` provenance inside `Cli::parse_argv`.
    let command_line: Vec<OsString> = match args {
        Some(args) => args.into_iter().map(Into::into).collect(),
        None => std::env::args_os().collect(),
    };
    let cli = Cli::parse_argv(command_line)?;

    // `mp ec`: resolve and print the effective config, then exit — no tracing
    // init, key loading, or session loop.
    if let Some(Commands::Ec { json }) = cli.command() {
        let config = load::<Cli, Config, Cli>(&cli, &cli, false)
            .with_context(|| MoshpitError::ConfigLoad)?;
        let config_path = config_file_path(&cli).with_context(|| MoshpitError::ConfigLoad)?;
        let rows = effective::resolve_effective(&cli, &config, &config_path);
        if *json {
            effective::print_json(&rows);
        } else {
            effective::print_table(&rows);
        }
        return Ok(());
    }

    let mut config =
        load::<Cli, Config, Cli>(&cli, &cli, false).with_context(|| MoshpitError::ConfigLoad)?;
    init_tracing(&FileLayer::default(), config.tracing().file(), &cli, None)
        .with_context(|| MoshpitError::TracingInit)?;
    maybe_generate_keypair(&config)?;

    if config.server_destination().is_empty() {
        bail!(
            "a server destination is required, e.g. `mp user@host` (run `mp ec` to inspect config)"
        );
    }
    // Resolve and validate the force-quit prefix key up front so a bad value
    // fails fast with a clear message instead of mid-session.
    let escape_byte = parse_escape_key(config.escape_key())
        .with_context(|| format!("invalid escape_key {:?}", config.escape_key()))?;
    let (user, socket_addr) =
        parse_server_destination(config.server_destination(), config.server_port())?;
    let server_ip = socket_addr.ip().to_string();
    let server_port = config.server_port();
    let _ = config.set_user(user);

    run_session_loop(config, socket_addr, server_ip, server_port, escape_byte).await
}

/// Cached passphrase state, avoiding re-prompting across reconnects.
#[derive(Debug)]
enum PassCache {
    /// Not yet prompted.
    Uncached,
    /// Prompted; key is unencrypted — no passphrase needed.
    NoPassphrase,
    /// Prompted; encrypted key passphrase.
    Passphrase(String),
}

impl PassCache {
    /// Returns `true` when a cached answer is available.
    fn is_cached(&self) -> bool {
        !matches!(self, Self::Uncached)
    }

    /// Returns the cached passphrase.  `None` means the key is unencrypted.
    ///
    /// Panics if called while `Uncached`.
    fn passphrase(&self) -> Option<String> {
        match self {
            Self::Uncached => unreachable!("passphrase() called before caching"),
            Self::NoPassphrase => None,
            Self::Passphrase(s) => Some(s.clone()),
        }
    }
}

/// Maximum time allowed for the entire TCP key exchange.  If the server accepts
/// the TCP connection but never sends a frame the client would otherwise block
/// forever inside `read_frame().await`; this bound converts that hang into a
/// retriable network error.
const KEX_TIMEOUT: Duration = Duration::from_secs(30);

/// An unrecoverable key-exchange error that should not trigger the retry loop.
#[derive(Debug)]
struct FatalKexError {
    inner: MoshpitError,
    key_path: PathBuf,
}

impl std::fmt::Display for FatalKexError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} (key: {})", self.inner, self.key_path.display())
    }
}

impl std::error::Error for FatalKexError {}

#[derive(Clone, Copy, Default)]
enum EscapeState {
    #[default]
    Normal,
    PendingDot,
}

/// Map a key character to the control byte produced by pressing `Ctrl` with it.
///
/// Covers the canonical ASCII control mappings: `@` → `0x00`, `a`–`z`
/// (case-insensitive) → `0x01`–`0x1A`, `\` → `0x1C`, `]` → `0x1D`, `^` → `0x1E`,
/// `_` → `0x1F`.  `[` (which maps to `0x1B` / `ESC`) is intentionally excluded:
/// using `ESC` as the escape prefix would swallow arrow keys and every other
/// terminal escape sequence.  Returns `None` for any other character.
fn ctrl_byte(c: char) -> Option<u8> {
    match c.to_ascii_lowercase() {
        '@' => Some(0x00),
        c @ 'a'..='z' => Some(c as u8 - b'a' + 1),
        '\\' => Some(0x1c),
        ']' => Some(0x1d),
        '^' => Some(0x1e),
        '_' => Some(0x1f),
        _ => None,
    }
}

/// Parse a force-quit escape-prefix key (e.g. `"ctrl-^"`) into its control byte.
///
/// Accepts a leading `ctrl-` or `c-` prefix (case-insensitive) followed by a
/// single key character resolved via [`ctrl_byte`].  The prefix must resolve to
/// a control byte so it never collides with normal typed input.
///
/// # Errors
/// Returns an error for an empty value, a missing/garbled `ctrl-` prefix, more
/// than one key character, or a key that does not map to a control byte
/// (including `ctrl-[`, which would be `ESC`).
fn parse_escape_key(s: &str) -> Result<u8> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        bail!("escape_key is empty; expected something like \"ctrl-^\"");
    }
    let lower = trimmed.to_ascii_lowercase();
    let key = lower
        .strip_prefix("ctrl-")
        .or_else(|| lower.strip_prefix("c-"))
        .with_context(|| {
            format!("escape_key {trimmed:?} must start with \"ctrl-\" (e.g. \"ctrl-^\")")
        })?;
    let mut chars = key.chars();
    let (Some(c), None) = (chars.next(), chars.next()) else {
        bail!("escape_key {trimmed:?} must name exactly one key after \"ctrl-\"");
    };
    ctrl_byte(c).with_context(|| {
        if c == '[' {
            "escape_key \"ctrl-[\" is ESC and cannot be used as the escape key".to_string()
        } else {
            format!("escape_key {trimmed:?} does not map to a control key")
        }
    })
}

/// Render a control byte as a human-readable `Ctrl-<key>` label for the
/// reconnect banner hint.  Inverse of [`ctrl_byte`].
fn ctrl_label(byte: u8) -> String {
    let key = match byte {
        0x00 => '@',
        0x01..=0x1a => (b'A' + (byte - 1)) as char,
        0x1c => '\\',
        0x1d => ']',
        0x1e => '^',
        0x1f => '_',
        _ => '?',
    };
    format!("Ctrl-{key}")
}

/// Show a mosh-style reconnecting banner at the top of the terminal.
///
/// The banner is white-on-blue, occupies the entire first row, and is
/// rendered by writing raw ANSI escape sequences through the same stdout
/// channel used for normal terminal output.
async fn show_reconnect_banner(stdout_tx: &Sender<Vec<u8>>) {
    // ESC[s          – save cursor position
    // ESC[1;1H       – move to row 1, col 1
    // ESC[44;97;1m   – blue background, bright-white bold text
    // ESC[K          – erase to end of line (fills line with blue)
    // ESC[0m         – reset attributes
    // ESC[u          – restore cursor position
    let msg = b"\x1b[s\x1b[1;1H\x1b[44;97;1m [moshpit] server unreachable, reconnecting... \x1b[K\x1b[0m\x1b[u";
    drop(stdout_tx.send(msg.to_vec()).await);
}

/// Clear the reconnecting banner and restore the first row to normal.
async fn clear_reconnect_banner(stdout_tx: &Sender<Vec<u8>>) {
    // Reset attributes first so the erase uses the default background.
    let msg = b"\x1b[s\x1b[1;1H\x1b[0m\x1b[K\x1b[u";
    drop(stdout_tx.send(msg.to_vec()).await);
}

/// Redraw the banner once per second, counting down from `total_secs` to 0.
/// Returns `true` if the user pressed the escape sequence (`Ctrl-^ .`) to quit.
async fn countdown_reconnect_banner(
    stdout_tx: &Sender<Vec<u8>>,
    total_secs: u64,
    attempt: u32,
    max_backoff_secs: u64,
    exit_token: &CancellationToken,
    escape_label: &str,
) -> bool {
    for remaining in (0..=total_secs).rev() {
        let msg = format!(
            "\x1b[s\x1b[1;1H\x1b[44;97;1m [moshpit] server unreachable, reconnecting \
(attempt #{attempt}, {remaining}s, max {max_backoff_secs}s, {escape_label} . to quit)... \x1b[K\x1b[0m\x1b[u"
        );
        drop(stdout_tx.send(msg.into_bytes()).await);
        if remaining > 0 {
            select! {
                () = exit_token.cancelled() => return true,
                () = time::sleep(Duration::from_secs(1)) => {}
            }
        }
    }
    exit_token.is_cancelled()
}

/// Holds the `kb_rx` mutex during reconnect countdowns and detects `Ctrl-^ .`.
/// Cancels `exit_token` when the escape sequence is detected, then returns.
/// Stops when `done_token` is cancelled (countdown finished normally).
async fn run_escape_listener(
    kb_rx: Arc<Mutex<Receiver<Vec<u8>>>>,
    exit_token: CancellationToken,
    done_token: CancellationToken,
    ready_tx: tokio::sync::oneshot::Sender<()>,
    escape_byte: u8,
) {
    let mut state = EscapeState::Normal;
    // Acquire the lock interruptibly: if the countdown finishes before we can
    // get the lock (e.g. the session forwarder is still holding it), return
    // immediately so countdown_with_escape doesn't block on escape_handle.await.
    let mut rx = select! {
        guard = kb_rx.lock() => guard,
        () = done_token.cancelled() => return,
    };
    // Lock acquired — notify the caller so it can display the Ctrl-^. hint.
    let _ = ready_tx.send(());
    loop {
        select! {
            () = done_token.cancelled() => break,
            data = rx.recv() => match data {
                None => break,
                Some(data) => {
                    for &byte in &data {
                        state = match state {
                            EscapeState::Normal => {
                                if byte == escape_byte { EscapeState::PendingDot } else { EscapeState::Normal }
                            }
                            EscapeState::PendingDot => {
                                if byte == 0x2E {
                                    exit_token.cancel();
                                    return;
                                } else if byte == escape_byte {
                                    EscapeState::PendingDot
                                } else {
                                    EscapeState::Normal
                                }
                            }
                        };
                    }
                }
            }
        }
    }
}

#[cfg(not(unix))]
fn encode_char_key(c: char, ctrl: bool, alt: bool) -> Vec<u8> {
    let mut out = Vec::new();
    if ctrl {
        let byte = match c.to_ascii_lowercase() {
            '@' => 0x00,
            'a'..='z' => c.to_ascii_lowercase() as u8 - b'a' + 1,
            '[' => 0x1b,
            // crossterm's Unix parser maps 0x1C-0x1F to Char('4'-'7') + CONTROL
            // (e.g. Ctrl+6 / Ctrl+^ → 0x1E → Char('6') + CONTROL).  Accepting
            // both the digit and the traditional symbol form keeps behaviour
            // consistent across platforms and terminal emulators.
            '\\' | '4' => 0x1c,
            ']' | '5' => 0x1d,
            '^' | '6' => 0x1e,
            '_' | '7' => 0x1f,
            _ => {
                let mut buf = [0u8; 4];
                let s = c.encode_utf8(&mut buf);
                if alt {
                    out.push(0x1b);
                }
                out.extend_from_slice(s.as_bytes());
                return out;
            }
        };
        if alt {
            out.push(0x1b);
        }
        out.push(byte);
        return out;
    }

    if alt {
        out.push(0x1b);
    }
    let mut buf = [0u8; 4];
    out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
    out
}

#[cfg(not(unix))]
fn encode_nav_key(
    code: crossterm::event::KeyCode,
    has_mod: bool,
    mod_param: u8,
) -> Option<Vec<u8>> {
    use crossterm::event::KeyCode;

    let bytes = match code {
        KeyCode::Up => {
            if has_mod {
                format!("\x1b[1;{mod_param}A").into_bytes()
            } else {
                b"\x1b[A".to_vec()
            }
        }
        KeyCode::Down => {
            if has_mod {
                format!("\x1b[1;{mod_param}B").into_bytes()
            } else {
                b"\x1b[B".to_vec()
            }
        }
        KeyCode::Right => {
            if has_mod {
                format!("\x1b[1;{mod_param}C").into_bytes()
            } else {
                b"\x1b[C".to_vec()
            }
        }
        KeyCode::Left => {
            if has_mod {
                format!("\x1b[1;{mod_param}D").into_bytes()
            } else {
                b"\x1b[D".to_vec()
            }
        }
        KeyCode::Home => {
            if has_mod {
                format!("\x1b[1;{mod_param}H").into_bytes()
            } else {
                b"\x1b[H".to_vec()
            }
        }
        KeyCode::End => {
            if has_mod {
                format!("\x1b[1;{mod_param}F").into_bytes()
            } else {
                b"\x1b[F".to_vec()
            }
        }
        KeyCode::Insert => {
            if has_mod {
                format!("\x1b[2;{mod_param}~").into_bytes()
            } else {
                b"\x1b[2~".to_vec()
            }
        }
        KeyCode::Delete => {
            if has_mod {
                format!("\x1b[3;{mod_param}~").into_bytes()
            } else {
                b"\x1b[3~".to_vec()
            }
        }
        KeyCode::PageUp => {
            if has_mod {
                format!("\x1b[5;{mod_param}~").into_bytes()
            } else {
                b"\x1b[5~".to_vec()
            }
        }
        KeyCode::PageDown => {
            if has_mod {
                format!("\x1b[6;{mod_param}~").into_bytes()
            } else {
                b"\x1b[6~".to_vec()
            }
        }
        _ => return None,
    };
    Some(bytes)
}

#[cfg(not(unix))]
fn encode_function_key(n: u8, has_mod: bool, mod_param: u8) -> Vec<u8> {
    match n {
        1 => {
            if has_mod {
                format!("\x1b[1;{mod_param}P").into_bytes()
            } else {
                b"\x1bOP".to_vec()
            }
        }
        2 => {
            if has_mod {
                format!("\x1b[1;{mod_param}Q").into_bytes()
            } else {
                b"\x1bOQ".to_vec()
            }
        }
        3 => {
            if has_mod {
                format!("\x1b[1;{mod_param}R").into_bytes()
            } else {
                b"\x1bOR".to_vec()
            }
        }
        4 => {
            if has_mod {
                format!("\x1b[1;{mod_param}S").into_bytes()
            } else {
                b"\x1bOS".to_vec()
            }
        }
        5 => {
            if has_mod {
                format!("\x1b[15;{mod_param}~").into_bytes()
            } else {
                b"\x1b[15~".to_vec()
            }
        }
        6 => {
            if has_mod {
                format!("\x1b[17;{mod_param}~").into_bytes()
            } else {
                b"\x1b[17~".to_vec()
            }
        }
        7 => {
            if has_mod {
                format!("\x1b[18;{mod_param}~").into_bytes()
            } else {
                b"\x1b[18~".to_vec()
            }
        }
        8 => {
            if has_mod {
                format!("\x1b[19;{mod_param}~").into_bytes()
            } else {
                b"\x1b[19~".to_vec()
            }
        }
        9 => {
            if has_mod {
                format!("\x1b[20;{mod_param}~").into_bytes()
            } else {
                b"\x1b[20~".to_vec()
            }
        }
        10 => {
            if has_mod {
                format!("\x1b[21;{mod_param}~").into_bytes()
            } else {
                b"\x1b[21~".to_vec()
            }
        }
        11 => {
            if has_mod {
                format!("\x1b[23;{mod_param}~").into_bytes()
            } else {
                b"\x1b[23~".to_vec()
            }
        }
        12 => {
            if has_mod {
                format!("\x1b[24;{mod_param}~").into_bytes()
            } else {
                b"\x1b[24~".to_vec()
            }
        }
        _ => Vec::new(),
    }
}

/// Converts a crossterm `KeyEvent` to the ANSI escape bytes a terminal would
/// produce for the same keypress.  Returns an empty `Vec` for events that
/// should not be forwarded (key-release events, unhandled keys, etc.).
///
/// On Windows the console API reports key presses as structured events; on Unix
/// crossterm parses raw stdin bytes in raw mode.  Either way this re-encodes
/// the event as ANSI bytes for forwarding to the server.
#[cfg(not(unix))]
fn key_event_to_bytes(event: crossterm::event::KeyEvent) -> Vec<u8> {
    use crossterm::event::{KeyCode, KeyEventKind, KeyModifiers};
    // Only forward press events; Windows always reports both press and release.
    if event.kind != KeyEventKind::Press {
        return Vec::new();
    }
    let mods = event.modifiers;
    let ctrl = mods.contains(KeyModifiers::CONTROL);
    let alt = mods.contains(KeyModifiers::ALT);
    let shift = mods.contains(KeyModifiers::SHIFT);
    // CSI modifier parameter: 1 + shift + alt*2 + ctrl*4
    let mod_param = 1u8 + u8::from(shift) + (u8::from(alt) * 2) + (u8::from(ctrl) * 4);
    let has_mod = mod_param > 1;

    match event.code {
        KeyCode::Char(c) => encode_char_key(c, ctrl, alt),
        KeyCode::Backspace => vec![0x7f],
        KeyCode::Enter => vec![b'\r'],
        KeyCode::Tab => vec![b'\t'],
        KeyCode::BackTab => b"\x1b[Z".to_vec(),
        KeyCode::Esc => vec![0x1b],
        KeyCode::Null => vec![0x00],
        KeyCode::F(n) => encode_function_key(n, has_mod, mod_param),
        code => encode_nav_key(code, has_mod, mod_param).unwrap_or_default(),
    }
}

/// Temporarily pauses the stdin reader and restores cooked mode, calls `f`,
/// then re-enables raw mode and resumes the reader.  Wraps interactive prompts
/// (passphrase, TOFU, key-mismatch) that require a functioning line editor.
#[cfg_attr(coverage_nightly, coverage(off))]
fn with_cooked_term<T>(paused: &AtomicBool, f: impl FnOnce() -> T) -> T {
    paused.store(true, Ordering::SeqCst);
    // Give the reader thread time to observe the pause before raw mode drops.
    thread::sleep(Duration::from_millis(100));
    drop(disable_raw_mode());
    let result = f();
    drop(enable_raw_mode());
    paused.store(false, Ordering::SeqCst);
    result
}

/// Unix: read raw bytes from stdin using `select(2)` + `read(2)` with a 50 ms
/// timeout.  Raw mode is set by crossterm before this thread starts; the
/// terminal therefore encodes every keypress as the correct byte sequence
/// (including DECCKM application-cursor sequences when vi enables them) without
/// any intermediate parsing layer.  The `Ctrl-^ .` disconnect sequence arrives
/// as bytes `0x1E 0x2E` and is handled by the forwarder's escape state machine.
///
/// Using the raw fd bypasses crossterm's mio-based event reactor, which has
/// been observed to silently exit or stop delivering events when vi enters
/// alternate-screen mode, permanently freezing all keyboard input.
#[cfg(unix)]
#[allow(unsafe_code)]
fn stdin_reader_loop(kb_tx: &Sender<Vec<u8>>, paused: &AtomicBool) {
    use std::os::unix::io::AsRawFd;
    let stdin_fd = stdin().as_raw_fd();
    let mut buf = [0u8; 256];
    debug!("stdin reader thread started (raw-fd mode, fd={stdin_fd})");
    loop {
        while paused.load(Ordering::Relaxed) {
            thread::sleep(Duration::from_millis(50));
        }
        // select() with 50 ms timeout so the paused flag is checked at least
        // every 100 ms (sleep above + this timeout).
        let ready = unsafe {
            let mut read_set: libc::fd_set = std::mem::zeroed();
            libc::FD_SET(stdin_fd, std::ptr::addr_of_mut!(read_set));
            let mut tv = libc::timeval {
                tv_sec: 0,
                tv_usec: 50_000,
            };
            libc::select(
                stdin_fd + 1,
                std::ptr::addr_of_mut!(read_set),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::addr_of_mut!(tv),
            )
        };
        if ready <= 0 {
            continue; // timeout or EINTR on select
        }
        let n = unsafe { libc::read(stdin_fd, buf.as_mut_ptr().cast::<libc::c_void>(), buf.len()) };
        match n {
            n if n > 0 => {
                if kb_tx
                    .blocking_send(buf[..n.cast_unsigned()].to_vec())
                    .is_err()
                {
                    break;
                }
            }
            0 => break, // EOF
            _ => {
                if std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
                    break;
                }
            }
        }
    }
    warn!("stdin reader thread exited");
}

/// Windows: crossterm event-based stdin reader.  Polls for key events and
/// forwards their ANSI byte encoding to the keyboard channel.  When `paused`
/// is set, idles so `with_cooked_term` can safely disable raw mode around
/// interactive prompts.
///
/// Also used on Unix when the raw-fd implementation is unavailable.  Includes
/// diagnostic logging that identifies whether crossterm stops delivering events
/// (log shows repeated `alive` heartbeats) or exits with a poll error.
#[cfg(not(unix))]
fn stdin_reader_loop(kb_tx: &Sender<Vec<u8>>, paused: &AtomicBool) {
    use crossterm::event::{Event, poll, read};
    debug!("stdin reader thread started (crossterm mode)");
    let mut idle_cycles: u32 = 0;
    loop {
        if paused.load(Ordering::Relaxed) {
            idle_cycles = 0;
            thread::sleep(Duration::from_millis(50));
            continue;
        }
        match poll(Duration::from_millis(50)) {
            Ok(true) => {
                idle_cycles = 0;
                match read() {
                    Ok(Event::Key(ke)) => {
                        let bytes = key_event_to_bytes(ke);
                        if !bytes.is_empty() && kb_tx.blocking_send(bytes).is_err() {
                            debug!("stdin: channel closed, exiting");
                            break;
                        }
                    }
                    Ok(_other) => {}
                    Err(e) => {
                        warn!("stdin: read() error: {e}");
                    }
                }
            }
            Ok(false) => {
                idle_cycles += 1;
                if idle_cycles.is_multiple_of(20) {
                    trace!("stdin: alive, {idle_cycles} idle cycles");
                }
            }
            Err(e) => {
                error!("stdin: poll() error: {e}, thread exiting");
                break;
            }
        }
    }
    warn!("stdin reader thread exited");
}

/// Runs the reconnect countdown alongside an escape-sequence listener.
/// Returns `true` if the user pressed `Ctrl-^ .` to quit.
#[cfg_attr(nightly, allow(clippy::too_many_arguments))]
#[cfg_attr(coverage_nightly, coverage(off))]
async fn countdown_with_escape(
    stdout_tx: &Sender<Vec<u8>>,
    backoff_secs: u64,
    attempt: u32,
    max_backoff_secs: u64,
    exit_token: &CancellationToken,
    kb_rx: Arc<Mutex<Receiver<Vec<u8>>>>,
    escape_byte: u8,
    escape_label: &str,
) -> bool {
    let escape_done = CancellationToken::new();
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let escape_handle = spawn(run_escape_listener(
        kb_rx,
        exit_token.clone(),
        escape_done.clone(),
        ready_tx,
        escape_byte,
    ));
    // Wait for the listener to acquire kb_rx before showing the Ctrl-^. hint.
    // In practice nearly instant; 200ms guards against a slow forwarder cleanup.
    drop(time::timeout(Duration::from_millis(200), ready_rx).await);
    let exiting = countdown_reconnect_banner(
        stdout_tx,
        backoff_secs,
        attempt,
        max_backoff_secs,
        exit_token,
        escape_label,
    )
    .await;
    escape_done.cancel();
    drop(escape_handle.await);
    exiting
}

/// Shared holder for the message printed when the client exits.  Set by the
/// exit-triggering path; read by [`restore_terminal_and_exit`].
type ExitMsg = Arc<std::sync::Mutex<Option<&'static [u8]>>>;

/// Restore the terminal and terminate the process.
///
/// Leaves the alternate screen (a server-side app may have entered it), shows
/// the cursor, clears the *visible* screen, and homes the cursor so the next
/// shell prompt starts cleanly at the top.  Scrollback is preserved (`\x1b[2J`,
/// not `\x1b[3J`).  `exit_msg`, if present, is printed after the clear so it
/// sits at the top of the fresh screen.
///
/// Everything is written directly to stdout in one flushed sequence so the
/// ordering is deterministic (the async stdout writer thread is bypassed); the
/// clear also wipes any residual diff bytes that thread may have flushed.
#[cfg_attr(coverage_nightly, coverage(off))]
fn restore_terminal_and_exit(exit_msg: Option<&[u8]>) -> ! {
    let mut out = stdout();
    // Leave alt-screen, show cursor, clear the visible screen, home + reset SGR.
    drop(out.write_all(b"\x1b[?1049l\x1b[?25h\x1b[2J\x1b[H\x1b[0m"));
    if let Some(msg) = exit_msg {
        drop(out.write_all(msg));
    }
    drop(out.flush());
    drop(disable_raw_mode());
    std::process::exit(0);
}

/// Persistent reconnect loop.  Runs until the shell exits (via `process::exit`).
#[cfg_attr(nightly, allow(clippy::too_many_lines))]
#[cfg_attr(coverage_nightly, coverage(off))]
async fn run_session_loop(
    config: Config,
    socket_addr: SocketAddr,
    server_ip: String,
    server_port: u16,
    escape_byte: u8,
) -> Result<()> {
    // Clamp to [2 s, 24 h].
    let max_backoff = Duration::from_secs(config.max_reconnect_backoff_secs().clamp(2, 86_400));
    // Human-readable label (e.g. "Ctrl-^") for the reconnect-countdown hint.
    let escape_label = ctrl_label(escape_byte);

    // Persistent stdout writer — survives reconnects.
    let (stdout_tx, mut stdout_rx) = channel::<Vec<u8>>(256);
    let _stdout_thread = thread::spawn(move || {
        let mut out = stdout();
        while let Some(msg) = stdout_rx.blocking_recv() {
            drop(out.write_all(&msg));
            drop(out.flush());
        }
    });

    // Passphrase cache: avoids re-prompting on reconnect.
    let pass_cache: Arc<std::sync::Mutex<PassCache>> =
        Arc::new(std::sync::Mutex::new(PassCache::Uncached));

    let mut config = config;
    let mut backoff = Duration::from_secs(2);
    let mut reconnect_attempt: u32 = 0;
    // Shared exit token: cancelled when the user presses Ctrl-^ . to quit.
    let exit_token = CancellationToken::new();
    // Message printed (after the screen is cleared) once the client exits.
    // Set by whichever path triggers the exit: the stdin forwarder on Ctrl-^ .,
    // the reader on a server PtyExit, or the reconnect countdown. `None` exits
    // silently (e.g. OSC-title exit) but still clears the screen.
    let exit_msg: ExitMsg = Arc::new(std::sync::Mutex::new(None));

    // Start the stdin reader before the first KEX so Ctrl-^ . is always
    // detectable.  with_cooked_term pauses it around interactive prompts.
    let stdin_paused = Arc::new(AtomicBool::new(false));
    enable_raw_mode()?;
    let (kb_tx, kb_rx) = channel::<Vec<u8>>(64);
    let paused_for_reader = stdin_paused.clone();
    let _stdin_thread = thread::spawn(move || stdin_reader_loop(&kb_tx, &paused_for_reader));
    let kb_rx_shared = Arc::new(Mutex::new(kb_rx));

    let mut had_successful_kex = false;

    loop {
        match connect_and_kex(
            &mut config,
            socket_addr,
            &server_ip,
            server_port,
            &pass_cache,
            stdin_paused.clone(),
        )
        .await
        {
            Ok((kex, udp_arc, nak_timeout)) => {
                backoff = Duration::from_secs(2);
                clear_reconnect_banner(&stdout_tx).await;
                had_successful_kex = true;
                // Informational: the wire protocol version both ends agreed on.
                // Future wire-format changes should branch on kex.protocol_version().
                info!("negotiated wire protocol v{}", kex.protocol_version());

                let session_result = run_udp_session(
                    kex,
                    udp_arc,
                    nak_timeout,
                    kb_rx_shared.clone(),
                    config.nat_warmup(),
                    config.nat_warmup_count(),
                    stdout_tx.clone(),
                    config.predict(),
                    config.diff_mode(),
                    config.legacy_passthrough(),
                    escape_byte,
                    exit_token.clone(),
                    exit_msg.clone(),
                )
                .await;
                if let Err(e) = session_result {
                    drop(disable_raw_mode());
                    return Err(e);
                }
                if exit_token.is_cancelled() {
                    // Let the stdout channel settle before the direct teardown write.
                    time::sleep(Duration::from_millis(100)).await;
                    let msg = *exit_msg
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    restore_terminal_and_exit(msg);
                }
                // Session dropped — restore the terminal (the server-side app may
                // have left us in alternate-screen mode) then show the reconnect banner.
                drop(crossterm::execute!(
                    stdout(),
                    crossterm::terminal::LeaveAlternateScreen,
                    crossterm::cursor::Show,
                ));
                show_reconnect_banner(&stdout_tx).await;
                time::sleep(Duration::from_millis(500)).await;
            }
            Err(e) => {
                if let Some(fatal) = e.downcast_ref::<FatalKexError>() {
                    eprintln!("mp: fatal key error: {fatal}");
                    eprintln!(
                        "mp: run `mp-keygen` to regenerate your keypair at {}",
                        fatal.key_path.display()
                    );
                    drop(disable_raw_mode());
                    return Err(e);
                }
                if e.downcast_ref::<MoshpitError>()
                    .is_some_and(|e| *e == MoshpitError::HostKeyRejected)
                {
                    drop(disable_raw_mode());
                    return Err(e);
                }
                if let Some(&err) = e.downcast_ref::<MoshpitError>() {
                    match err {
                        MoshpitError::KeyNotEstablished => {
                            eprintln!("mp: server rejected the key exchange");
                            eprintln!(
                                "mp: ensure your public key is listed in \
                                 ~/.mp/authorized_keys on the server"
                            );
                            drop(disable_raw_mode());
                            return Err(e);
                        }
                        MoshpitError::NoCommonAlgorithm => {
                            eprintln!("mp: no common algorithm found during key exchange");
                            eprintln!(
                                "mp: check --kex-algos, --aead-algos, --mac-algos, \
                                 and --kdf-algos settings on both client and server"
                            );
                            drop(disable_raw_mode());
                            return Err(e);
                        }
                        MoshpitError::IncompatibleProtocolVersion => {
                            eprintln!(
                                "mp: server's wire protocol is incompatible with this client"
                            );
                            eprintln!(
                                "mp: upgrade moshpit on whichever side is older (the server may \
                                 have raised its minimum supported version)"
                            );
                            drop(disable_raw_mode());
                            return Err(e);
                        }
                        _ => {}
                    }
                }
                reconnect_attempt = reconnect_attempt.saturating_add(1);
                error!("Failed to connect to {socket_addr}: {e}, retrying in {backoff:?}");
                // Reset passphrase cache on early failures so the user can
                // re-enter it on the next attempt.
                if !had_successful_kex {
                    *pass_cache
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) = PassCache::Uncached;
                }
                if countdown_with_escape(
                    &stdout_tx,
                    backoff.as_secs(),
                    reconnect_attempt,
                    max_backoff.as_secs(),
                    &exit_token,
                    kb_rx_shared.clone(),
                    escape_byte,
                    &escape_label,
                )
                .await
                {
                    clear_reconnect_banner(&stdout_tx).await;
                    // Let the stdout channel settle before the direct teardown write.
                    time::sleep(Duration::from_millis(100)).await;
                    restore_terminal_and_exit(Some(b"[moshpit] Disconnected.\r\n"));
                }
                backoff = (backoff * 2).min(max_backoff);
            }
        }
    }
}

/// Connect via TCP, run the key exchange, and persist the session UUID.
#[cfg_attr(nightly, allow(clippy::too_many_lines))]
async fn connect_and_kex(
    config: &mut Config,
    socket_addr: SocketAddr,
    server_ip: &str,
    server_port: u16,
    pass_cache: &Arc<std::sync::Mutex<PassCache>>,
    stdin_paused: Arc<AtomicBool>,
) -> Result<(Kex, Arc<UdpSocket>, Duration)> {
    // Refresh resume UUID from disk (may have been updated by previous connection).
    let _ = config.set_resume_session_uuid(read_session_uuid(server_ip, server_port));

    let socket = time::timeout(KEX_TIMEOUT, TcpStream::connect(socket_addr))
        .await
        .map_err(|_| anyhow::anyhow!("TCP connection timed out after {KEX_TIMEOUT:?}"))??;
    info!("Connected to {}", socket.peer_addr()?);

    let cache = pass_cache.clone();
    let paused_pass = stdin_paused.clone();
    let pass_fn = move || -> Result<Option<String>> {
        let guard = cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if guard.is_cached() {
            info!(
                "passphrase: returning cached value (has_passphrase={})",
                guard.passphrase().is_some()
            );
            return Ok(guard.passphrase());
        }
        drop(guard);
        info!("passphrase: prompting user");
        let result =
            tokio::task::block_in_place(|| with_cooked_term(&paused_pass, read_passpharase));
        match &result {
            Ok(Some(_)) => info!("passphrase: prompt returned a passphrase"),
            Ok(None) => info!("passphrase: prompt returned None (key may be unencrypted)"),
            Err(e) => error!("passphrase: prompt failed: {e}"),
        }
        if let Ok(ref pass) = result {
            *cache
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = match pass {
                Some(s) => PassCache::Passphrase(s.clone()),
                None => PassCache::NoPassphrase,
            };
        }
        result
    };

    let (sock_read, sock_write) = socket.into_split();

    let paused_tofu = stdin_paused.clone();
    let tofu_fn: libmoshpit::TofuFn =
        Arc::new(move |host: &str, fingerprint: &str| -> Result<bool> {
            tokio::task::block_in_place(|| {
                with_cooked_term(&paused_tofu, || {
                    let prompt = format!(
                        "The authenticity of host '{host}' can't be established.\n\
                     Fingerprint is SHA256:{fingerprint}.\n\
                     Are you sure you want to continue connecting? (yes/no)"
                    );
                    let input: String = dialoguer::Input::new()
                        .with_prompt(prompt)
                        .interact_text()?;
                    Ok(input.eq_ignore_ascii_case("yes"))
                })
            })
        });

    let paused_mismatch = stdin_paused;
    let mismatch_fn: libmoshpit::HostKeyMismatchFn = Arc::new(
        move |host: &str, old_fingerprint: &str, new_fingerprint: &str| -> Result<bool> {
            tokio::task::block_in_place(|| {
                with_cooked_term(&paused_mismatch, || {
                    eprintln!("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
                    eprintln!("@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @");
                    eprintln!("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
                    eprintln!("Potential DNS spoofing or machine-in-the-middle detected.");
                    eprintln!("Host: {host}");
                    eprintln!("Offending key fingerprint: SHA256:{old_fingerprint}");
                    eprintln!("Presented key fingerprint: SHA256:{new_fingerprint}");

                    Confirm::new()
                        .with_prompt(
                            "Update ~/.mp/known_hosts with the newly presented key for this host?",
                        )
                        .default(false)
                        .wait_for_newline(true)
                        .interact()
                        .map_err(Into::into)
                })
            })
        },
    );

    let kex_start = Instant::now();
    let kex_result = time::timeout(
        KEX_TIMEOUT,
        run_key_exchange(
            config.clone(),
            sock_read,
            sock_write,
            pass_fn,
            Some(tofu_fn),
            Some(mismatch_fn),
        ),
    )
    .await;
    let (kex, udp_arc, _) = match kex_result {
        Err(_elapsed) => {
            return Err(anyhow::anyhow!(
                "key exchange timed out after {KEX_TIMEOUT:?} — \
                 server accepted TCP connection but sent no data"
            ));
        }
        Ok(inner) => inner,
    }
    .map_err(|e| {
        if let Some(&moshpit_err) = e.downcast_ref::<MoshpitError>() {
            match moshpit_err {
                MoshpitError::KeyFileMissing
                | MoshpitError::KeyCorrupt
                | MoshpitError::KeyPairMismatch
                | MoshpitError::DecryptionFailed
                | MoshpitError::InvalidPublicKeyFormat
                | MoshpitError::InvalidKeyHeader => {
                    let key_path = config
                        .key_pair_paths()
                        .ok()
                        .map(|(p, _)| p)
                        .unwrap_or_default();
                    return anyhow::anyhow!(FatalKexError {
                        inner: moshpit_err,
                        key_path,
                    });
                }
                _ => {}
            }
        }
        e
    })?;

    if let Some(session_uuid) = kex.session_uuid() {
        if let Err(e) = write_session_uuid(server_ip, server_port, session_uuid) {
            trace!("Failed to write session file: {e}");
        }
        if kex.is_resume() {
            info!("Session {session_uuid} resumed");
        } else {
            info!("New session {session_uuid} started");
        }
    }
    // Use the TCP KEX elapsed time as a proxy for network RTT.  The key
    // exchange involves ~2 round trips, so the total elapsed time is
    // approximately 2× RTT, making it a reasonable base for the NAK backoff
    // schedule.  Clamp to [20 ms, 500 ms] to handle both LAN and high-latency
    // paths without risking spurious NAKs or excessively slow recovery.
    let nak_timeout = kex_start
        .elapsed()
        .clamp(Duration::from_millis(20), Duration::from_millis(500));
    info!("nak_timeout set to {:?} from kex elapsed time", nak_timeout);
    Ok((kex, udp_arc, nak_timeout))
}

/// Set up UDP tasks for one session and wait until the server disconnects.
#[cfg_attr(nightly, allow(clippy::too_many_lines))]
#[cfg_attr(nightly, allow(clippy::too_many_arguments))]
#[cfg_attr(coverage_nightly, coverage(off))]
async fn run_udp_session(
    kex: Kex,
    udp_arc: Arc<UdpSocket>,
    nak_timeout: Duration,
    kb_rx: Arc<Mutex<Receiver<Vec<u8>>>>,
    nat_warmup: bool,
    nat_warmup_count: u32,
    stdout_tx: Sender<Vec<u8>>,
    display_preference: DisplayPreference,
    diff_mode: DiffMode,
    legacy_passthrough: bool,
    escape_byte: u8,
    exit_token: CancellationToken,
    exit_msg: ExitMsg,
) -> Result<()> {
    let (reconnect_tx, mut reconnect_rx) = channel::<()>(1);
    let token = CancellationToken::new();
    let (tx, rx) = channel::<EncryptedFrame>(256);
    let (_control_tx, control_rx) = channel::<EncryptedFrame>(16);
    let (retransmit_tx, retransmit_rx) = channel::<Vec<u64>>(512);

    // Derive silence timeout from path RTT: max(nak_timeout × 30, 9 s).
    // With a 3 s server keepalive interval this guarantees ≥ 3 keepalives
    // arrive before the silence window closes.  On LAN (nak_timeout ≈ 20 ms)
    // this gives 9 s vs the former fixed 15 s; on high-latency paths it scales
    // up proportionally so a single slow keepalive never causes a false disconnect.
    let silence_timeout = (nak_timeout * 30).max(Duration::from_secs(9));
    let mac_tag_len = kex.mac_tag_len();
    let mut udp_reader = UdpReader::builder()
        .socket(udp_arc.clone())
        .id(kex.uuid())
        .hmac(kex.build_hmac())
        .rnk(kex.build_aead_key()?)
        .mac_tag_len(mac_tag_len)
        .nak_out_tx(tx.clone())
        .retransmit_tx(retransmit_tx)
        .silence_timeout(silence_timeout)
        .nak_timeout(nak_timeout)
        .reconnect_tx(reconnect_tx)
        .query_response_tx(tx.clone())
        .diff_mode(diff_mode)
        .passthrough(legacy_passthrough)
        .build();

    let mut udp_sender = UdpSender::builder()
        .socket(udp_arc)
        .control_rx(control_rx)
        .rx(rx)
        .retransmit_rx(retransmit_rx)
        .id(kex.uuid())
        .hmac(kex.build_hmac())
        .rnk(kex.build_aead_key()?)
        .diff_mode(diff_mode)
        .build();

    let sender_token = token.clone();
    let _sender = spawn(async move { udp_sender.frame_loop(sender_token).await });

    let (cols, rows) = terminal_size().map_or((80, 24), |(w, h)| (w.0, h.0));
    tx.send(EncryptedFrame::Resize((kex.uuid_wrapper(), cols, rows)))
        .await?;

    // NAT warmup: send keepalive frames before the session loop begins so that
    // a bidirectional NAT binding is established before the server starts
    // sending terminal diffs.  This prevents the initial burst of dropped
    // packets that causes head-of-line blocking under some NAT configurations.
    // Off by default; opt in with `--nat-warmup` / `MOSHPIT_NAT_WARMUP=true`.
    if nat_warmup {
        info!(
            "NAT warmup: sending {} keepalive frame(s)",
            nat_warmup_count
        );
        for _ in 0..nat_warmup_count {
            let ts = u64::try_from(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_micros(),
            )
            .unwrap_or(0);
            tx.send(EncryptedFrame::Keepalive(ts)).await?;
        }
    }

    // ── Prediction / emulator shared state ──────────────────────────────────
    let emulator = Arc::new(std::sync::Mutex::new(Emulator::new(rows, cols)));
    let prediction = Arc::new(std::sync::Mutex::new(PredictionEngine::new(
        display_preference,
    )));
    let renderer = Arc::new(std::sync::Mutex::new(Renderer::new(rows, cols)));
    let in_alt_screen = Arc::new(AtomicBool::new(false));

    let reader_token = token.clone();
    let emu_reader = emulator.clone();
    let pred_reader = prediction.clone();
    let rend_reader = renderer.clone();
    let stdout_tx_reader = stdout_tx.clone();
    let exit_token_reader = exit_token.clone();
    let exit_msg_reader = exit_msg.clone();
    let in_alt_screen_reader = Arc::clone(&in_alt_screen);
    let _reader = spawn(async move {
        udp_reader
            .client_frame_loop(
                reader_token,
                exit_token_reader,
                exit_msg_reader,
                stdout_tx_reader,
                emu_reader,
                pred_reader,
                rend_reader,
                in_alt_screen_reader,
            )
            .await;
    });

    spawn_resize_handler(
        tx.clone(),
        kex.uuid_wrapper(),
        token.clone(),
        emulator.clone(),
        renderer.clone(),
    );

    // Stdin forwarder: holds the shared kb_rx mutex for this session's lifetime.
    let fwd_token = token.clone();
    let exit_token_fwd = exit_token.clone();
    let exit_msg_fwd = exit_msg.clone();
    let session_tx = tx;
    let uuid_wrapper = kex.uuid_wrapper();
    let emu_fwd = emulator.clone();
    let pred_fwd = prediction.clone();
    let renderer_fwd = renderer.clone();
    let stdout_tx_fwd = stdout_tx;
    let in_alt_screen_fwd = Arc::clone(&in_alt_screen);
    let forwarder = spawn(async move {
        let mut rx = kb_rx.lock().await;
        let mut escape_state = EscapeState::Normal;
        loop {
            select! {
                () = fwd_token.cancelled() => break,
                data = rx.recv() => match data {
                    Some(data) => {
                        let mut to_forward: Vec<u8> = Vec::new();
                        let mut exit_requested = false;
                        for &byte in &data {
                            escape_state = match escape_state {
                                EscapeState::Normal => {
                                    if byte == escape_byte {
                                        EscapeState::PendingDot
                                    } else {
                                        to_forward.push(byte);
                                        EscapeState::Normal
                                    }
                                }
                                EscapeState::PendingDot => {
                                    if byte == 0x2E {
                                        exit_requested = true;
                                        break;
                                    } else if byte == escape_byte {
                                        // Repeated prefix: discard, stay pending
                                        EscapeState::PendingDot
                                    } else {
                                        // Forward the held prefix byte and the current byte
                                        to_forward.push(escape_byte);
                                        to_forward.push(byte);
                                        EscapeState::Normal
                                    }
                                }
                            };
                        }
                        if !to_forward.is_empty() {
                            // Forward to server.
                            if session_tx
                                .send(EncryptedFrame::Bytes((uuid_wrapper, to_forward.clone())))
                                .await
                                .is_err()
                            {
                                break;
                            }
                            // Local echo prediction: feed each byte to the engine.
                            // Skip in alternate-screen mode (vi, htop, etc.) —
                            // the app owns the screen and prediction adds only lock contention.
                            // Use an atomic boolean updated by the frame loop so we never block
                            // a Tokio worker thread on std::sync::Mutex during vi rendering bursts.
                            let in_alt = in_alt_screen_fwd.load(Ordering::Relaxed);
                            if !in_alt {
                                let preview = if legacy_passthrough {
                                    // Legacy: paint the prediction out-of-band on top of
                                    // the raw bytes the renderer is not tracking.
                                    let (overlays, cursor) = {
                                        let emu = emu_fwd.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                                        let screen = emu.screen();
                                        let mut pred = pred_fwd.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                                        for byte in &to_forward {
                                            pred.new_user_byte(*byte, screen);
                                        }
                                        pred.apply(screen)
                                    };
                                    paint_overlays_to_ansi(&overlays, cursor)
                                } else {
                                    // Unified: render the local echo through the single
                                    // renderer so its `displayed` baseline stays exact and
                                    // the prediction self-heals when the server echoes.
                                    render_prediction_update(
                                        &emu_fwd,
                                        &pred_fwd,
                                        &renderer_fwd,
                                        &to_forward,
                                    )
                                };
                                if !preview.is_empty() {
                                    drop(stdout_tx_fwd.send(preview).await);
                                }
                            }
                        }
                        if exit_requested {
                            *exit_msg_fwd
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner) =
                                Some(b"[moshpit] Disconnected.\r\n");
                            exit_token_fwd.cancel();
                            fwd_token.cancel();
                            break;
                        }
                    }
                    None => break,
                },
            }
        }
    });
    let forwarder_abort = forwarder.abort_handle();

    // Wait for a reconnect signal or a user-requested exit (Ctrl-^ .).
    select! {
        _ = reconnect_rx.recv() => {}
        () = exit_token.cancelled() => {}
    }
    token.cancel();
    // Wait for the forwarder to release the kb_rx mutex. Give it 500 ms to exit
    // gracefully (it should be nearly instant once the token fires), then abort
    // it to guarantee the lock is released before we return.
    if time::timeout(Duration::from_millis(500), forwarder)
        .await
        .is_err()
    {
        forwarder_abort.abort();
        // Yield so the executor can drop the aborted task and release the lock.
        tokio::task::yield_now().await;
    }
    Ok(())
}

#[cfg(unix)]
fn spawn_resize_handler(
    resize_tx: Sender<EncryptedFrame>,
    resize_uuid: UuidWrapper,
    resize_token: CancellationToken,
    emulator: Arc<std::sync::Mutex<Emulator>>,
    renderer: Arc<std::sync::Mutex<Renderer>>,
) {
    let _resize_handle = spawn(async move {
        match signal(SignalKind::window_change()) {
            Ok(mut sigwinch) => loop {
                tokio::select! {
                    () = resize_token.cancelled() => break,
                    _ = sigwinch.recv() => {
                        let (columns, rows) = terminal_size()
                            .map_or((80, 24), |(width, height)| (width.0, height.0));
                        emulator.lock().unwrap_or_else(std::sync::PoisonError::into_inner).set_size(rows, columns);
                        renderer.lock().unwrap_or_else(std::sync::PoisonError::into_inner).set_size(rows, columns);
                        if let Err(e) =
                            resize_tx.send(EncryptedFrame::Resize((resize_uuid, columns, rows))).await
                        {
                            error!("Failed to send resize frame: {e}");
                            break;
                        }
                    }
                }
            },
            Err(e) => error!("Failed to register SIGWINCH handler: {e}"),
        }
    });
}

// On Windows there is no SIGWINCH.  Instead, poll GetConsoleScreenBufferInfo
// (via terminal_size) every 250 ms and send a Resize frame whenever the
// dimensions change.  This avoids touching the console input buffer so it
// does not conflict with the stdin reader below.
#[cfg(windows)]
fn spawn_resize_handler(
    resize_tx: Sender<EncryptedFrame>,
    resize_uuid: UuidWrapper,
    resize_token: CancellationToken,
    emulator: Arc<std::sync::Mutex<Emulator>>,
    renderer: Arc<std::sync::Mutex<Renderer>>,
) {
    let _resize_handle = thread::spawn(move || {
        let mut last_size = terminal_size().map_or((80, 24), |(w, h)| (w.0, h.0));
        loop {
            if resize_token.is_cancelled() {
                break;
            }
            thread::sleep(Duration::from_millis(250));
            let current_size = terminal_size().map_or(last_size, |(w, h)| (w.0, h.0));
            if current_size != last_size {
                last_size = current_size;
                let (columns, rows) = current_size;
                emulator
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .set_size(rows, columns);
                renderer
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .set_size(rows, columns);
                if let Err(e) =
                    resize_tx.blocking_send(EncryptedFrame::Resize((resize_uuid, columns, rows)))
                {
                    error!("Failed to send resize frame: {e}");
                    break;
                }
            }
        }
    });
}

fn maybe_generate_keypair(config: &Config) -> Result<()> {
    let (priv_key_path, pub_key_path) = config.key_pair_paths()?;
    if priv_key_path.try_exists()? && pub_key_path.try_exists()? {
        return Ok(());
    }

    println!("No keypair found at the configured location.");
    println!("  Private key: {}", priv_key_path.display());
    println!("  Public key:  {}", pub_key_path.display());

    let generate = Confirm::new()
        .with_prompt("Generate a new keypair now?")
        .default(true)
        .wait_for_newline(true)
        .interact()?;

    if !generate {
        return Ok(());
    }

    // Create the parent directory for the private key if needed
    if let Some(parent) = priv_key_path.parent() {
        create_key_dir(parent)?;
    }

    let passphrase: String = Password::new()
        .with_prompt(format!(
            "Enter passphrase for \"{}\"",
            priv_key_path.display()
        ))
        .with_confirmation(
            "Enter same passphrase again",
            "Passphrases do not match. Try again.",
        )
        .allow_empty_password(false)
        .report(false)
        .interact()?;
    let passphrase_opt = Some(passphrase);

    let keypair = KeyPair::generate_key_pair(
        passphrase_opt.as_ref(),
        KexMode::Client,
        KEY_ALGORITHM_X25519,
    )?;

    let mut priv_key_file = {
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&priv_key_path)?
        }
        #[cfg(not(unix))]
        {
            OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&priv_key_path)?
        }
    };
    keypair.write_private_key(&mut priv_key_file)?;

    let mut pub_key_file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&pub_key_path)?;
    keypair.write_public_key(&mut pub_key_file)?;

    println!(
        "Your identification has been saved in {}",
        priv_key_path.display()
    );
    println!(
        "Your public key has been saved in {}",
        pub_key_path.display()
    );
    println!("The key fingerprint is:");
    println!("{}", keypair.fingerprint()?);
    println!("The key's randomart image is:");
    print!("{}", keypair.randomart());

    Ok(())
}

#[cfg(target_family = "unix")]
fn create_key_dir(path: &Path) -> Result<()> {
    DirBuilder::new().mode(0o700).recursive(true).create(path)?;
    Ok(())
}

#[cfg(not(target_family = "unix"))]
fn create_key_dir(path: &Path) -> Result<()> {
    DirBuilder::new().recursive(true).create(path)?;
    Ok(())
}

fn read_passpharase() -> Result<Option<String>> {
    Password::new()
        .with_prompt("Please enter your private key passphrase")
        .report(false)
        .interact()
        .map(Some)
        .map_err(Into::into)
}

/// Returns a sanitized string identifying the current terminal, used to give each
/// terminal window its own independent session slot.
///
/// Resolves the stdin file descriptor to its TTY device path and sanitizes it for
/// use as a filename component (e.g. `/dev/pts/3` → `dev_pts_3`).  Returns `None`
/// when stdin is not a TTY (piped/scripted invocations).
#[cfg(unix)]
fn tty_id() -> Option<String> {
    use std::io::IsTerminal as _;
    if !stdin().is_terminal() {
        return None;
    }
    // Linux exposes a symlink at /proc/self/fd/0 → the actual TTY device.
    // Other Unix systems expose the same information at /dev/fd/0.
    #[cfg(target_os = "linux")]
    let link = std::fs::read_link("/proc/self/fd/0").ok()?;
    #[cfg(not(target_os = "linux"))]
    let link = std::fs::read_link("/dev/fd/0").ok()?;
    let raw = link.to_string_lossy();
    // Strip the leading slash and replace non-alphanumeric chars with '_'.
    let sanitized: String = raw
        .trim_start_matches('/')
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if sanitized.is_empty() {
        None
    } else {
        Some(sanitized)
    }
}

/// Windows equivalent: `GetConsoleWindow()` returns the HWND of the console
/// window associated with the calling process.  Like the TTY device path on
/// Unix, the HWND is:
/// - unique per console window (cmd.exe window, Windows Terminal tab, etc.)
/// - stable across process restarts within the same window
/// - different between simultaneously open windows
#[cfg(windows)]
#[allow(unsafe_code)]
fn tty_id() -> Option<String> {
    use std::io::IsTerminal as _;
    // Call Win32 GetConsoleWindow() via raw FFI — no extra crate required.
    unsafe extern "system" {
        fn GetConsoleWindow() -> *mut std::ffi::c_void;
    }
    if !stdin().is_terminal() {
        return None;
    }
    let hwnd = unsafe { GetConsoleWindow() };
    if hwnd.is_null() {
        None
    } else {
        Some(format!("{:x}", hwnd.addr()))
    }
}

#[cfg(not(any(unix, windows)))]
fn tty_id() -> Option<String> {
    None
}

fn client_id_path(home: &Path) -> PathBuf {
    home.join(".mp").join("client_id")
}

/// Returns (or creates) a stable random UUID that uniquely identifies this client
/// installation.  Written once to `~/.mp/client_id` and reused on every subsequent
/// run, so the session file for a given server can always be found regardless of the
/// current process PID.
fn client_id() -> Option<Uuid> {
    client_id_in_home(&dirs2::home_dir()?)
}

#[allow(clippy::unnecessary_wraps)]
fn client_id_in_home(home: &Path) -> Option<Uuid> {
    let path = client_id_path(home);
    if let Ok(mut f) = std::fs::File::open(&path) {
        let mut buf = String::new();
        drop(f.read_to_string(&mut buf));
        if let Ok(uuid) = buf.trim().parse::<Uuid>() {
            return Some(uuid);
        }
    }
    // First run: generate a new client ID and persist it.
    let id = Uuid::new_v4();
    if let Some(parent) = path.parent() {
        drop(std::fs::create_dir_all(parent));
    }
    if let Ok(mut f) = std::fs::File::create(&path) {
        drop(write!(f, "{id}"));
    }
    Some(id)
}

/// Returns the path `~/.mp/sessions/<client_id>_<host>_<port>[_<tty_id>]` for
/// session UUID persistence.
///
/// When stdin is a TTY the filename includes a sanitized TTY identifier (e.g.
/// `dev_pts_3`), giving each terminal window its own independent session slot.
/// Restarting after a crash in the same window reuses the same slot, enabling
/// transparent resume.  When stdin is not a TTY the TTY suffix is omitted and
/// the connection falls back to last-connect-wins semantics.
fn session_file_path(host: &str, port: u16) -> Option<PathBuf> {
    let home = dirs2::home_dir()?;
    // Sanitize host so it is safe as a file-name component.
    let safe_host: String = host
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let cid = client_id()?;
    let name = match tty_id() {
        Some(tty) => format!("{cid}_{safe_host}_{port}_{tty}"),
        None => format!("{cid}_{safe_host}_{port}"),
    };
    Some(home.join(".mp").join("sessions").join(name))
}

#[cfg(test)]
fn session_file_path_in_home(home: &Path, host: &str, port: u16) -> Option<PathBuf> {
    // Sanitize host so it is safe as a file-name component.
    let safe_host: String = host
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let cid = client_id_in_home(home)?;
    let name = match tty_id() {
        Some(tty) => format!("{cid}_{safe_host}_{port}_{tty}"),
        None => format!("{cid}_{safe_host}_{port}"),
    };
    Some(home.join(".mp").join("sessions").join(name))
}

fn read_uuid_from_path(path: &Path) -> Option<Uuid> {
    let mut file = std::fs::File::open(path).ok()?;
    let mut buf = String::new();
    let _ = file.read_to_string(&mut buf).ok();
    buf.trim().parse::<Uuid>().ok()
}

fn write_uuid_to_path(path: &Path, uuid: Uuid) -> Result<()> {
    if let Some(parent) = path.parent() {
        #[cfg(unix)]
        {
            DirBuilder::new()
                .mode(0o700)
                .recursive(true)
                .create(parent)?;
        }
        #[cfg(not(unix))]
        {
            DirBuilder::new().recursive(true).create(parent)?;
        }
    }
    let mut file = {
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(path)?
        }
        #[cfg(not(unix))]
        {
            std::fs::File::create(path)?
        }
    };
    write!(file, "{uuid}")?;
    Ok(())
}

/// Read a persisted session UUID from disk, if any.
fn read_session_uuid(host: &str, port: u16) -> Option<Uuid> {
    read_uuid_from_path(&session_file_path(host, port)?)
}

/// Write (or overwrite) the session UUID to disk.
fn write_session_uuid(host: &str, port: u16, session_uuid: Uuid) -> Result<()> {
    let path = session_file_path(host, port).ok_or_else(|| anyhow::anyhow!("no home dir"))?;
    write_uuid_to_path(&path, session_uuid)
}

#[cfg(test)]
mod tests {
    use std::{
        fs::DirBuilder,
        io::Read as _,
        path::{Path, PathBuf},
        sync::{Arc, atomic::AtomicBool},
    };

    use anyhow::Result;
    use tokio::{spawn, sync::mpsc::channel};
    use tokio_util::sync::CancellationToken;
    use uuid::Uuid;

    #[cfg(not(unix))]
    use super::key_event_to_bytes;
    use super::{
        Cli, Config, FatalKexError, PassCache, clear_reconnect_banner, client_id_in_home,
        client_id_path, connect_and_kex, countdown_reconnect_banner, create_key_dir, load,
        maybe_generate_keypair, read_uuid_from_path, session_file_path_in_home,
        show_reconnect_banner, write_uuid_to_path,
    };

    struct TestHome {
        path: PathBuf,
    }

    impl TestHome {
        fn new() -> Self {
            let path = std::env::temp_dir().join(Uuid::new_v4().to_string());
            std::fs::create_dir_all(&path).expect("failed to create temp dir");
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TestHome {
        fn drop(&mut self) {
            drop(std::fs::remove_dir_all(&self.path));
        }
    }

    /// RAII guard that temporarily overrides (or removes) an env var.
    /// Restores the original value on drop.
    struct EnvGuard {
        key: &'static str,
        original: Option<String>,
    }

    impl EnvGuard {
        #[allow(unsafe_code)]
        fn new(key: &'static str, value: Option<&str>) -> Self {
            let original = std::env::var(key).ok();
            // SAFETY: test-only; nextest runs each test in its own process so
            // there is no concurrent env access from other threads.
            match value {
                Some(v) => unsafe { std::env::set_var(key, v) },
                None => unsafe { std::env::remove_var(key) },
            }
            Self { key, original }
        }
    }

    #[allow(unsafe_code)]
    impl Drop for EnvGuard {
        fn drop(&mut self) {
            // SAFETY: same as EnvGuard::new.
            match &self.original {
                Some(v) => unsafe { std::env::set_var(self.key, v) },
                None => unsafe { std::env::remove_var(self.key) },
            }
        }
    }

    #[test]
    #[allow(unsafe_code)]
    fn env_guard_restores_original_value() {
        // Safety: nextest runs each test in its own process; no concurrent env access.
        const KEY: &str = "MOSHPIT_TEST_ENV_GUARD_RESTORE";
        unsafe { std::env::set_var(KEY, "original") };
        {
            let _guard = EnvGuard::new(KEY, Some("overridden"));
            assert_eq!(std::env::var(KEY).ok().as_deref(), Some("overridden"));
        }
        assert_eq!(std::env::var(KEY).ok().as_deref(), Some("original"));
        unsafe { std::env::remove_var(KEY) };
    }

    #[test]
    fn test_pass_cache() {
        let mut cache = PassCache::Uncached;
        assert!(!cache.is_cached());

        cache = PassCache::NoPassphrase;
        assert!(cache.is_cached());
        assert_eq!(cache.passphrase(), None);

        cache = PassCache::Passphrase("secret".to_string());
        assert!(cache.is_cached());
        assert_eq!(cache.passphrase(), Some("secret".to_string()));
    }

    #[test]
    #[should_panic(expected = "passphrase() called before caching")]
    fn test_pass_cache_panic() {
        let cache = PassCache::Uncached;
        drop(cache.passphrase());
    }

    #[tokio::test]
    async fn test_banners() -> Result<()> {
        let (tx, mut rx) = channel(10);
        show_reconnect_banner(&tx).await;
        let msg = rx
            .recv()
            .await
            .ok_or_else(|| anyhow::anyhow!("channel closed"))?;
        assert!(
            String::from_utf8_lossy(&msg).contains("[moshpit] server unreachable, reconnecting...")
        );

        clear_reconnect_banner(&tx).await;
        let msg = rx
            .recv()
            .await
            .ok_or_else(|| anyhow::anyhow!("channel closed"))?;
        assert!(String::from_utf8_lossy(&msg).ends_with("\x1b[0m\x1b[K\x1b[u"));

        let token = CancellationToken::new();
        let _ = countdown_reconnect_banner(&tx, 0, 1, 10, &token, "Ctrl-^").await;
        let msg = rx
            .recv()
            .await
            .ok_or_else(|| anyhow::anyhow!("channel closed"))?;
        assert!(String::from_utf8_lossy(&msg).contains("attempt #1"));
        assert!(String::from_utf8_lossy(&msg).contains("Ctrl-^ . to quit"));
        Ok(())
    }

    #[tokio::test]
    async fn countdown_banner_pre_cancelled_returns_true() {
        let (tx, mut _rx) = channel(10);
        let token = CancellationToken::new();
        token.cancel();
        let result = countdown_reconnect_banner(&tx, 0, 1, 10, &token, "Ctrl-^").await;
        assert!(result);
    }

    #[test]
    fn read_uuid_from_path_missing_file_returns_none() {
        let dir = std::env::temp_dir().join(Uuid::new_v4().to_string());
        let path = dir.join("session");
        assert!(read_uuid_from_path(&path).is_none());
    }

    #[test]
    fn read_uuid_from_path_garbage_returns_none() {
        let dir = std::env::temp_dir().join(Uuid::new_v4().to_string());
        std::fs::create_dir_all(&dir).expect("failed to create temp dir");
        let path = dir.join("session");
        std::fs::write(&path, "not-a-uuid").expect("failed to write test file");
        assert!(read_uuid_from_path(&path).is_none());
    }

    #[test]
    fn write_and_read_uuid_roundtrip() -> Result<()> {
        let dir = std::env::temp_dir().join(Uuid::new_v4().to_string());
        let path = dir.join("sub").join("session");
        let uuid = Uuid::new_v4();
        write_uuid_to_path(&path, uuid)?;
        assert_eq!(read_uuid_from_path(&path), Some(uuid));
        Ok(())
    }

    #[test]
    fn write_uuid_creates_parent_directories() -> Result<()> {
        let dir = std::env::temp_dir().join(Uuid::new_v4().to_string());
        let nested = dir.join("a").join("b").join("c").join("session");
        let uuid = Uuid::new_v4();
        write_uuid_to_path(&nested, uuid)?;
        assert!(nested.exists());
        Ok(())
    }

    #[test]
    fn client_id_path_is_under_dot_mp() {
        let home = TestHome::new();
        let path = client_id_path(home.path());
        assert!(path.starts_with(home.path().join(".mp")));
        assert_eq!(path.file_name().expect("path has a file name"), "client_id");
    }

    #[test]
    fn test_client_id() {
        let home = TestHome::new();
        let id1 = client_id_in_home(home.path());
        assert!(id1.is_some());
        let id2 = client_id_in_home(home.path());
        assert_eq!(id1, id2); // Should read the same from disk
    }

    #[test]
    fn test_session_uuid_persistence() -> Result<()> {
        let home = TestHome::new();
        let host = "test.host";
        let port = 12345;
        let uuid = Uuid::new_v4();

        // Write it
        let path = session_file_path_in_home(home.path(), host, port)
            .ok_or_else(|| anyhow::anyhow!("no session file path"))?;
        if let Some(parent) = path.parent() {
            DirBuilder::new().recursive(true).create(parent)?;
        }
        std::fs::write(&path, uuid.to_string())?;

        // Read it back
        let read_uuid = {
            let mut file = std::fs::File::open(&path)?;
            let mut buf = String::new();
            let _ = file.read_to_string(&mut buf)?;
            buf.trim().parse::<Uuid>()?
        };
        assert_eq!(uuid, read_uuid);
        Ok(())
    }

    #[test]
    fn test_session_file_path() -> Result<()> {
        let home = TestHome::new();
        let host = "some_host.com";
        let port = 2222;
        let path = session_file_path_in_home(home.path(), host, port)
            .ok_or_else(|| anyhow::anyhow!("no session file path"))?;
        assert!(path.to_string_lossy().contains("some_host.com"));
        assert!(path.to_string_lossy().contains("2222"));
        Ok(())
    }

    #[test]
    fn test_create_key_dir() -> Result<()> {
        let dir = std::env::temp_dir().join(Uuid::new_v4().to_string());
        let key_dir = dir.join("keys");
        create_key_dir(&key_dir)?;
        assert!(key_dir.exists());
        assert!(key_dir.is_dir());
        Ok(())
    }

    #[test]
    fn test_maybe_generate_keypair_existing() -> Result<()> {
        let dir = std::env::temp_dir().join(Uuid::new_v4().to_string());
        std::fs::create_dir_all(&dir)?;
        let priv_path = dir.join("id_x25519");
        let pub_path = dir.join("id_x25519.pub");
        let config_path = dir.join("config.toml");

        std::fs::write(&priv_path, "fake private key")?;
        std::fs::write(&pub_path, "fake public key")?;
        std::fs::write(
            &config_path,
            "[tracing.stdout]\n\
             with_target = false\n\
             with_thread_ids = false\n\
             with_thread_names = false\n\
             with_line_number = false\n\
             with_level = false\n\
             [tracing.file]\n\
             quiet = 0\n\
             verbose = 0\n\
             [tracing.file.layer]\n\
             with_target = false\n\
             with_thread_ids = false\n\
             with_thread_names = false\n\
             with_line_number = false\n\
             with_level = false\n",
        )?;

        let cli = Cli::parse_argv([
            "moshpit",
            "-c",
            config_path.to_str().expect("path is valid UTF-8"),
            "-p",
            priv_path.to_str().expect("path is valid UTF-8"),
            "-k",
            pub_path.to_str().expect("path is valid UTF-8"),
            "user@host",
        ])?;
        let config = load::<Cli, Config, Cli>(&cli, &cli, false)?;

        // Should return Ok(()) immediately without prompting
        let result = maybe_generate_keypair(&config);
        assert!(result.is_ok());
        Ok(())
    }

    #[tokio::test]
    async fn test_connect_and_kex_tcp_failure() -> Result<()> {
        let mut config = Config::default();
        let pass_cache = Arc::new(std::sync::Mutex::new(PassCache::Uncached));

        // Bind to a random port and immediately close it
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        let port = listener.local_addr()?.port();
        drop(listener);

        let addr = format!("127.0.0.1:{port}").parse()?;

        // This should fail with ConnectionRefused
        let result = connect_and_kex(
            &mut config,
            addr,
            "127.0.0.1",
            port,
            &pass_cache,
            Arc::new(AtomicBool::new(false)),
        )
        .await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .to_lowercase()
                .contains("refused")
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_connect_and_kex_kex_failure() -> Result<()> {
        // A live agent would supply an identity and bypass the empty-key-file path.
        let _agent_guard = EnvGuard::new("MOSHPIT_AGENT_SOCK", None);
        let dir = std::env::temp_dir().join(Uuid::new_v4().to_string());
        std::fs::create_dir_all(&dir)?;
        let config_path = dir.join("config.toml");
        // Empty key files: /dev/null doesn't exist on Windows, so create real empty files.
        let empty_priv_key_path = dir.join("empty_priv_key");
        let empty_pub_key_path = dir.join("empty_pub_key");
        std::fs::write(&empty_priv_key_path, b"")?;
        std::fs::write(&empty_pub_key_path, b"")?;
        std::fs::write(
            &config_path,
            "[tracing.stdout]\n\
             with_target = false\n\
             with_thread_ids = false\n\
             with_thread_names = false\n\
             with_line_number = false\n\
             with_level = false\n\
             [tracing.file]\n\
             quiet = 0\n\
             verbose = 0\n\
             [tracing.file.layer]\n\
             with_target = false\n\
             with_thread_ids = false\n\
             with_thread_names = false\n\
             with_line_number = false\n\
             with_level = false\n",
        )?;
        let cli = Cli::parse_argv([
            "moshpit",
            "-c",
            config_path.to_str().expect("test path is valid UTF-8"),
            "-p",
            empty_priv_key_path
                .to_str()
                .expect("test path is valid UTF-8"),
            "-k",
            empty_pub_key_path
                .to_str()
                .expect("test path is valid UTF-8"),
            "user@host",
        ])?;
        let mut config = load::<Cli, Config, Cli>(&cli, &cli, false)?;

        let pass_cache = Arc::new(std::sync::Mutex::new(PassCache::Uncached));

        // Bind a real listener
        let listener = match tokio::net::TcpListener::bind("127.0.0.1:0").await {
            Ok(listener) => listener,
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => return Ok(()),
            Err(e) => return Err(e.into()),
        };
        let port = listener.local_addr()?.port();

        // Spawn a task to accept the connection and send the greeting, then drop
        drop(spawn(async move {
            use tokio::io::AsyncWriteExt;
            if let Ok((mut socket, _)) = listener.accept().await {
                drop(socket.write_all(b"SSH-2.0-Moshpit\r\n").await);
            }
        }));

        let addr = format!("127.0.0.1:{port}").parse()?;

        // TcpStream::connect will succeed, but run_key_exchange will fail
        let result = connect_and_kex(
            &mut config,
            addr,
            "127.0.0.1",
            port,
            &pass_cache,
            Arc::new(AtomicBool::new(false)),
        )
        .await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.downcast_ref::<FatalKexError>().is_some(),
            "empty key files should produce FatalKexError, got: {err}"
        );
        Ok(())
    }

    #[test]
    fn fatal_kex_error_display_includes_error_and_path() {
        use libmoshpit::MoshpitError;
        let key_path = PathBuf::from("/home/user/.mp/id_x25519");
        let fatal = FatalKexError {
            inner: MoshpitError::KeyFileMissing,
            key_path: key_path.clone(),
        };
        let display = format!("{fatal}");
        assert!(
            display.contains("Key file not found"),
            "display should contain error message, got: {display}"
        );
        assert!(
            display.contains("/home/user/.mp/id_x25519"),
            "display should contain key path, got: {display}"
        );
    }

    #[tokio::test]
    async fn connect_and_kex_missing_key_file_wrapped_as_fatal_error() -> Result<()> {
        // A live agent would supply an identity and bypass the missing-key-file path.
        let _agent_guard = EnvGuard::new("MOSHPIT_AGENT_SOCK", None);
        let home = TestHome::new();
        let config_path = home.path().join("config.toml");
        // Non-existent key paths
        let priv_path = home.path().join("nonexistent_id_x25519");
        let pub_path = home.path().join("nonexistent_id_x25519.pub");
        std::fs::write(
            &config_path,
            "[tracing.stdout]\n\
             with_target = false\n\
             with_thread_ids = false\n\
             with_thread_names = false\n\
             with_line_number = false\n\
             with_level = false\n\
             [tracing.file]\n\
             quiet = 0\n\
             verbose = 0\n\
             [tracing.file.layer]\n\
             with_target = false\n\
             with_thread_ids = false\n\
             with_thread_names = false\n\
             with_line_number = false\n\
             with_level = false\n",
        )?;
        let cli = Cli::parse_argv([
            "moshpit",
            "-c",
            config_path.to_str().expect("path is valid UTF-8"),
            "-p",
            priv_path.to_str().expect("path is valid UTF-8"),
            "-k",
            pub_path.to_str().expect("path is valid UTF-8"),
            "user@host",
        ])?;
        let mut config = load::<Cli, Config, Cli>(&cli, &cli, false)?;
        let pass_cache = Arc::new(std::sync::Mutex::new(PassCache::Uncached));

        // Bind a real listener so TCP connection succeeds
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        drop(spawn(async move {
            if let Ok((_, _)) = listener.accept().await {}
        }));

        let addr = format!("127.0.0.1:{port}").parse()?;
        let result = connect_and_kex(
            &mut config,
            addr,
            "127.0.0.1",
            port,
            &pass_cache,
            Arc::new(AtomicBool::new(false)),
        )
        .await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.downcast_ref::<FatalKexError>().is_some(),
            "missing key file should produce FatalKexError, got: {err}"
        );
        Ok(())
    }

    // crossterm's Unix parser maps 0x1C-0x1F bytes to Char('4'-'7') + CONTROL.
    // Verify that encode_char_key round-trips these correctly on all platforms.
    #[cfg(not(unix))]
    #[test]
    fn ctrl_digit_aliases_produce_correct_control_codes() {
        use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyEventState, KeyModifiers};

        fn ctrl_char(c: char) -> KeyEvent {
            KeyEvent {
                code: KeyCode::Char(c),
                modifiers: KeyModifiers::CONTROL,
                kind: KeyEventKind::Press,
                state: KeyEventState::empty(),
            }
        }

        // Ctrl+6 (crossterm Unix: 0x1E → Char('6') + CONTROL) — escape prefix
        assert_eq!(key_event_to_bytes(ctrl_char('6')), b"\x1e");
        // Ctrl+4 (0x1C), Ctrl+5 (0x1D), Ctrl+7 (0x1F)
        assert_eq!(key_event_to_bytes(ctrl_char('4')), b"\x1c");
        assert_eq!(key_event_to_bytes(ctrl_char('5')), b"\x1d");
        assert_eq!(key_event_to_bytes(ctrl_char('7')), b"\x1f");
    }

    mod escape_listener {
        use std::sync::Arc;
        use tokio::sync::Mutex;
        use tokio::sync::mpsc::channel;
        use tokio_util::sync::CancellationToken;

        use super::super::run_escape_listener;

        #[tokio::test]
        async fn done_token_cancels_listener_without_triggering_exit() {
            let (tx, rx) = channel::<Vec<u8>>(8);
            let kb_rx = Arc::new(Mutex::new(rx));
            let exit_token = CancellationToken::new();
            let done_token = CancellationToken::new();
            done_token.cancel();
            run_escape_listener(
                kb_rx,
                exit_token.clone(),
                done_token,
                tokio::sync::oneshot::channel().0,
                0x1E,
            )
            .await;
            assert!(!exit_token.is_cancelled());
            drop(tx);
        }

        #[tokio::test]
        async fn sender_drop_stops_listener_without_triggering_exit() {
            let (tx, rx) = channel::<Vec<u8>>(8);
            let kb_rx = Arc::new(Mutex::new(rx));
            let exit_token = CancellationToken::new();
            let done_token = CancellationToken::new();
            drop(tx);
            run_escape_listener(
                kb_rx,
                exit_token.clone(),
                done_token,
                tokio::sync::oneshot::channel().0,
                0x1E,
            )
            .await;
            assert!(!exit_token.is_cancelled());
        }

        #[tokio::test]
        async fn normal_bytes_do_not_trigger_exit() -> anyhow::Result<()> {
            let (tx, rx) = channel::<Vec<u8>>(8);
            let kb_rx = Arc::new(Mutex::new(rx));
            let exit_token = CancellationToken::new();
            let done_token = CancellationToken::new();
            tx.send(b"hello".to_vec()).await?;
            drop(tx);
            run_escape_listener(
                kb_rx,
                exit_token.clone(),
                done_token,
                tokio::sync::oneshot::channel().0,
                0x1E,
            )
            .await;
            assert!(!exit_token.is_cancelled());
            Ok(())
        }

        #[tokio::test]
        async fn escape_prefix_then_non_dot_does_not_trigger_exit() -> anyhow::Result<()> {
            let (tx, rx) = channel::<Vec<u8>>(8);
            let kb_rx = Arc::new(Mutex::new(rx));
            let exit_token = CancellationToken::new();
            let done_token = CancellationToken::new();
            // 0x1E followed by 'x' — state resets to Normal
            tx.send(vec![0x1E, b'x']).await?;
            drop(tx);
            run_escape_listener(
                kb_rx,
                exit_token.clone(),
                done_token,
                tokio::sync::oneshot::channel().0,
                0x1E,
            )
            .await;
            assert!(!exit_token.is_cancelled());
            Ok(())
        }

        #[tokio::test]
        async fn repeated_escape_prefix_stays_pending_without_triggering_exit() -> anyhow::Result<()>
        {
            let (tx, rx) = channel::<Vec<u8>>(8);
            let kb_rx = Arc::new(Mutex::new(rx));
            let exit_token = CancellationToken::new();
            let done_token = CancellationToken::new();
            // Multiple 0x1E bytes — stays in PendingDot but never completes
            tx.send(vec![0x1E, 0x1E, 0x1E]).await?;
            drop(tx);
            run_escape_listener(
                kb_rx,
                exit_token.clone(),
                done_token,
                tokio::sync::oneshot::channel().0,
                0x1E,
            )
            .await;
            assert!(!exit_token.is_cancelled());
            Ok(())
        }

        #[tokio::test]
        async fn full_sequence_in_one_chunk_triggers_exit() -> anyhow::Result<()> {
            let (tx, rx) = channel::<Vec<u8>>(8);
            let kb_rx = Arc::new(Mutex::new(rx));
            let exit_token = CancellationToken::new();
            let done_token = CancellationToken::new();
            tx.send(vec![0x1E, 0x2E]).await?;
            run_escape_listener(
                kb_rx,
                exit_token.clone(),
                done_token,
                tokio::sync::oneshot::channel().0,
                0x1E,
            )
            .await;
            assert!(exit_token.is_cancelled());
            Ok(())
        }

        #[tokio::test]
        async fn sequence_split_across_sends_triggers_exit() -> anyhow::Result<()> {
            let (tx, rx) = channel::<Vec<u8>>(8);
            let kb_rx = Arc::new(Mutex::new(rx));
            let exit_token = CancellationToken::new();
            let done_token = CancellationToken::new();
            tx.send(vec![0x1E]).await?;
            tx.send(vec![0x2E]).await?;
            run_escape_listener(
                kb_rx,
                exit_token.clone(),
                done_token,
                tokio::sync::oneshot::channel().0,
                0x1E,
            )
            .await;
            assert!(exit_token.is_cancelled());
            Ok(())
        }

        #[tokio::test]
        async fn custom_escape_byte_triggers_and_default_does_not() -> anyhow::Result<()> {
            // With a custom prefix (0x01 / Ctrl-a), the old default prefix (0x1E)
            // must NOT trigger, and the custom prefix + '.' MUST trigger.
            let (tx, rx) = channel::<Vec<u8>>(8);
            let kb_rx = Arc::new(Mutex::new(rx));
            let exit_token = CancellationToken::new();
            let done_token = CancellationToken::new();
            // Old default sequence under a custom binding: must be ignored.
            tx.send(vec![0x1E, 0x2E]).await?;
            // Custom sequence: must trigger exit.
            tx.send(vec![0x01, 0x2E]).await?;
            run_escape_listener(
                kb_rx,
                exit_token.clone(),
                done_token,
                tokio::sync::oneshot::channel().0,
                0x01,
            )
            .await;
            assert!(exit_token.is_cancelled());
            Ok(())
        }
    }

    mod escape_key_parsing {
        use super::super::{ctrl_byte, ctrl_label, parse_escape_key};

        #[test]
        fn parses_valid_escape_keys() -> anyhow::Result<()> {
            assert_eq!(parse_escape_key("ctrl-^")?, 0x1E);
            assert_eq!(parse_escape_key("ctrl-a")?, 0x01);
            assert_eq!(parse_escape_key("CTRL-A")?, 0x01);
            assert_eq!(parse_escape_key("C-]")?, 0x1D);
            assert_eq!(parse_escape_key("  ctrl-@  ")?, 0x00);
            assert_eq!(parse_escape_key("ctrl-_")?, 0x1F);
            Ok(())
        }

        #[test]
        fn rejects_invalid_escape_keys() {
            assert!(parse_escape_key("").is_err());
            assert!(parse_escape_key("   ").is_err());
            assert!(parse_escape_key("^").is_err()); // missing ctrl- prefix
            assert!(parse_escape_key("ctrl-").is_err()); // no key char
            assert!(parse_escape_key("ctrl-ab").is_err()); // more than one key
            assert!(parse_escape_key("ctrl-[").is_err()); // ESC is rejected
            assert!(parse_escape_key("ctrl-1").is_err()); // not a control key
            assert!(parse_escape_key("nope").is_err());
        }

        #[test]
        fn ctrl_byte_excludes_esc() {
            assert_eq!(ctrl_byte('['), None);
            assert_eq!(ctrl_byte('^'), Some(0x1E));
            assert_eq!(ctrl_byte('A'), Some(0x01));
        }

        #[test]
        fn labels_round_trip_with_parse() -> anyhow::Result<()> {
            assert_eq!(ctrl_label(0x1E), "Ctrl-^");
            assert_eq!(ctrl_label(0x01), "Ctrl-A");
            assert_eq!(ctrl_label(0x1D), "Ctrl-]");
            assert_eq!(ctrl_label(0x00), "Ctrl-@");
            assert_eq!(ctrl_label(0x1F), "Ctrl-_");
            for key in ["ctrl-^", "ctrl-a", "ctrl-]", "ctrl-@", "ctrl-_"] {
                let byte = parse_escape_key(key)?;
                assert_eq!(parse_escape_key(&ctrl_label(byte))?, byte);
            }
            Ok(())
        }
    }

    #[cfg(not(unix))]
    mod key_encoding {
        use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyEventState, KeyModifiers};

        use super::super::key_event_to_bytes;

        fn press(code: KeyCode) -> KeyEvent {
            KeyEvent {
                code,
                modifiers: KeyModifiers::NONE,
                kind: KeyEventKind::Press,
                state: KeyEventState::empty(),
            }
        }

        fn press_mod(code: KeyCode, mods: KeyModifiers) -> KeyEvent {
            KeyEvent {
                code,
                modifiers: mods,
                kind: KeyEventKind::Press,
                state: KeyEventState::empty(),
            }
        }

        fn release(code: KeyCode) -> KeyEvent {
            KeyEvent {
                code,
                modifiers: KeyModifiers::NONE,
                kind: KeyEventKind::Release,
                state: KeyEventState::empty(),
            }
        }

        #[test]
        fn release_events_produce_no_bytes() {
            assert!(key_event_to_bytes(release(KeyCode::Char('a'))).is_empty());
            assert!(key_event_to_bytes(release(KeyCode::Up)).is_empty());
        }

        #[test]
        fn arrow_keys_produce_csi_sequences() {
            assert_eq!(key_event_to_bytes(press(KeyCode::Up)), b"\x1b[A");
            assert_eq!(key_event_to_bytes(press(KeyCode::Down)), b"\x1b[B");
            assert_eq!(key_event_to_bytes(press(KeyCode::Right)), b"\x1b[C");
            assert_eq!(key_event_to_bytes(press(KeyCode::Left)), b"\x1b[D");
        }

        #[test]
        fn arrow_keys_with_shift_use_modifier_param() {
            let shift = KeyModifiers::SHIFT;
            assert_eq!(
                key_event_to_bytes(press_mod(KeyCode::Up, shift)),
                b"\x1b[1;2A"
            );
            assert_eq!(
                key_event_to_bytes(press_mod(KeyCode::Down, shift)),
                b"\x1b[1;2B"
            );
            assert_eq!(
                key_event_to_bytes(press_mod(KeyCode::Right, shift)),
                b"\x1b[1;2C"
            );
            assert_eq!(
                key_event_to_bytes(press_mod(KeyCode::Left, shift)),
                b"\x1b[1;2D"
            );
        }

        #[test]
        fn arrow_keys_with_ctrl_use_modifier_param() {
            let ctrl = KeyModifiers::CONTROL;
            assert_eq!(
                key_event_to_bytes(press_mod(KeyCode::Up, ctrl)),
                b"\x1b[1;5A"
            );
            assert_eq!(
                key_event_to_bytes(press_mod(KeyCode::Left, ctrl)),
                b"\x1b[1;5D"
            );
        }

        #[test]
        fn navigation_keys() {
            assert_eq!(key_event_to_bytes(press(KeyCode::Home)), b"\x1b[H");
            assert_eq!(key_event_to_bytes(press(KeyCode::End)), b"\x1b[F");
            assert_eq!(key_event_to_bytes(press(KeyCode::Insert)), b"\x1b[2~");
            assert_eq!(key_event_to_bytes(press(KeyCode::Delete)), b"\x1b[3~");
            assert_eq!(key_event_to_bytes(press(KeyCode::PageUp)), b"\x1b[5~");
            assert_eq!(key_event_to_bytes(press(KeyCode::PageDown)), b"\x1b[6~");
        }

        #[test]
        fn navigation_keys_with_modifier() {
            let ctrl = KeyModifiers::CONTROL;
            assert_eq!(
                key_event_to_bytes(press_mod(KeyCode::Home, ctrl)),
                b"\x1b[1;5H"
            );
            assert_eq!(
                key_event_to_bytes(press_mod(KeyCode::End, ctrl)),
                b"\x1b[1;5F"
            );
            assert_eq!(
                key_event_to_bytes(press_mod(KeyCode::Insert, ctrl)),
                b"\x1b[2;5~"
            );
            assert_eq!(
                key_event_to_bytes(press_mod(KeyCode::Delete, ctrl)),
                b"\x1b[3;5~"
            );
            assert_eq!(
                key_event_to_bytes(press_mod(KeyCode::PageUp, ctrl)),
                b"\x1b[5;5~"
            );
            assert_eq!(
                key_event_to_bytes(press_mod(KeyCode::PageDown, ctrl)),
                b"\x1b[6;5~"
            );
        }

        #[test]
        fn function_keys() {
            assert_eq!(key_event_to_bytes(press(KeyCode::F(1))), b"\x1bOP");
            assert_eq!(key_event_to_bytes(press(KeyCode::F(2))), b"\x1bOQ");
            assert_eq!(key_event_to_bytes(press(KeyCode::F(3))), b"\x1bOR");
            assert_eq!(key_event_to_bytes(press(KeyCode::F(4))), b"\x1bOS");
            assert_eq!(key_event_to_bytes(press(KeyCode::F(5))), b"\x1b[15~");
            assert_eq!(key_event_to_bytes(press(KeyCode::F(6))), b"\x1b[17~");
            assert_eq!(key_event_to_bytes(press(KeyCode::F(7))), b"\x1b[18~");
            assert_eq!(key_event_to_bytes(press(KeyCode::F(8))), b"\x1b[19~");
            assert_eq!(key_event_to_bytes(press(KeyCode::F(9))), b"\x1b[20~");
            assert_eq!(key_event_to_bytes(press(KeyCode::F(10))), b"\x1b[21~");
            assert_eq!(key_event_to_bytes(press(KeyCode::F(11))), b"\x1b[23~");
            assert_eq!(key_event_to_bytes(press(KeyCode::F(12))), b"\x1b[24~");
        }

        #[test]
        fn function_keys_out_of_range_produce_no_bytes() {
            assert!(key_event_to_bytes(press(KeyCode::F(0))).is_empty());
            assert!(key_event_to_bytes(press(KeyCode::F(13))).is_empty());
        }

        #[test]
        fn function_keys_with_modifier() {
            let shift = KeyModifiers::SHIFT;
            assert_eq!(
                key_event_to_bytes(press_mod(KeyCode::F(1), shift)),
                b"\x1b[1;2P"
            );
            assert_eq!(
                key_event_to_bytes(press_mod(KeyCode::F(5), shift)),
                b"\x1b[15;2~"
            );
            assert_eq!(
                key_event_to_bytes(press_mod(KeyCode::F(12), shift)),
                b"\x1b[24;2~"
            );
        }

        #[test]
        fn simple_keys() {
            assert_eq!(key_event_to_bytes(press(KeyCode::Backspace)), b"\x7f");
            assert_eq!(key_event_to_bytes(press(KeyCode::Enter)), b"\r");
            assert_eq!(key_event_to_bytes(press(KeyCode::Tab)), b"\t");
            assert_eq!(key_event_to_bytes(press(KeyCode::BackTab)), b"\x1b[Z");
            assert_eq!(key_event_to_bytes(press(KeyCode::Esc)), b"\x1b");
            assert_eq!(key_event_to_bytes(press(KeyCode::Null)), b"\x00");
        }

        #[test]
        fn printable_chars() {
            assert_eq!(key_event_to_bytes(press(KeyCode::Char('a'))), b"a");
            assert_eq!(key_event_to_bytes(press(KeyCode::Char('Z'))), b"Z");
            assert_eq!(key_event_to_bytes(press(KeyCode::Char('!'))), b"!");
        }

        #[test]
        fn non_ascii_char_encodes_utf8() {
            assert_eq!(
                key_event_to_bytes(press(KeyCode::Char('\u{00e9}'))), // é
                "\u{00e9}".as_bytes()
            );
        }

        #[test]
        fn ctrl_chars_produce_control_codes() {
            let ctrl = KeyModifiers::CONTROL;
            assert_eq!(
                key_event_to_bytes(press_mod(KeyCode::Char('a'), ctrl)),
                b"\x01"
            );
            assert_eq!(
                key_event_to_bytes(press_mod(KeyCode::Char('c'), ctrl)),
                b"\x03"
            );
            assert_eq!(
                key_event_to_bytes(press_mod(KeyCode::Char('z'), ctrl)),
                b"\x1a"
            );
            // Ctrl-@ → NUL (0x00)
            assert_eq!(
                key_event_to_bytes(press_mod(KeyCode::Char('@'), ctrl)),
                b"\x00"
            );
            // Ctrl-[ → ESC (0x1B)
            assert_eq!(
                key_event_to_bytes(press_mod(KeyCode::Char('['), ctrl)),
                b"\x1b"
            );
            // Ctrl-^ is the moshpit escape prefix
            assert_eq!(
                key_event_to_bytes(press_mod(KeyCode::Char('^'), ctrl)),
                b"\x1e"
            );
        }

        #[test]
        fn ctrl_non_ascii_encodes_utf8_fallback() {
            let ctrl = KeyModifiers::CONTROL;
            // Non-ASCII + Ctrl has no standard control code; falls through to UTF-8
            let result = key_event_to_bytes(press_mod(KeyCode::Char('\u{00e9}'), ctrl));
            assert_eq!(result, "\u{00e9}".as_bytes());
        }

        #[test]
        fn alt_chars_prefix_with_escape() {
            let alt = KeyModifiers::ALT;
            assert_eq!(
                key_event_to_bytes(press_mod(KeyCode::Char('a'), alt)),
                b"\x1ba"
            );
            assert_eq!(
                key_event_to_bytes(press_mod(KeyCode::Char('z'), alt)),
                b"\x1bz"
            );
        }

        #[test]
        fn ctrl_alt_chars_prefix_with_escape_and_control_code() {
            let ctrl_alt = KeyModifiers::CONTROL | KeyModifiers::ALT;
            // Ctrl+Alt+a → ESC + 0x01
            assert_eq!(
                key_event_to_bytes(press_mod(KeyCode::Char('a'), ctrl_alt)),
                b"\x1b\x01"
            );
        }

        #[test]
        fn ctrl_alt_non_ascii_utf8_fallback() {
            let ctrl_alt = KeyModifiers::CONTROL | KeyModifiers::ALT;
            // Non-ASCII + Ctrl+Alt falls through to UTF-8 with ESC prefix
            let result = key_event_to_bytes(press_mod(KeyCode::Char('\u{00e9}'), ctrl_alt));
            let mut expected = b"\x1b".to_vec();
            expected.extend_from_slice("\u{00e9}".as_bytes());
            assert_eq!(result, expected);
        }
    }
}
