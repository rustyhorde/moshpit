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
    sync::Arc,
    thread,
    time::Duration,
};

#[cfg(target_family = "unix")]
use std::os::unix::fs::DirBuilderExt;

use anyhow::{Context as _, Result};
use clap::Parser as _;
use crossterm::terminal::enable_raw_mode;
use dialoguer::{Confirm, Password};
use libmoshpit::{
    DisplayPreference, Emulator, EncryptedFrame, Kex, KexConfig as _, KexMode, KeyPair,
    MoshpitError, PredictionEngine, Renderer, UdpReader, UdpSender, UuidWrapper, init_tracing,
    load, paint_overlays_to_ansi, parse_server_destination, run_key_exchange,
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
use tracing::{error, info, trace};
use uuid::Uuid;

use crate::{cli::Cli, config::Config};

#[cfg_attr(coverage_nightly, coverage(off))]
pub(crate) async fn run<I, T>(args: Option<I>) -> Result<()>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let cli = if let Some(args) = args {
        Cli::try_parse_from(args)?
    } else {
        Cli::try_parse()?
    };
    let mut config =
        load::<Cli, Config, Cli>(&cli, &cli).with_context(|| MoshpitError::ConfigLoad)?;
    init_tracing(&config, config.tracing().file(), &cli, None)
        .with_context(|| MoshpitError::TracingInit)?;
    maybe_generate_keypair(&config)?;

    let (user, socket_addr) =
        parse_server_destination(config.server_destination(), config.server_port())?;
    let server_ip = socket_addr.ip().to_string();
    let server_port = config.server_port();
    let _ = config.set_user(user);

    run_session_loop(config, socket_addr, server_ip, server_port).await
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
async fn countdown_reconnect_banner(
    stdout_tx: &Sender<Vec<u8>>,
    total_secs: u64,
    attempt: u32,
    max_backoff_secs: u64,
) {
    for remaining in (0..=total_secs).rev() {
        let msg = format!(
            "\x1b[s\x1b[1;1H\x1b[44;97;1m [moshpit] server unreachable, reconnecting \
(attempt #{attempt}, {remaining}s, max {max_backoff_secs}s)... \x1b[K\x1b[0m\x1b[u"
        );
        drop(stdout_tx.send(msg.into_bytes()).await);
        if remaining > 0 {
            time::sleep(Duration::from_secs(1)).await;
        }
    }
}

/// Persistent reconnect loop.  Runs until the shell exits (via `process::exit`).
#[cfg_attr(coverage_nightly, coverage(off))]
async fn run_session_loop(
    config: Config,
    socket_addr: SocketAddr,
    server_ip: String,
    server_port: u16,
) -> Result<()> {
    // Clamp to [2 s, 24 h].
    let max_backoff = Duration::from_secs(config.max_reconnect_backoff_secs().clamp(2, 86_400));

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
    // Stdin reader is started once, after the first successful kex (so that raw
    // mode is not active while dialoguer reads the passphrase).
    let mut kb_rx_shared: Option<Arc<Mutex<Receiver<Vec<u8>>>>> = None;

    loop {
        match connect_and_kex(
            &mut config,
            socket_addr,
            &server_ip,
            server_port,
            &pass_cache,
        )
        .await
        {
            Ok((kex, udp_arc)) => {
                backoff = Duration::from_secs(2);

                // Enable raw mode and start the stdin reader on the first
                // successful kex.  By this point the passphrase has been
                // collected and cached, so raw mode won't interfere with it
                // on reconnects.
                let kb_rx = if let Some(ref rx) = kb_rx_shared {
                    // This is a reconnect — clear the banner before the session starts.
                    clear_reconnect_banner(&stdout_tx).await;
                    rx.clone()
                } else {
                    enable_raw_mode()?;
                    let (kb_tx, kb_rx) = channel::<Vec<u8>>(64);
                    let _stdin_thread = thread::spawn(move || {
                        let mut buf = [0u8; 4096];
                        loop {
                            match stdin().read(&mut buf) {
                                Ok(0) | Err(_) => break,
                                Ok(n) => {
                                    if kb_tx.blocking_send(buf[..n].to_vec()).is_err() {
                                        break;
                                    }
                                }
                            }
                        }
                    });
                    let shared = Arc::new(Mutex::new(kb_rx));
                    kb_rx_shared = Some(shared.clone());
                    shared
                };

                run_udp_session(kex, udp_arc, kb_rx, stdout_tx.clone(), config.predict()).await?;
                // Session dropped — show the reconnecting banner while we retry.
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
                    return Err(e);
                }
                reconnect_attempt = reconnect_attempt.saturating_add(1);
                error!("Failed to connect to {socket_addr}: {e}, retrying in {backoff:?}");
                // If raw mode is not yet active (first connection attempt), the
                // failure may be due to a wrong passphrase.  Reset the cache so
                // the user can re-enter it with a clean terminal on the next try.
                if kb_rx_shared.is_none() {
                    *pass_cache.lock().unwrap() = PassCache::Uncached;
                }
                countdown_reconnect_banner(
                    &stdout_tx,
                    backoff.as_secs(),
                    reconnect_attempt,
                    max_backoff.as_secs(),
                )
                .await;
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
) -> Result<(Kex, Arc<UdpSocket>)> {
    // Refresh resume UUID from disk (may have been updated by previous connection).
    let _ = config.set_resume_session_uuid(read_session_uuid(server_ip, server_port));

    let socket = TcpStream::connect(socket_addr).await?;
    info!("Connected to {}", socket.peer_addr()?);

    let cache = pass_cache.clone();
    let pass_fn = move || -> Result<Option<String>> {
        let guard = cache.lock().unwrap();
        if guard.is_cached() {
            info!(
                "passphrase: returning cached value (has_passphrase={})",
                guard.passphrase().is_some()
            );
            return Ok(guard.passphrase());
        }
        drop(guard);
        info!("passphrase: prompting user");
        let result = tokio::task::block_in_place(read_passpharase);
        match &result {
            Ok(Some(_)) => info!("passphrase: prompt returned a passphrase"),
            Ok(None) => info!("passphrase: prompt returned None (key may be unencrypted)"),
            Err(e) => error!("passphrase: prompt failed: {e}"),
        }
        if let Ok(ref pass) = result {
            *cache.lock().unwrap() = match pass {
                Some(s) => PassCache::Passphrase(s.clone()),
                None => PassCache::NoPassphrase,
            };
        }
        result
    };

    let (sock_read, sock_write) = socket.into_split();

    let tofu_fn: libmoshpit::TofuFn = Arc::new(|host: &str, fingerprint: &str| -> Result<bool> {
        tokio::task::block_in_place(|| {
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
    });

    let mismatch_fn: libmoshpit::HostKeyMismatchFn = Arc::new(
        |host: &str, old_fingerprint: &str, new_fingerprint: &str| -> Result<bool> {
            tokio::task::block_in_place(|| {
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
        },
    );

    let (kex, udp_arc, _) = run_key_exchange(
        config.clone(),
        sock_read,
        sock_write,
        pass_fn,
        Some(tofu_fn),
        Some(mismatch_fn),
    )
    .await
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
    Ok((kex, udp_arc))
}

/// Set up UDP tasks for one session and wait until the server disconnects.
#[cfg_attr(nightly, allow(clippy::too_many_lines))]
#[cfg_attr(coverage_nightly, coverage(off))]
async fn run_udp_session(
    kex: Kex,
    udp_arc: Arc<UdpSocket>,
    kb_rx: Arc<Mutex<Receiver<Vec<u8>>>>,
    stdout_tx: Sender<Vec<u8>>,
    display_preference: DisplayPreference,
) -> Result<()> {
    let (reconnect_tx, mut reconnect_rx) = channel::<()>(1);
    let token = CancellationToken::new();
    let (tx, rx) = channel::<EncryptedFrame>(256);
    let (retransmit_tx, retransmit_rx) = channel::<Vec<u64>>(512);

    let mut udp_reader = UdpReader::builder()
        .socket(udp_arc.clone())
        .id(kex.uuid())
        .hmac(kex.hmac_key())
        .rnk(kex.key())?
        .nak_out_tx(tx.clone())
        .retransmit_tx(retransmit_tx)
        .silence_timeout(Duration::from_secs(15))
        .reconnect_tx(reconnect_tx)
        .query_response_tx(tx.clone())
        .build();

    let mut udp_sender = UdpSender::builder()
        .socket(udp_arc)
        .rx(rx)
        .retransmit_rx(retransmit_rx)
        .id(kex.uuid())
        .hmac(kex.hmac_key())
        .rnk(kex.key())?
        .build();

    let sender_token = token.clone();
    let _sender = spawn(async move { udp_sender.frame_loop(sender_token).await });

    let (cols, rows) = terminal_size().map_or((80, 24), |(w, h)| (w.0, h.0));
    tx.send(EncryptedFrame::Resize((kex.uuid_wrapper(), cols, rows)))
        .await?;

    // ── Prediction / emulator shared state ──────────────────────────────────
    let emulator = Arc::new(std::sync::Mutex::new(Emulator::new(rows, cols)));
    let prediction = Arc::new(std::sync::Mutex::new(PredictionEngine::new(
        display_preference,
    )));
    let renderer = Arc::new(std::sync::Mutex::new(Renderer::new(rows, cols)));

    let reader_token = token.clone();
    let emu_reader = emulator.clone();
    let pred_reader = prediction.clone();
    let rend_reader = renderer.clone();
    let stdout_tx_reader = stdout_tx.clone();
    let _reader = spawn(async move {
        udp_reader
            .client_frame_loop(
                reader_token,
                stdout_tx_reader,
                emu_reader,
                pred_reader,
                rend_reader,
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
    let session_tx = tx;
    let uuid_wrapper = kex.uuid_wrapper();
    let emu_fwd = emulator.clone();
    let pred_fwd = prediction.clone();
    let stdout_tx_fwd = stdout_tx;
    let _forwarder = spawn(async move {
        let mut rx = kb_rx.lock().await;
        loop {
            select! {
                () = fwd_token.cancelled() => break,
                data = rx.recv() => match data {
                    Some(data) => {
                        // Forward to server.
                        if session_tx
                            .send(EncryptedFrame::Bytes((uuid_wrapper, data.clone())))
                            .await
                            .is_err()
                        {
                            break;
                        }
                        // Local echo prediction: feed each byte to the engine.
                        let (overlays, cursor) = {
                            let emu = emu_fwd.lock().unwrap();
                            let screen = emu.screen();
                            let mut pred = pred_fwd.lock().unwrap();
                            for byte in &data {
                                pred.new_user_byte(*byte, screen);
                            }
                            pred.apply(screen)
                        };
                        let preview = paint_overlays_to_ansi(&overlays, cursor);
                        if !preview.is_empty() {
                            drop(stdout_tx_fwd.send(preview).await);
                        }
                    }
                    None => break,
                },
            }
        }
    });

    // Wait for reconnect signal; `process::exit` handles all clean exits.
    let _ = reconnect_rx.recv().await;
    token.cancel();
    // Allow the stdin forwarder to release the kb_rx mutex before the next session.
    time::sleep(Duration::from_millis(150)).await;
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
                        emulator.lock().unwrap().set_size(rows, columns);
                        renderer.lock().unwrap().set_size(rows, columns);
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
                emulator.lock().unwrap().set_size(rows, columns);
                renderer.lock().unwrap().set_size(rows, columns);
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

    let keypair = KeyPair::generate_key_pair(passphrase_opt.as_ref(), KexMode::Client)?;

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

/// Read a persisted session UUID from disk, if any.
fn read_session_uuid(host: &str, port: u16) -> Option<Uuid> {
    let path = session_file_path(host, port)?;
    let mut file = std::fs::File::open(&path).ok()?;
    let mut buf = String::new();
    let _ = file.read_to_string(&mut buf).ok();
    buf.trim().parse::<Uuid>().ok()
}

/// Write (or overwrite) the session UUID to disk.
fn write_session_uuid(host: &str, port: u16, session_uuid: Uuid) -> Result<()> {
    let path = session_file_path(host, port).ok_or_else(|| anyhow::anyhow!("no home dir"))?;
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
                .open(&path)?
        }
        #[cfg(not(unix))]
        {
            std::fs::File::create(&path)?
        }
    };
    write!(file, "{session_uuid}")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    struct TestHome {
        path: PathBuf,
    }

    impl TestHome {
        fn new() -> Self {
            let path = std::env::temp_dir().join(Uuid::new_v4().to_string());
            std::fs::create_dir_all(&path).unwrap();
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
    async fn test_banners() {
        let (tx, mut rx) = channel(10);
        show_reconnect_banner(&tx).await;
        let msg = rx.recv().await.unwrap();
        assert!(
            String::from_utf8_lossy(&msg).contains("[moshpit] server unreachable, reconnecting...")
        );

        clear_reconnect_banner(&tx).await;
        let msg = rx.recv().await.unwrap();
        assert!(String::from_utf8_lossy(&msg).ends_with("\x1b[0m\x1b[K\x1b[u"));

        countdown_reconnect_banner(&tx, 0, 1, 10).await;
        let msg = rx.recv().await.unwrap();
        assert!(String::from_utf8_lossy(&msg).contains("attempt #1"));
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
    fn test_session_uuid_persistence() {
        let home = TestHome::new();
        let host = "test.host";
        let port = 12345;
        let uuid = Uuid::new_v4();

        // Write it
        let path = session_file_path_in_home(home.path(), host, port).unwrap();
        if let Some(parent) = path.parent() {
            DirBuilder::new().recursive(true).create(parent).unwrap();
        }
        std::fs::write(&path, uuid.to_string()).unwrap();

        // Read it back
        let read_uuid = {
            let mut file = std::fs::File::open(&path).unwrap();
            let mut buf = String::new();
            let _ = file.read_to_string(&mut buf).unwrap();
            buf.trim().parse::<Uuid>().unwrap()
        };
        assert_eq!(uuid, read_uuid);
    }

    #[test]
    fn test_session_file_path() {
        let home = TestHome::new();
        let host = "some_host.com";
        let port = 2222;
        let path = session_file_path_in_home(home.path(), host, port).unwrap();
        assert!(path.to_string_lossy().contains("some_host.com"));
        assert!(path.to_string_lossy().contains("2222"));
    }

    #[test]
    fn test_create_key_dir() {
        let dir = std::env::temp_dir().join(Uuid::new_v4().to_string());
        let key_dir = dir.join("keys");
        create_key_dir(&key_dir).unwrap();
        assert!(key_dir.exists());
        assert!(key_dir.is_dir());
    }

    #[test]
    fn test_maybe_generate_keypair_existing() {
        let dir = std::env::temp_dir().join(Uuid::new_v4().to_string());
        std::fs::create_dir_all(&dir).unwrap();
        let priv_path = dir.join("id_ed25519");
        let pub_path = dir.join("id_ed25519.pub");
        let config_path = dir.join("config.toml");

        std::fs::write(&priv_path, "fake private key").unwrap();
        std::fs::write(&pub_path, "fake public key").unwrap();
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
        )
        .unwrap();

        let cli = Cli::try_parse_from([
            "moshpit",
            "-c",
            config_path.to_str().unwrap(),
            "-p",
            priv_path.to_str().unwrap(),
            "-k",
            pub_path.to_str().unwrap(),
            "user@host",
        ])
        .unwrap();
        let config = load::<Cli, Config, Cli>(&cli, &cli).unwrap();

        // Should return Ok(()) immediately without prompting
        let result = maybe_generate_keypair(&config);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_connect_and_kex_tcp_failure() {
        let mut config = Config::default();
        let pass_cache = Arc::new(std::sync::Mutex::new(PassCache::Uncached));

        // Bind to a random port and immediately close it
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let addr = format!("127.0.0.1:{port}").parse().unwrap();

        // This should fail with ConnectionRefused
        let result = connect_and_kex(&mut config, addr, "127.0.0.1", port, &pass_cache).await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .to_lowercase()
                .contains("refused")
        );
    }

    #[tokio::test]
    #[should_panic(expected = "split_to out of bounds")]
    async fn test_connect_and_kex_kex_failure() {
        let dir = std::env::temp_dir().join(Uuid::new_v4().to_string());
        std::fs::create_dir_all(&dir).unwrap();
        let config_path = dir.join("config.toml");
        // Empty key files: /dev/null doesn't exist on Windows, so create real empty files.
        let empty_priv_key_path = dir.join("empty_priv_key");
        let empty_pub_key_path = dir.join("empty_pub_key");
        std::fs::write(&empty_priv_key_path, b"").unwrap();
        std::fs::write(&empty_pub_key_path, b"").unwrap();
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
        )
        .unwrap();
        let cli = Cli::try_parse_from([
            "moshpit",
            "-c",
            config_path.to_str().unwrap(),
            "-p",
            empty_priv_key_path.to_str().unwrap(),
            "-k",
            empty_pub_key_path.to_str().unwrap(),
            "user@host",
        ])
        .unwrap();
        let mut config = load::<Cli, Config, Cli>(&cli, &cli).unwrap();

        let pass_cache = Arc::new(std::sync::Mutex::new(PassCache::Uncached));

        // Bind a real listener
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        // Spawn a task to accept the connection and send the greeting, then drop
        drop(spawn(async move {
            use tokio::io::AsyncWriteExt;
            if let Ok((mut socket, _)) = listener.accept().await {
                drop(socket.write_all(b"SSH-2.0-Moshpit\r\n").await);
            }
        }));

        let addr = format!("127.0.0.1:{port}").parse().unwrap();

        // TcpStream::connect will succeed, but run_key_exchange will fail
        let result = connect_and_kex(&mut config, addr, "127.0.0.1", port, &pass_cache).await;
        assert!(result.is_err());
    }

    #[test]
    fn fatal_kex_error_display_includes_error_and_path() {
        use libmoshpit::MoshpitError;
        let key_path = PathBuf::from("/home/user/.mp/id_ed25519");
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
            display.contains("/home/user/.mp/id_ed25519"),
            "display should contain key path, got: {display}"
        );
    }

    #[tokio::test]
    async fn connect_and_kex_missing_key_file_wrapped_as_fatal_error() {
        use clap::Parser as _;
        let home = TestHome::new();
        let config_path = home.path().join("config.toml");
        // Non-existent key paths
        let priv_path = home.path().join("nonexistent_id_ed25519");
        let pub_path = home.path().join("nonexistent_id_ed25519.pub");
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
        )
        .unwrap();
        let cli = Cli::try_parse_from([
            "moshpit",
            "-c",
            config_path.to_str().unwrap(),
            "-p",
            priv_path.to_str().unwrap(),
            "-k",
            pub_path.to_str().unwrap(),
            "user@host",
        ])
        .unwrap();
        let mut config = load::<Cli, Config, Cli>(&cli, &cli).unwrap();
        let pass_cache = Arc::new(std::sync::Mutex::new(PassCache::Uncached));

        // Bind a real listener so TCP connection succeeds
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(spawn(async move {
            if let Ok((_, _)) = listener.accept().await {}
        }));

        let addr = format!("127.0.0.1:{port}").parse().unwrap();
        let result = connect_and_kex(&mut config, addr, "127.0.0.1", port, &pass_cache).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.downcast_ref::<FatalKexError>().is_some(),
            "missing key file should produce FatalKexError, got: {err}"
        );
    }
}
