// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

//! Minimal systemd-logind client.
//!
//! When `mps` runs as root it registers a logind session for each spawned login
//! shell by calling `org.freedesktop.login1.Manager.CreateSession` over the
//! system D-Bus bus.  This is exactly what `pam_systemd.so` does during an SSH
//! login: it makes logind create `/run/user/UID`, start `user@UID.service` (and
//! therefore the user's `systemctl --user` units), and expose the user D-Bus
//! bus.
//!
//! We talk to logind directly via the pure-Rust `zbus` crate rather than linking
//! `libpam`, so this works in a fully static MUSL binary (`libpam` `dlopen`s
//! glibc modules and cannot be statically linked).

use anyhow::{Context as _, Result};
use zbus::zvariant::{OwnedFd, OwnedObjectPath, Value};

/// Reply tuple from `org.freedesktop.login1.Manager.CreateSession`:
/// `(session_id, object_path, runtime_path, fifo_fd, uid, seat_id, vtnr, existing)`.
type CreateSessionReply = (
    String,
    OwnedObjectPath,
    String,
    OwnedFd,
    u32,
    String,
    u32,
    bool,
);

#[zbus::proxy(
    interface = "org.freedesktop.login1.Manager",
    default_service = "org.freedesktop.login1",
    default_path = "/org/freedesktop/login1"
)]
trait Manager {
    /// Register a new session with logind.  Mirrors the call `pam_systemd` makes.
    #[allow(clippy::too_many_arguments)]
    fn create_session(
        &self,
        uid: u32,
        leader_pid: u32,
        service: &str,
        session_type: &str,
        class: &str,
        desktop: &str,
        seat_id: &str,
        vtnr: u32,
        tty: &str,
        display: &str,
        remote: bool,
        remote_user: &str,
        remote_host: &str,
        properties: &[(&str, Value<'_>)],
    ) -> zbus::Result<CreateSessionReply>;
}

/// A live logind session.
///
/// The session stays registered for as long as `_fifo` is held open; dropping
/// this value closes the fd, which tells logind to release the session (the same
/// lifetime contract `pam_systemd` relies on).  `mps` keeps it alive in the PTY
/// thread for the duration of the login shell.
pub(crate) struct LogindSession {
    pub(crate) session_id: String,
    pub(crate) runtime_path: String,
    _fifo: OwnedFd,
}

/// Register a logind session whose scope leader is `leader_pid` (the login
/// shell).  `tty` is the slave terminal name relative to `/dev` (e.g. `pts/3`).
///
/// Requires the caller to be privileged (root); logind rejects `CreateSession`
/// from unprivileged callers.
pub(crate) fn create_session(
    uid: u32,
    leader_pid: u32,
    tty: &str,
    remote_host: Option<&str>,
) -> Result<LogindSession> {
    let connection = zbus::blocking::Connection::system().context("connect to system D-Bus bus")?;
    let manager = ManagerProxyBlocking::new(&connection).context("build login1 manager proxy")?;

    let remote = remote_host.is_some();
    let remote_host = remote_host.unwrap_or("");
    let no_properties: &[(&str, Value<'_>)] = &[];

    let (session_id, _object_path, runtime_path, fifo, _uid, _seat, _vtnr, _existing) = manager
        .create_session(
            uid,
            leader_pid,
            "mps",
            "tty",
            "user",
            "",
            "",
            0,
            tty,
            "",
            remote,
            "",
            remote_host,
            no_properties,
        )
        .context("logind CreateSession failed")?;

    Ok(LogindSession {
        session_id,
        runtime_path,
        _fifo: fifo,
    })
}
