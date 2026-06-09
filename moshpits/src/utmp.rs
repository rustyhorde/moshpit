// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

//! Classic `utmp`/`wtmp` login accounting.
//!
//! When `mps` runs as root it records each spawned login shell in the legacy
//! login databases so the session shows up in `who`, `w`, and `last` — exactly
//! like an SSH login does.  On connect we write a `USER_PROCESS` record into
//! `/var/run/utmp` ("who is on now") and append it to `/var/log/wtmp` (the login
//! history `last` reads); on disconnect we flip the utmp slot to `DEAD_PROCESS`
//! and append a matching record to wtmp.
//!
//! We write the glibc `struct utmpx` on-disk format directly rather than calling
//! libc's `pututxline`/`updwtmp`.  This is deliberate: those functions are no-ops
//! under musl (musl points `utmp`/`wtmp` at `/dev/null`), so a static MUSL binary
//! cannot rely on them, yet the consumers (`who`/`w`/`last`) on the target glibc
//! systems read the glibc binary layout.  Writing the bytes ourselves keeps the
//! fully static MUSL build intact with no new dependency, mirroring how
//! [`crate::logind`] talks to logind via `zbus` instead of linking `libpam`.

use anyhow::{Context as _, Result};
use core::mem::offset_of;
use std::fs::{File, OpenOptions};
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::net::IpAddr;
use std::os::unix::io::AsRawFd as _;
use std::time::{SystemTime, UNIX_EPOCH};

/// The current login databases written by [`login`]/[`logout`].
const UTMP_PATH: &str = "/var/run/utmp";
/// The append-only login history read by `last`.
const WTMP_PATH: &str = "/var/log/wtmp";

// `ut_type` values (see `bits/utmp.h`).
const EMPTY: i16 = 0;
const USER_PROCESS: i16 = 7;
const DEAD_PROCESS: i16 = 8;

/// glibc `struct utmpx` as written to disk on 64-bit little-endian targets
/// (`x86_64`, `aarch64`), where `__WORDSIZE_TIME64_COMPAT32` makes `ut_session` an
/// `i32` and `ut_tv` a pair of `i32`s so the record is identical for 32- and
/// 64-bit readers.  We never construct or read this struct directly — it is the
/// single source of truth for field offsets via [`offset_of!`], so the byte
/// serializer in [`record_bytes`] cannot drift from the real layout.
#[repr(C)]
#[allow(dead_code)]
struct Utmpx {
    ut_type: i16,
    ut_pid: i32,
    ut_line: [u8; 32],
    ut_id: [u8; 4],
    ut_user: [u8; 32],
    ut_host: [u8; 256],
    ut_exit: ExitStatus,
    ut_session: i32,
    ut_tv: TimeVal,
    ut_addr_v6: [u32; 4],
    glibc_reserved: [u8; 20],
}

#[repr(C)]
#[allow(dead_code)]
struct ExitStatus {
    e_termination: i16,
    e_exit: i16,
}

#[repr(C)]
#[allow(dead_code)]
struct TimeVal {
    tv_sec: i32,
    tv_usec: i32,
}

/// Size of one on-disk record (384 bytes on the supported targets).
const RECORD_SIZE: usize = size_of::<Utmpx>();

// The layout we serialize against must match glibc's 384-byte record exactly.
const _: () = assert!(RECORD_SIZE == 384);

// Field offsets taken straight from the `#[repr(C)]` struct above.
const OFF_TYPE: usize = offset_of!(Utmpx, ut_type);
const OFF_PID: usize = offset_of!(Utmpx, ut_pid);
const OFF_LINE: usize = offset_of!(Utmpx, ut_line);
const OFF_ID: usize = offset_of!(Utmpx, ut_id);
const OFF_USER: usize = offset_of!(Utmpx, ut_user);
const OFF_HOST: usize = offset_of!(Utmpx, ut_host);
const OFF_TV: usize = offset_of!(Utmpx, ut_tv);
const OFF_ADDR: usize = offset_of!(Utmpx, ut_addr_v6);

const LINE_LEN: usize = 32;
const ID_LEN: usize = 4;
const USER_LEN: usize = 32;
const HOST_LEN: usize = 256;

/// A live utmp record, held for the lifetime of the PTY thread so the matching
/// slot can be cleared (turned into a `DEAD_PROCESS`) on logout.  The caller
/// keeps this alive and calls [`logout`] when the login shell ends.
pub(crate) struct UtmpSession {
    line: String,
    id: [u8; ID_LEN],
    pid: i32,
}

/// Record a login: write a `USER_PROCESS` record into `/var/run/utmp` and append
/// it to `/var/log/wtmp`.  `tty` is the slave terminal name relative to `/dev`
/// (e.g. `pts/3`); `remote_host` is the client address, stored in `ut_host` and
/// (when it parses as an IP) `ut_addr_v6`.
///
/// Requires write access to the login databases (root); a permission error or a
/// missing file is surfaced to the caller, which logs it and carries on.
pub(crate) fn login(
    user: &str,
    pid: u32,
    tty: &str,
    remote_host: Option<&str>,
) -> Result<UtmpSession> {
    login_to(UTMP_PATH, WTMP_PATH, user, pid, tty, remote_host)
}

/// [`login`] against caller-supplied database paths, so tests can drive it
/// against temp files instead of the root-owned `/var/run/utmp` and
/// `/var/log/wtmp`.
fn login_to(
    utmp_path: &str,
    wtmp_path: &str,
    user: &str,
    pid: u32,
    tty: &str,
    remote_host: Option<&str>,
) -> Result<UtmpSession> {
    let id = ut_id_from_line(tty);
    let bytes = record_bytes(USER_PROCESS, pid, tty, id, user, remote_host);

    put_utmp(utmp_path, tty, &bytes).context("update /var/run/utmp")?;
    put_wtmp(wtmp_path, &bytes).context("append /var/log/wtmp")?;

    Ok(UtmpSession {
        line: tty.to_owned(),
        id,
        #[allow(clippy::cast_possible_wrap)]
        pid: pid as i32,
    })
}

/// Record a logout: flip the session's `/var/run/utmp` slot to `DEAD_PROCESS`
/// (clearing the user and host) and append a matching record to `/var/log/wtmp`.
pub(crate) fn logout(session: &UtmpSession) -> Result<()> {
    logout_to(UTMP_PATH, WTMP_PATH, session)
}

/// [`logout`] against caller-supplied database paths (see [`login_to`]).
fn logout_to(utmp_path: &str, wtmp_path: &str, session: &UtmpSession) -> Result<()> {
    #[allow(clippy::cast_sign_loss)]
    let pid = session.pid as u32;
    let bytes = record_bytes_raw(DEAD_PROCESS, pid, &session.line, session.id, "", None);

    put_utmp(utmp_path, &session.line, &bytes).context("update /var/run/utmp")?;
    put_wtmp(wtmp_path, &bytes).context("append /var/log/wtmp")?;

    Ok(())
}

/// Derive the 4-byte `ut_id` from a terminal name: the suffix after `pts/`
/// (e.g. `pts/3` → `3`, `pts/1234` → `1234`), truncated to the last 4 bytes and
/// left-aligned/zero-padded — the same `strncpy` convention `login`(3) uses.
fn ut_id_from_line(line: &str) -> [u8; ID_LEN] {
    let suffix = line.strip_prefix("pts/").unwrap_or(line).as_bytes();
    let start = suffix.len().saturating_sub(ID_LEN);
    let tail = &suffix[start..];
    let mut id = [0u8; ID_LEN];
    id[..tail.len()].copy_from_slice(tail);
    id
}

/// Serialize one record, deriving `ut_id` from `tty`.
fn record_bytes(
    ut_type: i16,
    pid: u32,
    tty: &str,
    id: [u8; ID_LEN],
    user: &str,
    remote_host: Option<&str>,
) -> [u8; RECORD_SIZE] {
    record_bytes_raw(ut_type, pid, tty, id, user, remote_host)
}

/// Serialize one glibc `utmpx` record into its 384-byte on-disk form.
fn record_bytes_raw(
    ut_type: i16,
    pid: u32,
    line: &str,
    id: [u8; ID_LEN],
    user: &str,
    remote_host: Option<&str>,
) -> [u8; RECORD_SIZE] {
    let mut b = [0u8; RECORD_SIZE];

    b[OFF_TYPE..OFF_TYPE + 2].copy_from_slice(&ut_type.to_ne_bytes());
    #[allow(clippy::cast_possible_wrap)]
    let pid = pid as i32;
    b[OFF_PID..OFF_PID + 4].copy_from_slice(&pid.to_ne_bytes());

    write_field(&mut b[OFF_LINE..OFF_LINE + LINE_LEN], line.as_bytes());
    b[OFF_ID..OFF_ID + ID_LEN].copy_from_slice(&id);
    write_field(&mut b[OFF_USER..OFF_USER + USER_LEN], user.as_bytes());
    if let Some(host) = remote_host {
        write_field(&mut b[OFF_HOST..OFF_HOST + HOST_LEN], host.as_bytes());
    }

    let (secs, micros) = now();
    b[OFF_TV..OFF_TV + 4].copy_from_slice(&secs.to_ne_bytes());
    b[OFF_TV + 4..OFF_TV + 8].copy_from_slice(&micros.to_ne_bytes());

    for (i, word) in addr_v6(remote_host).iter().enumerate() {
        let off = OFF_ADDR + i * 4;
        b[off..off + 4].copy_from_slice(&word.to_ne_bytes());
    }

    b
}

/// Copy `src` into a fixed-size, zero-padded field, truncating if it overflows.
fn write_field(field: &mut [u8], src: &[u8]) {
    let n = src.len().min(field.len());
    field[..n].copy_from_slice(&src[..n]);
}

/// Current time as the glibc on-disk `(tv_sec, tv_usec)` pair (32-bit each).
fn now() -> (i32, i32) {
    let d = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
    (d.as_secs() as i32, d.subsec_micros() as i32)
}

/// Encode `remote_host` into the network-order `ut_addr_v6` words: a v4 address
/// fills the first word, a v6 address all four, anything else (a hostname, or
/// `None`) stays zero.
fn addr_v6(remote_host: Option<&str>) -> [u32; 4] {
    match remote_host.and_then(|h| h.parse::<IpAddr>().ok()) {
        Some(IpAddr::V4(v4)) => [u32::from_ne_bytes(v4.octets()), 0, 0, 0],
        Some(IpAddr::V6(v6)) => {
            let o = v6.octets();
            let mut words = [0u32; 4];
            for (i, word) in words.iter_mut().enumerate() {
                *word = u32::from_ne_bytes([o[i * 4], o[i * 4 + 1], o[i * 4 + 2], o[i * 4 + 3]]);
            }
            words
        }
        None => [0; 4],
    }
}

/// Take an exclusive `flock` on `file`, released when the file is closed.
// flock is released automatically on close; we only need the exclusive hold for
// the read-modify-write of utmp / the append to wtmp.
#[allow(unsafe_code)]
fn lock_exclusive(file: &File) -> std::io::Result<()> {
    // SAFETY: `file` owns a valid fd for the duration of the call; flock only
    // advises a lock on it and has no other side effects.
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// Write `bytes` into the utmp slot for `line`: reuse the slot whose `ut_line`
/// matches (re-login or our own logout), else the first `EMPTY`/`DEAD_PROCESS`
/// slot, else append a new record.  Mirrors `getutline`/`pututline`.
fn put_utmp(path: &str, line: &str, bytes: &[u8; RECORD_SIZE]) -> std::io::Result<()> {
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)?;
    lock_exclusive(&file)?;

    let len = file.metadata()?.len();
    let count = len / RECORD_SIZE as u64;
    let mut matching: Option<u64> = None;
    let mut first_free: Option<u64> = None;

    let mut buf = [0u8; RECORD_SIZE];
    for i in 0..count {
        let off = i * RECORD_SIZE as u64;
        let _ = file.seek(SeekFrom::Start(off))?;
        file.read_exact(&mut buf)?;

        if line_matches(&buf[OFF_LINE..OFF_LINE + LINE_LEN], line) {
            matching = Some(off);
            break;
        }
        let ut_type = i16::from_ne_bytes([buf[OFF_TYPE], buf[OFF_TYPE + 1]]);
        if first_free.is_none() && (ut_type == EMPTY || ut_type == DEAD_PROCESS) {
            first_free = Some(off);
        }
    }

    let off = matching.or(first_free).unwrap_or(len);
    let _ = file.seek(SeekFrom::Start(off))?;
    file.write_all(bytes)?;
    Ok(())
}

/// Append `bytes` to the wtmp history log.  `O_APPEND` makes the write atomic;
/// the `flock` matches what the system tools take.
fn put_wtmp(path: &str, bytes: &[u8; RECORD_SIZE]) -> std::io::Result<()> {
    let mut file = OpenOptions::new().append(true).create(true).open(path)?;
    lock_exclusive(&file)?;
    file.write_all(bytes)?;
    Ok(())
}

/// Whether a zero-padded `ut_line` field equals `line`.
fn line_matches(field: &[u8], line: &str) -> bool {
    let end = field.iter().position(|&b| b == 0).unwrap_or(field.len());
    field[..end] == *line.as_bytes()
}

#[cfg(test)]
mod test {
    use core::mem::offset_of;

    use super::{
        DEAD_PROCESS, LINE_LEN, OFF_ADDR, OFF_HOST, OFF_ID, OFF_LINE, OFF_PID, OFF_TV, OFF_TYPE,
        OFF_USER, RECORD_SIZE, USER_PROCESS, Utmpx, addr_v6, line_matches, login_to, logout_to,
        put_utmp, put_wtmp, record_bytes, record_bytes_raw, ut_id_from_line,
    };

    #[test]
    fn record_is_glibc_sized() {
        assert_eq!(RECORD_SIZE, 384);
    }

    #[test]
    fn offsets_match_glibc_layout() {
        // The fixed offsets glibc readers (who/w/last, utmpdump) expect.
        assert_eq!(OFF_TYPE, 0);
        assert_eq!(OFF_PID, 4);
        assert_eq!(OFF_LINE, 8);
        assert_eq!(OFF_ID, 40);
        assert_eq!(OFF_USER, 44);
        assert_eq!(OFF_HOST, 76);
        assert_eq!(offset_of!(Utmpx, ut_exit), 332);
        assert_eq!(offset_of!(Utmpx, ut_session), 336);
        assert_eq!(OFF_TV, 340);
        assert_eq!(OFF_ADDR, 348);
        assert_eq!(offset_of!(Utmpx, glibc_reserved), 364);
    }

    #[test]
    fn ut_id_derivation() {
        assert_eq!(&ut_id_from_line("pts/3"), b"3\0\0\0");
        assert_eq!(&ut_id_from_line("pts/12"), b"12\0\0");
        // Suffix longer than the field keeps the last 4 bytes.
        assert_eq!(&ut_id_from_line("pts/12345"), b"2345");
        // No pts/ prefix falls back to the last 4 bytes of the line.
        assert_eq!(&ut_id_from_line("tty1"), b"tty1");
    }

    #[test]
    fn record_fields_serialize_at_their_offsets() {
        let bytes = record_bytes(
            USER_PROCESS,
            4242,
            "pts/7",
            ut_id_from_line("pts/7"),
            "alice",
            Some("203.0.113.9"),
        );

        assert_eq!(
            i16::from_ne_bytes([bytes[OFF_TYPE], bytes[OFF_TYPE + 1]]),
            USER_PROCESS
        );
        assert_eq!(
            i32::from_ne_bytes(bytes[OFF_PID..OFF_PID + 4].try_into().unwrap()),
            4242
        );
        assert!(line_matches(&bytes[OFF_LINE..OFF_LINE + LINE_LEN], "pts/7"));
        assert_eq!(&bytes[OFF_USER..OFF_USER + 5], b"alice");
        assert_eq!(&bytes[OFF_HOST..OFF_HOST + 11], b"203.0.113.9");
        // v4 address stored network-order in the first ut_addr_v6 word.
        assert_eq!(&bytes[OFF_ADDR..OFF_ADDR + 4], &[203, 0, 113, 9]);
    }

    #[test]
    fn addr_v6_encodes_v4_and_ignores_hostnames() {
        assert_eq!(
            addr_v6(Some("203.0.113.9")).map(u32::to_ne_bytes)[0],
            [203, 0, 113, 9]
        );
        assert_eq!(addr_v6(Some("example.com")), [0; 4]);
        assert_eq!(addr_v6(None), [0; 4]);
    }

    #[test]
    fn addr_v6_encodes_v6() {
        // Each word holds 4 octets of the address in network order.
        let words = addr_v6(Some("2001:db8::1"));
        assert_eq!(words.map(u32::to_ne_bytes)[0], [0x20, 0x01, 0x0d, 0xb8]);
        assert_eq!(words.map(u32::to_ne_bytes)[1], [0, 0, 0, 0]);
        assert_eq!(words.map(u32::to_ne_bytes)[2], [0, 0, 0, 0]);
        assert_eq!(words.map(u32::to_ne_bytes)[3], [0, 0, 0, 1]);
    }

    #[test]
    fn login_then_logout_reuses_the_same_utmp_slot() {
        let dir = std::env::temp_dir();
        let utmp = dir.join(format!("moshpit-utmp-test-{}", std::process::id()));
        let utmp = utmp.to_str().unwrap();
        drop(std::fs::remove_file(utmp));

        // Login: a single USER_PROCESS slot for pts/9.
        let login = record_bytes(
            USER_PROCESS,
            100,
            "pts/9",
            ut_id_from_line("pts/9"),
            "bob",
            None,
        );
        put_utmp(utmp, "pts/9", &login).unwrap();

        let after_login = std::fs::read(utmp).unwrap();
        assert_eq!(after_login.len(), RECORD_SIZE);
        assert_eq!(
            i16::from_ne_bytes([after_login[OFF_TYPE], after_login[OFF_TYPE + 1]]),
            USER_PROCESS
        );

        // Logout: the same slot is rewritten in place as DEAD_PROCESS.
        let logout = record_bytes_raw(
            DEAD_PROCESS,
            100,
            "pts/9",
            ut_id_from_line("pts/9"),
            "",
            None,
        );
        put_utmp(utmp, "pts/9", &logout).unwrap();

        let after_logout = std::fs::read(utmp).unwrap();
        assert_eq!(after_logout.len(), RECORD_SIZE, "slot reused, not appended");
        assert_eq!(
            i16::from_ne_bytes([after_logout[OFF_TYPE], after_logout[OFF_TYPE + 1]]),
            DEAD_PROCESS
        );
        assert!(line_matches(
            &after_logout[OFF_LINE..OFF_LINE + LINE_LEN],
            "pts/9"
        ));

        drop(std::fs::remove_file(utmp));
    }

    #[test]
    fn put_wtmp_appends_records() {
        let dir = std::env::temp_dir();
        let wtmp = dir.join(format!("moshpit-wtmp-test-{}", std::process::id()));
        let wtmp = wtmp.to_str().unwrap();
        drop(std::fs::remove_file(wtmp));

        let rec = record_bytes(
            USER_PROCESS,
            1,
            "pts/1",
            ut_id_from_line("pts/1"),
            "bob",
            None,
        );
        put_wtmp(wtmp, &rec).unwrap();
        put_wtmp(wtmp, &rec).unwrap();

        assert_eq!(
            std::fs::metadata(wtmp).unwrap().len(),
            2 * RECORD_SIZE as u64
        );
        drop(std::fs::remove_file(wtmp));
    }

    #[test]
    fn login_to_then_logout_to_round_trip() {
        let dir = std::env::temp_dir();
        let pid = std::process::id();
        let utmp = dir.join(format!("moshpit-utmp-rt-{pid}"));
        let wtmp = dir.join(format!("moshpit-wtmp-rt-{pid}"));
        let utmp = utmp.to_str().unwrap();
        let wtmp = wtmp.to_str().unwrap();
        drop(std::fs::remove_file(utmp));
        drop(std::fs::remove_file(wtmp));

        // Login records a USER_PROCESS in utmp and appends it to wtmp.
        let session = login_to(utmp, wtmp, "carol", 4242, "pts/5", Some("203.0.113.9")).unwrap();
        assert_eq!(session.line, "pts/5");
        assert_eq!(session.id, ut_id_from_line("pts/5"));
        assert_eq!(session.pid, 4242);

        let after_login = std::fs::read(utmp).unwrap();
        assert_eq!(after_login.len(), RECORD_SIZE);
        assert_eq!(
            i16::from_ne_bytes([after_login[OFF_TYPE], after_login[OFF_TYPE + 1]]),
            USER_PROCESS
        );
        assert!(line_matches(
            &after_login[OFF_LINE..OFF_LINE + LINE_LEN],
            "pts/5"
        ));
        assert_eq!(std::fs::metadata(wtmp).unwrap().len(), RECORD_SIZE as u64);

        // Logout reuses the same utmp slot as DEAD_PROCESS and appends to wtmp.
        logout_to(utmp, wtmp, &session).unwrap();

        let after_logout = std::fs::read(utmp).unwrap();
        assert_eq!(after_logout.len(), RECORD_SIZE, "slot reused, not appended");
        assert_eq!(
            i16::from_ne_bytes([after_logout[OFF_TYPE], after_logout[OFF_TYPE + 1]]),
            DEAD_PROCESS
        );
        assert!(line_matches(
            &after_logout[OFF_LINE..OFF_LINE + LINE_LEN],
            "pts/5"
        ));
        assert_eq!(
            std::fs::metadata(wtmp).unwrap().len(),
            2 * RECORD_SIZE as u64
        );

        drop(std::fs::remove_file(utmp));
        drop(std::fs::remove_file(wtmp));
    }

    #[test]
    fn put_utmp_reuses_first_free_slot() {
        let dir = std::env::temp_dir();
        let utmp = dir.join(format!("moshpit-utmp-free-{}", std::process::id()));
        let utmp = utmp.to_str().unwrap();
        drop(std::fs::remove_file(utmp));

        // Pre-seed two records directly: a DEAD_PROCESS (free) slot, then a
        // USER_PROCESS for pts/8.  Written as raw bytes so put_utmp doesn't
        // reuse the free slot while seeding.
        let dead = record_bytes_raw(DEAD_PROCESS, 1, "pts/2", ut_id_from_line("pts/2"), "", None);
        let live = record_bytes(
            USER_PROCESS,
            2,
            "pts/8",
            ut_id_from_line("pts/8"),
            "dave",
            None,
        );
        let mut seed = Vec::with_capacity(2 * RECORD_SIZE);
        seed.extend_from_slice(&dead);
        seed.extend_from_slice(&live);
        std::fs::write(utmp, &seed).unwrap();

        // A new login for pts/4 takes the free slot 0, not a new record.
        let fresh = record_bytes(
            USER_PROCESS,
            3,
            "pts/4",
            ut_id_from_line("pts/4"),
            "erin",
            None,
        );
        put_utmp(utmp, "pts/4", &fresh).unwrap();

        let data = std::fs::read(utmp).unwrap();
        assert_eq!(
            data.len(),
            2 * RECORD_SIZE,
            "free slot reused, not appended"
        );
        assert_eq!(
            i16::from_ne_bytes([data[OFF_TYPE], data[OFF_TYPE + 1]]),
            USER_PROCESS
        );
        assert!(line_matches(&data[OFF_LINE..OFF_LINE + LINE_LEN], "pts/4"));

        drop(std::fs::remove_file(utmp));
    }

    #[test]
    fn put_utmp_appends_when_no_match_or_free() {
        let dir = std::env::temp_dir();
        let utmp = dir.join(format!("moshpit-utmp-append-{}", std::process::id()));
        let utmp = utmp.to_str().unwrap();
        drop(std::fs::remove_file(utmp));

        // A single live slot for pts/8 — no match for pts/4, no free slot.
        let live = record_bytes(
            USER_PROCESS,
            2,
            "pts/8",
            ut_id_from_line("pts/8"),
            "dave",
            None,
        );
        put_utmp(utmp, "pts/8", &live).unwrap();

        let fresh = record_bytes(
            USER_PROCESS,
            3,
            "pts/4",
            ut_id_from_line("pts/4"),
            "erin",
            None,
        );
        put_utmp(utmp, "pts/4", &fresh).unwrap();

        let data = std::fs::read(utmp).unwrap();
        assert_eq!(data.len(), 2 * RECORD_SIZE, "new record appended");
        let second = &data[RECORD_SIZE..];
        assert!(line_matches(
            &second[OFF_LINE..OFF_LINE + LINE_LEN],
            "pts/4"
        ));

        drop(std::fs::remove_file(utmp));
    }
}
