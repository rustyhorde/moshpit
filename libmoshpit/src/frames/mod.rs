// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

//! Frame encoding and decryption: [`Frame`] ↔ [`EncryptedFrame`] via AES-256-GCM-SIV.
//!
//! [`Frame`]: crate::Frame
//! [`EncryptedFrame`]: crate::EncryptedFrame

use std::io::Cursor;
use std::panic::{AssertUnwindSafe, catch_unwind};

use anyhow::{Result, anyhow};
use aws_lc_rs::aead::NONCE_LEN;
use bincode_next::{Decode, config::standard, decode_from_slice};
use bytes::Buf as _;

pub(crate) mod encframe;
pub(crate) mod frame;

const USIZE_LENGTH: usize = 8;

/// The bincode length limit applied to every frame decode (64 KB), matching the
/// per-frame size gates in [`frame`] and [`encframe`].
const DECODE_LIMIT: usize = 65536;

/// Decode a bincode-serialized frame from `data`, converting **both** decode
/// errors and any panic inside the decoder into an `Err`.
///
/// `bincode-next` 3.0.0-rc.15 has an integer-underflow panic in its
/// `Vec<integer>` varint fast-path: a crafted `EncryptedFrame::Nak(Vec<u64>)`
/// (e.g. inner bytes `[2, 1, 253, 0, 0, 1, 0, 0, 0, 0, 0]`) makes it compute
/// `len * size_of::<u64>() - consumed` and underflow. Frames are parsed from
/// attacker-controlled bytes — the server decodes `Nak` from any authenticated
/// client, and the client decodes everything the server sends — so a decoder
/// panic must be contained as a clean parse error instead of unwinding through
/// the transport. Every caller already drops the packet on `Err`.
///
/// `AssertUnwindSafe` is sound here: on a caught unwind we discard the partially
/// built value entirely and return an error, leaving no observable broken state.
pub(crate) fn decode_frame<T: Decode<()>>(data: &[u8]) -> Result<T> {
    let config = standard().with_limit::<DECODE_LIMIT>();
    match catch_unwind(AssertUnwindSafe(|| decode_from_slice::<T, _>(data, config))) {
        Ok(Ok((frame, _))) => Ok(frame),
        Ok(Err(e)) => Err(e.into()),
        Err(_) => Err(anyhow!("frame decode panicked on malformed input")),
    }
}

pub(crate) fn get_usize<'a>(src: &mut Cursor<&'a [u8]>) -> Result<Option<&'a [u8]>> {
    if src.remaining() < USIZE_LENGTH {
        Ok(None)
    } else {
        let start = usize::try_from(src.position())?;
        let end = start + USIZE_LENGTH;
        src.set_position(u64::try_from(end)?);
        Ok(Some(&src.get_ref()[start..end]))
    }
}

pub(crate) fn get_nonce<'a>(src: &mut Cursor<&'a [u8]>) -> Result<Option<&'a [u8]>> {
    if src.remaining() < NONCE_LEN {
        Ok(None)
    } else {
        let start = usize::try_from(src.position())?;
        let end = start + NONCE_LEN;
        src.set_position(u64::try_from(end)?);
        Ok(Some(&src.get_ref()[start..end]))
    }
}

pub(crate) fn get_bytes<'a>(src: &mut Cursor<&'a [u8]>, length: usize) -> Result<Option<&'a [u8]>> {
    if src.remaining() < length {
        Ok(None)
    } else {
        let start = usize::try_from(src.position())?;
        let end = start + length;
        src.set_position(u64::try_from(end)?);
        Ok(Some(&src.get_ref()[start..end]))
    }
}
