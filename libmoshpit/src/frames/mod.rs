// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

use std::io::Cursor;

use anyhow::Result;
use aws_lc_rs::aead::NONCE_LEN;
use bytes::Buf as _;

pub(crate) mod encframe;
pub(crate) mod frame;

const USIZE_LENGTH: usize = 8;

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
