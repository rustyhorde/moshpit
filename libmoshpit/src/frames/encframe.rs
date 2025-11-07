// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

use std::io::Cursor;

use anyhow::Result;
use aws_lc_rs::{
    aead::{Aad, Nonce, RandomizedNonceKey},
    digest::SHA512_OUTPUT_LEN,
    error::Unspecified,
    hmac::{Key, verify},
};
use bincode::{Decode, Encode};
use tracing::{error, info, trace};
use uuid::Uuid;

use crate::{
    UuidWrapper,
    frames::{get_bytes, get_nonce, get_usize},
};

const UUID_LEN: usize = 16;

/// A moshpit frame.
#[derive(Clone, Debug, Decode, Encode, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum EncryptedFrame {
    /// An encrypted UDP packet.
    Bytes((UuidWrapper, Vec<u8>)),
}

impl EncryptedFrame {
    /// Parse a moshpit frame from the given byte source.
    ///
    /// # Errors
    /// * Incomplete data.
    ///
    pub fn parse(
        src: &mut Cursor<&[u8]>,
        hmac: &Key,
        rnk: &RandomizedNonceKey,
    ) -> Result<Option<Self>> {
        if let Some(nonce_bytes) = get_nonce(src)? {
            if let Some(tag_bytes) = get_bytes(src, SHA512_OUTPUT_LEN)?
                && let Some(length_slice) = get_usize(src)?
            {
                let length = usize::from_be_bytes(length_slice.try_into()?);
                if let Some(data) = get_bytes(src, length)? {
                    if let Ok(()) = verify(hmac, data, tag_bytes) {
                        let mut data = data.to_vec();
                        let nonce = Nonce::try_assume_unique_for_key(nonce_bytes)?;
                        let _ = rnk.open_in_place(nonce, Aad::empty(), &mut data)?;
                        info!("trying to parse uuid");
                        let (uuid_bytes, rest) = data.split_at(UUID_LEN);
                        let uuid = Uuid::from_bytes(uuid_bytes.try_into()?);
                        let uuid_wrapper = UuidWrapper::new(uuid);
                        trace!("uuid: {uuid_wrapper}");
                        let encframe = EncryptedFrame::Bytes((uuid_wrapper, rest.to_vec()));
                        return Ok(Some(encframe));
                    }
                    error!("HMAC verification failed");
                    return Err(Unspecified.into());
                }
            }
            Ok(None)
        } else {
            Ok(None)
        }
    }
}
