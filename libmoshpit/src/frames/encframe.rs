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
    aead::{AES_256_GCM_SIV, Aad, Nonce, RandomizedNonceKey},
    digest::SHA512_OUTPUT_LEN,
    error::Unspecified,
    hmac::{Key, verify},
};
use bincode_next::{Decode, Encode, config::standard, decode_from_slice};
use tracing::error;
use uuid::Uuid;

use crate::{
    MoshpitError, UuidWrapper,
    frames::{get_bytes, get_nonce, get_usize},
};

const UUID_LEN: usize = 16;

/// A moshpit frame.
#[derive(Clone, Debug, Decode, Encode, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum EncryptedFrame {
    /// An encrypted UDP packet.
    Bytes((UuidWrapper, Vec<u8>)),
    /// Resize the pseudo-terminal.
    Resize((UuidWrapper, u16, u16)),
    /// Request retransmission of the given sequence numbers.
    Nak(Vec<u64>),
    /// Server is shutting down; client should exit cleanly.
    Shutdown,
    /// Server keepalive; client should reset its silence deadline and discard.
    Keepalive,
    /// Signals the start of a scrollback replay block; client should enter silent-absorb mode.
    ScrollbackStart,
    /// Signals the end of a scrollback replay block; client should repaint from emulator state.
    ScrollbackEnd,
    /// Full screen state from the server-side vt100 emulator; client feeds bytes into a
    /// temporary [`vt100::Parser`] and renders the result for an instant clean repaint.
    ScreenState(Vec<u8>),
}

impl EncryptedFrame {
    /// Get the id associated with this frame.
    #[must_use]
    pub fn id(&self) -> u8 {
        match self {
            EncryptedFrame::Bytes(_) => 0,
            EncryptedFrame::Resize(_) => 1,
            EncryptedFrame::Nak(_) => 2,
            EncryptedFrame::Shutdown => 3,
            EncryptedFrame::Keepalive => 4,
            EncryptedFrame::ScrollbackStart => 5,
            EncryptedFrame::ScrollbackEnd => 6,
            EncryptedFrame::ScreenState(_) => 7,
        }
    }

    /// Parse a moshpit frame from the given byte source.
    ///
    /// Wire format: `[nonce (12)] [seq (8)] [hmac_tag (64)] [length (8)] [ciphertext]`
    ///
    /// The sequence number is authenticated (included in HMAC input) and used as AEAD AAD,
    /// which allows retransmitting the original wire bytes without re-encryption.
    ///
    /// # Errors
    /// * Incomplete data.
    ///
    pub fn parse(
        src: &mut Cursor<&[u8]>,
        id: Uuid,
        hmac: &Key,
        rnk: &RandomizedNonceKey,
    ) -> Result<Option<(Self, u64)>> {
        let Some(nonce_bytes) = get_nonce(src)? else {
            return Ok(None);
        };
        let Some(seq_bytes) = get_usize(src)? else {
            return Ok(None);
        };
        let seq = u64::from_be_bytes(seq_bytes.try_into()?);
        if let Some(tag_bytes) = get_bytes(src, SHA512_OUTPUT_LEN)?
            && let Some(length_slice) = get_usize(src)?
        {
            let length = usize::from_be_bytes(length_slice.try_into()?);
            if let Some(data) = get_bytes(src, length)? {
                // Verify HMAC over seq_bytes || ciphertext to authenticate the sequence number
                let mut to_verify = seq_bytes.to_vec();
                to_verify.extend_from_slice(data);
                if let Ok(()) = verify(hmac, &to_verify, tag_bytes) {
                    let mut data = data.to_vec();
                    let nonce = Nonce::try_assume_unique_for_key(nonce_bytes)?;
                    let aad = Aad::from(seq.to_be_bytes());
                    let _ = rnk.open_in_place(nonce, aad, &mut data)?;
                    let (uuid_bytes, rest) = data.split_at(UUID_LEN);
                    let uuid = Uuid::from_bytes(uuid_bytes.try_into()?);
                    if uuid != id {
                        error!("UUID mismatch: expected {id}, got {uuid}");
                        return Err(MoshpitError::UuidMismatch.into());
                    }
                    let mut message_with_tag = rest.to_vec();
                    message_with_tag.reverse();
                    let mut message = message_with_tag.split_off(AES_256_GCM_SIV.tag_len());
                    message.reverse();
                    let frame_data: (EncryptedFrame, _) = decode_from_slice(&message, standard())?;
                    return Ok(Some((frame_data.0, seq)));
                }
                error!("HMAC verification failed");
                return Err(Unspecified.into());
            }
        }
        Ok(None)
    }
}
