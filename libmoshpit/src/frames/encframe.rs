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
    aead::{Aad, LessSafeKey, Nonce},
    error::Unspecified,
    hmac::{Key, verify},
};
use bincode_next::{Decode, Encode, config::standard, decode_from_slice};
use tracing::error;
use uuid::Uuid;

use crate::{
    MoshpitError, UuidWrapper,
    error::Error,
    frames::{get_bytes, get_nonce, get_usize},
};

const UUID_LEN: usize = 16;
/// AEAD authentication tag length for all supported ciphers (16 bytes per RFC 5116).
const AEAD_TAG_LEN: usize = 16;
/// The maximum size of a UDP encrypted frame ciphertext in bytes (64 KB).
///
/// The ciphertext includes the 16-byte UUID prefix, the encrypted payload, and
/// the 16-byte AES-256-GCM-SIV AEAD tag.  `ScreenState` frames carry
/// `vt100::Screen::contents_formatted()` output which can be 4–15 KB for a
/// typical terminal, and larger terminals or high-density output may exceed
/// that.  64 KB comfortably accommodates all realistic terminal sizes while
/// still bounding the memory allocated per received UDP packet.
pub(crate) const MAX_ENCFRAME_LENGTH: usize = 65536;

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
    /// Server keepalive carrying a microsecond wall-clock timestamp from the sender.
    /// The receiver echoes this frame unchanged so the sender can measure round-trip time.
    Keepalive(u64),
    /// Signals the start of a scrollback replay block; client should enter silent-absorb mode.
    ScrollbackStart,
    /// Signals the end of a scrollback replay block; client should repaint from emulator state.
    ScrollbackEnd,
    /// Full screen state from the server-side vt100 emulator; client feeds bytes into a
    /// temporary [`vt100::Parser`] and renders the result for an instant clean repaint.
    ScreenState(Vec<u8>),
    /// Client requests an immediate full-screen repaint from the server.
    /// Sent when NAK retries for any gap reach the repaint threshold.
    RepaintRequest,
    /// Full screen state compressed with zstd for reliable single-datagram delivery.
    /// Replaces uncompressed [`EncryptedFrame::ScreenState`] for all normal screen syncs.
    /// Client decompresses before feeding bytes into a temporary [`vt100::Parser`].
    ScreenStateCompressed(Vec<u8>),
    /// Incremental PTY diff compressed with zstd level 1 for bandwidth efficiency.
    /// Sent by the server in place of [`EncryptedFrame::Bytes`] when compression reduces
    /// payload size, fitting bursts into a single datagram and reducing NAK exposure.
    /// Client decompresses and processes identically to [`EncryptedFrame::Bytes`].
    CompressedBytes((UuidWrapper, Vec<u8>)),
    /// Server → client in [`DiffMode::StateSync`](crate::DiffMode): a vt100 diff computed from
    /// the screen state identified by `base_id` (the client's last-acked diff id) to the
    /// current screen.  `diff_id` is a server-side monotonic counter unique to this diff;
    /// the client echoes it in [`EncryptedFrame::ClientAck`] so the server can look up the
    /// matching `contents_formatted()` snapshot and advance its ack baseline.
    /// Carries zstd-compressed output of `vt100::Screen::contents_diff(ack_screen, current)`.
    /// Client discards if `base_id != ack_state_seq`; applies and sends
    /// [`EncryptedFrame::ClientAck`] otherwise.
    StateSyncDiff((u64, u64, Vec<u8>)),
    /// Client → server in [`DiffMode::StateSync`](crate::DiffMode): the seq of the last
    /// [`EncryptedFrame::StateSyncDiff`] the client successfully applied and rendered.
    /// Server looks up the matching `contents_formatted()` snapshot and advances its ack
    /// baseline, so future diffs start from the confirmed client state.
    ClientAck(u64),
    /// Server → client: the remote PTY process has exited.
    /// Client should exit cleanly without entering the reconnect loop.
    PtyExit,
    /// Server → client: one chunk of a multi-part full-state push too large for a single UDP
    /// datagram.  `seq` is 0-based; `total` is the total chunk count.  Client buffers until
    /// `seq == total - 1`, then concatenates in order and processes the assembled bytes
    /// identically to a [`EncryptedFrame::ScreenStateCompressed`] payload.
    StateChunk((u16, u16, Vec<u8>)),
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
            EncryptedFrame::Keepalive(_) => 4,
            EncryptedFrame::ScrollbackStart => 5,
            EncryptedFrame::ScrollbackEnd => 6,
            EncryptedFrame::ScreenState(_) => 7,
            EncryptedFrame::RepaintRequest => 8,
            EncryptedFrame::ScreenStateCompressed(_) => 9,
            EncryptedFrame::CompressedBytes(_) => 10,
            EncryptedFrame::StateSyncDiff(_) => 11,
            EncryptedFrame::ClientAck(_) => 12,
            EncryptedFrame::PtyExit => 13,
            EncryptedFrame::StateChunk(_) => 14,
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
        rnk: &LessSafeKey,
        mac_tag_len: usize,
    ) -> Result<Option<(Self, u64)>> {
        let Some(nonce_bytes) = get_nonce(src)? else {
            return Ok(None);
        };
        let Some(seq_bytes) = get_usize(src)? else {
            return Ok(None);
        };
        let seq = u64::from_be_bytes(seq_bytes.try_into()?);
        if let Some(tag_bytes) = get_bytes(src, mac_tag_len)?
            && let Some(length_slice) = get_usize(src)?
        {
            let length = usize::from_be_bytes(length_slice.try_into()?);
            if length > MAX_ENCFRAME_LENGTH {
                return Err(Error::FrameTooLarge.into());
            }
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
                    let mut message = message_with_tag.split_off(AEAD_TAG_LEN);
                    message.reverse();
                    let config = standard().with_limit::<65536>();
                    let frame_data: (EncryptedFrame, _) = decode_from_slice(&message, config)?;
                    return Ok(Some((frame_data.0, seq)));
                }
                error!("HMAC verification failed");
                return Err(Unspecified.into());
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use aws_lc_rs::{
        aead::{AES_256_GCM_SIV, Aad, LessSafeKey, NONCE_LEN, UnboundKey},
        hmac::{HMAC_SHA512, Key, sign},
        rand,
    };
    use bincode_next::{config::standard, encode_to_vec};
    use uuid::Uuid;

    use crate::UuidWrapper;

    use super::EncryptedFrame;

    fn make_keys() -> (Uuid, LessSafeKey, Key) {
        let id = Uuid::new_v4();
        let rnk = LessSafeKey::new(UnboundKey::new(&AES_256_GCM_SIV, &[1u8; 32]).unwrap());
        let hmac = Key::new(HMAC_SHA512, &[2u8; 64]);
        (id, rnk, hmac)
    }

    fn encrypt_frame(
        frame: &EncryptedFrame,
        seq: u64,
        id: Uuid,
        rnk: &LessSafeKey,
        hmac: &Key,
    ) -> Vec<u8> {
        let data = encode_to_vec(frame, standard()).unwrap();
        let aad = Aad::from(seq.to_be_bytes());
        let mut encrypted_part = id.as_bytes().to_vec();
        encrypted_part.extend_from_slice(&data);
        let mut nonce_bytes = [0u8; NONCE_LEN];
        rand::fill(&mut nonce_bytes).unwrap();
        let nonce = aws_lc_rs::aead::Nonce::try_assume_unique_for_key(&nonce_bytes).unwrap();
        rnk.seal_in_place_append_tag(nonce, aad, &mut encrypted_part)
            .unwrap();
        let seq_bytes = seq.to_be_bytes();
        let mut to_sign = seq_bytes.to_vec();
        to_sign.extend_from_slice(&encrypted_part);
        let tag = sign(hmac, &to_sign);
        let tag_bytes: [u8; 64] = tag.as_ref().try_into().unwrap();
        let len = encrypted_part.len().to_be_bytes();
        let mut packet = nonce_bytes.to_vec();
        packet.extend_from_slice(&seq_bytes);
        packet.extend_from_slice(&tag_bytes);
        packet.extend_from_slice(&len);
        packet.extend_from_slice(&encrypted_part);
        packet
    }

    #[test]
    fn frame_id_variants_are_correct() {
        let uuid = Uuid::new_v4();
        assert_eq!(
            EncryptedFrame::Bytes((UuidWrapper::new(uuid), vec![])).id(),
            0
        );
        assert_eq!(
            EncryptedFrame::Resize((UuidWrapper::new(uuid), 0, 0)).id(),
            1
        );
        assert_eq!(EncryptedFrame::Nak(vec![]).id(), 2);
        assert_eq!(EncryptedFrame::Shutdown.id(), 3);
        assert_eq!(EncryptedFrame::Keepalive(0).id(), 4);
        assert_eq!(EncryptedFrame::ScrollbackStart.id(), 5);
        assert_eq!(EncryptedFrame::ScrollbackEnd.id(), 6);
        assert_eq!(EncryptedFrame::ScreenState(vec![]).id(), 7);
        assert_eq!(EncryptedFrame::RepaintRequest.id(), 8);
        assert_eq!(EncryptedFrame::ScreenStateCompressed(vec![]).id(), 9);
        assert_eq!(
            EncryptedFrame::CompressedBytes((UuidWrapper::new(uuid), vec![])).id(),
            10
        );
        assert_eq!(EncryptedFrame::StateSyncDiff((0, 0, vec![])).id(), 11);
        assert_eq!(EncryptedFrame::ClientAck(0).id(), 12);
        assert_eq!(EncryptedFrame::PtyExit.id(), 13);
        assert_eq!(EncryptedFrame::StateChunk((0, 1, vec![])).id(), 14);
    }

    #[test]
    fn parse_round_trip_keepalive() {
        let (id, rnk, hmac) = make_keys();
        let ts = 1_234_567_890_u64;
        let packet = encrypt_frame(&EncryptedFrame::Keepalive(ts), 0, id, &rnk, &hmac);
        let mut cursor = Cursor::new(packet.as_slice());
        let (parsed_frame, seq) = EncryptedFrame::parse(&mut cursor, id, &hmac, &rnk, 64)
            .unwrap()
            .unwrap();
        assert_eq!(parsed_frame, EncryptedFrame::Keepalive(ts));
        assert_eq!(seq, 0);
    }

    /// Verify that two independent `RandomizedNonceKey` instances constructed from the
    /// same key bytes can cross-encrypt/decrypt — this mirrors the real system where the
    /// UDP sender and UDP reader each hold separate instances.  Tested for each
    /// supported AEAD algorithm to catch per-algorithm regressions.
    /// Verify that two independent `LessSafeKey` instances constructed from the
    /// same key bytes can cross-encrypt/decrypt — this mirrors the real system where the
    /// UDP sender and UDP reader each hold separate instances.  Tested for each
    /// supported AEAD algorithm to catch per-algorithm regressions.
    #[test]
    fn parse_round_trip_all_aead_algorithms_separate_key_instances() {
        use aws_lc_rs::aead::{AES_128_GCM_SIV, AES_256_GCM, CHACHA20_POLY1305};

        let algorithms: &[(&aws_lc_rs::aead::Algorithm, &[u8])] = &[
            (&AES_256_GCM_SIV, &[1u8; 32]),
            (&AES_256_GCM, &[2u8; 32]),
            (&CHACHA20_POLY1305, &[3u8; 32]),
            (&AES_128_GCM_SIV, &[4u8; 16]),
        ];

        for (alg, key_bytes) in algorithms {
            eprintln!("testing alg={alg:?} key_len={}", key_bytes.len());
            let id = Uuid::new_v4();
            let hmac = Key::new(HMAC_SHA512, &[5u8; 64]);
            // Two independent LessSafeKey instances from the same key — one for encrypt, one for decrypt.
            let enc_key = LessSafeKey::new(
                UnboundKey::new(alg, key_bytes)
                    .unwrap_or_else(|e| panic!("enc_key creation failed for {alg:?}: {e:?}")),
            );
            let dec_key = LessSafeKey::new(
                UnboundKey::new(alg, key_bytes)
                    .unwrap_or_else(|e| panic!("dec_key creation failed for {alg:?}: {e:?}")),
            );

            let ts = 42_u64;
            let packet = encrypt_frame(&EncryptedFrame::Keepalive(ts), 7, id, &enc_key, &hmac);
            let mut cursor = Cursor::new(packet.as_slice());
            let result = EncryptedFrame::parse(&mut cursor, id, &hmac, &dec_key, 64);
            let (parsed_frame, seq) = match result {
                Ok(Some(inner)) => inner,
                Ok(None) => panic!("parse returned None for algorithm {alg:?}"),
                Err(e) => panic!("parse failed for algorithm {alg:?}: {e}"),
            };
            assert_eq!(
                parsed_frame,
                EncryptedFrame::Keepalive(ts),
                "wrong frame for {alg:?}"
            );
            assert_eq!(seq, 7, "wrong seq for {alg:?}");
        }
    }

    #[test]
    fn parse_round_trip_shutdown() {
        let (id, rnk, hmac) = make_keys();
        let packet = encrypt_frame(&EncryptedFrame::Shutdown, 42, id, &rnk, &hmac);
        let mut cursor = Cursor::new(packet.as_slice());
        let (parsed_frame, seq) = EncryptedFrame::parse(&mut cursor, id, &hmac, &rnk, 64)
            .unwrap()
            .unwrap();
        assert_eq!(parsed_frame, EncryptedFrame::Shutdown);
        assert_eq!(seq, 42);
    }

    #[test]
    fn parse_truncated_returns_none() {
        let (id, rnk, hmac) = make_keys();
        let packet = [0u8; 4];
        let mut cursor = Cursor::new(packet.as_slice());
        let result = EncryptedFrame::parse(&mut cursor, id, &hmac, &rnk, 64).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn parse_wrong_uuid_returns_error() {
        let (id, rnk, hmac) = make_keys();
        let packet = encrypt_frame(&EncryptedFrame::Keepalive(0), 0, id, &rnk, &hmac);
        let wrong_id = Uuid::new_v4();
        let mut cursor = Cursor::new(packet.as_slice());
        let result = EncryptedFrame::parse(&mut cursor, wrong_id, &hmac, &rnk, 64);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_oversized_encframe() {
        use crate::frames::encframe::MAX_ENCFRAME_LENGTH;
        let (id, rnk, hmac) = make_keys();
        // Construct a packet with oversized length
        let oversized_len = MAX_ENCFRAME_LENGTH + 1;

        let seq = 0u64;
        let aad = Aad::from(seq.to_be_bytes());
        let mut encrypted_part = id.as_bytes().to_vec();
        // Add fake payload to match length
        encrypted_part.extend_from_slice(&[0u8; 10]);
        let mut nonce_bytes = [0u8; NONCE_LEN];
        rand::fill(&mut nonce_bytes).unwrap();
        let nonce = aws_lc_rs::aead::Nonce::try_assume_unique_for_key(&nonce_bytes).unwrap();
        rnk.seal_in_place_append_tag(nonce, aad, &mut encrypted_part)
            .unwrap();

        let seq_bytes = seq.to_be_bytes();
        let mut to_sign = seq_bytes.to_vec();
        to_sign.extend_from_slice(&encrypted_part);
        let tag = sign(&hmac, &to_sign);
        let tag_bytes: [u8; 64] = tag.as_ref().try_into().unwrap();

        let len = oversized_len.to_be_bytes(); // Oversized!

        let mut packet = nonce_bytes.to_vec();
        packet.extend_from_slice(&seq_bytes);
        packet.extend_from_slice(&tag_bytes);
        packet.extend_from_slice(&len);
        packet.extend_from_slice(&encrypted_part);

        let mut cursor = Cursor::new(packet.as_slice());
        let result = EncryptedFrame::parse(&mut cursor, id, &hmac, &rnk, 64);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            crate::error::Error::FrameTooLarge.to_string()
        );
    }
}
