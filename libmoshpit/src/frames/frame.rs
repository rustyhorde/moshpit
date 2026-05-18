// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

use std::{fmt::Display, io::Cursor, net::SocketAddr};

use anyhow::Result;
use bincode_next::{Decode, Encode, config::standard, decode_from_slice};
use bytes::Buf as _;

use crate::{
    error::Error,
    frames::{get_bytes, get_usize},
    kex::negotiate::AlgorithmList,
    uuid::UuidWrapper,
};

/// The maximum size of a TCP frame payload in bytes (64KB).
pub(crate) const MAX_FRAME_LENGTH: usize = 65536;

/// A moshpit frame.
#[derive(Clone, Debug, Decode, Encode, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Frame {
    /// An initialization frame from moshpit.
    Initialize(Vec<u8>, Vec<u8>, Vec<u8>),
    /// A peer initialization frame from moshpits.
    /// Fields: (`identity_pk`, `ephemeral_pk`, `salt`)
    PeerInitialize(Vec<u8>, Vec<u8>, Vec<u8>),
    /// A check message from moshpit.
    Check([u8; 12], Vec<u8>),
    /// A key agreement message from moshpits.
    KeyAgreement(UuidWrapper),
    /// The address the moshpits listener is bound to.
    MoshpitsAddr(SocketAddr),
    /// Key exchange failure notification.
    KexFailure,
    /// A stable session token sent from moshpits to moshpit after key agreement.
    /// The client stores this UUID and presents it on reconnect to resume the session.
    SessionToken(UuidWrapper),
    /// A request from moshpit to resume a previous session.
    /// Contains (`session_uuid`, `user_bytes`, `ephemeral_public_key`, `full_public_key`).
    ResumeRequest(UuidWrapper, Vec<u8>, Vec<u8>, Vec<u8>),
    /// Transport options sent by the client immediately after `Initialize` or
    /// `ResumeRequest` and before `Check`.  Allows the client to request a
    /// specific [`DiffMode`](crate::udp::DiffMode) without a separate negotiation round-trip.
    /// The payload byte encodes the mode: `0` = Reliable (default), `1` = Datagram.
    /// Servers that recognise this frame adapt per-session; older servers that
    /// do not know ID 8 will treat it as an unknown frame — clients MUST only
    /// send this frame when connecting to a server that supports it (i.e. same
    /// version or newer).
    ClientOptions(u8),
    /// SSH-style algorithm negotiation frame sent by both client and server at
    /// the very start of the handshake (before `Initialize` / `PeerInitialize`).
    /// Each side lists its supported algorithms in preference order; the
    /// receiver runs [`negotiate`](crate::kex::negotiate::negotiate) to pick
    /// the first common algorithm in each category.
    KexInit(AlgorithmList),
    /// Experimental identity-key proof over the key-exchange transcript.
    IdentityProof(Vec<u8>),
    /// Environment variable passthrough and PATH additions from the client.
    /// Sent after [`ClientOptions`](Frame::ClientOptions) (if any) and before
    /// [`Check`](Frame::Check).
    /// Fields: (`env_vars`, `extra_path`)
    /// - `env_vars`: `(name, value)` pairs filtered by the client's `send_env` config;
    ///   the server applies only those matching its own `accept_env` list.
    /// - `extra_path`: directories to prepend to the server's base `server_path`;
    ///   ignored when the server has `path_locked = true`.
    ClientEnv(Vec<(String, String)>, Vec<String>),
}

impl Frame {
    /// Get the frame identifier.
    #[must_use]
    pub fn id(&self) -> u8 {
        match self {
            Frame::Initialize(_, _, _) => 0,
            Frame::PeerInitialize(_, _, _) => 1,
            Frame::Check(_, _) => 2,
            Frame::KeyAgreement(_) => 3,
            Frame::MoshpitsAddr(_) => 4,
            Frame::KexFailure => 5,
            Frame::SessionToken(_) => 6,
            Frame::ResumeRequest(_, _, _, _) => 7,
            Frame::ClientOptions(_) => 8,
            Frame::KexInit(_) => 9,
            Frame::IdentityProof(_) => 10,
            Frame::ClientEnv(_, _) => 11,
        }
    }

    /// Parse a moshpit frame from the given byte source.
    ///
    /// # Errors
    /// * Incomplete data.
    ///
    pub fn parse(src: &mut Cursor<&[u8]>) -> Result<Option<Self>> {
        match get_u8(src) {
            Some(0..=11) => {
                if let Some(length_slice) = get_usize(src)? {
                    let length = usize::from_be_bytes(length_slice.try_into()?);
                    if length > MAX_FRAME_LENGTH {
                        return Err(Error::FrameTooLarge.into());
                    }
                    if let Some(data) = get_bytes(src, length)? {
                        let config = standard().with_limit::<65536>();
                        let (frame, _): (Frame, _) = decode_from_slice(data, config)?;
                        return Ok(Some(frame));
                    }
                }
                Ok(None)
            }
            Some(_) | None => Ok(None),
        }
    }
}

fn get_u8(src: &mut Cursor<&[u8]>) -> Option<u8> {
    if !src.has_remaining() {
        return None;
    }

    Some(src.get_u8())
}

impl Display for Frame {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Frame::Initialize(user, pk, full_pk) => {
                write!(
                    f,
                    "Initialize({} bytes, {} bytes, {} bytes)",
                    user.len(),
                    pk.len(),
                    full_pk.len()
                )
            }
            Frame::PeerInitialize(identity_pk, ephemeral_pk, salt) => write!(
                f,
                "PeerInitialize({} bytes, {} bytes, {} bytes)",
                identity_pk.len(),
                ephemeral_pk.len(),
                salt.len(),
            ),
            Frame::Check(nonce, data) => {
                write!(f, "Check({} bytes, {} bytes)", nonce.len(), data.len())
            }
            Frame::KeyAgreement(uuid) => write!(f, "KeyAgreement({uuid})"),
            Frame::MoshpitsAddr(addr) => write!(f, "MoshpitsAddr({addr})"),
            Frame::KexFailure => write!(f, "KexFailure"),
            Frame::SessionToken(uuid) => write!(f, "SessionToken({uuid})"),
            Frame::ResumeRequest(uuid, user, epk, fpk) => write!(
                f,
                "ResumeRequest({uuid}, {} bytes, {} bytes, {} bytes)",
                user.len(),
                epk.len(),
                fpk.len()
            ),
            Frame::ClientOptions(mode) => write!(f, "ClientOptions({mode})"),
            Frame::KexInit(list) => write!(
                f,
                "KexInit(kex={:?}, aead={:?}, mac={:?}, kdf={:?})",
                list.kex, list.aead, list.mac, list.kdf
            ),
            Frame::IdentityProof(signature) => {
                write!(f, "IdentityProof({} bytes)", signature.len())
            }
            Frame::ClientEnv(env_vars, extra_path) => write!(
                f,
                "ClientEnv({} vars, {} path entries)",
                env_vars.len(),
                extra_path.len()
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use anyhow::Result;
    use bincode_next::{config::standard, encode_to_vec};

    use crate::frames::USIZE_LENGTH;

    use super::{Frame, get_bytes, get_u8, get_usize};

    const TEST_USIZE: usize = 12;

    fn validate_get_u8(cursor: &mut Cursor<&[u8]>) {
        let flag = get_u8(cursor);
        assert!(flag.is_some());
        let flag = flag.unwrap();
        assert_eq!(flag, 0);
        assert_eq!(cursor.position(), 1);
    }

    fn validate_get_usize(cursor: &mut Cursor<&[u8]>, expected: usize) -> Result<()> {
        let line = get_usize(cursor)?;
        assert!(line.is_some());
        let line = line.unwrap();
        let value = usize::from_be_bytes(line.try_into()?);
        assert_eq!(value, expected);
        assert_eq!(cursor.position(), u64::try_from(USIZE_LENGTH + 1)?);
        Ok(())
    }

    fn validate_get_bytes(cursor: &mut Cursor<&[u8]>, expected: &[u8]) -> Result<()> {
        let bytes = get_bytes(cursor, expected.len())?;
        assert!(bytes.is_some());
        let bytes = bytes.unwrap();
        assert_eq!(bytes, expected);
        assert_eq!(
            cursor.position(),
            u64::try_from(USIZE_LENGTH + 1 + expected.len())?
        );
        Ok(())
    }

    enum Completness {
        Complete,
        Incomplete,
    }

    enum DataKind {
        U8,
        Usize,
        Bytes,
    }

    fn test_data(kind: DataKind, completeness: Completness) -> (Vec<u8>, usize, Vec<u8>) {
        match (kind, completeness) {
            (DataKind::U8, Completness::Complete) => (vec![0u8], 0, vec![]),
            (DataKind::U8, Completness::Incomplete) => (vec![], 0, vec![]),
            (DataKind::Usize, Completness::Complete) => {
                let val = TEST_USIZE;
                let data = val.to_be_bytes();
                ([&[0], data.as_slice()].concat(), val, vec![])
            }
            (DataKind::Usize, Completness::Incomplete) => {
                let val = TEST_USIZE;
                let data = val.to_be_bytes();
                ([&[0], &data[..4]].concat(), val, vec![])
            }
            (DataKind::Bytes, Completness::Complete) => {
                let data = b"hello";
                let length = data.len();
                let length_bytes = length.to_be_bytes();
                (
                    [&[0], length_bytes.as_slice(), data.as_slice()].concat(),
                    length,
                    data.to_vec(),
                )
            }
            (DataKind::Bytes, Completness::Incomplete) => {
                let data = b"hello";
                let length = data.len() + 5; // Intentionally incorrect length
                let length_bytes = length.to_be_bytes();
                (
                    [&[0], length_bytes.as_slice(), data.as_slice()].concat(),
                    length,
                    data.to_vec(),
                )
            }
        }
    }

    #[test]
    fn test_get_u8() {
        let (all_data, _, _) = test_data(DataKind::U8, Completness::Complete);
        let mut cursor = Cursor::new(&all_data[..]);
        validate_get_u8(&mut cursor);
    }

    #[test]
    fn test_get_u8_incomplete() {
        let (all_data, _, _) = test_data(DataKind::U8, Completness::Incomplete);
        let mut cursor = Cursor::new(&all_data[..]);
        assert!(get_u8(&mut cursor).is_none());
    }

    #[test]
    fn test_get_usize() -> Result<()> {
        let (all_data, expected_usize, _) = test_data(DataKind::Usize, Completness::Complete);
        let mut cursor = Cursor::new(&all_data[..]);
        validate_get_u8(&mut cursor);
        validate_get_usize(&mut cursor, expected_usize)?;
        Ok(())
    }

    #[test]
    fn test_get_usize_incomplete() {
        let (all_data, _, _) = test_data(DataKind::Usize, Completness::Incomplete);
        let mut cursor = Cursor::new(&all_data[..]);
        validate_get_u8(&mut cursor);
        let res = get_usize(&mut cursor);
        assert!(res.is_ok());
        let maybe_usize = res.unwrap();
        assert!(maybe_usize.is_none());
    }

    #[test]
    fn test_get_bytes() -> Result<()> {
        let (all_data, expected_usize, expected_bytes) =
            test_data(DataKind::Bytes, Completness::Complete);
        let mut cursor = Cursor::new(&all_data[..]);
        validate_get_u8(&mut cursor);
        validate_get_usize(&mut cursor, expected_usize)?;
        validate_get_bytes(&mut cursor, &expected_bytes)?;
        Ok(())
    }

    #[test]
    fn test_get_bytes_incomplete() -> Result<()> {
        let (all_data, expected_usize, _) = test_data(DataKind::Bytes, Completness::Incomplete);
        let mut cursor = Cursor::new(&all_data[..]);
        validate_get_u8(&mut cursor);
        validate_get_usize(&mut cursor, expected_usize)?;
        let res = get_bytes(&mut cursor, expected_usize);
        assert!(res.is_ok());
        let maybe_bytes = res.unwrap();
        assert!(maybe_bytes.is_none());
        Ok(())
    }

    #[test]
    fn test_parse() -> Result<()> {
        let user = b"user".to_vec();
        let data = b"hello world".to_vec();
        let full_data = b"full key data".to_vec();
        let frame = Frame::Initialize(user.clone(), data.clone(), full_data.clone());
        let encoded_frame = encode_to_vec(&frame, standard())?;
        let length = encoded_frame.len();
        let length_bytes = length.to_be_bytes();

        let mut all_data = vec![0u8];
        all_data.extend_from_slice(&length_bytes);
        all_data.extend_from_slice(&encoded_frame);

        let mut cursor = Cursor::new(&all_data[..]);
        let parsed_frame = Frame::parse(&mut cursor)?;
        assert!(parsed_frame.is_some());
        let parsed_frame = parsed_frame.unwrap();
        assert_eq!(parsed_frame, frame);
        Ok(())
    }

    #[test]
    fn test_parse_incomplete() {
        let all_data = [200u8];
        let mut cursor = Cursor::new(&all_data[..]);
        let result = Frame::parse(&mut cursor);
        assert!(result.is_ok());
        let maybe_frame = result.unwrap();
        assert!(maybe_frame.is_none());
    }

    #[test]
    fn test_parse_error() {
        let all_data = [];
        let mut cursor = Cursor::new(&all_data[..]);
        let result = Frame::parse(&mut cursor);
        assert!(result.is_ok());
        let maybe_frame = result.unwrap();
        assert!(maybe_frame.is_none());
    }

    #[test]
    fn test_parse_oversized() {
        use crate::frames::frame::MAX_FRAME_LENGTH;
        let oversized_len = MAX_FRAME_LENGTH + 1;
        let length_bytes = oversized_len.to_be_bytes();
        let mut all_data = vec![0u8];
        all_data.extend_from_slice(&length_bytes);
        all_data.extend_from_slice(&[0u8; 10]); // Mock data

        let mut cursor = Cursor::new(&all_data[..]);
        let result = Frame::parse(&mut cursor);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            crate::error::Error::FrameTooLarge.to_string()
        );
    }

    #[test]
    fn test_parse_unknown_frame_id_returns_none() {
        // Frame IDs 0-11 are known; anything above 11 must be silently ignored (Ok(None)).
        let all_data = [12u8, 0, 0, 0, 0, 0, 0, 0, 0]; // id=12, length=0, no payload
        let mut cursor = Cursor::new(&all_data[..]);
        let result = Frame::parse(&mut cursor);
        assert!(result.is_ok(), "unknown frame id must not be an error");
        assert!(
            result.unwrap().is_none(),
            "unknown frame id must return Ok(None)"
        );
    }

    #[test]
    fn test_kex_init_round_trips() -> Result<()> {
        use crate::kex::negotiate::{AlgorithmList, supported_algorithms};

        let list: AlgorithmList = supported_algorithms();
        let frame = Frame::KexInit(list.clone());
        let encoded_frame = encode_to_vec(&frame, standard())?;
        let length = encoded_frame.len();
        let length_bytes = length.to_be_bytes();

        let mut all_data = vec![9u8]; // KexInit id=9
        all_data.extend_from_slice(&length_bytes);
        all_data.extend_from_slice(&encoded_frame);

        let mut cursor = Cursor::new(&all_data[..]);
        let parsed = Frame::parse(&mut cursor)?;
        assert!(parsed.is_some());
        let Frame::KexInit(parsed_list) = parsed.unwrap() else {
            panic!("expected KexInit");
        };
        assert_eq!(parsed_list, list);
        Ok(())
    }

    #[test]
    fn test_identity_proof_round_trips() -> Result<()> {
        let sig = vec![1u8, 2, 3, 4, 5];
        let frame = Frame::IdentityProof(sig.clone());
        let encoded_frame = encode_to_vec(&frame, standard())?;
        let length = encoded_frame.len();
        let length_bytes = length.to_be_bytes();

        let mut all_data = vec![10u8]; // IdentityProof id=10
        all_data.extend_from_slice(&length_bytes);
        all_data.extend_from_slice(&encoded_frame);

        let mut cursor = Cursor::new(&all_data[..]);
        let parsed = Frame::parse(&mut cursor)?;
        assert!(parsed.is_some());
        let Frame::IdentityProof(parsed_sig) = parsed.unwrap() else {
            panic!("expected IdentityProof");
        };
        assert_eq!(parsed_sig, sig);
        Ok(())
    }

    #[test]
    fn test_identity_proof_display() {
        let frame = Frame::IdentityProof(vec![0u8; 42]);
        assert_eq!(format!("{frame}"), "IdentityProof(42 bytes)");
    }
}
