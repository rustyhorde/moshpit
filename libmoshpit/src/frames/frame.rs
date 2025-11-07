// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

use std::{fmt::Display, io::Cursor};

use anyhow::Result;
use bincode::{Decode, Encode, config::standard, decode_from_slice};
use bytes::Buf as _;
use tracing::trace;

use crate::{
    frames::{get_bytes, get_usize},
    uuid::UuidWrapper,
};

/// A moshpit frame.
#[derive(Clone, Debug, Decode, Encode, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Frame {
    /// An initialization frame from moshpit.
    Initialize(Vec<u8>),
    /// A peer initialization frame from moshpits.
    PeerInitialize(Vec<u8>, Vec<u8>),
    /// A check message from moshpit.
    Check([u8; 12], Vec<u8>),
    /// A key agreement message from moshpits.
    KeyAgreement(UuidWrapper),
}

impl Frame {
    /// Get the frame identifier.
    #[must_use]
    pub fn id(&self) -> u8 {
        match self {
            Frame::Initialize(_) => 0,
            Frame::PeerInitialize(_, _) => 1,
            Frame::Check(_, _) => 2,
            Frame::KeyAgreement(_) => 3,
        }
    }

    /// Parse a moshpit frame from the given byte source.
    ///
    /// # Errors
    /// * Incomplete data.
    ///
    pub fn parse(src: &mut Cursor<&[u8]>) -> Result<Option<Self>> {
        match get_u8(src) {
            Some(0..=3) => {
                if let Some(length_slice) = get_usize(src)? {
                    let length = usize::from_be_bytes(length_slice.try_into()?);
                    if let Some(data) = get_bytes(src, length)? {
                        let (frame, _): (Frame, _) = decode_from_slice(data, standard())?;
                        return Ok(Some(frame));
                    }
                }
                Ok(None)
            }
            Some(_) => {
                trace!("Unknown frame");
                Ok(None)
            }
            None => {
                trace!("Incomplete frame");
                Ok(None)
            }
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
            Frame::Initialize(data) => write!(f, "Initialize({} bytes)", data.len()),
            Frame::PeerInitialize(pk, salt) => write!(
                f,
                "PeerInitialize({} bytes, {} bytes)",
                pk.len(),
                salt.len(),
            ),
            Frame::Check(nonce, data) => {
                write!(f, "Check({} bytes, {} bytes)", nonce.len(), data.len())
            }
            Frame::KeyAgreement(uuid) => write!(f, "KeyAgreement({uuid})"),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use anyhow::Result;
    use bincode::{config::standard, encode_to_vec};

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
        let data = b"hello world".to_vec();
        let frame = Frame::Initialize(data.clone());
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
}
