use std::{fmt::Display, io::Cursor};

use anyhow::Result;
use bincode::{Decode, Encode, config::standard, decode_from_slice, encode_to_vec};
use bytes::Buf as _;
use tracing::trace;

use crate::error::Error;

const USIZE_LENGTH: usize = 8;

/// A moshpit frame.
#[derive(Clone, Debug, Decode, Encode, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Frame {
    /// An initialization frame.
    Initialize(Vec<u8>),
}

impl Frame {
    /// Parse a moshpit frame from the given byte source.
    ///
    /// # Errors
    /// * Incomplete data.
    ///
    pub fn parse(src: &mut Cursor<&[u8]>) -> Result<Option<Self>> {
        match get_u8(src) {
            Some(0) => {
                let length_slice = get_usize(src)?;
                let length = usize::from_be_bytes(length_slice.try_into()?);
                let data = get_bytes(src, length)?;
                let (frame, _): (Frame, _) = decode_from_slice(data, standard())?;
                Ok(Some(frame))
            }
            Some(_) => {
                trace!("Unsupported frame");
                Ok(None)
            }
            None => {
                trace!("Incomplete frame");
                Ok(None)
            }
        }
    }

    /// Create an initialization frame with the given data.
    ///
    /// # Errors
    /// * Encoding error.
    ///
    pub fn initialize(data: Vec<u8>) -> Result<Vec<u8>> {
        let frame = Frame::Initialize(data);
        let encoded = encode_to_vec(&frame, standard())?;
        let length = encoded.len();
        let all_data = [&[0], length.to_be_bytes().as_slice(), &encoded].concat();
        Ok(all_data)
    }
}

fn get_u8(src: &mut Cursor<&[u8]>) -> Option<u8> {
    if !src.has_remaining() {
        return None;
    }

    Some(src.get_u8())
}

fn get_usize<'a>(src: &mut Cursor<&'a [u8]>) -> Result<&'a [u8]> {
    if src.remaining() < USIZE_LENGTH {
        Err(Error::Incomplete.into())
    } else {
        let start = usize::try_from(src.position())?;
        let end = start + USIZE_LENGTH;
        src.set_position(u64::try_from(end)?);
        Ok(&src.get_ref()[start..end])
    }
}

fn get_bytes<'a>(src: &mut Cursor<&'a [u8]>, length: usize) -> Result<&'a [u8]> {
    if src.remaining() < length {
        Err(Error::Incomplete.into())
    } else {
        let start = usize::try_from(src.position())?;
        let end = start + length;
        src.set_position(u64::try_from(end)?);
        Ok(&src.get_ref()[start..end])
    }
}

impl Display for Frame {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Frame::Initialize(data) => write!(f, "Initialize({} bytes)", data.len()),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use anyhow::Result;
    use bincode::{config::standard, encode_to_vec};

    use super::{Frame, USIZE_LENGTH, get_bytes, get_u8, get_usize};
    use crate::error::Error;

    const TEST_USIZE: usize = 12;

    fn validate_get_u8(cursor: &mut Cursor<&[u8]>) {
        let flag = get_u8(cursor);
        assert!(flag.is_some());
        let flag = flag.unwrap();
        assert_eq!(flag, 0);
        assert_eq!(cursor.position(), 1);
    }

    fn error_is_incomplete<T>(res: Result<T>) {
        assert!(res.is_err());
        let err = res.err().unwrap();
        let err = err.downcast_ref::<Error>().unwrap();
        assert_eq!(err, &Error::Incomplete);
    }

    fn validate_get_usize(cursor: &mut Cursor<&[u8]>, expected: usize) -> Result<()> {
        let line = get_usize(cursor)?;
        let value = usize::from_be_bytes(line.try_into()?);
        assert_eq!(value, expected);
        assert_eq!(cursor.position(), u64::try_from(USIZE_LENGTH + 1)?);
        Ok(())
    }

    fn validate_get_bytes(cursor: &mut Cursor<&[u8]>, expected: &[u8]) -> Result<()> {
        let bytes = get_bytes(cursor, expected.len())?;
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
        error_is_incomplete(get_usize(&mut cursor));
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
        error_is_incomplete(get_bytes(&mut cursor, expected_usize));
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
        let all_data = [1u8];
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
    fn test_initialize() -> Result<()> {
        let data = b"hello world".to_vec();
        let frame_bytes = Frame::initialize(data.clone())?;
        let mut cursor = Cursor::new(&frame_bytes[..]);
        let parsed_frame = Frame::parse(&mut cursor)?;
        assert!(parsed_frame.is_some());
        let parsed_frame = parsed_frame.unwrap();
        assert_eq!(parsed_frame, Frame::Initialize(data));
        Ok(())
    }
}
