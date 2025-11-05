use std::io::Cursor;

use anyhow::Result;
use bincode::{Decode, Encode, config::standard, decode_from_slice};
use bytes::Buf as _;

use crate::error::Error;

const USIZE_LENGTH: usize = 8;

#[derive(Clone, Debug, Decode, Encode, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Frame {
    Initialize(Vec<u8>),
}

impl Frame {
    pub fn parse(src: &mut Cursor<&[u8]>) -> Result<Self> {
        match get_u8(src) {
            Ok(0) => {
                let length_slice = get_usize(src)?;
                let length = usize::from_be_bytes(length_slice.try_into()?);
                let data = get_bytes(src, length)?;
                decode_from_slice(data, standard())
                    .map_err(|e| e.into())
                    .map(|(frame, _)| frame)
            }
            Ok(_) => Err(Error::Incomplete.into()),
            Err(e) => Err(e),
        }
    }
}

fn get_u8(src: &mut Cursor<&[u8]>) -> Result<u8> {
    if !src.has_remaining() {
        return Err(Error::Incomplete.into());
    }

    Ok(src.get_u8())
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

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use anyhow::Result;

    use super::{USIZE_LENGTH, get_bytes, get_u8, get_usize};
    use crate::error::Error;

    #[test]
    fn test_get_u8() -> Result<()> {
        let all_data = [0u8];
        let mut cursor = Cursor::new(&all_data[..]);
        let flag = get_u8(&mut cursor)?;
        assert_eq!(flag, 0);
        assert_eq!(cursor.position(), 1);
        Ok(())
    }

    #[test]
    fn test_get_u8_incomplete() -> Result<()> {
        let all_data: [u8; 0] = [];
        let mut cursor = Cursor::new(&all_data[..]);
        let result = get_u8(&mut cursor);
        assert!(result.is_err());
        let err = result.err().unwrap();
        let err = err.downcast_ref::<Error>().unwrap();
        assert_eq!(err, &Error::Incomplete);
        Ok(())
    }

    #[test]
    fn test_get_usize() -> Result<()> {
        let data = 12usize.to_be_bytes();
        let all_data = [&vec![0], data.as_slice(), b"rest of data"].concat();
        let mut cursor = Cursor::new(&all_data[..]);
        let flag = get_u8(&mut cursor)?;
        assert_eq!(flag, 0);
        assert_eq!(cursor.position(), 1);
        let line = get_usize(&mut cursor)?;
        let value = usize::from_be_bytes(line.try_into()?);
        assert_eq!(value, 12);
        assert_eq!(cursor.position(), u64::try_from(USIZE_LENGTH + 1)?);
        assert_eq!(
            &cursor.get_ref()[cursor.position() as usize..],
            b"rest of data"
        );
        Ok(())
    }

    #[test]
    fn test_get_usize_incomplete() -> Result<()> {
        let data = 12usize.to_be_bytes();
        let all_data = [&vec![0], &data[..4]].concat();
        let mut cursor = Cursor::new(&all_data[..]);
        let flag = get_u8(&mut cursor)?;
        assert_eq!(flag, 0);
        assert_eq!(cursor.position(), 1);
        let result = get_usize(&mut cursor);
        assert!(result.is_err());
        let err = result.err().unwrap();
        let err = err.downcast_ref::<Error>().unwrap();
        assert_eq!(err, &Error::Incomplete);
        Ok(())
    }

    #[test]
    fn test_get_bytes() -> Result<()> {
        let data = b"hello world";
        let length = data.len();
        let length_bytes = length.to_be_bytes();
        let all_data = [&vec![0], length_bytes.as_slice(), data.as_slice()].concat();
        let mut cursor = Cursor::new(&all_data[..]);
        let flag = get_u8(&mut cursor)?;
        assert_eq!(flag, 0);
        assert_eq!(cursor.position(), 1);
        let length_slice = get_usize(&mut cursor)?;
        let length = usize::from_be_bytes(length_slice.try_into()?);
        assert_eq!(length, data.len());
        assert_eq!(cursor.position(), 9);
        let bytes = get_bytes(&mut cursor, length)?;
        assert_eq!(bytes, data);
        assert_eq!(cursor.position(), u64::try_from(all_data.len())?);
        Ok(())
    }

    #[test]
    fn test_get_bytes_incomplete() -> Result<()> {
        let data = b"hello world";
        let length = data.len() + 5; // Intentionally incorrect length
        let length_bytes = length.to_be_bytes();
        let all_data = [&vec![0], length_bytes.as_slice(), data.as_slice()].concat();
        let mut cursor = Cursor::new(&all_data[..]);
        let flag = get_u8(&mut cursor)?;
        assert_eq!(flag, 0);
        assert_eq!(cursor.position(), 1);
        let length_slice = get_usize(&mut cursor)?;
        let length = usize::from_be_bytes(length_slice.try_into()?);
        assert_eq!(length, data.len() + 5);
        assert_eq!(cursor.position(), 9);
        let result = get_bytes(&mut cursor, length);
        assert!(result.is_err());
        let err = result.err().unwrap();
        let err = err.downcast_ref::<Error>().unwrap();
        assert_eq!(err, &Error::Incomplete);
        Ok(())
    }
}
