// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

//! UUID wrapper for session identifiers.

use std::fmt::{Display, Formatter, Result as FmtResult};

use bincode_next::{
    BorrowDecode, Decode, Encode,
    de::{BorrowDecoder, Decoder},
    enc::Encoder,
    error::{DecodeError, EncodeError},
};
use uuid::Uuid;

#[cfg(test)]
use crate::utils::Mock;

/// A `Uuid` wrapper that implements `bincode::Encode` and `bincode::Decode`
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct UuidWrapper(Uuid);

impl UuidWrapper {
    /// Create a new `UuidWrapper` from the given `Uuid`.
    #[must_use]
    pub fn new(uuid: Uuid) -> Self {
        Self(uuid)
    }

    /// Get the inner `Uuid`.
    #[must_use]
    pub fn as_uuid(&self) -> Uuid {
        self.0
    }
}

impl Default for UuidWrapper {
    fn default() -> Self {
        Self(Uuid::new_v4())
    }
}

impl From<Uuid> for UuidWrapper {
    fn from(uuid: Uuid) -> Self {
        Self(uuid)
    }
}

impl AsRef<Uuid> for UuidWrapper {
    fn as_ref(&self) -> &Uuid {
        &self.0
    }
}

#[cfg(test)]
impl Mock for UuidWrapper {
    fn mock() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Display for UuidWrapper {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{}", self.0)
    }
}

impl<Context> Decode<Context> for UuidWrapper {
    fn decode<D: Decoder<Context = Context>>(decoder: &mut D) -> Result<Self, DecodeError> {
        let s = String::decode(decoder)?;
        // `Uuid::try_parse` instead of `Uuid::parse_str`: the latter's error
        // path (`InvalidUuid::into_err`) slices the input by byte offset and
        // panics on non-ASCII multi-byte UTF-8.  `try_parse` returns a generic
        // error without that slicing, so untrusted input can never panic here.
        let uuid = Uuid::try_parse(&s).map_err(|e| {
            DecodeError::OtherString(format!("failed to parse Uuid from string: {e}"))
        })?;
        Ok(UuidWrapper(uuid))
    }
}

impl<'de, Context> BorrowDecode<'de, Context> for UuidWrapper {
    fn borrow_decode<D: BorrowDecoder<'de, Context = Context>>(
        decoder: &mut D,
    ) -> Result<Self, DecodeError> {
        let s = String::decode(decoder)?;
        // See the note in `Decode::decode`: `try_parse` avoids the panicking
        // error path of `parse_str` on non-ASCII input.
        let uuid = Uuid::try_parse(&s).map_err(|e| {
            DecodeError::OtherString(format!("failed to parse Uuid from string: {e}"))
        })?;
        Ok(UuidWrapper(uuid))
    }
}

impl Encode for UuidWrapper {
    fn encode<E: Encoder>(&self, encoder: &mut E) -> Result<(), EncodeError> {
        let s = format!("{}", self.0);
        s.encode(encoder)
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use bincode_next::{config::standard, decode_from_slice, encode_to_vec};
    use uuid::Uuid;

    use super::UuidWrapper;

    #[test]
    fn uuid_wrapper_bincode_round_trip() -> Result<()> {
        let uuid = Uuid::new_v4();
        let wrapper = UuidWrapper::new(uuid);
        let encoded = encode_to_vec(wrapper, standard())?;
        let (decoded, _): (UuidWrapper, _) = decode_from_slice(&encoded, standard())?;
        assert_eq!(decoded.as_uuid(), uuid);
        Ok(())
    }

    #[test]
    fn uuid_wrapper_display_matches_hyphenated() {
        let uuid = Uuid::new_v4();
        let wrapper = UuidWrapper::new(uuid);
        assert_eq!(format!("{wrapper}"), uuid.to_string());
    }

    #[test]
    fn uuid_wrapper_from_uuid() {
        let uuid = Uuid::new_v4();
        let wrapper = UuidWrapper::from(uuid);
        assert_eq!(wrapper.as_uuid(), uuid);
    }

    /// A bincode-encoded string that is valid UTF-8 but not a UUID — and
    /// contains a multi-byte sequence (`0xc3 0xa9` = `é`) — must decode to a
    /// structured error, not panic.  `Uuid::parse_str` would slice this string
    /// on a non-char boundary in its error path and panic; `try_parse` does not.
    #[test]
    fn uuid_wrapper_decode_non_ascii_errors_without_panic() {
        // bincode `standard`: varint length prefix (3) followed by the UTF-8
        // bytes of "aé" (a, then 0xc3 0xa9).
        let encoded = [3u8, b'a', 0xc3, 0xa9];
        let result: Result<(UuidWrapper, usize), _> = decode_from_slice(&encoded, standard());
        assert!(result.is_err(), "non-UUID string must yield Err, not panic");
    }
}
