// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

use std::fmt::{Display, Formatter};

use bincode::{
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
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl<Context> Decode<Context> for UuidWrapper {
    fn decode<D: Decoder<Context = Context>>(decoder: &mut D) -> Result<Self, DecodeError> {
        let s = String::decode(decoder)?;
        let uuid = Uuid::parse_str(&s).map_err(|e| {
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
        let uuid = Uuid::parse_str(&s).map_err(|e| {
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
