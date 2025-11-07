// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

use anyhow::Result;
use aws_lc_rs::aead::{AES_256_GCM_SIV, RandomizedNonceKey};
use bon::Builder;
use getset::Getters;
use uuid::Uuid;

/// State needed for UDP communication
#[derive(Clone, Copy, Debug)]
pub enum UdpState {
    /// Key material for encrypting/decrypting UDP packets
    Key([u8; 32]),
    /// HMAC key for signing UDP packets
    HmacKey([u8; 64]),
    /// Client UUID
    Uuid(Uuid),
}

/// UDP client data
#[derive(Builder, Debug, Getters)]
#[getset(get = "pub")]
pub struct UdpClient {
    /// Client UUID
    uuid: Uuid,
    /// Key for encrypting/decrypting UDP packets
    #[builder(with = |key: [u8; 32]| -> Result<_> { RandomizedNonceKey::new(&AES_256_GCM_SIV, &key).map_err(Into::into) })]
    rnk: RandomizedNonceKey,
}
