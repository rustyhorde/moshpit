// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

//! Secret Service API backend (GNOME Keyring / `KWallet`).
//!
//! Retrieves the vault master passphrase from the session keyring, allowing
//! automatic unlock when the user logs in.

use anyhow::{Result, anyhow};
use secret_service as _;

use super::UnlockBackend;

#[allow(dead_code)]
const SERVICE: &str = "moshpit-agent";
#[allow(dead_code)]
const ACCOUNT: &str = "vault-master";

/// Retrieves the vault passphrase from the Secret Service (e.g. GNOME Keyring).
pub(crate) struct SecretServiceBackend;

impl UnlockBackend for SecretServiceBackend {
    fn retrieve_passphrase(&self) -> Result<String> {
        // TODO: implement using the `secret-service` crate
        // Use secret_service::SecretService to open a session, find the item
        // matching SERVICE/ACCOUNT, and return the secret as a String.
        Err(anyhow!(
            "secret-service backend is not yet implemented; use the passphrase backend"
        ))
    }

    fn name(&self) -> &'static str {
        "secret-service"
    }
}
