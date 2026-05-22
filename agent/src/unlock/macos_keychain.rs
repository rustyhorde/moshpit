// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

//! macOS Keychain unlock backend.

use anyhow::{Result, anyhow};
use security_framework as _;

use super::UnlockBackend;

#[allow(dead_code)]
const SERVICE: &str = "moshpit-agent";
#[allow(dead_code)]
const ACCOUNT: &str = "vault-master";

/// Retrieves the vault passphrase from the macOS Keychain.
pub(crate) struct MacosKeychainBackend;

impl UnlockBackend for MacosKeychainBackend {
    fn retrieve_passphrase(&self) -> Result<String> {
        // TODO: implement using the `security-framework` crate
        // Use security_framework::os::macos::keychain::SecKeychain::default()
        // and SecKeychainItem to find the generic password for SERVICE/ACCOUNT.
        Err(anyhow!(
            "macos-keychain backend is not yet implemented; use the passphrase backend"
        ))
    }

    fn name(&self) -> &'static str {
        "macos-keychain"
    }
}
