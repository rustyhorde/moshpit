// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

//! Interactive master-passphrase unlock backend.

use anyhow::Result;
use dialoguer::Password;

use super::UnlockBackend;

/// Prompts the user for the vault master passphrase interactively.
pub(crate) struct PassphraseBackend;

impl UnlockBackend for PassphraseBackend {
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn retrieve_passphrase(&self) -> Result<String> {
        Ok(Password::new()
            .with_prompt("Enter moshpit-agent master passphrase")
            .interact()?)
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn set_passphrase(&self) -> Result<String> {
        Ok(Password::new()
            .with_prompt("Set moshpit-agent master passphrase")
            .with_confirmation("Confirm master passphrase", "Passphrases do not match")
            .interact()?)
    }

    fn name(&self) -> &'static str {
        "passphrase"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backend_name() {
        assert_eq!(PassphraseBackend.name(), "passphrase");
    }
}
