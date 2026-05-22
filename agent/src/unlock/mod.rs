// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

//! Vault unlock backends.
//!
//! Each backend implements [`UnlockBackend`] and returns the master passphrase
//! (or an error if the user cancelled or hardware is unavailable).
//!
//! The passphrase backend is always compiled in.  All others are gated behind
//! Cargo features so users only pull in the dependencies they need.

pub(crate) mod passphrase;

#[cfg(feature = "secret-service")]
pub(crate) mod secret_service;

#[cfg(feature = "macos-keychain")]
pub(crate) mod macos_keychain;

#[cfg(feature = "fido2")]
pub(crate) mod fido2;

#[cfg(feature = "tpm")]
pub(crate) mod tpm;

#[cfg(feature = "systemd-creds")]
pub(crate) mod systemd_creds;

#[cfg(feature = "fprintd")]
pub(crate) mod fprintd;

#[cfg(feature = "ssh-agent-piggyback")]
pub(crate) mod ssh_agent;

use anyhow::Result;

/// A backend that retrieves the master passphrase used to decrypt the vault.
#[cfg_attr(
    all(feature = "unstable", nightly),
    allow(multiple_supertrait_upcastable)
)]
pub(crate) trait UnlockBackend: Send + Sync {
    /// Retrieve the master passphrase for an existing vault.
    ///
    /// Returns the passphrase string on success, or an error if the backend
    /// failed, is unavailable, or the user cancelled.
    fn retrieve_passphrase(&self) -> Result<String>;

    /// Set the master passphrase when creating a new vault (first launch).
    ///
    /// The default implementation delegates to [`retrieve_passphrase`].
    /// Backends that support interactive setup (e.g. passphrase with
    /// confirmation) should override this.
    fn set_passphrase(&self) -> Result<String> {
        self.retrieve_passphrase()
    }

    /// A human-readable name for this backend (used in log messages).
    #[allow(dead_code)]
    fn name(&self) -> &'static str;
}

#[cfg(test)]
mod tests {
    use super::UnlockBackend;

    struct AlwaysOkBackend;

    impl UnlockBackend for AlwaysOkBackend {
        fn retrieve_passphrase(&self) -> anyhow::Result<String> {
            Ok("the-passphrase".to_string())
        }

        fn name(&self) -> &'static str {
            "always-ok"
        }
    }

    #[test]
    fn default_set_passphrase_delegates_to_retrieve() {
        assert_eq!(AlwaysOkBackend.set_passphrase().unwrap(), "the-passphrase");
    }

    #[test]
    fn backend_name_returns_correct_str() {
        assert_eq!(AlwaysOkBackend.name(), "always-ok");
    }
}
