// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

//! systemd credentials unlock backend.
//!
//! When the agent runs as a systemd user service, systemd can decrypt a
//! `LoadCredentialEncrypted=moshpit-agent-vault-key:...` credential at service
//! start time and place it in `$CREDENTIALS_DIRECTORY/moshpit-agent-vault-key`.
//!
//! This backend reads the plaintext credential file and returns it as the
//! vault master passphrase — no interactive prompt needed.

use std::fs;

use anyhow::{Result, anyhow};

use super::UnlockBackend;

const CREDENTIAL_NAME: &str = "moshpit-agent-vault-key";

/// Reads the vault master passphrase from the systemd credential directory.
pub(crate) struct SystemdCredsBackend;

impl UnlockBackend for SystemdCredsBackend {
    fn retrieve_passphrase(&self) -> Result<String> {
        let creds_dir = std::env::var("CREDENTIALS_DIRECTORY")
            .map_err(|_| anyhow!("CREDENTIALS_DIRECTORY not set — not running under systemd"))?;
        let path = std::path::Path::new(&creds_dir).join(CREDENTIAL_NAME);
        let passphrase = fs::read_to_string(&path)
            .map_err(|e| anyhow!("failed to read systemd credential {}: {e}", path.display()))?;
        Ok(passphrase.trim_end_matches(['\n', '\r']).to_string())
    }

    fn name(&self) -> &'static str {
        "systemd-creds"
    }
}
