// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

//! TPM 2.0 sealing unlock backend.
//!
//! Seals the vault master key into a TPM 2.0 NV index (or sealed object) so
//! it can only be unsealed on this specific machine.  Optionally bound to
//! PCR measurements to require a trusted boot state.

use anyhow::{Result, anyhow};
use tss_esapi as _;

use super::UnlockBackend;

/// Unseals the vault passphrase from a TPM 2.0 sealed object.
pub(crate) struct TpmBackend;

impl UnlockBackend for TpmBackend {
    fn retrieve_passphrase(&self) -> Result<String> {
        // TODO: implement using `tss-esapi`:
        // 1. Open a TPM context (tss_esapi::Context::new)
        // 2. Load the sealed object from a side-car file (~/.mp/agent-vault.tpm)
        // 3. Call Esys_Unseal to retrieve the secret
        // 4. Return secret bytes as a hex or base64 string used as the vault passphrase
        Err(anyhow!(
            "tpm backend is not yet implemented; use the passphrase backend"
        ))
    }

    fn name(&self) -> &'static str {
        "tpm"
    }
}
