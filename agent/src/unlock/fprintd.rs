// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

//! Fingerprint (fprintd) unlock backend.
//!
//! Uses the `fprintd` D-Bus service to verify the user's fingerprint, then
//! retrieves the vault passphrase from an encrypted side-car file that is only
//! accessible once fprintd authorization succeeds.

use anyhow::{Result, anyhow};
use zbus as _;

use super::UnlockBackend;

/// Unlocks the vault after a fingerprint scan via fprintd.
pub(crate) struct FprintdBackend;

impl UnlockBackend for FprintdBackend {
    fn retrieve_passphrase(&self) -> Result<String> {
        // TODO: implement using `zbus`:
        // 1. Connect to the system bus
        // 2. Call net.reactivated.Fprint.Manager.GetDefaultDevice
        // 3. Claim the device, run VerifyStart("any"), wait for VerifyFingerSelected
        //    and VerifyStatus signals
        // 4. On success, read the passphrase from an encrypted side-car file
        Err(anyhow!(
            "fprintd backend is not yet implemented; use the passphrase backend"
        ))
    }

    fn name(&self) -> &'static str {
        "fprintd"
    }
}
