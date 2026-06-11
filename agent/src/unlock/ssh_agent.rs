// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

//! SSH agent piggyback unlock backend.
//!
//! If `SSH_AUTH_SOCK` is set, derives the vault master key by requesting a
//! signature from the running ssh-agent over a fixed challenge nonce and using
//! the SHA256 hash of the signature as the vault passphrase.
//!
//! This provides seamless unlock when the user already has an ssh-agent session,
//! without exposing the vault passphrase directly.

use std::env::var;

use anyhow::{Result, anyhow};

use super::UnlockBackend;

/// Derives the vault passphrase from an SSH agent challenge-response signature.
pub(crate) struct SshAgentBackend;

impl UnlockBackend for SshAgentBackend {
    fn retrieve_passphrase(&self) -> Result<String> {
        // TODO: implement SSH agent protocol client:
        // 1. Connect to $SSH_AUTH_SOCK
        // 2. Send SSH2_AGENTC_REQUEST_IDENTITIES and pick a key
        // 3. Send SSH2_AGENTC_SIGN_REQUEST with a fixed challenge nonce
        //    (b"moshpit-vault-challenge-v1" padded to 64 bytes)
        // 4. Hash the returned signature with SHA256, base64-encode → use as passphrase
        drop(
            var("SSH_AUTH_SOCK")
                .map_err(|_| anyhow!("SSH_AUTH_SOCK not set — no ssh-agent running"))?,
        );
        Err(anyhow!(
            "ssh-agent-piggyback backend is not yet implemented; use the passphrase backend"
        ))
    }

    fn name(&self) -> &'static str {
        "ssh-agent-piggyback"
    }
}
