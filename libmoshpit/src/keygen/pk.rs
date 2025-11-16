// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

use std::io::{BufReader, Read};

use anyhow::Result;
use aws_lc_rs::digest::{self, SHA256};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use bishop::{BishopArt, DrawingOptions};
use whoami::fallible::{hostname, username};

use crate::MoshpitError;

fn generate_encoded_digest(key_bytes: &[u8]) -> String {
    let sha256_digest = digest::digest(&SHA256, key_bytes);
    STANDARD.encode(sha256_digest.as_ref())
}

/// Extract the public key bytes from a moshpit public key reader
///
/// SHA256:S8hOlxbLPA/1jl9fP40JDxRgAeJ//o4kZOvHCUA1+4w= jozias@CachyOS
/// # Errors
/// * If the reader cannot be read
///
pub fn extract_public_key_bytes<R: Read>(reader: R) -> Result<Vec<u8>> {
    let mut reader = BufReader::new(reader);
    let mut pk_file_bytes = String::new();
    let _count = reader.read_to_string(&mut pk_file_bytes)?;
    let split = pk_file_bytes.split_whitespace().collect::<Vec<&str>>();

    if split.len() == 3 {
        Ok(STANDARD.decode(split[1])?)
    } else {
        Err(MoshpitError::InvalidPublicKeyFormat.into())
    }
}

/// Generate the fingerprint for the given key bytes
///
/// # Errors
///
/// Returns an error if the key bytes are invalid or if the system cannot determine the username or hostname.
///
pub fn fingerprint(key_bytes: &[u8]) -> Result<String> {
    let encoded_digest = generate_encoded_digest(key_bytes);
    let username = username().unwrap_or("unknown-user".to_string());
    let hostname = hostname().unwrap_or("unknown-host".to_string());
    Ok(format!("SHA256:{encoded_digest} {username}@{hostname}"))
}

/// Get the randomart image for the given key bytes
#[must_use]
pub fn randomart(key_bytes: &[u8]) -> String {
    let draw_opts = DrawingOptions {
        top_text: "X25519 SHA256".to_string(),
        bottom_text: "SHA256".to_string(),
        ..Default::default()
    };
    let mut art = BishopArt::new();
    art.input(key_bytes);
    art.draw_with_opts(&draw_opts).clone()
}

/// Verify a public key fingerprint against the provided key bytes
#[must_use]
pub fn verify_fingerprint(fingerprint: &str, key_bytes: &[u8]) -> bool {
    generate_encoded_digest(key_bytes) == fingerprint
}
