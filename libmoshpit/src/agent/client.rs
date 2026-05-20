// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

//! Async Unix-socket client for the moshpit agent.

use std::path::PathBuf;

use anyhow::{Result, anyhow};
use bincode_next::{config::standard, decode_from_slice, encode_to_vec};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::UnixStream,
};

use super::protocol::{AgentIdentityInfo, AgentRequest, AgentResponse};

/// An async client that communicates with a running `mpa` agent over a Unix socket.
#[derive(Debug)]
pub struct AgentClient {
    socket_path: PathBuf,
}

impl AgentClient {
    /// Create a client targeting the given socket path.
    #[must_use]
    pub fn new(socket_path: PathBuf) -> Self {
        Self { socket_path }
    }

    /// Connect to the agent socket, send `request`, and return the response.
    ///
    /// # Errors
    /// Returns an error if the socket connection fails, encoding fails, or the
    /// response cannot be decoded.
    pub async fn send(&self, request: &AgentRequest) -> Result<AgentResponse> {
        let mut stream = UnixStream::connect(&self.socket_path).await?;
        let encoded = encode_to_vec(request, standard())?;
        let len = u32::try_from(encoded.len())?;
        stream.write_all(&len.to_be_bytes()).await?;
        stream.write_all(&encoded).await?;
        stream.flush().await?;

        let resp_len = stream.read_u32().await? as usize;
        let mut buf = vec![0u8; resp_len];
        let _ = stream.read_exact(&mut buf).await?;
        let (response, _) = decode_from_slice::<AgentResponse, _>(&buf, standard())?;
        Ok(response)
    }

    /// List identities held by the agent.
    ///
    /// # Errors
    /// Returns an error if the agent is unreachable or returns an error response.
    pub async fn list_identities(&self) -> Result<Vec<AgentIdentityInfo>> {
        match self.send(&AgentRequest::ListIdentities).await? {
            AgentResponse::Identities(ids) => Ok(ids),
            AgentResponse::Error(e) => Err(anyhow!("agent error: {e}")),
            other => Err(anyhow!("unexpected agent response: {other:?}")),
        }
    }

    /// Fetch the full public key file bytes for the given fingerprint.
    ///
    /// # Errors
    /// Returns an error if the agent is unreachable, the fingerprint is unknown,
    /// or the agent is locked.
    pub async fn get_public_key(&self, fingerprint: &str) -> Result<Vec<u8>> {
        match self
            .send(&AgentRequest::GetPublicKey(fingerprint.to_string()))
            .await?
        {
            AgentResponse::PublicKey(bytes) => Ok(bytes),
            AgentResponse::Error(e) => Err(anyhow!("agent error: {e}")),
            other => Err(anyhow!("unexpected agent response: {other:?}")),
        }
    }

    /// Sign `data` with the key identified by `fingerprint`.
    ///
    /// # Errors
    /// Returns an error if the agent is unreachable, the fingerprint is unknown,
    /// or the agent is locked.
    pub async fn sign(&self, fingerprint: &str, data: &[u8]) -> Result<Vec<u8>> {
        match self
            .send(&AgentRequest::Sign {
                fingerprint: fingerprint.to_string(),
                data: data.to_vec(),
            })
            .await?
        {
            AgentResponse::Signature(sig) => Ok(sig),
            AgentResponse::Error(e) => Err(anyhow!("agent error: {e}")),
            other => Err(anyhow!("unexpected agent response: {other:?}")),
        }
    }
}
