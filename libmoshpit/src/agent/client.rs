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

    /// List only identities whose algorithm the client supports.
    ///
    /// Prefer this over [`AgentClient::list_identities`] when the caller may not support all
    /// algorithms the agent holds; the agent filters the response so only usable
    /// identities are returned.
    ///
    /// Pass `libmoshpit::keygen::SUPPORTED_IDENTITY_ALGORITHMS` to advertise the
    /// compile-time capability set of this build.
    ///
    /// # Errors
    /// Returns an error if the agent is unreachable or returns an error response.
    pub async fn list_supported_identities(
        &self,
        supported_algorithms: &[&str],
    ) -> Result<Vec<AgentIdentityInfo>> {
        let supported_algorithms = supported_algorithms
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        match self
            .send(&AgentRequest::ListSupportedIdentities {
                supported_algorithms,
            })
            .await?
        {
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

    /// Query the agent's current state: whether it is locked and which identities are loaded.
    ///
    /// Returns `(locked, identities)`. A connection error means the agent is not running.
    ///
    /// # Errors
    /// Returns an error if the agent returns an unexpected response.
    pub async fn status(&self) -> Result<(bool, Vec<AgentIdentityInfo>)> {
        match self.send(&AgentRequest::Status).await? {
            AgentResponse::AgentStatus { locked, identities } => Ok((locked, identities)),
            AgentResponse::Error(e) => Err(anyhow!("agent error: {e}")),
            other => Err(anyhow!("unexpected agent response: {other:?}")),
        }
    }
}

#[cfg(test)]
#[cfg(unix)]
mod tests {
    use tempfile::TempDir;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::UnixListener;

    use super::*;

    fn spawn_mock_agent(
        socket_path: &PathBuf,
        response: AgentResponse,
    ) -> tokio::task::JoinHandle<()> {
        let listener = UnixListener::bind(socket_path).expect("bind test agent socket");
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept test connection");
            let req_len = stream.read_u32().await.expect("read request length") as usize;
            let mut buf = vec![0u8; req_len];
            let _ = stream
                .read_exact(&mut buf)
                .await
                .expect("read request body");
            let encoded = encode_to_vec(&response, standard()).expect("encode mock response");
            let len = u32::try_from(encoded.len()).expect("response length fits u32");
            stream
                .write_all(&len.to_be_bytes())
                .await
                .expect("write response length");
            stream.write_all(&encoded).await.expect("write response");
            stream.flush().await.expect("flush response");
        })
    }

    #[tokio::test]
    async fn status_unlocked_with_identities() {
        let dir = TempDir::new().expect("temp dir");
        let socket_path = dir.path().join("test-agent.sock");
        drop(spawn_mock_agent(
            &socket_path,
            AgentResponse::AgentStatus {
                locked: false,
                identities: vec![AgentIdentityInfo {
                    algorithm: "X25519".to_string(),
                    fingerprint: "SHA256:aabbcc".to_string(),
                    comment: String::new(),
                }],
            },
        ));
        let client = AgentClient::new(socket_path);
        let (locked, ids) = client.status().await.expect("status should succeed");
        assert!(!locked);
        assert_eq!(ids.len(), 1);
        assert_eq!(ids[0].fingerprint, "SHA256:aabbcc");
    }

    #[tokio::test]
    async fn status_locked_no_identities() {
        let dir = TempDir::new().expect("temp dir");
        let socket_path = dir.path().join("test-agent-locked.sock");
        drop(spawn_mock_agent(
            &socket_path,
            AgentResponse::AgentStatus {
                locked: true,
                identities: vec![],
            },
        ));
        let client = AgentClient::new(socket_path);
        let (locked, ids) = client.status().await.expect("status should succeed");
        assert!(locked);
        assert!(ids.is_empty());
    }

    #[tokio::test]
    async fn status_propagates_agent_error() {
        let dir = TempDir::new().expect("temp dir");
        let socket_path = dir.path().join("test-agent-err.sock");
        drop(spawn_mock_agent(
            &socket_path,
            AgentResponse::Error("daemon error".to_string()),
        ));
        let client = AgentClient::new(socket_path);
        let err = client
            .status()
            .await
            .expect_err("expected error from agent");
        assert!(err.to_string().contains("daemon error"), "err: {err}");
    }

    #[tokio::test]
    async fn status_unexpected_response_errors() {
        let dir = TempDir::new().expect("temp dir");
        let socket_path = dir.path().join("test-agent-unexpected.sock");
        drop(spawn_mock_agent(&socket_path, AgentResponse::Ok));
        let client = AgentClient::new(socket_path);
        assert!(client.status().await.is_err());
    }
}
