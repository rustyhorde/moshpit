// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

#![cfg(unix)]

//! Integration tests for the libmoshpit agent client/protocol.
//!
//! These tests spin up a minimal in-process agent server to verify the full
//! request/response framing without requiring a running `mpa` binary.

use std::path::PathBuf;

use anyhow::Result;
use bincode_next::{config::standard, encode_to_vec};
use libmoshpit::{AgentIdentityInfo, AgentResponse};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::UnixListener,
};

/// Minimal in-process server: accepts one connection, handles one request,
/// responds, then exits.
async fn run_one_shot_server(socket_path: PathBuf, response: AgentResponse) -> Result<()> {
    let listener = UnixListener::bind(&socket_path)?;
    let (mut stream, _) = listener.accept().await?;

    let req_len = stream.read_u32().await? as usize;
    let mut buf = vec![0u8; req_len];
    stream.read_exact(&mut buf).await?;

    let encoded = encode_to_vec(&response, standard())?;
    let len = u32::try_from(encoded.len())?;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(&encoded).await?;
    stream.flush().await?;
    Ok(())
}

fn temp_socket_path(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("moshpit-test-{name}-{}.sock", std::process::id()))
}

#[tokio::test]
async fn agent_client_list_identities() -> Result<()> {
    let path = temp_socket_path("list");
    let server_path = path.clone();
    let expected = vec![AgentIdentityInfo {
        algorithm: "X25519".into(),
        fingerprint: "SHA256:test".into(),
        comment: "user@host".into(),
    }];
    let server_response = AgentResponse::Identities(expected.clone());

    let server = tokio::spawn(run_one_shot_server(server_path, server_response));

    // Give the server a moment to bind.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let client = libmoshpit::AgentClient::new(path.clone());
    let ids = client.list_identities().await?;
    assert_eq!(ids.len(), 1);
    assert_eq!(ids[0].fingerprint, "SHA256:test");
    assert_eq!(ids[0].algorithm, "X25519");

    server.await??;
    let _ = std::fs::remove_file(&path);
    Ok(())
}

#[tokio::test]
async fn agent_client_list_supported_identities() -> Result<()> {
    let path = temp_socket_path("list-supported");
    let server_path = path.clone();
    let expected = vec![AgentIdentityInfo {
        algorithm: "P384".into(),
        fingerprint: "SHA256:filtered".into(),
        comment: String::new(),
    }];
    let server_response = AgentResponse::Identities(expected.clone());

    let server = tokio::spawn(run_one_shot_server(server_path, server_response));
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let client = libmoshpit::AgentClient::new(path.clone());
    let ids = client
        .list_supported_identities(&["P384", "P256", "X25519"])
        .await?;
    assert_eq!(ids.len(), 1);
    assert_eq!(ids[0].algorithm, "P384");
    assert_eq!(ids[0].fingerprint, "SHA256:filtered");

    server.await??;
    let _ = std::fs::remove_file(&path);
    Ok(())
}

#[tokio::test]
async fn agent_client_get_public_key() -> Result<()> {
    let path = temp_socket_path("pubkey");
    let server_path = path.clone();
    let pk_bytes = b"moshpit AAAA== user@host".to_vec();
    let server_response = AgentResponse::PublicKey(pk_bytes.clone());

    let server = tokio::spawn(run_one_shot_server(server_path, server_response));
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let client = libmoshpit::AgentClient::new(path.clone());
    let pk = client.get_public_key("SHA256:test").await?;
    assert_eq!(pk, pk_bytes);

    server.await??;
    let _ = std::fs::remove_file(&path);
    Ok(())
}

#[tokio::test]
async fn agent_client_sign() -> Result<()> {
    let path = temp_socket_path("sign");
    let server_path = path.clone();
    let sig_bytes = vec![0xDE, 0xAD, 0xBE, 0xEF];
    let server_response = AgentResponse::Signature(sig_bytes.clone());

    let server = tokio::spawn(run_one_shot_server(server_path, server_response));
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let client = libmoshpit::AgentClient::new(path.clone());
    let sig = client.sign("SHA256:test", b"data").await?;
    assert_eq!(sig, sig_bytes);

    server.await??;
    let _ = std::fs::remove_file(&path);
    Ok(())
}

#[tokio::test]
async fn agent_client_error_response() -> Result<()> {
    let path = temp_socket_path("error");
    let server_path = path.clone();
    let server_response = AgentResponse::Error("no such identity".into());

    let server = tokio::spawn(run_one_shot_server(server_path, server_response));
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let client = libmoshpit::AgentClient::new(path.clone());
    let result = client.get_public_key("SHA256:missing").await;
    assert!(result.is_err());
    let err_msg = result.expect_err("expected error response").to_string();
    assert!(err_msg.contains("no such identity"));

    server.await??;
    let _ = std::fs::remove_file(&path);
    Ok(())
}

#[tokio::test]
async fn agent_client_list_identities_unexpected_response() -> Result<()> {
    let path = temp_socket_path("list-unexpected");
    let server_path = path.clone();
    // Return PublicKey instead of Identities — client should error
    let server_response = AgentResponse::PublicKey(b"unexpected".to_vec());

    let server = tokio::spawn(run_one_shot_server(server_path, server_response));
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let client = libmoshpit::AgentClient::new(path.clone());
    let result = client.list_identities().await;
    assert!(result.is_err());

    server.await??;
    let _ = std::fs::remove_file(&path);
    Ok(())
}

#[tokio::test]
async fn agent_client_list_supported_identities_unexpected_response() -> Result<()> {
    let path = temp_socket_path("list-sup-unexpected");
    let server_path = path.clone();
    // Return Signature instead of Identities — client should error
    let server_response = AgentResponse::Signature(vec![0xAA, 0xBB]);

    let server = tokio::spawn(run_one_shot_server(server_path, server_response));
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let client = libmoshpit::AgentClient::new(path.clone());
    let result = client.list_supported_identities(&["P384", "X25519"]).await;
    assert!(result.is_err());

    server.await??;
    let _ = std::fs::remove_file(&path);
    Ok(())
}

#[tokio::test]
async fn agent_client_get_public_key_unexpected_response() -> Result<()> {
    let path = temp_socket_path("pubkey-unexpected");
    let server_path = path.clone();
    // Return Identities instead of PublicKey — client should error
    let server_response = AgentResponse::Identities(vec![]);

    let server = tokio::spawn(run_one_shot_server(server_path, server_response));
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let client = libmoshpit::AgentClient::new(path.clone());
    let result = client.get_public_key("SHA256:test").await;
    assert!(result.is_err());

    server.await??;
    let _ = std::fs::remove_file(&path);
    Ok(())
}

#[tokio::test]
async fn agent_client_sign_unexpected_response() -> Result<()> {
    let path = temp_socket_path("sign-unexpected");
    let server_path = path.clone();
    // Return Ok instead of Signature — client should error
    let server_response = AgentResponse::Ok;

    let server = tokio::spawn(run_one_shot_server(server_path, server_response));
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let client = libmoshpit::AgentClient::new(path.clone());
    let result = client.sign("SHA256:test", b"data").await;
    assert!(result.is_err());

    server.await??;
    let _ = std::fs::remove_file(&path);
    Ok(())
}
