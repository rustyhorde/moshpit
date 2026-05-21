// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

//! Integration tests for the libmoshpit agent client/protocol.
//!
//! These tests spin up a minimal in-process agent server to verify the full
//! request/response framing without requiring a running `mpa` binary.

use std::path::PathBuf;

use bincode_next::{config::standard, encode_to_vec};
use libmoshpit::{AgentIdentityInfo, AgentResponse};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::UnixListener,
};

/// Minimal in-process server: accepts one connection, handles one request,
/// responds, then exits.
async fn run_one_shot_server(socket_path: PathBuf, response: AgentResponse) {
    let listener = UnixListener::bind(&socket_path).unwrap();
    let (mut stream, _) = listener.accept().await.unwrap();

    let req_len = stream.read_u32().await.unwrap() as usize;
    let mut buf = vec![0u8; req_len];
    stream.read_exact(&mut buf).await.unwrap();

    let encoded = encode_to_vec(&response, standard()).unwrap();
    let len = u32::try_from(encoded.len()).unwrap();
    stream.write_all(&len.to_be_bytes()).await.unwrap();
    stream.write_all(&encoded).await.unwrap();
    stream.flush().await.unwrap();
}

fn temp_socket_path(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("moshpit-test-{name}-{}.sock", std::process::id()))
}

#[tokio::test]
async fn agent_client_list_identities() {
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
    let ids = client.list_identities().await.unwrap();
    assert_eq!(ids.len(), 1);
    assert_eq!(ids[0].fingerprint, "SHA256:test");
    assert_eq!(ids[0].algorithm, "X25519");

    server.await.unwrap();
    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn agent_client_list_supported_identities() {
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
        .await
        .unwrap();
    assert_eq!(ids.len(), 1);
    assert_eq!(ids[0].algorithm, "P384");
    assert_eq!(ids[0].fingerprint, "SHA256:filtered");

    server.await.unwrap();
    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn agent_client_get_public_key() {
    let path = temp_socket_path("pubkey");
    let server_path = path.clone();
    let pk_bytes = b"moshpit AAAA== user@host".to_vec();
    let server_response = AgentResponse::PublicKey(pk_bytes.clone());

    let server = tokio::spawn(run_one_shot_server(server_path, server_response));
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let client = libmoshpit::AgentClient::new(path.clone());
    let pk = client.get_public_key("SHA256:test").await.unwrap();
    assert_eq!(pk, pk_bytes);

    server.await.unwrap();
    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn agent_client_sign() {
    let path = temp_socket_path("sign");
    let server_path = path.clone();
    let sig_bytes = vec![0xDE, 0xAD, 0xBE, 0xEF];
    let server_response = AgentResponse::Signature(sig_bytes.clone());

    let server = tokio::spawn(run_one_shot_server(server_path, server_response));
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let client = libmoshpit::AgentClient::new(path.clone());
    let sig = client.sign("SHA256:test", b"data").await.unwrap();
    assert_eq!(sig, sig_bytes);

    server.await.unwrap();
    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn agent_client_error_response() {
    let path = temp_socket_path("error");
    let server_path = path.clone();
    let server_response = AgentResponse::Error("no such identity".into());

    let server = tokio::spawn(run_one_shot_server(server_path, server_response));
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let client = libmoshpit::AgentClient::new(path.clone());
    let result = client.get_public_key("SHA256:missing").await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("no such identity"));

    server.await.unwrap();
    let _ = std::fs::remove_file(&path);
}
