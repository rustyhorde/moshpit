// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

//! Integration tests for the `mpa` agent daemon.
//!
//! These tests start the agent as a child process (using the compiled binary
//! from the same build), communicate over the Unix socket, and verify
//! observable behaviour: add-key, list, lock, unlock, remove-all.

use std::{
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::Duration,
};

use libmoshpit::{AgentClient, AgentRequest, AgentResponse};

const TEST_KEY_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../libmoshpit/tests/keys/id_x25519_test"
);
const TEST_KEY_ENC_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../libmoshpit/tests/keys/id_x25519_test_enc"
);
const TEST_KEY_ENC_PASSPHRASE: &str = "test";

fn agent_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_mpa"))
}

fn temp_socket(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "moshpit-agent-test-{}-{}.sock",
        name,
        std::process::id()
    ))
}

fn temp_vault(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "moshpit-agent-test-{}-{}.vault",
        name,
        std::process::id()
    ))
}

/// Start the agent in foreground mode and return the child process.
///
/// Passes `--passphrase-stdin` with an empty passphrase so the daemon starts
/// non-interactively in test environments.
fn start_agent(socket: &Path, vault: &Path) -> Child {
    use std::io::Write as _;
    let mut child = Command::new(agent_binary())
        .args([
            "start",
            "--foreground",
            "--passphrase-stdin",
            "--socket",
            socket.to_str().unwrap(),
            "--vault",
            vault.to_str().unwrap(),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to start mpa");
    // Write empty passphrase (newline) then close stdin so the daemon doesn't block.
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(b"\n");
    }
    child
}

async fn wait_for_socket(socket: &Path, timeout: Duration) -> bool {
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if socket.exists() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}

#[tokio::test]
async fn agent_lifecycle_add_list_lock_unlock() {
    let socket = temp_socket("lifecycle");
    let vault = temp_vault("lifecycle");

    let mut child = start_agent(&socket, &vault);

    let ready = wait_for_socket(&socket, Duration::from_secs(5)).await;
    if !ready {
        child.kill().ok();
        child.wait().ok();
        panic!("agent socket did not appear within 5s");
    }

    let client = AgentClient::new(socket.clone());

    // Initially no identities
    let ids = client.list_identities().await.expect("list");
    assert!(ids.is_empty(), "expected empty list on fresh agent");

    // Add unencrypted key
    let resp = client
        .send(&AgentRequest::AddIdentity {
            key_path: TEST_KEY_PATH.to_string(),
            passphrase: None,
        })
        .await
        .expect("add identity");
    assert!(
        matches!(resp, AgentResponse::Ok),
        "add identity should succeed"
    );

    // List should now have one entry
    let ids = client.list_identities().await.expect("list after add");
    assert_eq!(ids.len(), 1, "expected 1 identity after add");
    let fp = ids[0].fingerprint.clone();
    assert!(
        fp.starts_with("SHA256:"),
        "fingerprint should have SHA256: prefix"
    );

    // GetPublicKey should return non-empty bytes
    let pk = client.get_public_key(&fp).await.expect("get public key");
    assert!(!pk.is_empty(), "public key bytes should not be empty");

    // Lock clears identities from memory
    let resp = client.send(&AgentRequest::Lock).await.expect("lock");
    assert!(matches!(resp, AgentResponse::Ok));

    let ids_after_lock = client.list_identities().await.expect("list after lock");
    assert!(
        ids_after_lock.is_empty(),
        "agent should have no identities after lock"
    );

    // GetPublicKey should fail after lock
    let resp = client.get_public_key(&fp).await;
    assert!(
        resp.is_err(),
        "get_public_key should fail when agent is locked"
    );

    // Unlock reloads from vault (vault has no master passphrase for this test)
    let resp = client
        .send(&AgentRequest::Unlock(String::new()))
        .await
        .expect("unlock");
    assert!(matches!(resp, AgentResponse::Ok));

    let ids_after_unlock = client.list_identities().await.expect("list after unlock");
    assert_eq!(
        ids_after_unlock.len(),
        1,
        "agent should have 1 identity after unlock"
    );

    // RemoveAllIdentities
    let resp = client
        .send(&AgentRequest::RemoveAllIdentities)
        .await
        .expect("remove all");
    assert!(matches!(resp, AgentResponse::Ok));
    let ids_empty = client.list_identities().await.expect("final list");
    assert!(ids_empty.is_empty());

    child.kill().ok();
    child.wait().ok();
    let _ = std::fs::remove_file(&socket);
    let _ = std::fs::remove_file(&vault);
}

#[tokio::test]
async fn agent_add_encrypted_key() {
    let socket = temp_socket("enc");
    let vault = temp_vault("enc");

    let mut child = start_agent(&socket, &vault);
    let ready = wait_for_socket(&socket, Duration::from_secs(5)).await;
    if !ready {
        child.kill().ok();
        child.wait().ok();
        panic!("agent socket did not appear");
    }

    let client = AgentClient::new(socket.clone());

    // Add encrypted key with correct passphrase
    let resp = client
        .send(&AgentRequest::AddIdentity {
            key_path: TEST_KEY_ENC_PATH.to_string(),
            passphrase: Some(TEST_KEY_ENC_PASSPHRASE.to_string()),
        })
        .await
        .expect("add encrypted identity");
    assert!(
        matches!(resp, AgentResponse::Ok),
        "add encrypted identity should succeed, got {resp:?}"
    );

    let ids = client.list_identities().await.expect("list");
    assert_eq!(ids.len(), 1);

    // Add same key with wrong passphrase should fail
    let resp = client
        .send(&AgentRequest::AddIdentity {
            key_path: TEST_KEY_ENC_PATH.to_string(),
            passphrase: Some("wrong".to_string()),
        })
        .await
        .expect("request succeeded but response should be error");
    assert!(
        matches!(resp, AgentResponse::Error(_)),
        "expected error for wrong passphrase"
    );

    child.kill().ok();
    child.wait().ok();
    let _ = std::fs::remove_file(&socket);
    let _ = std::fs::remove_file(&vault);
}
