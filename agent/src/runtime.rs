// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

use std::{
    collections::HashMap,
    ffi::OsString,
    fs,
    io::BufRead as _,
    path::{Path, PathBuf},
    sync::Arc,
};

#[cfg(target_family = "unix")]
use std::os::unix::fs::DirBuilderExt as _;

use anyhow::{Result, anyhow};
use bincode_next::{config::standard, decode_from_slice, encode_to_vec};
use clap::Parser as _;
use dialoguer::Password;
use libmoshpit::{
    AgentIdentityInfo, AgentRequest, AgentResponse, fingerprint, load_identity_key, load_public_key,
};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::{UnixListener, UnixStream},
    sync::Mutex,
};
use tracing::{error, info, warn};
use zeroize::Zeroize as _;

use crate::{
    cli::{Cli, Commands},
    config::AgentConfig,
    unlock::{UnlockBackend, passphrase::PassphraseBackend},
    vault::Vault,
};

#[cfg(feature = "fido2")]
use crate::unlock::fido2::Fido2Backend;
#[cfg(feature = "fprintd")]
use crate::unlock::fprintd::FprintdBackend;
#[cfg(feature = "macos-keychain")]
use crate::unlock::macos_keychain::MacosKeychainBackend;
#[cfg(feature = "secret-service")]
use crate::unlock::secret_service::SecretServiceBackend;
#[cfg(feature = "ssh-agent-piggyback")]
use crate::unlock::ssh_agent::SshAgentBackend;
#[cfg(feature = "systemd-creds")]
use crate::unlock::systemd_creds::SystemdCredsBackend;
#[cfg(feature = "tpm")]
use crate::unlock::tpm::TpmBackend;

/// In-memory identity: decrypted key pair + full public key file bytes.
#[derive(Clone)]
struct Identity {
    /// Full public key file content (as stored on disk) used in `Initialize` frames.
    full_pub_key_bytes: Vec<u8>,
    /// Key algorithm string.
    algorithm: String,
    /// SHA256 fingerprint for lookup.
    fingerprint: String,
    /// Decrypted private key bytes (zeroized on removal/lock).
    private_key: Vec<u8>,
}

impl Drop for Identity {
    fn drop(&mut self) {
        self.private_key.zeroize();
    }
}

type IdentityMap = Arc<Mutex<HashMap<String, Identity>>>;

/// Loaded identities keyed by fingerprint.
#[must_use]
fn new_identity_map() -> IdentityMap {
    Arc::new(Mutex::new(HashMap::new()))
}

/// Load a key from disk into the identity map.
async fn load_key_into_map(
    map: &IdentityMap,
    key_path: &str,
    passphrase: Option<&str>,
    vault: &Arc<Mutex<Option<Vault>>>,
    vault_path: &Path,
    master_passphrase: &str,
) -> Result<AgentIdentityInfo> {
    let priv_path = PathBuf::from(key_path);
    let mut pub_path = priv_path.clone();
    let _ = pub_path.set_extension("pub");

    let (full_pub_key_bytes, pub_key_bytes) = load_public_key(&pub_path)?;
    let identity_key = load_identity_key(&priv_path, passphrase)?;

    let fp = fingerprint(&pub_key_bytes)?;
    let fp_short = fp.split_whitespace().next().unwrap_or(&fp).to_string();
    let comment = fp.split_whitespace().nth(1).unwrap_or("").to_string();

    let identity = Identity {
        full_pub_key_bytes,
        algorithm: identity_key.key_algorithm().clone(),
        fingerprint: fp_short.clone(),
        private_key: identity_key.private_key().clone(),
    };

    drop(map.lock().await.insert(fp_short.clone(), identity.clone()));

    // Persist to vault
    {
        let mut vault_guard = vault.lock().await;
        let v = vault_guard.get_or_insert_with(Vault::new);
        v.upsert(key_path.to_string(), passphrase.unwrap_or("").to_string());
        if master_passphrase.is_empty() {
            v.save_plaintext(vault_path)?;
        } else {
            v.save_encrypted(vault_path, master_passphrase)?;
        }
    }

    Ok(AgentIdentityInfo {
        algorithm: identity.algorithm.clone(),
        fingerprint: fp_short,
        comment,
    })
}

/// Handle a single client connection.
async fn handle_connection(
    mut stream: UnixStream,
    identities: IdentityMap,
    vault: Arc<Mutex<Option<Vault>>>,
    vault_path: PathBuf,
    master_passphrase: Arc<Mutex<String>>,
) {
    while let Ok(raw_len) = stream.read_u32().await {
        let req_len = raw_len as usize;
        if req_len == 0 {
            break;
        }
        let mut buf = vec![0u8; req_len];
        if stream.read_exact(&mut buf).await.is_err() {
            break;
        }
        let request = match decode_from_slice::<AgentRequest, _>(&buf, standard()) {
            Ok((r, _)) => r,
            Err(e) => {
                error!("failed to decode agent request: {e}");
                break;
            }
        };

        let response = dispatch_request(
            request,
            &identities,
            &vault,
            &vault_path,
            &master_passphrase,
        )
        .await;

        let encoded = match encode_to_vec(&response, standard()) {
            Ok(b) => b,
            Err(e) => {
                error!("failed to encode agent response: {e}");
                break;
            }
        };
        let Ok(len) = u32::try_from(encoded.len()) else {
            break;
        };
        if stream.write_all(&len.to_be_bytes()).await.is_err()
            || stream.write_all(&encoded).await.is_err()
            || stream.flush().await.is_err()
        {
            break;
        }
    }
}

fn sign_data(id: &Identity, data: &[u8]) -> AgentResponse {
    #[cfg(feature = "unstable")]
    {
        use aws_lc_rs::unstable::signature::{
            ML_DSA_44_SIGNING, ML_DSA_65_SIGNING, ML_DSA_87_SIGNING, PqdsaKeyPair,
        };
        use libmoshpit::KEY_ALGORITHM_ML_DSA_44;
        use libmoshpit::KEY_ALGORITHM_ML_DSA_65;
        use libmoshpit::KEY_ALGORITHM_ML_DSA_87;
        let signing_alg = match id.algorithm.as_str() {
            KEY_ALGORITHM_ML_DSA_44 => &ML_DSA_44_SIGNING,
            KEY_ALGORITHM_ML_DSA_65 => &ML_DSA_65_SIGNING,
            KEY_ALGORITHM_ML_DSA_87 => &ML_DSA_87_SIGNING,
            _ => {
                return AgentResponse::Error(format!(
                    "algorithm {} does not support signing",
                    id.algorithm
                ));
            }
        };
        match PqdsaKeyPair::from_raw_private_key(signing_alg, &id.private_key) {
            Ok(kp) => {
                let mut sig = vec![0u8; signing_alg.signature_len()];
                match kp.sign(data, &mut sig) {
                    Ok(len) => {
                        sig.truncate(len);
                        AgentResponse::Signature(sig)
                    }
                    Err(e) => AgentResponse::Error(format!("signing failed: {e}")),
                }
            }
            Err(e) => AgentResponse::Error(format!("key load failed: {e}")),
        }
    }
    #[cfg(not(feature = "unstable"))]
    {
        let _ = data;
        AgentResponse::Error(format!(
            "algorithm {} does not support signing (build without unstable feature)",
            id.algorithm
        ))
    }
}

async fn dispatch_request(
    request: AgentRequest,
    identities: &IdentityMap,
    vault: &Arc<Mutex<Option<Vault>>>,
    vault_path: &Path,
    master_passphrase: &Arc<Mutex<String>>,
) -> AgentResponse {
    match request {
        AgentRequest::ListIdentities => {
            let map = identities.lock().await;
            let ids: Vec<AgentIdentityInfo> = map
                .values()
                .map(|id| AgentIdentityInfo {
                    algorithm: id.algorithm.clone(),
                    fingerprint: id.fingerprint.clone(),
                    comment: String::new(),
                })
                .collect();
            AgentResponse::Identities(ids)
        }

        AgentRequest::GetPublicKey(fp) => {
            let map = identities.lock().await;
            match map.get(&fp) {
                Some(id) => AgentResponse::PublicKey(id.full_pub_key_bytes.clone()),
                None => AgentResponse::Error(format!("identity not found: {fp}")),
            }
        }

        AgentRequest::Sign {
            fingerprint: fp,
            data,
        } => {
            let map = identities.lock().await;
            match map.get(&fp) {
                Some(id) => sign_data(id, &data),
                None => AgentResponse::Error(format!("identity not found: {fp}")),
            }
        }

        AgentRequest::AddIdentity {
            key_path,
            passphrase,
        } => {
            let mp = master_passphrase.lock().await.clone();
            match load_key_into_map(
                identities,
                &key_path,
                passphrase.as_deref(),
                vault,
                vault_path,
                &mp,
            )
            .await
            {
                Ok(_) => AgentResponse::Ok,
                Err(e) => AgentResponse::Error(e.to_string()),
            }
        }

        AgentRequest::RemoveIdentity(fp) => {
            let removed = identities.lock().await.remove(&fp).is_some();
            if removed {
                // Update vault
                let mut vault_guard = vault.lock().await;
                if let Some(v) = vault_guard.as_mut() {
                    let mp = master_passphrase.lock().await.clone();
                    if !mp.is_empty() {
                        drop(v.save_encrypted(vault_path, &mp));
                    }
                }
                AgentResponse::Ok
            } else {
                AgentResponse::Error(format!("identity not found: {fp}"))
            }
        }

        AgentRequest::RemoveAllIdentities => {
            identities.lock().await.clear();
            AgentResponse::Ok
        }

        AgentRequest::Lock => {
            let mut map = identities.lock().await;
            for id in map.values_mut() {
                id.private_key.zeroize();
            }
            map.clear();
            info!("agent locked");
            AgentResponse::Ok
        }

        AgentRequest::Unlock(passphrase) => {
            let mut mp = master_passphrase.lock().await;
            (*mp).clone_from(&passphrase);
            drop(mp);
            match reload_from_vault(identities, vault, vault_path, &passphrase).await {
                Ok(n) => {
                    info!("agent unlocked, {n} identities loaded");
                    AgentResponse::Ok
                }
                Err(e) => AgentResponse::Error(e.to_string()),
            }
        }
    }
}

async fn reload_from_vault(
    identities: &IdentityMap,
    vault: &Arc<Mutex<Option<Vault>>>,
    vault_path: &Path,
    master_passphrase: &str,
) -> Result<usize> {
    let loaded_vault = if vault_path.exists() {
        Vault::load_encrypted(vault_path, master_passphrase)?
    } else {
        return Ok(0);
    };

    let mut map = identities.lock().await;
    map.clear();
    let mut count = 0;
    for entry in loaded_vault.entries() {
        let priv_path = PathBuf::from(&entry.key_path);
        let mut pub_path = priv_path.clone();
        let _ = pub_path.set_extension("pub");
        let passphrase_opt = if entry.passphrase.is_empty() {
            None
        } else {
            Some(entry.passphrase.as_str())
        };
        match load_public_key(&pub_path) {
            Ok((full_pub_key_bytes, pub_key_bytes)) => {
                match load_identity_key(&priv_path, passphrase_opt) {
                    Ok(identity_key) => {
                        let fp_full = fingerprint(&pub_key_bytes).unwrap_or_default();
                        let fp = fp_full
                            .split_whitespace()
                            .next()
                            .unwrap_or(&fp_full)
                            .to_string();
                        drop(map.insert(
                            fp.clone(),
                            Identity {
                                full_pub_key_bytes,
                                algorithm: identity_key.key_algorithm().clone(),
                                fingerprint: fp,
                                private_key: identity_key.private_key().clone(),
                            },
                        ));
                        count += 1;
                    }
                    Err(e) => warn!("skipping {}: {e}", entry.key_path),
                }
            }
            Err(e) => warn!("skipping {}: {e}", entry.key_path),
        }
    }
    *vault.lock().await = Some(loaded_vault);
    Ok(count)
}

/// Send a request to a running agent and print the response.
async fn send_to_agent(socket_path: &Path, request: AgentRequest) -> Result<AgentResponse> {
    use libmoshpit::AgentClient;
    let client = AgentClient::new(socket_path.to_path_buf());
    client.send(&request).await
}

fn read_key_passphrase(from_stdin: bool, key_path: &str) -> Result<Option<String>> {
    if from_stdin {
        let mut line = String::new();
        let _n = std::io::stdin().lock().read_line(&mut line)?;
        let trimmed = line.trim_end_matches(['\n', '\r']).to_string();
        Ok(if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        })
    } else {
        let pw = Password::new()
            .with_prompt(format!("Passphrase for {key_path}"))
            .allow_empty_password(true)
            .interact()?;
        Ok(if pw.is_empty() { None } else { Some(pw) })
    }
}

#[cfg_attr(coverage_nightly, coverage(off))]
pub(crate) async fn run<I, T>(args: Option<I>) -> Result<()>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let cli = if let Some(args) = args {
        Cli::try_parse_from(args)?
    } else {
        Cli::try_parse()?
    };

    match cli.command() {
        Commands::Start {
            socket,
            vault,
            foreground,
            backend,
        } => {
            run_daemon(
                socket.as_deref(),
                vault.as_deref(),
                *foreground,
                backend.clone(),
            )
            .await
        }
        Commands::AddKey {
            key_path,
            passphrase_stdin,
        } => {
            let passphrase = read_key_passphrase(*passphrase_stdin, key_path)?;
            let socket_path = socket_from_env()?;
            let resp = send_to_agent(
                &socket_path,
                AgentRequest::AddIdentity {
                    key_path: key_path.clone(),
                    passphrase,
                },
            )
            .await?;
            match resp {
                AgentResponse::Ok => println!("Identity added."),
                AgentResponse::Error(e) => return Err(anyhow!("agent error: {e}")),
                _ => return Err(anyhow!("unexpected response")),
            }
            Ok(())
        }
        Commands::List => {
            let socket_path = socket_from_env()?;
            let resp = send_to_agent(&socket_path, AgentRequest::ListIdentities).await?;
            match resp {
                AgentResponse::Identities(ids) => {
                    if ids.is_empty() {
                        println!("No identities.");
                    } else {
                        for id in &ids {
                            println!("{} {} {}", id.fingerprint, id.algorithm, id.comment);
                        }
                    }
                }
                AgentResponse::Error(e) => return Err(anyhow!("agent error: {e}")),
                _ => return Err(anyhow!("unexpected response")),
            }
            Ok(())
        }
        Commands::RemoveKey { fingerprint } => {
            let socket_path = socket_from_env()?;
            let resp = send_to_agent(
                &socket_path,
                AgentRequest::RemoveIdentity(fingerprint.clone()),
            )
            .await?;
            match resp {
                AgentResponse::Ok => println!("Identity removed."),
                AgentResponse::Error(e) => return Err(anyhow!("agent error: {e}")),
                _ => return Err(anyhow!("unexpected response")),
            }
            Ok(())
        }
        Commands::Lock => {
            let socket_path = socket_from_env()?;
            let resp = send_to_agent(&socket_path, AgentRequest::Lock).await?;
            match resp {
                AgentResponse::Ok => println!("Agent locked."),
                AgentResponse::Error(e) => return Err(anyhow!("agent error: {e}")),
                _ => return Err(anyhow!("unexpected response")),
            }
            Ok(())
        }
        Commands::Unlock => {
            let socket_path = socket_from_env()?;
            let passphrase = Password::new()
                .with_prompt("Master passphrase")
                .interact()?;
            let resp = send_to_agent(&socket_path, AgentRequest::Unlock(passphrase)).await?;
            match resp {
                AgentResponse::Ok => println!("Agent unlocked."),
                AgentResponse::Error(e) => return Err(anyhow!("agent error: {e}")),
                _ => return Err(anyhow!("unexpected response")),
            }
            Ok(())
        }
    }
}

fn socket_from_env() -> Result<PathBuf> {
    std::env::var("MOSHPIT_AGENT_SOCK")
        .map(PathBuf::from)
        .map_err(|_| anyhow!("MOSHPIT_AGENT_SOCK not set — is the agent running?"))
}

fn unlock_backend(config: &AgentConfig) -> Box<dyn UnlockBackend> {
    // config.backend is read by feature-gated blocks; this reference prevents
    // an unused-variable warning in passphrase-only builds.
    let _ = &config.backend;
    #[cfg(feature = "fido2")]
    if config.backend == "fido2" {
        return Box::new(Fido2Backend {
            state_path: config.fido2_state_path.clone(),
        });
    }
    #[cfg(feature = "systemd-creds")]
    if config.backend == "systemd-creds" {
        return Box::new(SystemdCredsBackend);
    }
    #[cfg(feature = "ssh-agent-piggyback")]
    if config.backend == "ssh-agent-piggyback" {
        return Box::new(SshAgentBackend);
    }
    #[cfg(feature = "tpm")]
    if config.backend == "tpm" {
        return Box::new(TpmBackend);
    }
    #[cfg(feature = "fprintd")]
    if config.backend == "fprintd" {
        return Box::new(FprintdBackend);
    }
    #[cfg(feature = "secret-service")]
    if config.backend == "secret-service" {
        return Box::new(SecretServiceBackend);
    }
    #[cfg(feature = "macos-keychain")]
    if config.backend == "macos-keychain" {
        return Box::new(MacosKeychainBackend);
    }
    Box::new(PassphraseBackend)
}

#[cfg_attr(coverage_nightly, coverage(off))]
async fn run_daemon(
    socket_override: Option<&str>,
    vault_override: Option<&str>,
    foreground: bool,
    backend: String,
) -> Result<()> {
    let config = AgentConfig::resolve(socket_override, vault_override, foreground, backend);

    // Create parent directories for socket and vault
    if let Some(parent) = config.socket_path.parent() {
        #[cfg(target_family = "unix")]
        fs::DirBuilder::new()
            .mode(0o700)
            .recursive(true)
            .create(parent)?;
        #[cfg(not(target_family = "unix"))]
        fs::DirBuilder::new().recursive(true).create(parent)?;
    }
    if let Some(parent) = config.vault_path.parent() {
        #[cfg(target_family = "unix")]
        fs::DirBuilder::new()
            .mode(0o700)
            .recursive(true)
            .create(parent)?;
        #[cfg(not(target_family = "unix"))]
        fs::DirBuilder::new().recursive(true).create(parent)?;
    }

    let backend = unlock_backend(&config);
    let needs_passphrase = config.vault_path.exists() || config.backend == "fido2";
    let master_passphrase = if needs_passphrase {
        backend.retrieve_passphrase()?
    } else {
        String::new()
    };

    let identities = new_identity_map();
    let vault: Arc<Mutex<Option<Vault>>> = Arc::new(Mutex::new(None));
    let master_passphrase_arc = Arc::new(Mutex::new(master_passphrase.clone()));

    // Load from vault if it exists
    if config.vault_path.exists() {
        match reload_from_vault(&identities, &vault, &config.vault_path, &master_passphrase).await {
            Ok(n) => info!("loaded {n} identities from vault"),
            Err(e) => error!("failed to load vault: {e}"),
        }
    }

    // Remove stale socket
    if config.socket_path.exists() {
        fs::remove_file(&config.socket_path)?;
    }

    let listener = UnixListener::bind(&config.socket_path)?;

    // Announce socket path so the caller can eval the output
    println!(
        "MOSHPIT_AGENT_SOCK={}; export MOSHPIT_AGENT_SOCK",
        config.socket_path.display()
    );

    if !config.foreground {
        // Simple daemonisation: we've already bound the socket and printed the
        // export line; in a real deployment the systemd unit handles this, but
        // for manual use we just continue running (background via shell `&`
        // or eval). On Linux we could double-fork here in the future.
    }

    info!(
        "moshpit-agent listening on {}",
        config.socket_path.display()
    );

    // Graceful shutdown on SIGTERM/SIGINT
    let socket_path_cleanup = config.socket_path.clone();
    #[cfg(target_family = "unix")]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut sigterm = signal(SignalKind::terminate())?;
        let mut sigint = signal(SignalKind::interrupt())?;
        let cleanup_path = socket_path_cleanup.clone();
        drop(tokio::spawn(async move {
            tokio::select! {
                _ = sigterm.recv() => {}
                _ = sigint.recv() => {}
            }
            drop(fs::remove_file(&cleanup_path));
            std::process::exit(0);
        }));
    }

    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let ids = Arc::clone(&identities);
                let v = Arc::clone(&vault);
                let vp = config.vault_path.clone();
                let mp = Arc::clone(&master_passphrase_arc);
                drop(tokio::spawn(async move {
                    handle_connection(stream, ids, v, vp, mp).await;
                }));
            }
            Err(e) => error!("accept error: {e}"),
        }
    }
}
