// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

use std::{
    collections::HashMap,
    env::{current_exe, var},
    ffi::OsString,
    fs,
    io::{BufRead as _, stdin},
    path::{Path, PathBuf},
    process::{Command, Stdio, exit},
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
    spawn,
    sync::Mutex,
};
use tracing::{error, info, warn};
use zeroize::Zeroize as _;

use crate::{
    cli::{Cli, Commands, ShellKind},
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

/// Shared daemon state handed to each connection handler.
#[derive(Clone)]
struct ConnectionState {
    identities: IdentityMap,
    vault: Arc<Mutex<Option<Vault>>>,
    vault_path: PathBuf,
    master_passphrase: Arc<Mutex<String>>,
    socket_path: PathBuf,
    lock_path: PathBuf,
    locked: Arc<Mutex<bool>>,
}

/// Handle a single client connection.
async fn handle_connection(mut stream: UnixStream, state: ConnectionState) {
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

        let is_shutdown = matches!(request, AgentRequest::Shutdown);
        let response = dispatch_request(
            request,
            &state.identities,
            &state.vault,
            &state.vault_path,
            &state.master_passphrase,
            &state.locked,
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
        if is_shutdown {
            drop(fs::remove_file(&state.socket_path));
            drop(fs::remove_file(&state.lock_path));
            exit(0);
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

#[cfg_attr(nightly, allow(clippy::too_many_lines))]
async fn dispatch_request(
    request: AgentRequest,
    identities: &IdentityMap,
    vault: &Arc<Mutex<Option<Vault>>>,
    vault_path: &Path,
    master_passphrase: &Arc<Mutex<String>>,
    locked: &Arc<Mutex<bool>>,
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

        AgentRequest::ListSupportedIdentities {
            supported_algorithms,
        } => {
            let map = identities.lock().await;
            let ids: Vec<AgentIdentityInfo> = map
                .values()
                .filter(|id| supported_algorithms.contains(&id.algorithm))
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
            *locked.lock().await = true;
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
                    *locked.lock().await = false;
                    info!("agent unlocked, {n} identities loaded");
                    AgentResponse::Ok
                }
                Err(e) => AgentResponse::Error(e.to_string()),
            }
        }

        AgentRequest::Status => {
            let is_locked = *locked.lock().await;
            let map = identities.lock().await;
            let identities = map
                .values()
                .map(|id| AgentIdentityInfo {
                    algorithm: id.algorithm.clone(),
                    fingerprint: id.fingerprint.clone(),
                    comment: String::new(),
                })
                .collect();
            AgentResponse::AgentStatus {
                locked: is_locked,
                identities,
            }
        }

        AgentRequest::Shutdown => AgentResponse::Ok,
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

#[cfg_attr(coverage_nightly, coverage(off))]
fn read_passphrase_stdin() -> Result<String> {
    let mut line = String::new();
    let _n = stdin().lock().read_line(&mut line)?;
    Ok(line.trim_end_matches(['\n', '\r']).to_string())
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn read_key_passphrase(from_stdin: bool, key_path: &str) -> Result<Option<String>> {
    if from_stdin {
        let mut line = String::new();
        let _n = stdin().lock().read_line(&mut line)?;
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

/// Algorithms in preference order (strongest first), filtered to those supported by this build.
#[cfg(not(feature = "unstable"))]
const PREFERENCE_ORDER: &[&str] = &["P384", "P256", "X25519"];
#[cfg(feature = "unstable")]
const PREFERENCE_ORDER: &[&str] = &[
    "ML-DSA-87",
    "ML-DSA-65",
    "ML-DSA-44",
    "P384",
    "P256",
    "X25519",
];

/// Returns the identity that would be selected (highest-ranked algorithm).
fn best_identity(ids: &[AgentIdentityInfo]) -> &AgentIdentityInfo {
    for alg in PREFERENCE_ORDER {
        if let Some(id) = ids.iter().find(|id| id.algorithm == *alg) {
            return id;
        }
    }
    &ids[0]
}

/// Prints the key-selection hint to stderr when multiple keys are loaded.
#[cfg_attr(coverage_nightly, coverage(off))]
fn print_selection_hint(ids: &[AgentIdentityInfo], command: &str) {
    let best = best_identity(ids);
    let hierarchy = PREFERENCE_ORDER.join(" > ");
    eprintln!(
        "note: {} keys loaded — {} ({}) will be used (strongest available).",
        ids.len(),
        best.fingerprint,
        best.algorithm
    );
    eprintln!("      preference: {hierarchy}");
    eprintln!("      pass --no-hint to {command} to suppress");
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg_attr(nightly, allow(clippy::too_many_lines))]
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
            passphrase_stdin,
            shell,
            passphrase_pipe,
        } => {
            run_daemon(
                socket.as_deref(),
                vault.as_deref(),
                *foreground,
                backend.clone(),
                *passphrase_stdin,
                *shell,
                *passphrase_pipe,
            )
            .await
        }
        Commands::AddKey {
            key_path,
            passphrase_stdin,
            no_hint,
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
                AgentResponse::Ok => {
                    println!("Identity added.");
                    if !no_hint {
                        let list_resp =
                            send_to_agent(&socket_path, AgentRequest::ListIdentities).await?;
                        if let AgentResponse::Identities(ids) = list_resp
                            && ids.len() > 1
                        {
                            print_selection_hint(&ids, "add-key");
                        }
                    }
                }
                AgentResponse::Error(e) => return Err(anyhow!("agent error: {e}")),
                _ => return Err(anyhow!("unexpected response")),
            }
            Ok(())
        }
        Commands::List { no_hint } => {
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
                        if !no_hint && ids.len() > 1 {
                            print_selection_hint(&ids, "list");
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
        Commands::Status => {
            let socket_path = var("MOSHPIT_AGENT_SOCK")
                .map_or_else(|_| crate::config::default_socket_path(), PathBuf::from);
            let client = libmoshpit::AgentClient::new(socket_path);
            match client.status().await {
                Err(_) => println!("stopped"),
                Ok((is_locked, ids)) => {
                    if is_locked {
                        println!("running (locked)");
                    } else if ids.is_empty() {
                        println!("running (no keys)");
                    } else {
                        println!("running");
                        for id in &ids {
                            println!("  {} {} {}", id.fingerprint, id.algorithm, id.comment);
                        }
                    }
                }
            }
            Ok(())
        }
        Commands::Stop { socket, shell } => {
            let socket_path = socket
                .as_deref()
                .map(PathBuf::from)
                .map_or_else(socket_from_env, Ok)?;
            // Best-effort: ignore errors — daemon may already be dead (e.g. after SIGKILL).
            drop(send_to_agent(&socket_path, AgentRequest::Shutdown).await);
            print_unset_socket_env(*shell);
            Ok(())
        }
    }
}

fn socket_from_env() -> Result<PathBuf> {
    var("MOSHPIT_AGENT_SOCK")
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

fn format_socket_env(path: &Path, shell: ShellKind) -> String {
    match shell {
        ShellKind::Fish => format!("set -Ux MOSHPIT_AGENT_SOCK {}", path.display()),
        ShellKind::Bash => format!(
            "MOSHPIT_AGENT_SOCK={}; export MOSHPIT_AGENT_SOCK",
            path.display()
        ),
    }
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn print_socket_env(path: &Path, shell: ShellKind) {
    println!("{}", format_socket_env(path, shell));
}

fn format_unset_socket_env(shell: ShellKind) -> String {
    match shell {
        ShellKind::Fish => "set -e MOSHPIT_AGENT_SOCK".to_string(),
        ShellKind::Bash => "unset MOSHPIT_AGENT_SOCK".to_string(),
    }
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn print_unset_socket_env(shell: ShellKind) {
    println!("{}", format_unset_socket_env(shell));
}

/// Re-exec this binary as `mpa start --foreground` with the passphrase piped
/// to its stdin so the parent can return control to the shell immediately.
#[cfg_attr(coverage_nightly, coverage(off))]
fn is_process_alive(pid: u32) -> bool {
    #[cfg(target_family = "unix")]
    {
        use nix::{errno::Errno, sys::signal::kill, unistd::Pid};
        matches!(
            kill(Pid::from_raw(pid.cast_signed()), None),
            Ok(()) | Err(Errno::EPERM)
        )
    }
    #[cfg(not(target_family = "unix"))]
    {
        let _ = pid;
        true // can't check without platform API; let socket check decide
    }
}

async fn check_not_already_running(lock_path: &Path, socket_path: &Path) -> Result<()> {
    if lock_path.exists() {
        let pid_str = fs::read_to_string(lock_path).unwrap_or_default();
        let pid: u32 = pid_str.trim().parse().unwrap_or(0);
        if pid > 0
            && is_process_alive(pid)
            && socket_path.exists()
            && UnixStream::connect(socket_path).await.is_ok()
        {
            return Err(anyhow!(
                "agent is already running (pid {pid}, socket: {})\n  To stop it: mpa stop",
                socket_path.display()
            ));
        }
        // Stale lock file — remove it and proceed.
        drop(fs::remove_file(lock_path));
    } else if socket_path.exists() && UnixStream::connect(socket_path).await.is_ok() {
        // No lock file but socket is live (e.g. upgrade from older binary).
        return Err(anyhow!(
            "agent is already running (socket: {})\n  To stop it: mpa stop",
            socket_path.display()
        ));
    }
    Ok(())
}

fn spawn_daemon_child(
    socket_override: Option<&str>,
    vault_override: Option<&str>,
    backend: &str,
    shell: ShellKind,
    master_passphrase: &str,
) -> Result<()> {
    let exe = current_exe()?;
    let shell_str = match shell {
        ShellKind::Fish => "fish",
        ShellKind::Bash => "bash",
    };
    let mut cmd = Command::new(exe);
    let _ = cmd
        .arg("start")
        .arg("--foreground")
        .arg("--shell")
        .arg(shell_str)
        .arg("--backend")
        .arg(backend)
        .arg("--passphrase-pipe");
    if let Some(s) = socket_override {
        let _ = cmd.arg("--socket").arg(s);
    }
    if let Some(v) = vault_override {
        let _ = cmd.arg("--vault").arg(v);
    }
    let _ = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(target_family = "unix")]
    {
        use std::os::unix::process::CommandExt as _;
        // Put the child in its own process group so it is detached from the
        // terminal's process group and won't receive keyboard signals.
        let _ = cmd.process_group(0);
    }
    let mut child = cmd.spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        use std::io::Write as _;
        drop(writeln!(stdin, "{master_passphrase}"));
    }
    Ok(())
}

#[cfg_attr(coverage_nightly, coverage(off))]
/// Create the parent directories for the socket and vault files (mode 0700 on unix).
fn create_runtime_dirs(config: &AgentConfig) -> Result<()> {
    for path in [&config.socket_path, &config.vault_path] {
        if let Some(parent) = path.parent() {
            #[cfg(target_family = "unix")]
            fs::DirBuilder::new()
                .mode(0o700)
                .recursive(true)
                .create(parent)?;
            #[cfg(not(target_family = "unix"))]
            fs::DirBuilder::new().recursive(true).create(parent)?;
        }
    }
    Ok(())
}

async fn run_daemon(
    socket_override: Option<&str>,
    vault_override: Option<&str>,
    foreground: bool,
    backend: String,
    passphrase_stdin: bool,
    shell: ShellKind,
    passphrase_pipe: bool,
) -> Result<()> {
    let config = AgentConfig::resolve(socket_override, vault_override, foreground, backend, shell);

    create_runtime_dirs(&config)?;

    let backend = unlock_backend(&config);
    let vault_exists = config.vault_path.exists();
    let master_passphrase = if passphrase_stdin || passphrase_pipe {
        read_passphrase_stdin()?
    } else if vault_exists {
        backend.retrieve_passphrase()?
    } else if config.backend == "fido2" || config.backend == "passphrase" {
        backend.set_passphrase()?
    } else {
        String::new()
    };

    let identities = new_identity_map();
    let vault: Arc<Mutex<Option<Vault>>> = Arc::new(Mutex::new(None));
    let master_passphrase_arc = Arc::new(Mutex::new(master_passphrase.clone()));
    let locked: Arc<Mutex<bool>> = Arc::new(Mutex::new(false));

    // Load from vault if it exists
    if config.vault_path.exists() {
        match reload_from_vault(&identities, &vault, &config.vault_path, &master_passphrase).await {
            Ok(n) => info!("loaded {n} identities from vault"),
            Err(e) => error!("failed to load vault: {e}"),
        }
    }

    // Refuse to start if a live instance is already running.
    if !config.foreground {
        check_not_already_running(&config.lock_path, &config.socket_path).await?;
    }

    // Remove stale socket
    if config.socket_path.exists() {
        fs::remove_file(&config.socket_path)?;
    }

    let listener = UnixListener::bind(&config.socket_path)?;

    // Announce socket path so the caller can source the output.
    print_socket_env(&config.socket_path, config.shell);

    if !config.foreground {
        return spawn_daemon_child(
            socket_override,
            vault_override,
            &config.backend,
            config.shell,
            &master_passphrase,
        );
    }

    info!(
        "moshpit-agent listening on {}",
        config.socket_path.display()
    );

    // Record our PID so concurrent `mpa start` invocations can detect us.
    let pid = std::process::id();
    if let Err(e) = fs::write(&config.lock_path, format!("{pid}\n")) {
        warn!(
            "failed to write lock file {}: {e}",
            config.lock_path.display()
        );
    }

    // Graceful shutdown on SIGTERM/SIGINT; ignore SIGHUP so the daemon survives terminal hangup.
    let socket_path_cleanup = config.socket_path.clone();
    let lock_path_cleanup = config.lock_path.clone();
    #[cfg(target_family = "unix")]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut sigterm = signal(SignalKind::terminate())?;
        let mut sigint = signal(SignalKind::interrupt())?;
        let mut sighup = signal(SignalKind::hangup())?;
        let cleanup_path = socket_path_cleanup.clone();
        let cleanup_lock = lock_path_cleanup.clone();
        drop(spawn(async move {
            loop {
                tokio::select! {
                    _ = sigterm.recv() => break,
                    _ = sigint.recv() => break,
                    _ = sighup.recv() => {} // ignore — daemon survives terminal hangup
                }
            }
            drop(fs::remove_file(&cleanup_path));
            drop(fs::remove_file(&cleanup_lock));
            exit(0);
        }));
    }

    let state = ConnectionState {
        identities,
        vault,
        vault_path: config.vault_path.clone(),
        master_passphrase: master_passphrase_arc,
        socket_path: config.socket_path.clone(),
        lock_path: config.lock_path.clone(),
        locked,
    };

    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let state = state.clone();
                drop(spawn(async move {
                    handle_connection(stream, state).await;
                }));
            }
            Err(e) => error!("accept error: {e}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        env::{remove_var, set_var},
        fs,
        path::{Path, PathBuf},
        process::Command,
        sync::Arc,
    };

    use bincode_next::{config::standard, decode_from_slice, encode_to_vec};
    use tempfile::tempdir;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::{UnixListener, UnixStream};
    use tokio::spawn;
    use tokio::sync::Mutex;

    use super::{
        AgentConfig, AgentIdentityInfo, AgentRequest, AgentResponse, ConnectionState, Identity,
        ShellKind, Vault, best_identity, check_not_already_running, dispatch_request,
        format_socket_env, format_unset_socket_env, handle_connection, is_process_alive,
        new_identity_map, sign_data, socket_from_env, unlock_backend,
    };

    const TEST_KEY_PATH: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../libmoshpit/tests/keys/id_x25519_test"
    );

    fn dummy_identity(fp: &str, algorithm: &str) -> Identity {
        Identity {
            full_pub_key_bytes: b"dummy pub key bytes".to_vec(),
            algorithm: algorithm.to_string(),
            fingerprint: fp.to_string(),
            private_key: vec![0u8; 32],
        }
    }

    fn empty_vault() -> Arc<Mutex<Option<Vault>>> {
        Arc::new(Mutex::new(None))
    }

    fn empty_passphrase() -> Arc<Mutex<String>> {
        Arc::new(Mutex::new(String::new()))
    }

    fn unlocked_state() -> Arc<Mutex<bool>> {
        Arc::new(Mutex::new(false))
    }

    #[test]
    fn new_identity_map_is_empty() {
        let map = new_identity_map();
        assert_eq!(Arc::strong_count(&map), 1);
    }

    #[tokio::test]
    async fn dispatch_list_identities_empty() {
        let ids = new_identity_map();
        let vault = empty_vault();
        let vault_path = PathBuf::from("/tmp/nonexistent-vault-agent-test");
        let mp = empty_passphrase();
        let resp = dispatch_request(
            AgentRequest::ListIdentities,
            &ids,
            &vault,
            &vault_path,
            &mp,
            &unlocked_state(),
        )
        .await;
        assert!(matches!(resp, AgentResponse::Identities(v) if v.is_empty()));
    }

    #[tokio::test]
    async fn dispatch_list_identities_populated() {
        let ids = new_identity_map();
        let fp = "SHA256:aaaabbbb".to_string();
        drop(
            ids.lock()
                .await
                .insert(fp.clone(), dummy_identity(&fp, "X25519")),
        );
        let vault = empty_vault();
        let vault_path = PathBuf::from("/tmp/nonexistent-vault-agent-test");
        let mp = empty_passphrase();
        let resp = dispatch_request(
            AgentRequest::ListIdentities,
            &ids,
            &vault,
            &vault_path,
            &mp,
            &unlocked_state(),
        )
        .await;
        match resp {
            AgentResponse::Identities(list) => {
                assert_eq!(list.len(), 1);
                assert_eq!(list[0].fingerprint, fp);
                assert_eq!(list[0].algorithm, "X25519");
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[tokio::test]
    async fn dispatch_list_supported_identities_filtered() {
        let ids = new_identity_map();
        let fp1 = "SHA256:fp1".to_string();
        let fp2 = "SHA256:fp2".to_string();
        drop(
            ids.lock()
                .await
                .insert(fp1.clone(), dummy_identity(&fp1, "X25519")),
        );
        drop(
            ids.lock()
                .await
                .insert(fp2.clone(), dummy_identity(&fp2, "P384")),
        );
        let vault = empty_vault();
        let vault_path = PathBuf::from("/tmp/nonexistent-vault-agent-test");
        let mp = empty_passphrase();
        let resp = dispatch_request(
            AgentRequest::ListSupportedIdentities {
                supported_algorithms: vec!["P384".to_string()],
            },
            &ids,
            &vault,
            &vault_path,
            &mp,
            &unlocked_state(),
        )
        .await;
        match resp {
            AgentResponse::Identities(list) => {
                assert_eq!(list.len(), 1);
                assert_eq!(list[0].algorithm, "P384");
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[tokio::test]
    async fn dispatch_get_public_key_found() {
        let ids = new_identity_map();
        let fp = "SHA256:found".to_string();
        drop(
            ids.lock()
                .await
                .insert(fp.clone(), dummy_identity(&fp, "X25519")),
        );
        let vault = empty_vault();
        let vault_path = PathBuf::from("/tmp/nonexistent-vault-agent-test");
        let mp = empty_passphrase();
        let resp = dispatch_request(
            AgentRequest::GetPublicKey(fp.clone()),
            &ids,
            &vault,
            &vault_path,
            &mp,
            &unlocked_state(),
        )
        .await;
        assert!(matches!(resp, AgentResponse::PublicKey(b) if b == b"dummy pub key bytes"));
    }

    #[tokio::test]
    async fn dispatch_get_public_key_not_found() {
        let ids = new_identity_map();
        let vault = empty_vault();
        let vault_path = PathBuf::from("/tmp/nonexistent-vault-agent-test");
        let mp = empty_passphrase();
        let resp = dispatch_request(
            AgentRequest::GetPublicKey("SHA256:missing".to_string()),
            &ids,
            &vault,
            &vault_path,
            &mp,
            &unlocked_state(),
        )
        .await;
        assert!(matches!(resp, AgentResponse::Error(_)));
    }

    #[tokio::test]
    async fn dispatch_sign_not_found() {
        let ids = new_identity_map();
        let vault = empty_vault();
        let vault_path = PathBuf::from("/tmp/nonexistent-vault-agent-test");
        let mp = empty_passphrase();
        let resp = dispatch_request(
            AgentRequest::Sign {
                fingerprint: "SHA256:nosuchkey".to_string(),
                data: b"hello".to_vec(),
            },
            &ids,
            &vault,
            &vault_path,
            &mp,
            &unlocked_state(),
        )
        .await;
        assert!(matches!(resp, AgentResponse::Error(_)));
    }

    #[tokio::test]
    async fn dispatch_sign_key_exists_non_unstable() {
        let ids = new_identity_map();
        let fp = "SHA256:signing".to_string();
        drop(
            ids.lock()
                .await
                .insert(fp.clone(), dummy_identity(&fp, "X25519")),
        );
        let vault = empty_vault();
        let vault_path = PathBuf::from("/tmp/nonexistent-vault-agent-test");
        let mp = empty_passphrase();
        let resp = dispatch_request(
            AgentRequest::Sign {
                fingerprint: fp.clone(),
                data: b"some data".to_vec(),
            },
            &ids,
            &vault,
            &vault_path,
            &mp,
            &unlocked_state(),
        )
        .await;
        // In non-unstable builds sign_data always returns an error
        assert!(matches!(resp, AgentResponse::Error(_)));
    }

    #[test]
    fn sign_data_non_unstable_returns_error() {
        let id = dummy_identity("SHA256:test", "X25519");
        let resp = sign_data(&id, b"data");
        assert!(
            matches!(resp, AgentResponse::Error(ref msg) if msg.contains("does not support signing"))
        );
    }

    #[tokio::test]
    async fn dispatch_add_identity() {
        let ids = new_identity_map();
        let vault = empty_vault();
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("vault");
        let mp = empty_passphrase();
        let resp = dispatch_request(
            AgentRequest::AddIdentity {
                key_path: TEST_KEY_PATH.to_string(),
                passphrase: None,
            },
            &ids,
            &vault,
            &vault_path,
            &mp,
            &unlocked_state(),
        )
        .await;
        assert!(matches!(resp, AgentResponse::Ok));
        assert_eq!(ids.lock().await.len(), 1);
    }

    #[tokio::test]
    async fn dispatch_add_identity_bad_path() {
        let ids = new_identity_map();
        let vault = empty_vault();
        let vault_path = PathBuf::from("/tmp/nonexistent-vault-agent-test");
        let mp = empty_passphrase();
        let resp = dispatch_request(
            AgentRequest::AddIdentity {
                key_path: "/nonexistent/key/path".to_string(),
                passphrase: None,
            },
            &ids,
            &vault,
            &vault_path,
            &mp,
            &unlocked_state(),
        )
        .await;
        assert!(matches!(resp, AgentResponse::Error(_)));
    }

    #[tokio::test]
    async fn dispatch_remove_identity_found() {
        let ids = new_identity_map();
        let fp = "SHA256:removeme".to_string();
        drop(
            ids.lock()
                .await
                .insert(fp.clone(), dummy_identity(&fp, "X25519")),
        );
        let vault = empty_vault();
        let vault_path = PathBuf::from("/tmp/nonexistent-vault-agent-test");
        let mp = empty_passphrase();
        let resp = dispatch_request(
            AgentRequest::RemoveIdentity(fp.clone()),
            &ids,
            &vault,
            &vault_path,
            &mp,
            &unlocked_state(),
        )
        .await;
        assert!(matches!(resp, AgentResponse::Ok));
        assert!(ids.lock().await.is_empty());
    }

    #[tokio::test]
    async fn dispatch_remove_identity_not_found() {
        let ids = new_identity_map();
        let vault = empty_vault();
        let vault_path = PathBuf::from("/tmp/nonexistent-vault-agent-test");
        let mp = empty_passphrase();
        let resp = dispatch_request(
            AgentRequest::RemoveIdentity("SHA256:nosuch".to_string()),
            &ids,
            &vault,
            &vault_path,
            &mp,
            &unlocked_state(),
        )
        .await;
        assert!(matches!(resp, AgentResponse::Error(_)));
    }

    #[tokio::test]
    async fn dispatch_remove_all_identities() {
        let ids = new_identity_map();
        let fp1 = "SHA256:one".to_string();
        let fp2 = "SHA256:two".to_string();
        drop(
            ids.lock()
                .await
                .insert(fp1.clone(), dummy_identity(&fp1, "X25519")),
        );
        drop(
            ids.lock()
                .await
                .insert(fp2.clone(), dummy_identity(&fp2, "P384")),
        );
        let vault = empty_vault();
        let vault_path = PathBuf::from("/tmp/nonexistent-vault-agent-test");
        let mp = empty_passphrase();
        let resp = dispatch_request(
            AgentRequest::RemoveAllIdentities,
            &ids,
            &vault,
            &vault_path,
            &mp,
            &unlocked_state(),
        )
        .await;
        assert!(matches!(resp, AgentResponse::Ok));
        assert!(ids.lock().await.is_empty());
    }

    #[tokio::test]
    async fn dispatch_lock() {
        let ids = new_identity_map();
        let fp = "SHA256:lockme".to_string();
        drop(
            ids.lock()
                .await
                .insert(fp.clone(), dummy_identity(&fp, "X25519")),
        );
        let vault = empty_vault();
        let vault_path = PathBuf::from("/tmp/nonexistent-vault-agent-test");
        let mp = empty_passphrase();
        let resp = dispatch_request(
            AgentRequest::Lock,
            &ids,
            &vault,
            &vault_path,
            &mp,
            &unlocked_state(),
        )
        .await;
        assert!(matches!(resp, AgentResponse::Ok));
        assert!(ids.lock().await.is_empty());
    }

    #[tokio::test]
    async fn dispatch_unlock_no_vault() {
        let ids = new_identity_map();
        let vault = empty_vault();
        let vault_path = PathBuf::from("/tmp/nonexistent-vault-for-unlock-agent-test");
        let mp = empty_passphrase();
        let resp = dispatch_request(
            AgentRequest::Unlock(String::new()),
            &ids,
            &vault,
            &vault_path,
            &mp,
            &unlocked_state(),
        )
        .await;
        assert!(matches!(resp, AgentResponse::Ok));
        assert!(ids.lock().await.is_empty());
    }

    #[tokio::test]
    async fn dispatch_status_unlocked_empty() {
        let ids = new_identity_map();
        let vault = empty_vault();
        let vault_path = PathBuf::from("/tmp/nonexistent-vault-agent-test");
        let mp = empty_passphrase();
        let resp = dispatch_request(
            AgentRequest::Status,
            &ids,
            &vault,
            &vault_path,
            &mp,
            &unlocked_state(),
        )
        .await;
        match resp {
            AgentResponse::AgentStatus { locked, identities } => {
                assert!(!locked);
                assert!(identities.is_empty());
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[tokio::test]
    async fn dispatch_status_unlocked_with_identity() {
        let ids = new_identity_map();
        let fp = "SHA256:status-key".to_string();
        drop(
            ids.lock()
                .await
                .insert(fp.clone(), dummy_identity(&fp, "X25519")),
        );
        let vault = empty_vault();
        let vault_path = PathBuf::from("/tmp/nonexistent-vault-agent-test");
        let mp = empty_passphrase();
        let resp = dispatch_request(
            AgentRequest::Status,
            &ids,
            &vault,
            &vault_path,
            &mp,
            &unlocked_state(),
        )
        .await;
        match resp {
            AgentResponse::AgentStatus { locked, identities } => {
                assert!(!locked);
                assert_eq!(identities.len(), 1);
                assert_eq!(identities[0].fingerprint, fp);
                assert_eq!(identities[0].algorithm, "X25519");
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[tokio::test]
    async fn dispatch_status_locked_state() {
        let ids = new_identity_map();
        let vault = empty_vault();
        let vault_path = PathBuf::from("/tmp/nonexistent-vault-agent-test");
        let mp = empty_passphrase();
        let locked = Arc::new(Mutex::new(true));
        let resp = dispatch_request(
            AgentRequest::Status,
            &ids,
            &vault,
            &vault_path,
            &mp,
            &locked,
        )
        .await;
        match resp {
            AgentResponse::AgentStatus { locked, identities } => {
                assert!(locked, "agent should report locked state");
                assert!(identities.is_empty());
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[tokio::test]
    async fn dispatch_lock_sets_locked_flag() {
        let ids = new_identity_map();
        let fp = "SHA256:flagme".to_string();
        drop(
            ids.lock()
                .await
                .insert(fp.clone(), dummy_identity(&fp, "P384")),
        );
        let vault = empty_vault();
        let vault_path = PathBuf::from("/tmp/nonexistent-vault-agent-test");
        let mp = empty_passphrase();
        let locked = unlocked_state();
        let resp =
            dispatch_request(AgentRequest::Lock, &ids, &vault, &vault_path, &mp, &locked).await;
        assert!(matches!(resp, AgentResponse::Ok));
        assert!(*locked.lock().await, "locked flag must be true after Lock");
    }

    #[tokio::test]
    async fn handle_connection_single_request() {
        let ids = new_identity_map();
        let vault = empty_vault();
        let vault_path = PathBuf::from("/tmp/nonexistent-vault-agent-test");
        let mp = empty_passphrase();

        let (mut client, server) = UnixStream::pair().unwrap();

        drop(spawn(handle_connection(
            server,
            ConnectionState {
                identities: ids,
                vault,
                vault_path,
                master_passphrase: mp,
                socket_path: PathBuf::from("/tmp/nonexistent-socket-agent-test"),
                lock_path: PathBuf::from("/tmp/nonexistent-lock-agent-test"),
                locked: Arc::new(Mutex::new(false)),
            },
        )));

        let req = AgentRequest::ListIdentities;
        let encoded = encode_to_vec(&req, standard()).unwrap();
        let len = u32::try_from(encoded.len()).unwrap();
        client.write_all(&len.to_be_bytes()).await.unwrap();
        client.write_all(&encoded).await.unwrap();
        client.flush().await.unwrap();

        let resp_len = client.read_u32().await.unwrap() as usize;
        let mut buf = vec![0u8; resp_len];
        let _ = client.read_exact(&mut buf).await.unwrap();
        let (resp, _): (AgentResponse, _) = decode_from_slice(&buf, standard()).unwrap();

        assert!(matches!(resp, AgentResponse::Identities(v) if v.is_empty()));
        drop(client);
    }

    #[tokio::test]
    async fn handle_connection_zero_length_breaks() {
        let ids = new_identity_map();
        let vault = empty_vault();
        let vault_path = PathBuf::from("/tmp/nonexistent-vault-agent-test");
        let mp = empty_passphrase();

        let (mut client, server) = UnixStream::pair().unwrap();

        let task = spawn(handle_connection(
            server,
            ConnectionState {
                identities: ids,
                vault,
                vault_path,
                master_passphrase: mp,
                socket_path: PathBuf::from("/tmp/nonexistent-socket-agent-test"),
                lock_path: PathBuf::from("/tmp/nonexistent-lock-agent-test"),
                locked: Arc::new(Mutex::new(false)),
            },
        ));

        client.write_all(&0u32.to_be_bytes()).await.unwrap();
        client.flush().await.unwrap();
        drop(client);

        task.await.unwrap();
    }

    #[tokio::test]
    async fn handle_connection_bad_decode_breaks() {
        let ids = new_identity_map();
        let vault = empty_vault();
        let vault_path = PathBuf::from("/tmp/nonexistent-vault-agent-test");
        let mp = empty_passphrase();

        let (mut client, server) = UnixStream::pair().unwrap();

        let task = spawn(handle_connection(
            server,
            ConnectionState {
                identities: ids,
                vault,
                vault_path,
                master_passphrase: mp,
                socket_path: PathBuf::from("/tmp/nonexistent-socket-agent-test"),
                lock_path: PathBuf::from("/tmp/nonexistent-lock-agent-test"),
                locked: Arc::new(Mutex::new(false)),
            },
        ));

        let garbage = vec![0xFF_u8, 0xFE, 0xFD, 0xFC];
        let len = u32::try_from(garbage.len()).unwrap();
        client.write_all(&len.to_be_bytes()).await.unwrap();
        client.write_all(&garbage).await.unwrap();
        client.flush().await.unwrap();
        drop(client);

        task.await.unwrap();
    }

    #[test]
    fn best_identity_prefers_p384_over_x25519() {
        let ids = vec![
            AgentIdentityInfo {
                algorithm: "X25519".into(),
                fingerprint: "SHA256:x25519".into(),
                comment: String::new(),
            },
            AgentIdentityInfo {
                algorithm: "P384".into(),
                fingerprint: "SHA256:p384".into(),
                comment: String::new(),
            },
        ];
        let best = best_identity(&ids);
        assert_eq!(best.algorithm, "P384");
    }

    #[test]
    fn best_identity_single_unknown_returns_first() {
        let ids = vec![AgentIdentityInfo {
            algorithm: "Unknown".into(),
            fingerprint: "SHA256:unk".into(),
            comment: String::new(),
        }];
        let best = best_identity(&ids);
        assert_eq!(best.algorithm, "Unknown");
    }

    #[test]
    #[allow(unsafe_code)]
    fn socket_from_env_set() {
        // Safety: nextest runs each test in its own process; no concurrent set_var calls.
        unsafe { set_var("MOSHPIT_AGENT_SOCK", "/tmp/mpa-test-socket.sock") };
        let result = socket_from_env();
        unsafe { remove_var("MOSHPIT_AGENT_SOCK") };
        assert_eq!(result.unwrap(), PathBuf::from("/tmp/mpa-test-socket.sock"));
    }

    #[test]
    #[allow(unsafe_code)]
    fn socket_from_env_not_set() {
        // Safety: nextest runs each test in its own process; no concurrent env access.
        unsafe { remove_var("MOSHPIT_AGENT_SOCK") };
        assert!(socket_from_env().is_err());
    }

    #[test]
    fn unlock_backend_passphrase_default() {
        let config = AgentConfig::resolve(
            Some("/tmp/dummy.sock"),
            Some("/tmp/dummy.vault"),
            false,
            "unknown-backend".to_string(),
            ShellKind::Fish,
        );
        let backend = unlock_backend(&config);
        assert_eq!(backend.name(), "passphrase");
    }

    #[test]
    fn format_socket_env_fish() {
        let path = Path::new("/run/user/1000/moshpit-agent.sock");
        let s = format_socket_env(path, ShellKind::Fish);
        assert_eq!(
            s,
            "set -Ux MOSHPIT_AGENT_SOCK /run/user/1000/moshpit-agent.sock"
        );
    }

    #[test]
    fn format_socket_env_bash() {
        let path = Path::new("/run/user/1000/moshpit-agent.sock");
        let s = format_socket_env(path, ShellKind::Bash);
        assert_eq!(
            s,
            "MOSHPIT_AGENT_SOCK=/run/user/1000/moshpit-agent.sock; export MOSHPIT_AGENT_SOCK"
        );
    }

    #[test]
    fn format_unset_socket_env_fish() {
        assert_eq!(
            format_unset_socket_env(ShellKind::Fish),
            "set -e MOSHPIT_AGENT_SOCK"
        );
    }

    #[test]
    fn format_unset_socket_env_bash() {
        assert_eq!(
            format_unset_socket_env(ShellKind::Bash),
            "unset MOSHPIT_AGENT_SOCK"
        );
    }

    // --- is_process_alive ---

    #[cfg(target_family = "unix")]
    #[test]
    fn is_process_alive_self() {
        assert!(is_process_alive(std::process::id()));
    }

    #[cfg(target_family = "unix")]
    #[test]
    fn is_process_alive_dead_pid() {
        // Spawn a trivial child, wait for it to exit, then check its PID is dead.
        let mut child = Command::new("true").spawn().unwrap();
        let pid = child.id();
        let _ = child.wait().unwrap();
        assert!(!is_process_alive(pid));
    }

    // --- check_not_already_running ---

    #[tokio::test]
    async fn check_no_files_ok() {
        let dir = tempdir().unwrap();
        let lock = dir.path().join("test.lock");
        let sock = dir.path().join("test.sock");
        assert!(check_not_already_running(&lock, &sock).await.is_ok());
    }

    #[tokio::test]
    async fn check_stale_lock_no_socket_cleans_up() {
        let dir = tempdir().unwrap();
        let lock = dir.path().join("test.lock");
        let sock = dir.path().join("test.sock");
        // Write a guaranteed-dead PID to the lock file.
        let mut child = Command::new("true").spawn().unwrap();
        let pid = child.id();
        let _ = child.wait().unwrap();
        fs::write(&lock, format!("{pid}\n")).unwrap();
        assert!(check_not_already_running(&lock, &sock).await.is_ok());
        assert!(!lock.exists(), "stale lock file must be removed");
    }

    #[tokio::test]
    async fn check_live_lock_and_socket_errors() {
        let dir = tempdir().unwrap();
        let lock = dir.path().join("test.lock");
        let sock = dir.path().join("test.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        drop(spawn(async move { drop(listener.accept().await) }));
        fs::write(&lock, format!("{}\n", std::process::id())).unwrap();
        let err = check_not_already_running(&lock, &sock).await.unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("already running"), "msg: {msg}");
        assert!(msg.contains("mpa stop"), "msg: {msg}");
    }

    #[tokio::test]
    async fn check_socket_live_no_lock_errors() {
        let dir = tempdir().unwrap();
        let lock = dir.path().join("test.lock");
        let sock = dir.path().join("test.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        drop(spawn(async move { drop(listener.accept().await) }));
        assert!(check_not_already_running(&lock, &sock).await.is_err());
    }
}
