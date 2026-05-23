// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

use std::path::PathBuf;

use crate::cli::ShellKind;

/// Resolved runtime configuration for the agent daemon.
#[derive(Debug)]
pub(crate) struct AgentConfig {
    /// Path to the Unix domain socket.
    pub socket_path: PathBuf,
    /// Path to the PID lock file (socket path with `.lock` extension).
    pub lock_path: PathBuf,
    /// Path to the encrypted vault file.
    pub vault_path: PathBuf,
    /// Whether to stay in the foreground instead of daemonising.
    pub foreground: bool,
    /// Name of the unlock backend to use (e.g. `"passphrase"`, `"fido2"`).
    pub backend: String,
    /// Shell syntax for the socket env var output.
    pub shell: ShellKind,
    /// Path to the FIDO2 state file (`{vault_path}.fido2`).
    #[cfg(feature = "fido2")]
    pub fido2_state_path: PathBuf,
}

impl AgentConfig {
    /// Build config from CLI values and environment.
    pub(crate) fn resolve(
        socket_override: Option<&str>,
        vault_override: Option<&str>,
        foreground: bool,
        backend: String,
        shell: ShellKind,
    ) -> Self {
        let socket_path = socket_override.map_or_else(default_socket_path, PathBuf::from);
        let lock_path = socket_path.with_extension("lock");

        let vault_path = vault_override.map_or_else(
            || {
                crate::vault::default_vault_path()
                    .unwrap_or_else(|| PathBuf::from(".mp/agent-vault"))
            },
            PathBuf::from,
        );

        #[cfg(feature = "fido2")]
        let fido2_state_path = vault_path.with_extension("fido2");

        Self {
            socket_path,
            lock_path,
            vault_path,
            foreground,
            backend,
            shell,
            #[cfg(feature = "fido2")]
            fido2_state_path,
        }
    }
}

/// Default socket path: `$XDG_RUNTIME_DIR/moshpit-agent-<uid>.sock`
/// or `~/.mp/agent.sock` as fallback.
pub(crate) fn default_socket_path() -> PathBuf {
    #[cfg(target_family = "unix")]
    {
        if let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR") {
            let uid = nix::unistd::getuid().as_raw();
            return PathBuf::from(runtime_dir).join(format!("moshpit-agent-{uid}.sock"));
        }
    }
    dirs2::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".mp")
        .join("agent.sock")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_with_overrides() {
        let cfg = AgentConfig::resolve(
            Some("/tmp/test.sock"),
            Some("/tmp/test-vault"),
            true,
            "passphrase".to_string(),
            ShellKind::Bash,
        );
        assert_eq!(cfg.socket_path, PathBuf::from("/tmp/test.sock"));
        assert_eq!(cfg.lock_path, PathBuf::from("/tmp/test.lock"));
        assert_eq!(cfg.vault_path, PathBuf::from("/tmp/test-vault"));
        assert!(cfg.foreground);
        assert_eq!(cfg.backend, "passphrase");
    }

    #[test]
    fn resolve_defaults() {
        let cfg =
            AgentConfig::resolve(None, None, false, "passphrase".to_string(), ShellKind::Fish);
        // Just verify we get non-empty paths — the exact values depend on env.
        assert!(!cfg.socket_path.as_os_str().is_empty());
        assert!(!cfg.lock_path.as_os_str().is_empty());
        assert!(!cfg.vault_path.as_os_str().is_empty());
    }
}
