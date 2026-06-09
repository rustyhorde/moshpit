// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

use std::{collections::BTreeSet, path::PathBuf, sync::Arc};

use anyhow::Result;
use getset::{CopyGetters, Getters, Setters};
use libmoshpit::{
    AlgorithmList, DiffMode, DisplayPreference, FileLayer, KEY_ALGORITHM_X25519, KexConfig,
    KexMode, KeyPair, supported_algorithms,
};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use uuid::Uuid;

/// Per-category algorithm preferences for TOML config and CLI overrides.
/// Each field is optional; missing categories fall back to `supported_algorithms()`.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct AlgorithmPreferences {
    #[serde(default)]
    pub(crate) kex: Option<Vec<String>>,
    #[serde(default)]
    pub(crate) aead: Option<Vec<String>>,
    #[serde(default)]
    pub(crate) mac: Option<Vec<String>>,
    #[serde(default)]
    pub(crate) kdf: Option<Vec<String>>,
}

impl AlgorithmPreferences {
    fn into_algorithm_list(self) -> AlgorithmList {
        let defaults = supported_algorithms();
        AlgorithmList {
            kex: self.kex.unwrap_or(defaults.kex),
            aead: self.aead.unwrap_or(defaults.aead),
            mac: self.mac.unwrap_or(defaults.mac),
            kdf: self.kdf.unwrap_or(defaults.kdf),
        }
    }
}

/// Client-side tracing configuration — file layer only.
/// The mp client never writes to stdout, so there is no stdout layer.
#[derive(Clone, Debug, Default, Deserialize, Eq, Getters, PartialEq, Serialize)]
pub(crate) struct ClientTracing {
    #[getset(get = "pub(crate)")]
    file: FileLayer,
}

#[derive(Clone, CopyGetters, Debug, Deserialize, Eq, Getters, PartialEq, Serialize, Setters)]
pub(crate) struct Config {
    #[serde(skip_deserializing)]
    #[getset(get_copy = "pub(crate)")]
    mode: KexMode,
    #[serde(skip_deserializing)]
    #[getset(get = "pub(crate)", set = "pub(crate)")]
    user: String,
    #[serde(default)]
    #[getset(get = "pub(crate)")]
    tracing: ClientTracing,
    #[serde(default = "Config::default_server_port")]
    #[getset(get_copy = "pub(crate)")]
    server_port: u16,
    #[serde(default)]
    #[getset(get = "pub(crate)")]
    server_destination: String,
    #[getset(get = "pub(crate)")]
    private_key_path: Option<String>,
    #[getset(get = "pub(crate)")]
    public_key_path: Option<String>,
    /// UUID of a previous session to attempt to resume (not persisted to config file).
    #[serde(skip)]
    #[getset(get_copy = "pub(crate)", set = "pub(crate)")]
    resume_session_uuid: Option<Uuid>,
    /// Maximum backoff interval between reconnect attempts, in seconds.
    /// Clamped to [2, 86400] (24 hours).  Defaults to 3600 (1 hour).
    #[serde(default = "Config::default_max_reconnect_backoff_secs")]
    #[getset(get_copy = "pub(crate)")]
    max_reconnect_backoff_secs: u64,
    /// Local-echo prediction display preference.
    #[serde(default)]
    #[getset(get_copy = "pub(crate)")]
    predict: DisplayPreference,
    /// Send NAT warmup keepalives before the UDP session loop starts.
    /// Off by default; enable with `--nat-warmup` / `MOSHPIT_NAT_WARMUP=true`.
    #[serde(default)]
    #[getset(get_copy = "pub(crate)")]
    nat_warmup: bool,
    /// Number of keepalive frames to send during NAT warmup.
    #[serde(default = "Config::default_nat_warmup_count")]
    #[getset(get_copy = "pub(crate)")]
    nat_warmup_count: u32,
    /// UDP diff transport mode.  Defaults to `Reliable`; set to `Datagram`
    /// via `--diff-mode datagram` / `MOSHPIT_DIFF_MODE=datagram`.
    #[serde(default)]
    #[getset(get_copy = "pub(crate)")]
    diff_mode: DiffMode,
    /// Legacy escape hatch: drive the terminal by forwarding raw server PTY
    /// bytes straight to stdout instead of rendering exclusively through the
    /// differential renderer.  Defaults to `false` (the artifact-free rendered
    /// path).  Enable via `--legacy-passthrough` / `MOSHPIT_LEGACY_PASSTHROUGH=true`
    /// only if the rendered path regresses.
    #[serde(default)]
    #[getset(get_copy = "pub(crate)")]
    legacy_passthrough: bool,
    /// Per-category algorithm overrides from TOML `[preferred_algorithms]` or CLI flags.
    #[serde(default)]
    preferred_algorithms: AlgorithmPreferences,
    /// Environment variable name patterns to send to the server via `ClientEnv`.
    /// Supports exact names (`LANG`) and suffix wildcards (`LC_*`).
    #[serde(default = "Config::default_send_env")]
    #[getset(get = "pub(crate)")]
    send_env: Vec<String>,
    /// Additional PATH directories to prepend to the server's `server_path`.
    /// Sent via `ClientEnv`; ignored by the server when `path_locked = true`.
    #[serde(default)]
    #[getset(get = "pub(crate)")]
    send_path: Vec<String>,
}

impl Config {
    fn default_server_port() -> u16 {
        40404
    }

    fn default_max_reconnect_backoff_secs() -> u64 {
        3600
    }

    fn default_nat_warmup_count() -> u32 {
        3
    }

    fn default_send_env() -> Vec<String> {
        vec!["LANG".into(), "LC_*".into(), "TZ".into()]
    }

    fn load_key_paths(&self) -> Result<(PathBuf, PathBuf)> {
        let (default_private_key_path, default_pub_key_ext) =
            KeyPair::default_key_path_ext(self.mode, KEY_ALGORITHM_X25519)?;
        let private_key_path = self
            .private_key_path
            .as_ref()
            .map_or(default_private_key_path, PathBuf::from);
        let public_key_path = self.public_key_path.as_ref().map_or(
            private_key_path.with_extension(default_pub_key_ext),
            PathBuf::from,
        );
        Ok((private_key_path, public_key_path))
    }
}

impl Default for Config {
    fn default() -> Self {
        Config {
            mode: KexMode::Client,
            user: String::new(),
            tracing: ClientTracing::default(),
            server_port: Self::default_server_port(),
            server_destination: String::new(),
            private_key_path: None,
            public_key_path: None,
            resume_session_uuid: None,
            max_reconnect_backoff_secs: Self::default_max_reconnect_backoff_secs(),
            predict: DisplayPreference::default(),
            nat_warmup: false,
            nat_warmup_count: Self::default_nat_warmup_count(),
            diff_mode: DiffMode::default(),
            legacy_passthrough: false,
            preferred_algorithms: AlgorithmPreferences::default(),
            send_env: Self::default_send_env(),
            send_path: Vec::new(),
        }
    }
}

impl KexConfig for Config {
    fn mode(&self) -> KexMode {
        self.mode
    }

    fn port_pool(&self) -> Option<Arc<Mutex<BTreeSet<u16>>>> {
        None
    }

    fn key_pair_paths(&self) -> Result<(PathBuf, PathBuf)> {
        self.load_key_paths()
    }

    fn user(&self) -> Option<String> {
        self.user.clone().into()
    }

    fn resume_session_uuid(&self) -> Option<Uuid> {
        self.resume_session_uuid
    }

    fn server_id(&self) -> Option<String> {
        Some(self.server_destination().clone())
    }

    fn diff_mode(&self) -> DiffMode {
        self.diff_mode
    }

    fn preferred_algorithms(&self) -> AlgorithmList {
        self.preferred_algorithms.clone().into_algorithm_list()
    }

    fn send_env(&self) -> Vec<String> {
        self.send_env.clone()
    }

    fn send_path(&self) -> Vec<String> {
        self.send_path.clone()
    }

    fn agent_socket(&self) -> Option<PathBuf> {
        std::env::var("MOSHPIT_AGENT_SOCK").ok().map(PathBuf::from)
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use anyhow::Result;
    use uuid::Uuid;

    use super::{Config, DisplayPreference, KexConfig, KexMode};

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.mode(), KexMode::Client);
        assert_eq!(config.server_port(), 40404);
        assert_eq!(config.server_destination(), "");
        assert_eq!(config.private_key_path(), &None);
        assert_eq!(config.public_key_path(), &None);
        assert_eq!(config.resume_session_uuid(), None);
        assert_eq!(config.max_reconnect_backoff_secs(), 3600);
        assert_eq!(config.predict(), DisplayPreference::default());
    }

    #[test]
    fn test_kex_config_impl() -> Result<()> {
        let mut config = Config::default();
        let _ = config.set_user("testuser".to_string());

        let uuid = Uuid::new_v4();
        let _ = config.set_resume_session_uuid(Some(uuid));

        assert_eq!(KexConfig::mode(&config), KexMode::Client);
        assert!(KexConfig::port_pool(&config).is_none());
        assert_eq!(
            KexConfig::user(&config).ok_or_else(|| anyhow::anyhow!("expected user to be set"))?,
            "testuser"
        );
        assert_eq!(KexConfig::resume_session_uuid(&config), Some(uuid));
        Ok(())
    }

    #[test]
    fn test_load_key_paths() -> Result<()> {
        // Without explicit paths, it should fall back to default
        let config = Config::default();
        let (priv_path, pub_path) = config.load_key_paths()?;
        assert!(priv_path.to_string_lossy().contains("id_x25519"));
        assert!(pub_path.to_string_lossy().contains("id_x25519.pub"));

        // With explicit paths
        let config = Config {
            private_key_path: Some("/tmp/my_priv".to_string()),
            public_key_path: Some("/tmp/my_pub".to_string()),
            ..Config::default()
        };
        let (priv_path, pub_path) = config.load_key_paths()?;
        assert_eq!(priv_path, PathBuf::from("/tmp/my_priv"));
        assert_eq!(pub_path, PathBuf::from("/tmp/my_pub"));
        Ok(())
    }
}
