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
    AlgorithmList, DiffMode, DisplayPreference, KexConfig, KexMode, KeyPair, Tracing,
    TracingConfigExt, supported_algorithms,
};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tracing::Level;
use tracing_subscriber_init::{TracingConfig, get_effective_level};
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

#[derive(Clone, CopyGetters, Debug, Deserialize, Eq, Getters, PartialEq, Serialize, Setters)]
pub(crate) struct Config {
    #[serde(skip_deserializing)]
    #[getset(get_copy = "pub(crate)")]
    mode: KexMode,
    #[serde(skip_deserializing)]
    #[getset(get = "pub(crate)", set = "pub(crate)")]
    user: String,
    #[getset(get_copy = "pub(crate)")]
    verbose: u8,
    #[getset(get_copy = "pub(crate)")]
    quiet: u8,
    #[getset(get = "pub(crate)")]
    tracing: Tracing,
    #[getset(get_copy = "pub(crate)")]
    server_port: u16,
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
    /// Per-category algorithm overrides from TOML `[preferred_algorithms]` or CLI flags.
    #[serde(default)]
    preferred_algorithms: AlgorithmPreferences,
}

impl Config {
    fn default_max_reconnect_backoff_secs() -> u64 {
        3600
    }

    fn default_nat_warmup_count() -> u32 {
        3
    }

    fn load_key_paths(&self) -> Result<(PathBuf, PathBuf)> {
        let (default_private_key_path, default_pub_key_ext) =
            KeyPair::default_key_path_ext(self.mode)?;
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
            verbose: 0,
            quiet: 0,
            tracing: Tracing::default(),
            server_port: 60001,
            server_destination: String::new(),
            private_key_path: None,
            public_key_path: None,
            resume_session_uuid: None,
            max_reconnect_backoff_secs: Self::default_max_reconnect_backoff_secs(),
            predict: DisplayPreference::default(),
            nat_warmup: false,
            nat_warmup_count: Self::default_nat_warmup_count(),
            diff_mode: DiffMode::default(),
            preferred_algorithms: AlgorithmPreferences::default(),
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
}

impl TracingConfig for Config {
    fn quiet(&self) -> u8 {
        self.quiet
    }

    fn verbose(&self) -> u8 {
        self.verbose
    }

    fn with_target(&self) -> bool {
        self.tracing().stdout().with_target()
    }

    fn with_thread_ids(&self) -> bool {
        self.tracing().stdout().with_thread_ids()
    }

    fn with_thread_names(&self) -> bool {
        self.tracing().stdout().with_thread_names()
    }

    fn with_line_number(&self) -> bool {
        self.tracing().stdout().with_line_number()
    }

    fn with_level(&self) -> bool {
        self.tracing().stdout().with_level()
    }
}

impl TracingConfigExt for Config {
    fn enable_stdout(&self) -> bool {
        false
    }

    fn directives(&self) -> Option<&String> {
        self.tracing().stdout().directives().as_ref()
    }

    fn level(&self) -> Level {
        get_effective_level(self.quiet(), self.verbose())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.mode(), KexMode::Client);
        assert_eq!(config.verbose(), 0);
        assert_eq!(config.quiet(), 0);
        assert_eq!(config.server_port(), 60001);
        assert_eq!(config.server_destination(), "");
        assert_eq!(config.private_key_path(), &None);
        assert_eq!(config.public_key_path(), &None);
        assert_eq!(config.resume_session_uuid(), None);
        assert_eq!(config.max_reconnect_backoff_secs(), 3600);
        assert_eq!(config.predict(), DisplayPreference::default());
    }

    #[test]
    fn test_kex_config_impl() {
        let mut config = Config::default();
        let _ = config.set_user("testuser".to_string());

        let uuid = Uuid::new_v4();
        let _ = config.set_resume_session_uuid(Some(uuid));

        assert_eq!(KexConfig::mode(&config), KexMode::Client);
        assert!(KexConfig::port_pool(&config).is_none());
        assert_eq!(KexConfig::user(&config).unwrap(), "testuser");
        assert_eq!(KexConfig::resume_session_uuid(&config), Some(uuid));
    }

    #[test]
    fn test_load_key_paths() {
        // Without explicit paths, it should fall back to default
        let config = Config::default();
        let (priv_path, pub_path) = config.load_key_paths().unwrap();
        assert!(priv_path.to_string_lossy().contains("id_ed25519"));
        assert!(pub_path.to_string_lossy().contains("id_ed25519.pub"));

        // With explicit paths
        let config = Config {
            private_key_path: Some("/tmp/my_priv".to_string()),
            public_key_path: Some("/tmp/my_pub".to_string()),
            ..Config::default()
        };
        let (priv_path, pub_path) = config.load_key_paths().unwrap();
        assert_eq!(priv_path, PathBuf::from("/tmp/my_priv"));
        assert_eq!(pub_path, PathBuf::from("/tmp/my_pub"));
    }

    #[test]
    fn test_tracing_config_impl() {
        let config = Config {
            verbose: 2,
            quiet: 1,
            ..Config::default()
        };

        assert_eq!(TracingConfig::verbose(&config), 2);
        assert_eq!(TracingConfig::quiet(&config), 1);

        // These will be false/default based on the default `Tracing` object inside Config
        assert!(!TracingConfig::with_target(&config));
        assert!(!TracingConfig::with_thread_ids(&config));
        assert!(!TracingConfig::with_thread_names(&config));
        assert!(!TracingConfig::with_line_number(&config));
        assert!(!TracingConfig::with_level(&config));
    }

    #[test]
    fn test_tracing_config_ext_impl() {
        let config = Config {
            verbose: 3,
            quiet: 0,
            ..Config::default()
        };

        assert!(!TracingConfigExt::enable_stdout(&config));
        assert!(TracingConfigExt::directives(&config).is_none());

        // Check effective level
        assert_eq!(TracingConfigExt::level(&config), Level::TRACE);
    }
}
