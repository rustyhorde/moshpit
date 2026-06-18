// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

use std::{collections::BTreeSet, env::var, path::PathBuf, sync::Arc};

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

/// Client diff-mode preference parsed from `--diff-mode` / `MOSHPIT_DIFF_MODE` /
/// TOML.  `Auto` (the default) resolves to a concrete [`DiffMode`] based on the
/// negotiated transport: `StateSync` over TCP, `Reliable` over UDP.  An explicit
/// mode is always honored regardless of transport.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum DiffModePref {
    /// Transport-dependent default: `StateSync` over TCP, `Reliable` over UDP.
    #[default]
    Auto,
    /// NAK-based selective retransmission.
    Reliable,
    /// Fire-and-forget diffs with periodic full-screen snapshots.
    Datagram,
    /// Mosh-style ack-based incremental diffs.
    Statesync,
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
    /// Diff transport mode preference.  Defaults to `Auto`, which resolves to
    /// `StateSync` over TCP and `Reliable` over UDP (see [`Config::diff_mode`]).
    /// Set explicitly via `--diff-mode <mode>` / `MOSHPIT_DIFF_MODE=<mode>`.
    #[serde(default)]
    diff_mode: DiffModePref,
    /// Data-channel transport mode.  `udp` (default) uses encrypted UDP;
    /// `tcp` uses the server's TCP data port (fallback for UDP-blocking firewalls).
    /// Set via `--transport tcp` / `MOSHPIT_TRANSPORT=tcp`.
    #[serde(default)]
    #[getset(get_copy = "pub(crate)")]
    transport: libmoshpit::TransportMode,
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
    /// Force-quit escape prefix key, e.g. `"ctrl-^"` (default).  Pressed and then
    /// followed by `.` to disconnect.  Must resolve to a control byte; parsed and
    /// validated at startup by `runtime::parse_escape_key`.
    #[serde(default = "Config::default_escape_key")]
    #[getset(get = "pub(crate)")]
    escape_key: String,
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

    fn default_escape_key() -> String {
        "ctrl-^".to_string()
    }

    /// Resolve the configured [`DiffModePref`] to a concrete [`DiffMode`].
    ///
    /// `Auto` picks `StateSync` over the TCP transport (incremental diffs keep
    /// server CPU low) and `Reliable` over UDP (the historical default).  An
    /// explicit preference is returned unchanged.
    pub(crate) fn diff_mode(&self) -> DiffMode {
        match self.diff_mode {
            DiffModePref::Reliable => DiffMode::Reliable,
            DiffModePref::Datagram => DiffMode::Datagram,
            DiffModePref::Statesync => DiffMode::StateSync,
            DiffModePref::Auto => match self.transport {
                libmoshpit::TransportMode::Tcp => DiffMode::StateSync,
                libmoshpit::TransportMode::Udp => DiffMode::Reliable,
            },
        }
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
            diff_mode: DiffModePref::default(),
            transport: libmoshpit::TransportMode::default(),
            legacy_passthrough: false,
            preferred_algorithms: AlgorithmPreferences::default(),
            send_env: Self::default_send_env(),
            send_path: Vec::new(),
            escape_key: Self::default_escape_key(),
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
        // Delegate to the inherent resolver (handles the `Auto` default).
        Config::diff_mode(self)
    }

    fn transport_preference(&self) -> libmoshpit::TransportMode {
        self.transport
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
        var("MOSHPIT_AGENT_SOCK").ok().map(PathBuf::from)
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use anyhow::Result;
    use uuid::Uuid;

    use libmoshpit::{DiffMode, TransportMode};

    use super::{Config, DisplayPreference, KexConfig, KexMode};

    #[test]
    fn test_transport_defaults_to_udp() {
        let config = Config::default();
        assert_eq!(config.transport(), TransportMode::Udp);
        assert_eq!(config.transport_preference(), TransportMode::Udp);
    }

    #[test]
    fn test_transport_tcp_from_toml() -> Result<()> {
        let toml = r#"
            private_key_path = "/tmp/priv"
            public_key_path = "/tmp/pub"
            transport = "tcp"
        "#;
        let config: Config = toml::from_str(toml)?;
        assert_eq!(config.transport(), TransportMode::Tcp);
        assert_eq!(config.transport_preference(), TransportMode::Tcp);
        Ok(())
    }

    #[test]
    fn test_transport_absent_in_toml_defaults_udp() -> Result<()> {
        let toml = r#"
            private_key_path = "/tmp/priv"
            public_key_path = "/tmp/pub"
        "#;
        let config: Config = toml::from_str(toml)?;
        assert_eq!(config.transport_preference(), TransportMode::Udp);
        Ok(())
    }

    #[test]
    fn auto_diff_mode_resolves_reliable_over_udp() {
        // Default config (UDP transport, Auto diff mode) keeps the historical
        // UDP default of Reliable.
        let config = Config::default();
        assert_eq!(config.diff_mode(), DiffMode::Reliable);
    }

    #[test]
    fn auto_diff_mode_resolves_statesync_over_tcp() -> Result<()> {
        let toml = r#"
            private_key_path = "/tmp/priv"
            public_key_path = "/tmp/pub"
            transport = "tcp"
        "#;
        let config: Config = toml::from_str(toml)?;
        assert_eq!(config.diff_mode(), DiffMode::StateSync);
        Ok(())
    }

    #[test]
    fn explicit_diff_mode_overrides_tcp_statesync_default() -> Result<()> {
        let toml = r#"
            private_key_path = "/tmp/priv"
            public_key_path = "/tmp/pub"
            transport = "tcp"
            diff_mode = "reliable"
        "#;
        let config: Config = toml::from_str(toml)?;
        assert_eq!(config.diff_mode(), DiffMode::Reliable);
        Ok(())
    }

    #[test]
    fn explicit_statesync_honored_over_udp() -> Result<()> {
        let toml = r#"
            private_key_path = "/tmp/priv"
            public_key_path = "/tmp/pub"
            diff_mode = "statesync"
        "#;
        let config: Config = toml::from_str(toml)?;
        assert_eq!(config.transport_preference(), TransportMode::Udp);
        assert_eq!(config.diff_mode(), DiffMode::StateSync);
        Ok(())
    }

    #[test]
    fn explicit_datagram_honored_over_tcp() -> Result<()> {
        let toml = r#"
            private_key_path = "/tmp/priv"
            public_key_path = "/tmp/pub"
            transport = "tcp"
            diff_mode = "datagram"
        "#;
        let config: Config = toml::from_str(toml)?;
        assert_eq!(config.diff_mode(), DiffMode::Datagram);
        Ok(())
    }

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
        assert_eq!(config.escape_key(), "ctrl-^");
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
