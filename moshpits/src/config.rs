// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

use std::{collections::BTreeSet, path::PathBuf, sync::Arc};

use anyhow::Result;
use getset::{CloneGetters, CopyGetters, Getters, Setters};
use libmoshpit::{KexConfig, KexMode, KeyPair, Mps, SessionRegistry, Tracing, TracingConfigExt};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tracing::Level;
use tracing_subscriber_init::{TracingConfig, get_effective_level};

#[derive(
    Clone, CloneGetters, CopyGetters, Debug, Default, Deserialize, Getters, Serialize, Setters,
)]
pub(crate) struct Config {
    #[serde(skip_deserializing)]
    #[getset(get_copy = "pub(crate)", set = "pub(crate)")]
    mode: KexMode,
    #[serde(skip)]
    #[getset(get_clone = "pub(crate)", set = "pub(crate)")]
    port_pool: Arc<Mutex<BTreeSet<u16>>>,
    #[serde(skip)]
    #[getset(get_clone = "pub(crate)", set = "pub(crate)")]
    session_registry: SessionRegistry,
    #[getset(get_copy = "pub(crate)")]
    verbose: u8,
    #[getset(get_copy = "pub(crate)")]
    quiet: u8,
    #[getset(get_copy = "pub(crate)", set = "pub(crate)")]
    enable_std_output: bool,
    #[getset(get = "pub(crate)")]
    tracing: Tracing,
    #[getset(get = "pub(crate)")]
    mps: Mps,
    #[getset(get = "pub(crate)")]
    private_key_path: Option<String>,
    #[getset(get = "pub(crate)")]
    public_key_path: Option<String>,
    /// Optional extra delay (ms) after peer discovery before bulk data is sent.
    /// Provides margin for NAT bindings on slow NAT devices.
    #[serde(default)]
    #[getset(get_copy = "pub(crate)")]
    warmup_delay_ms: Option<u64>,
}

impl Config {
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

impl KexConfig for Config {
    fn mode(&self) -> KexMode {
        self.mode()
    }

    fn port_pool(&self) -> Option<Arc<Mutex<BTreeSet<u16>>>> {
        self.port_pool().into()
    }

    fn key_pair_paths(&self) -> Result<(PathBuf, PathBuf)> {
        self.load_key_paths()
    }

    fn session_registry(&self) -> Option<SessionRegistry> {
        Some(self.session_registry.clone())
    }

    fn user(&self) -> Option<String> {
        None
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
        self.enable_std_output
    }

    fn directives(&self) -> Option<&String> {
        self.tracing().stdout().directives().as_ref()
    }

    fn level(&self) -> Level {
        get_effective_level(self.quiet(), self.verbose())
    }
}

#[cfg(test)]
mod test {
    use std::{net::SocketAddr, path::PathBuf};

    use libmoshpit::{KexConfig as _, KexMode, TracingConfigExt as _};

    use super::Config;

    fn server_mode() -> KexMode {
        KexMode::Server("0.0.0.0:0".parse::<SocketAddr>().unwrap())
    }

    #[test]
    fn config_default_is_sane() {
        let config = Config::default();
        assert_eq!(config.verbose(), 0);
        assert_eq!(config.quiet(), 0);
        assert!(!config.enable_stdout());
    }

    #[test]
    fn config_tracing_config_delegates() {
        let config = Config::default();
        assert_eq!(config.quiet(), 0);
        assert_eq!(config.verbose(), 0);
    }

    #[test]
    fn config_tracing_config_ext() {
        let config = Config::default();
        assert!(!config.enable_stdout());
        assert!(config.directives().is_none());
    }

    #[test]
    fn config_load_key_paths_explicit() {
        let priv_path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../libmoshpit/tests/keys/id_ed25519_test"
        );
        let pub_path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../libmoshpit/tests/keys/id_ed25519_test.pub"
        );
        let mut config = Config {
            private_key_path: Some(priv_path.to_string()),
            public_key_path: Some(pub_path.to_string()),
            ..Config::default()
        };
        let _ = config.set_mode(server_mode());
        let (got_priv, got_pub) = config.key_pair_paths().expect("key_pair_paths");
        assert_eq!(got_priv, PathBuf::from(priv_path));
        assert_eq!(got_pub, PathBuf::from(pub_path));
    }

    #[test]
    fn config_load_key_paths_default_derives_pub() {
        let priv_path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../libmoshpit/tests/keys/id_ed25519_test"
        );
        let mut config = Config {
            private_key_path: Some(priv_path.to_string()),
            ..Config::default()
        };
        let _ = config.set_mode(server_mode());
        let (got_priv, got_pub) = config.key_pair_paths().expect("key_pair_paths");
        assert_eq!(got_priv, PathBuf::from(priv_path));
        assert_eq!(got_pub, PathBuf::from(priv_path).with_extension("pub"));
    }
}
