// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

use std::{collections::BTreeSet, path::PathBuf, sync::Arc};

use anyhow::{Context as _, Result};
use config::{Config, Environment, File, FileFormat, Source};
use dirs2::config_dir;
use serde::Deserialize;
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::{KexMode, error::Error, session::SessionRegistry, to_path_buf};

pub(crate) mod mps;
pub(crate) mod tracing;

/// Trait to allow default paths to be supplied to [`load`]
pub trait PathDefaults {
    /// Environment variable prefix
    fn env_prefix(&self) -> String;
    /// The absolute path to use for the config file
    fn config_absolute_path(&self) -> Option<String>;
    /// The default file path to use
    fn default_file_path(&self) -> String;
    /// The default file name to use
    fn default_file_name(&self) -> String;
    /// The abolute path to use for tracing output
    fn tracing_absolute_path(&self) -> Option<String>;
    /// The default logging path to use
    fn default_tracing_path(&self) -> String;
    /// The default log file name to use
    fn default_tracing_file_name(&self) -> String;
}

/// Trait for key exchange configuration
pub trait KexConfig {
    /// The key exchange mode
    fn mode(&self) -> KexMode;
    /// An optional pool of ports to use for UDP connections, only relevant for server mode
    fn port_pool(&self) -> Option<Arc<Mutex<BTreeSet<u16>>>>;
    /// The paths to the public and private key files
    ///
    /// # Errors
    ///
    fn key_pair_paths(&self) -> Result<(PathBuf, PathBuf)>;
    /// The username to use for the key exchange, only relevant for client mode
    fn user(&self) -> Option<String>;
    /// The session registry for tracking active sessions, only relevant for server mode.
    /// Returns `None` by default; server implementations override this.
    fn session_registry(&self) -> Option<SessionRegistry> {
        None
    }
    /// The session UUID to attempt resuming, only relevant for client mode.
    /// Returns `None` by default; client implementations override this.
    fn resume_session_uuid(&self) -> Option<Uuid> {
        None
    }
    /// The server identifier (hostname or IP) used for `known_hosts` validation.
    /// Returns `None` by default.
    fn server_id(&self) -> Option<String> {
        None
    }
}

/// Load the configuration
///
/// # Errors
/// - [`Error::ConfigDir`] - No valid config directory could be found
/// - [`Error::ConfigBuild`] - Unable to build a valid configuration
/// - [`Error::ConfigDeserialize`] - Unable to deserialize configuration
/// - Any other error encountered while trying to read the config file
///
pub fn load<'a, S, T, D>(cli: &S, defaults: &D) -> Result<T>
where
    T: Deserialize<'a>,
    S: Source + Clone + Send + Sync + 'static,
    D: PathDefaults,
{
    let config_file_path = config_file_path(defaults)?;
    let config = Config::builder()
        .add_source(
            Environment::with_prefix(&defaults.env_prefix())
                .separator("_")
                .try_parsing(true),
        )
        .add_source(cli.clone())
        .add_source(File::from(config_file_path).format(FileFormat::Toml))
        .build()
        .with_context(|| Error::ConfigBuild)?;
    config
        .try_deserialize::<T>()
        .with_context(|| Error::ConfigDeserialize)
}

fn config_file_path<D>(defaults: &D) -> Result<PathBuf>
where
    D: PathDefaults,
{
    let default_fn = || -> Result<PathBuf> { default_config_file_path(defaults) };
    defaults
        .config_absolute_path()
        .as_ref()
        .map_or_else(default_fn, to_path_buf)
}

fn default_config_file_path<D>(defaults: &D) -> Result<PathBuf>
where
    D: PathDefaults,
{
    let mut config_file_path = config_dir().ok_or(Error::ConfigDir)?;
    config_file_path.push(defaults.default_file_path());
    config_file_path.push(defaults.default_file_name());
    let _ = config_file_path.set_extension("toml");
    Ok(config_file_path)
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, path::PathBuf, sync::Arc};

    use tokio::sync::Mutex;
    use uuid::Uuid;

    use super::{KexConfig, KexMode, PathDefaults, SessionRegistry, default_config_file_path};

    // ── minimal KexConfig implementor ─────────────────────────────────────────

    struct TestKexConfig;

    impl KexConfig for TestKexConfig {
        fn mode(&self) -> KexMode {
            KexMode::Client
        }
        fn port_pool(&self) -> Option<Arc<Mutex<BTreeSet<u16>>>> {
            None
        }
        fn key_pair_paths(&self) -> anyhow::Result<(PathBuf, PathBuf)> {
            Ok((PathBuf::from("/tmp/pub"), PathBuf::from("/tmp/priv")))
        }
        fn user(&self) -> Option<String> {
            Some("testuser".to_string())
        }
    }

    // ── default method impls ──────────────────────────────────────────────────

    #[test]
    fn kex_config_session_registry_default_is_none() {
        let cfg = TestKexConfig;
        let reg: Option<SessionRegistry> = cfg.session_registry();
        assert!(reg.is_none());
    }

    #[test]
    fn kex_config_resume_session_uuid_default_is_none() {
        let cfg = TestKexConfig;
        let uuid: Option<Uuid> = cfg.resume_session_uuid();
        assert!(uuid.is_none());
    }

    #[test]
    fn kex_config_server_id_default_is_none() {
        let cfg = TestKexConfig;
        let sid: Option<String> = cfg.server_id();
        assert!(sid.is_none());
    }

    // ── PathDefaults implementor ───────────────────────────────────────────────

    struct TestPathDefaults;

    impl PathDefaults for TestPathDefaults {
        fn env_prefix(&self) -> String {
            "TEST".to_string()
        }
        fn config_absolute_path(&self) -> Option<String> {
            None
        }
        fn default_file_path(&self) -> String {
            "moshpit-test".to_string()
        }
        fn default_file_name(&self) -> String {
            "config".to_string()
        }
        fn tracing_absolute_path(&self) -> Option<String> {
            None
        }
        fn default_tracing_path(&self) -> String {
            "moshpit-test".to_string()
        }
        fn default_tracing_file_name(&self) -> String {
            "moshpits".to_string()
        }
    }

    #[test]
    fn default_config_file_path_ends_with_toml() {
        let defaults = TestPathDefaults;
        // This may fail with ConfigDir if no home is set in the test environment,
        // but on CI with a real user home it should succeed.
        if let Ok(path) = default_config_file_path(&defaults) {
            assert_eq!(path.extension().and_then(|e| e.to_str()), Some("toml"));
            let path_str = path.to_string_lossy();
            assert!(
                path_str.contains("moshpit-test"),
                "path must contain the default file path component"
            );
        }
    }
}
