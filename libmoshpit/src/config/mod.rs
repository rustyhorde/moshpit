// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

//! Configuration traits and structures shared by the moshpit binary crates.

use std::{collections::BTreeSet, path::PathBuf, sync::Arc};

use anyhow::{Context as _, Result};
use config::{Config, Environment, File, FileFormat, Source};
use dirs2::config_dir;
use serde::Deserialize;
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::{
    KexMode,
    error::Error,
    kex::negotiate::{
        AlgorithmList, MIN_PROTOCOL_VERSION, PROTOCOL_VERSION, ProtocolSupport,
        supported_algorithms,
    },
    session::SessionRegistry,
    to_path_buf,
    udp::DiffMode,
};

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
    /// The requested UDP diff transport mode.
    /// Client implementations override this to return their configured mode;
    /// server implementations use the default (`Reliable`) since the server
    /// always supports both modes and the actual mode is determined from the
    /// client's `ClientOptions` KEX frame.
    fn diff_mode(&self) -> DiffMode {
        DiffMode::Reliable
    }
    /// The ordered list of algorithms this endpoint is willing to use.
    /// Both client and server send this list in a `KexInit` frame at the start
    /// of the handshake; the peer selects the first common algorithm in each
    /// category.  Defaults to the full set of algorithms supported by this build.
    fn preferred_algorithms(&self) -> AlgorithmList {
        supported_algorithms()
    }
    /// The effective minimum wire protocol version this endpoint will accept.
    ///
    /// Defaults to the build floor [`MIN_PROTOCOL_VERSION`].  Server
    /// implementations override this from their configured
    /// `--min-protocol-version` so an operator can retire old protocols without
    /// recompiling; the value is clamped by [`protocol_support`](Self::protocol_support).
    fn min_protocol_version(&self) -> u16 {
        MIN_PROTOCOL_VERSION
    }
    /// The supported wire protocol range this endpoint advertises in its
    /// `KexInit` frame and uses as the local side of version negotiation.
    ///
    /// The configured minimum is clamped to `[MIN_PROTOCOL_VERSION,
    /// PROTOCOL_VERSION]`: it can never drop below what this build can speak, nor
    /// rise above the highest version it implements.
    fn protocol_support(&self) -> ProtocolSupport {
        ProtocolSupport {
            min: self
                .min_protocol_version()
                .clamp(MIN_PROTOCOL_VERSION, PROTOCOL_VERSION),
            max: PROTOCOL_VERSION,
        }
    }
    /// Environment variable name patterns to send to the server via `ClientEnv`.
    /// Supports exact names (`LANG`) and suffix wildcards (`LC_*`).
    /// Returns an empty list by default; client implementations override this.
    fn send_env(&self) -> Vec<String> {
        vec![]
    }
    /// Additional PATH directories to prepend to the server's `server_path`.
    /// Sent via `ClientEnv`; ignored by the server when `path_locked = true`.
    /// Returns an empty list by default; client implementations override this.
    fn send_path(&self) -> Vec<String> {
        vec![]
    }
    /// Path to the moshpit-agent Unix socket.
    ///
    /// When `Some`, `run_client_kex` will use the agent for all identity-key
    /// operations instead of reading key files directly.  Returns `None` by
    /// default; client implementations override this to check
    /// `$MOSHPIT_AGENT_SOCK`.
    fn agent_socket(&self) -> Option<PathBuf> {
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

    use super::{
        KexConfig, KexMode, PathDefaults, SessionRegistry, config_file_path,
        default_config_file_path,
    };

    // ── minimal KexConfig implementor ─────────────────────────────────────────

    // A minimal `KexConfig`. `min_protocol_version` is configurable so the same
    // helper drives both the default-range and the clamp tests; `None` uses the
    // trait's build-floor default.
    #[derive(Default)]
    struct TestKexConfig {
        min_protocol_version: Option<u16>,
    }

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
        fn min_protocol_version(&self) -> u16 {
            self.min_protocol_version
                .unwrap_or(crate::kex::negotiate::MIN_PROTOCOL_VERSION)
        }
    }

    // ── default method impls ──────────────────────────────────────────────────

    #[test]
    fn protocol_support_default_uses_build_range() {
        use crate::kex::negotiate::{MIN_PROTOCOL_VERSION, PROTOCOL_VERSION};
        let s = TestKexConfig::default().protocol_support();
        assert_eq!(s.min, MIN_PROTOCOL_VERSION);
        assert_eq!(s.max, PROTOCOL_VERSION);
    }

    #[test]
    fn protocol_support_clamps_configured_min() {
        use crate::kex::negotiate::{MIN_PROTOCOL_VERSION, PROTOCOL_VERSION};
        // Below the build floor → clamped up to the floor.
        let too_low = TestKexConfig {
            min_protocol_version: Some(0),
        };
        assert_eq!(too_low.protocol_support().min, MIN_PROTOCOL_VERSION);
        // Above the highest version we speak → clamped down to PROTOCOL_VERSION.
        let too_high = TestKexConfig {
            min_protocol_version: Some(u16::MAX),
        };
        assert_eq!(too_high.protocol_support().min, PROTOCOL_VERSION);
    }

    #[test]
    fn kex_config_session_registry_default_is_none() {
        let cfg = TestKexConfig::default();
        let reg: Option<SessionRegistry> = cfg.session_registry();
        assert!(reg.is_none());
    }

    #[test]
    fn kex_config_resume_session_uuid_default_is_none() {
        let cfg = TestKexConfig::default();
        let uuid: Option<Uuid> = cfg.resume_session_uuid();
        assert!(uuid.is_none());
    }

    #[test]
    fn kex_config_server_id_default_is_none() {
        let cfg = TestKexConfig::default();
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

    struct AbsolutePathDefaults;

    impl PathDefaults for AbsolutePathDefaults {
        fn env_prefix(&self) -> String {
            "TEST".to_string()
        }
        fn config_absolute_path(&self) -> Option<String> {
            Some("/tmp/my-moshpit-config.toml".to_string())
        }
        fn default_file_path(&self) -> String {
            "unused".to_string()
        }
        fn default_file_name(&self) -> String {
            "unused".to_string()
        }
        fn tracing_absolute_path(&self) -> Option<String> {
            None
        }
        fn default_tracing_path(&self) -> String {
            "unused".to_string()
        }
        fn default_tracing_file_name(&self) -> String {
            "unused".to_string()
        }
    }

    #[test]
    fn config_file_path_uses_absolute_path_when_provided() {
        let defaults = AbsolutePathDefaults;
        let path =
            config_file_path(&defaults).expect("config_file_path must succeed with absolute path");
        assert_eq!(
            path,
            PathBuf::from("/tmp/my-moshpit-config.toml"),
            "config_file_path must return the exact absolute path from config_absolute_path()"
        );
    }

    #[test]
    fn kex_config_send_env_default_is_empty() {
        let cfg = TestKexConfig::default();
        assert!(
            cfg.send_env().is_empty(),
            "send_env() default must return an empty Vec"
        );
    }

    #[test]
    fn kex_config_send_path_default_is_empty() {
        let cfg = TestKexConfig::default();
        assert!(
            cfg.send_path().is_empty(),
            "send_path() default must return an empty Vec"
        );
    }

    #[test]
    fn kex_config_agent_socket_default_is_none() {
        // The default impl always returns None, independent of env vars.
        let cfg = TestKexConfig::default();
        assert!(
            cfg.agent_socket().is_none(),
            "agent_socket() default must return None"
        );
    }
}
