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
use libmoshpit::{DisplayPreference, KexConfig, KexMode, KeyPair, Tracing, TracingConfigExt};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tracing::Level;
use tracing_subscriber_init::{TracingConfig, get_effective_level};
use uuid::Uuid;

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
}

impl Config {
    fn default_max_reconnect_backoff_secs() -> u64 {
        3600
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
