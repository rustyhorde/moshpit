// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

use std::path::PathBuf;

use anyhow::{Context as _, Result};
use config::{Config, Environment, File, FileFormat, Source};
use dirs2::config_dir;
use serde::Deserialize;

use crate::{error::Error, to_path_buf};

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
