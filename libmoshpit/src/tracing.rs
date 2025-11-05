// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

use std::path::PathBuf;

use anyhow::Result;
use dirs2::data_dir;
use tracing::{Level, level_filters::LevelFilter, subscriber::DefaultGuard};
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::{EnvFilter, Layer, Registry};
#[cfg(not(test))]
use tracing_subscriber_init::try_init;
use tracing_subscriber_init::{Iso8601, TracingConfig, UtcTime, compact};

use crate::{PathDefaults, error::Error, utils::to_path_buf};

/// Extension trait for `TracingConfig` to add additional configuration options
pub trait TracingConfigExt: TracingConfig {
    /// Should we enable stdout logging
    fn enable_stdout(&self) -> bool;
    /// Additional tracing directives
    fn directives(&self) -> Option<&String>;
    /// Current tracing level
    fn level(&self) -> Level;
}

/// Initialize tracing
///
/// # Errors
/// * If the path to the tracing file cannot be created or found
///
pub fn init_tracing<T, U, V>(
    stdout: &T,
    file: &U,
    defaults: &V,
    layers_opt: Option<Vec<Box<dyn Layer<Registry> + Send + Sync>>>,
) -> Result<()>
where
    T: TracingConfigExt,
    U: TracingConfigExt,
    V: PathDefaults,
{
    let mut layers = layers_opt.unwrap_or_default();

    // Setup the stdout tracing layer if enabled
    if stdout.enable_stdout() {
        let (layer, level_filter) = compact(stdout);
        let mut directives = directives(stdout, level_filter);
        directives.push_str(",vergen_pretty=error");
        let filter = EnvFilter::builder()
            .with_default_directive(level_filter.into())
            .parse_lossy(directives);
        let stdout_layer = layer
            .with_timer(UtcTime::new(Iso8601::DEFAULT))
            .with_filter(filter);
        layers.push(stdout_layer.boxed());
    }

    // Setup the tracing file layer
    let (directory, logfile) = tracing_absolute_path(defaults)?;
    let tracing_file = RollingFileAppender::new(Rotation::DAILY, directory, logfile);
    let (layer, _level_filter) = compact(file);
    let level_filter = LevelFilter::from(file.level());
    let directives = directives(file, level_filter);
    let filter = EnvFilter::builder()
        .with_default_directive(level_filter.into())
        .parse_lossy(directives);
    let file_layer = layer
        .with_timer(UtcTime::new(Iso8601::DEFAULT))
        .with_writer(tracing_file)
        .with_filter(filter);
    layers.push(file_layer.boxed());

    let _guard_opt = try_initialize(layers)?;
    Ok(())
}

#[cfg(not(test))]
#[cfg_attr(coverage_nightly, coverage(off))]
fn try_initialize(
    layers: Vec<Box<dyn Layer<Registry> + Send + Sync + 'static>>,
) -> Result<Option<DefaultGuard>> {
    try_init(layers).map(|()| None)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
#[allow(clippy::unnecessary_wraps)]
fn try_initialize(
    layers: Vec<Box<dyn Layer<Registry> + Send + Sync + 'static>>,
) -> Result<Option<DefaultGuard>> {
    use tracing_subscriber_init::set_default;
    Ok(Some(set_default(layers)))
}

fn directives<T>(config: &T, level_filter: LevelFilter) -> String
where
    T: TracingConfigExt,
{
    let directives_base = match level_filter.into_level() {
        Some(level) => match level {
            Level::TRACE => "trace",
            Level::DEBUG => "debug",
            Level::INFO => "info",
            Level::WARN => "warn",
            Level::ERROR => "error",
        },
        None => "info",
    };

    if let Some(directives) = config.directives() {
        format!("{directives_base},{directives}")
    } else {
        directives_base.to_string()
    }
}

fn tracing_absolute_path<D>(defaults: &D) -> Result<(PathBuf, PathBuf)>
where
    D: PathDefaults,
{
    let default_fn = || -> Result<PathBuf> { default_tracing_absolute_path(defaults) };
    let mut full_path = defaults
        .tracing_absolute_path()
        .as_ref()
        .map_or_else(default_fn, to_path_buf)?;

    let file_path = PathBuf::from(full_path.file_name().ok_or(Error::DataDir)?);
    let _ = full_path.pop();
    Ok((full_path, file_path))
}

#[allow(clippy::unnecessary_wraps)]
fn default_tracing_absolute_path<D>(defaults: &D) -> Result<PathBuf>
where
    D: PathDefaults,
{
    let mut config_file_path = data_dir().ok_or(Error::DataDir)?;
    config_file_path.push(defaults.default_tracing_path());
    config_file_path.push(defaults.default_tracing_file_name());
    let _ = config_file_path.set_extension("log");
    Ok(config_file_path)
}

#[cfg(test)]
mod test {
    use tempfile::NamedTempFile;
    use tracing::level_filters::LevelFilter;

    use crate::{PathDefaults, utils::test::TestConfig};

    use super::{directives, init_tracing};

    impl PathDefaults for TestConfig {
        fn default_tracing_path(&self) -> String {
            let blah = NamedTempFile::new().unwrap();
            blah.path().display().to_string()
        }

        fn default_tracing_file_name(&self) -> String {
            "moshpit.log".to_string()
        }

        fn env_prefix(&self) -> String {
            "MOSHPIT".to_string()
        }

        fn config_absolute_path(&self) -> Option<String> {
            None
        }

        fn default_file_path(&self) -> String {
            "moshpit".to_string()
        }

        fn default_file_name(&self) -> String {
            "moshpit.toml".to_string()
        }

        fn tracing_absolute_path(&self) -> Option<String> {
            None
        }
    }

    #[test]
    fn init_tracing_works() {
        let config = TestConfig::default();
        assert_eq!(config.env_prefix(), "MOSHPIT");
        assert!(config.config_absolute_path().is_none());
        assert_eq!(config.default_file_path(), "moshpit");
        assert_eq!(config.default_file_name(), "moshpit.toml");
        assert!(init_tracing(&config, &config, &config, None).is_ok());
    }

    #[test]
    fn init_tracing_works_with_directives() {
        let config = TestConfig::with_directives(false);
        assert_eq!(config.env_prefix(), "MOSHPIT");
        assert!(config.config_absolute_path().is_none());
        assert_eq!(config.default_file_path(), "moshpit");
        assert_eq!(config.default_file_name(), "moshpit.toml");
        let res = init_tracing(&config, &config, &config, None);
        eprintln!("Result: {res:?}");
        assert!(res.is_ok());
    }

    #[test]
    fn init_tracing_works_with_directives_and_stdout() {
        let config = TestConfig::with_directives(true);
        assert_eq!(config.env_prefix(), "MOSHPIT");
        assert!(config.config_absolute_path().is_none());
        assert_eq!(config.default_file_path(), "moshpit");
        assert_eq!(config.default_file_name(), "moshpit.toml");
        let res = init_tracing(&config, &config, &config, None);
        eprintln!("Result: {res:?}");
        assert!(res.is_ok());
    }

    #[test]
    fn test_directives() {
        let config = TestConfig::default();
        let level_filter = LevelFilter::OFF;
        let dirs = directives(&config, level_filter);
        assert_eq!(dirs, "info");
        let level_filter = LevelFilter::TRACE;
        let dirs = directives(&config, level_filter);
        assert_eq!(dirs, "trace");
        let level_filter = LevelFilter::DEBUG;
        let dirs = directives(&config, level_filter);
        assert_eq!(dirs, "debug");
        let level_filter = LevelFilter::WARN;
        let dirs = directives(&config, level_filter);
        assert_eq!(dirs, "warn");
        let level_filter = LevelFilter::ERROR;
        let dirs = directives(&config, level_filter);
        assert_eq!(dirs, "error");
    }
}
