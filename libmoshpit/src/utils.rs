// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

use std::path::PathBuf;

use anyhow::Result;

/// Convert a string to a `PathBuf`
///
/// # Errors
/// * This function never errors, but is wrapped to use with `map_or_else` and similar
///
#[allow(clippy::unnecessary_wraps)]
pub fn to_path_buf(path: &String) -> Result<PathBuf> {
    Ok(PathBuf::from(path))
}

#[cfg(test)]
#[allow(dead_code)]
pub(crate) trait Mock {
    fn mock() -> Self;
}

#[cfg(test)]
pub(crate) mod test {
    use tracing::Level;
    use tracing_subscriber_init::TracingConfig;

    use crate::TracingConfigExt;

    use super::to_path_buf;

    pub(crate) struct TestConfig {
        verbose: u8,
        quiet: u8,
        level: Level,
        directives: Option<String>,
        enable_stdout: bool,
    }

    impl TestConfig {
        pub(crate) fn with_directives(enable_stdout: bool) -> Self {
            Self {
                verbose: 3,
                quiet: 0,
                level: Level::INFO,
                directives: Some("actix_web=error".to_string()),
                enable_stdout,
            }
        }
    }

    impl Default for TestConfig {
        fn default() -> Self {
            Self {
                verbose: 3,
                quiet: 0,
                level: Level::INFO,
                directives: None,
                enable_stdout: false,
            }
        }
    }

    impl TracingConfig for TestConfig {
        fn quiet(&self) -> u8 {
            self.quiet
        }

        fn verbose(&self) -> u8 {
            self.verbose
        }
    }

    impl TracingConfigExt for TestConfig {
        fn level(&self) -> Level {
            self.level
        }

        fn enable_stdout(&self) -> bool {
            self.enable_stdout
        }

        fn directives(&self) -> Option<&String> {
            self.directives.as_ref()
        }
    }

    #[test]
    fn test_to_path_buf() {
        let path_str = String::from("/some/test/path");
        let path_buf = to_path_buf(&path_str).unwrap();
        assert_eq!(path_buf.to_str().unwrap(), "/some/test/path");
    }
}
