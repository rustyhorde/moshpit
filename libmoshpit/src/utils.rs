// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

//! Utility functions shared across the moshpit crates.

use std::{net::SocketAddr, path::PathBuf, sync::LazyLock};

use anyhow::Result;
use regex::Regex;
use whoami::username;

use crate::MoshpitError;

/// Convert a string to a `PathBuf`
///
/// # Errors
/// * This function never errors, but is wrapped to use with `map_or_else` and similar
///
#[allow(clippy::unnecessary_wraps)]
pub fn to_path_buf(path: &String) -> Result<PathBuf> {
    Ok(PathBuf::from(path))
}

static SERVER_DEST_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^((.*)@)?((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3})(:(\d{1,5}))?$").expect("invalid regex literal")
});

/// Parse the server destination command line option into a `SocketAddr`
///
/// # Errors
/// * This function never errors, but is wrapped to use with `map_or_else` and similar
///
pub fn parse_server_destination(dest: &str, port: u16) -> Result<(String, SocketAddr)> {
    if let Some(captures) = SERVER_DEST_REGEX.captures(dest) {
        let user = captures
            .get(2)
            .map_or(username()?, |m| m.as_str().to_string());
        let ip_str = captures.get(3).map_or("", |m| m.as_str());
        let port_str = captures.get(8).map_or("", |m| m.as_str());
        let port_num = if port_str.is_empty() {
            port
        } else {
            port_str.parse().unwrap_or(port)
        };
        let socket_addr = format!("{ip_str}:{port_num}");
        Ok((user, socket_addr.parse()?))
    } else {
        Err(MoshpitError::InvalidServerDestination.into())
    }
}

static EXIT_TITLE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^0;exit$").expect("invalid regex literal"));
static EXIT_TITLE_RELAXED_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"0;exit").expect("invalid regex literal"));

/// Check if a terminal title indicates an exit command
pub fn is_exit_title(title: &str, relaxed: bool) -> bool {
    if relaxed {
        EXIT_TITLE_RELAXED_RE.is_match(title)
    } else {
        EXIT_TITLE_RE.is_match(title)
    }
}

#[cfg(test)]
#[allow(dead_code)]
pub(crate) trait Mock {
    fn mock() -> Self;
}

#[cfg(test)]
pub(crate) mod test {
    use anyhow::Result;
    use tracing::Level;
    use tracing_subscriber_init::TracingConfig;
    use whoami::username;

    use crate::TracingConfigExt;

    use super::{parse_server_destination, to_path_buf};

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
    fn test_to_path_buf() -> Result<()> {
        let path_str = String::from("/some/test/path");
        let path_buf = to_path_buf(&path_str)?;
        assert_eq!(
            path_buf.to_str().expect("path is valid UTF-8"),
            "/some/test/path"
        );
        Ok(())
    }

    #[test]
    fn bad_server_destination_is_err() {
        let dest = "invalid_destination";
        let port = 60000;
        assert!(parse_server_destination(dest, port).is_err());
    }

    #[test]
    fn server_destination_is_parsed() -> Result<()> {
        let dest = "user@192.168.1.1:12345";
        let port = 40404;
        let result = parse_server_destination(dest, port)?;
        assert_eq!(result.0, "user");
        assert_eq!(result.1.to_string(), "192.168.1.1:12345");

        let dest_no_port = "user@192.168.1.1";
        let result_no_port = parse_server_destination(dest_no_port, port)?;
        assert_eq!(result_no_port.0, "user");
        assert_eq!(result_no_port.1.to_string(), "192.168.1.1:40404");

        let dest_no_user = "192.168.1.1:12345";
        let result_no_user = parse_server_destination(dest_no_user, port)?;
        assert_eq!(result_no_user.0, username()?);
        assert_eq!(result_no_user.1.to_string(), "192.168.1.1:12345");

        let dest_no_user_no_port = "192.168.1.1";
        let result_no_user_no_port = parse_server_destination(dest_no_user_no_port, port)?;
        assert_eq!(result_no_user_no_port.0, username()?);
        assert_eq!(result_no_user_no_port.1.to_string(), "192.168.1.1:40404");
        Ok(())
    }
}
