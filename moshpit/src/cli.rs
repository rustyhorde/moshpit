// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

use std::{io::Cursor, sync::LazyLock};

use clap::{ArgAction, Parser};
use config::{ConfigError, Map, Source, Value, ValueKind};
use getset::{CopyGetters, Getters};
use libmoshpit::PathDefaults;
use vergen_pretty::{Pretty, vergen_pretty_env};

static LONG_VERSION: LazyLock<String> = LazyLock::new(|| {
    let pretty = Pretty::builder().env(vergen_pretty_env!()).build();
    let mut cursor = Cursor::new(vec![]);
    let mut output = env!("CARGO_PKG_VERSION").to_string();
    output.push_str("\n\n");
    pretty.display(&mut cursor).unwrap();
    output += &String::from_utf8_lossy(cursor.get_ref());
    output
});

#[derive(Clone, CopyGetters, Debug, Getters, Parser)]
#[command(author, version, about, long_version = LONG_VERSION.as_str(), long_about = None)]
pub(crate) struct Cli {
    /// Set logging verbosity.  More v's, more verbose.
    #[clap(
        short,
        long,
        action = ArgAction::Count,
        help = "Turn up logging verbosity (multiple will turn it up more)",
        conflicts_with = "quiet",
    )]
    #[getset(get_copy = "pub(crate)")]
    verbose: u8,
    /// Set logging quietness.  More q's, more quiet.
    #[clap(
        short,
        long,
        action = ArgAction::Count,
        help = "Turn down logging verbosity (multiple will turn it down more)",
        conflicts_with = "verbose",
    )]
    #[getset(get_copy = "pub(crate)")]
    quiet: u8,
    /// The absolute path to a non-standard config file
    #[clap(short, long, help = "Specify the absolute path to the config file")]
    #[getset(get = "pub(crate)")]
    config_absolute_path: Option<String>,
    /// The absolute path to a non-standard tracing output file
    #[clap(
        short,
        long,
        help = "Specify the absolute path to the tracing output file"
    )]
    #[getset(get = "pub(crate)")]
    tracing_absolute_path: Option<String>,
    /// An absolute path to a non-standard private key file
    #[clap(
        short,
        long,
        help = "Specify the absolute path to the private key file"
    )]
    #[getset(get = "pub(crate)")]
    private_key_path: Option<String>,
    /// An absolute path to a non-standard public key file
    #[clap(
        short = 'k',
        long,
        help = "Specify the absolute path to the public key file"
    )]
    #[getset(get = "pub(crate)")]
    public_key_path: Option<String>,
    /// An optional port number for the server to connect to
    /// defaults to 40404
    #[clap(
        short,
        long,
        help = "The port number of the server to connect to (default: 40404)",
        default_value_t = 40404
    )]
    #[getset(get_copy = "pub(crate)")]
    server_port: u16,
    /// The destination of the server to connect to
    /// This takes the form of 'user@ip address' where the user is optional
    /// and will default to the user executing the command.
    #[clap(help = "The IP address of the server to connect to")]
    #[getset(get = "pub(crate)")]
    server_destination: String,
    /// Local-echo prediction preference: adaptive (default), always, or never.
    #[clap(
        long,
        value_name = "MODE",
        default_value = "adaptive",
        help = "Local-echo prediction: adaptive (default), always, or never"
    )]
    #[getset(get = "pub(crate)")]
    predict: String,
    /// Send warmup keepalives before the UDP session starts to establish
    /// a bidirectional NAT binding before bulk terminal data flows.
    /// Only useful on NAT paths; adds one round-trip of startup latency.
    #[clap(
        long,
        help = "Send NAT warmup keepalives at UDP session start (opt-in)"
    )]
    #[getset(get_copy = "pub(crate)")]
    nat_warmup: bool,
    /// Number of keepalive frames to send during NAT warmup (default: 3).
    #[clap(
        long,
        value_name = "N",
        default_value_t = 3,
        help = "Number of NAT warmup keepalives to send (default: 3)"
    )]
    #[getset(get_copy = "pub(crate)")]
    nat_warmup_count: u32,
    /// UDP diff transport mode.
    ///
    /// `reliable` (default): NAK-based selective retransmission — best for
    /// low-loss networks where retransmit rarely fires.
    ///
    /// `datagram`: fire-and-forget diffs with no retransmission; the server
    /// sends a periodic full-screen snapshot for recovery instead.  Eliminates
    /// head-of-line blocking on flaky or high-loss connections.
    ///
    /// `statesync`: Mosh-style ack-based diffs; the server always sends
    /// `contents_diff(ack_state → current)` so each packet is self-contained.
    /// No NAKs, no reorder buffer.  Best for moderate-loss, low-bandwidth links.
    #[clap(
        long,
        value_name = "MODE",
        default_value = "reliable",
        help = "UDP diff transport mode: reliable (default), datagram, or statesync"
    )]
    #[getset(get = "pub(crate)")]
    diff_mode: String,
}

impl Source for Cli {
    fn clone_into_box(&self) -> Box<dyn Source + Send + Sync> {
        Box::new((*self).clone())
    }

    fn collect(&self) -> Result<Map<String, Value>, ConfigError> {
        let mut map = Map::new();
        let origin = String::from("command line");
        let _old = map.insert(
            "verbose".to_string(),
            Value::new(Some(&origin), ValueKind::U64(u8::into(self.verbose))),
        );
        let _old = map.insert(
            "quiet".to_string(),
            Value::new(Some(&origin), ValueKind::U64(u8::into(self.quiet))),
        );
        if let Some(config_path) = &self.config_absolute_path {
            let _old = map.insert(
                "config_path".to_string(),
                Value::new(Some(&origin), ValueKind::String(config_path.clone())),
            );
        }
        if let Some(tracing_path) = &self.tracing_absolute_path {
            let _old = map.insert(
                "tracing_path".to_string(),
                Value::new(Some(&origin), ValueKind::String(tracing_path.clone())),
            );
        }
        if let Some(private_key_path) = &self.private_key_path {
            let _old = map.insert(
                "private_key_path".to_string(),
                Value::new(Some(&origin), ValueKind::String(private_key_path.clone())),
            );
        }
        if let Some(public_key_path) = &self.public_key_path {
            let _old = map.insert(
                "public_key_path".to_string(),
                Value::new(Some(&origin), ValueKind::String(public_key_path.clone())),
            );
        }
        let _old = map.insert(
            "server_port".to_string(),
            Value::new(Some(&origin), ValueKind::U64(u16::into(self.server_port))),
        );
        let _old = map.insert(
            "server_destination".to_string(),
            Value::new(
                Some(&origin),
                ValueKind::String(self.server_destination.clone()),
            ),
        );
        let _old = map.insert(
            "predict".to_string(),
            Value::new(Some(&origin), ValueKind::String(self.predict.clone())),
        );
        let _old = map.insert(
            "nat_warmup".to_string(),
            Value::new(Some(&origin), ValueKind::Boolean(self.nat_warmup)),
        );
        let _old = map.insert(
            "nat_warmup_count".to_string(),
            Value::new(
                Some(&origin),
                ValueKind::U64(u32::into(self.nat_warmup_count)),
            ),
        );
        let _old = map.insert(
            "diff_mode".to_string(),
            Value::new(Some(&origin), ValueKind::String(self.diff_mode.clone())),
        );
        Ok(map)
    }
}

impl PathDefaults for Cli {
    fn env_prefix(&self) -> String {
        env!("CARGO_PKG_NAME").to_ascii_uppercase()
    }

    fn config_absolute_path(&self) -> Option<String> {
        self.config_absolute_path.clone()
    }

    fn default_file_path(&self) -> String {
        env!("CARGO_PKG_NAME").to_string()
    }

    fn default_file_name(&self) -> String {
        env!("CARGO_PKG_NAME").to_string()
    }

    fn tracing_absolute_path(&self) -> Option<String> {
        self.tracing_absolute_path.clone()
    }

    fn default_tracing_path(&self) -> String {
        format!("{}/logs", env!("CARGO_PKG_NAME"))
    }

    fn default_tracing_file_name(&self) -> String {
        env!("CARGO_PKG_NAME").to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cli_defaults() {
        let cli = Cli::try_parse_from(["moshpit", "user@host"]).unwrap();
        assert_eq!(cli.verbose(), 0);
        assert_eq!(cli.quiet(), 0);
        assert_eq!(cli.config_absolute_path(), &None);
        assert_eq!(cli.tracing_absolute_path(), &None);
        assert_eq!(cli.private_key_path(), &None);
        assert_eq!(cli.public_key_path(), &None);
        assert_eq!(cli.server_port(), 40404);
        assert_eq!(cli.server_destination(), "user@host");
        assert_eq!(cli.predict(), "adaptive");
    }

    #[test]
    fn test_cli_parsing() {
        let cli = Cli::try_parse_from([
            "moshpit",
            "-vv",
            "-c",
            "/tmp/config",
            "-t",
            "/tmp/trace",
            "-p",
            "/tmp/priv",
            "-k",
            "/tmp/pub",
            "-s",
            "1234",
            "--predict",
            "always",
            "admin@10.0.0.1",
        ])
        .unwrap();
        assert_eq!(cli.verbose(), 2);
        assert_eq!(cli.quiet(), 0);
        assert_eq!(cli.config_absolute_path().as_deref(), Some("/tmp/config"));
        assert_eq!(cli.tracing_absolute_path().as_deref(), Some("/tmp/trace"));
        assert_eq!(cli.private_key_path().as_deref(), Some("/tmp/priv"));
        assert_eq!(cli.public_key_path().as_deref(), Some("/tmp/pub"));
        assert_eq!(cli.server_port(), 1234);
        assert_eq!(cli.server_destination(), "admin@10.0.0.1");
        assert_eq!(cli.predict(), "always");
    }

    #[test]
    fn test_cli_quiet() {
        let cli = Cli::try_parse_from(["moshpit", "-qqq", "host"]).unwrap();
        assert_eq!(cli.quiet(), 3);
        assert_eq!(cli.verbose(), 0);
    }

    #[test]
    fn test_source_impl() {
        let cli = Cli::try_parse_from(["moshpit", "host"]).unwrap();
        let map = cli.collect().unwrap();

        assert!(matches!(
            map.get("verbose").unwrap().kind,
            ValueKind::U64(0)
        ));
        assert!(matches!(map.get("quiet").unwrap().kind, ValueKind::U64(0)));
        assert!(matches!(
            map.get("server_port").unwrap().kind,
            ValueKind::U64(40404)
        ));

        if let ValueKind::String(ref s) = map.get("server_destination").unwrap().kind {
            assert_eq!(s, "host");
        } else {
            panic!("Expected String");
        }

        if let ValueKind::String(ref s) = map.get("predict").unwrap().kind {
            assert_eq!(s, "adaptive");
        } else {
            panic!("Expected String");
        }

        assert!(!map.contains_key("config_path"));

        let boxed = cli.clone_into_box();
        let map2 = boxed.collect().unwrap();
        if let ValueKind::String(ref s) = map2.get("server_destination").unwrap().kind {
            assert_eq!(s, "host");
        } else {
            panic!("Expected String");
        }
    }

    #[test]
    fn test_source_impl_with_options() {
        let cli = Cli::try_parse_from([
            "moshpit", "-c", "cfg", "-t", "trc", "-p", "prv", "-k", "pub", "host",
        ])
        .unwrap();
        let map = cli.collect().unwrap();

        if let ValueKind::String(ref s) = map.get("config_path").unwrap().kind {
            assert_eq!(s, "cfg");
        } else {
            panic!("Expected String");
        }

        if let ValueKind::String(ref s) = map.get("tracing_path").unwrap().kind {
            assert_eq!(s, "trc");
        } else {
            panic!("Expected String");
        }

        if let ValueKind::String(ref s) = map.get("private_key_path").unwrap().kind {
            assert_eq!(s, "prv");
        } else {
            panic!("Expected String");
        }

        if let ValueKind::String(ref s) = map.get("public_key_path").unwrap().kind {
            assert_eq!(s, "pub");
        } else {
            panic!("Expected String");
        }
    }

    #[test]
    fn test_path_defaults() {
        let cli = Cli::try_parse_from(["moshpit", "-c", "cfg", "-t", "trc", "host"]).unwrap();
        assert_eq!(cli.env_prefix(), "MOSHPIT");
        assert_eq!(cli.config_absolute_path().as_deref(), Some("cfg"));
        assert_eq!(cli.default_file_path(), "moshpit");
        assert_eq!(cli.default_file_name(), "moshpit");
        assert_eq!(cli.tracing_absolute_path().as_deref(), Some("trc"));
        assert_eq!(cli.default_tracing_path(), "moshpit/logs");
        assert_eq!(cli.default_tracing_file_name(), "moshpit");
    }
}
