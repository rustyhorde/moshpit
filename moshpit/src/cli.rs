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
