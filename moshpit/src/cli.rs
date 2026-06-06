// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

use std::{collections::BTreeSet, ffi::OsString, io::Cursor, sync::LazyLock};

use clap::{ArgMatches, CommandFactory, Parser, Subcommand, parser::ValueSource};
use config::{ConfigError, Map, Source, Value, ValueKind};
use getset::{CopyGetters, Getters};
use libmoshpit::PathDefaults;
use vergen_pretty::{Pretty, vergen_pretty_env};

static LONG_VERSION: LazyLock<String> = LazyLock::new(|| {
    let pretty = Pretty::builder().env(vergen_pretty_env!()).build();
    let mut cursor = Cursor::new(vec![]);
    let mut output = env!("CARGO_PKG_VERSION").to_string();
    output.push_str("\n\n");
    pretty
        .display(&mut cursor)
        .expect("writing to Vec never fails");
    output += &String::from_utf8_lossy(cursor.get_ref());
    output
});

/// Client subcommands.  When absent, `mp` runs the connect flow against the
/// `server_destination` positional.
#[derive(Clone, Debug, Subcommand)]
pub(crate) enum Commands {
    /// Print the fully-resolved effective configuration and the source of each value.
    ///
    /// Resolution flags (`-c`, `-t`, `-p`, `-k`, value flags, …) must be supplied
    /// before the subcommand, e.g. `mp -c /path/to/config.toml ec`.
    Ec {
        /// Emit machine-readable JSON instead of a colored table.
        #[clap(long, help = "Emit machine-readable JSON instead of a table")]
        json: bool,
    },
}

#[derive(Clone, CopyGetters, Debug, Getters, Parser)]
#[command(author, version, about, long_version = LONG_VERSION.as_str(), long_about = None)]
pub(crate) struct Cli {
    /// Optional subcommand.  When `None`, the connect flow runs.
    #[command(subcommand)]
    #[getset(get = "pub(crate)")]
    command: Option<Commands>,
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
    ///
    /// Optional at the parse level so subcommands (e.g. `ec`) can run without a
    /// destination; the connect flow validates that it is present.
    #[clap(help = "The IP address of the server to connect to")]
    #[getset(get = "pub(crate)")]
    server_destination: Option<String>,
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
    /// Legacy escape hatch: forward raw server PTY bytes straight to the
    /// terminal instead of rendering exclusively through the differential
    /// renderer.  Off by default; enable only if the rendered path regresses.
    #[clap(
        long,
        help = "Forward raw server bytes to the terminal (legacy; disables unified rendering)"
    )]
    #[getset(get_copy = "pub(crate)")]
    legacy_passthrough: bool,
    /// Ordered KEX algorithms to offer (comma-separated).
    /// Example: `--kex-algos ml-kem-768-sha256,x25519-sha256`
    #[clap(
        long,
        value_name = "ALGOS",
        help = "Ordered KEX algorithms to offer, comma-separated [supported: x25519-sha256 (default), ml-kem-768-sha256, ml-kem-512-sha256, ml-kem-1024-sha256, p384-sha384, p256-sha256]"
    )]
    #[getset(get = "pub(crate)")]
    kex_algos: Option<String>,
    /// Ordered AEAD algorithms to offer (comma-separated).
    /// Example: `--aead-algos chacha20-poly1305,aes256-gcm-siv`
    #[clap(
        long,
        value_name = "ALGOS",
        help = "Ordered AEAD algorithms to offer, comma-separated [supported: aes256-gcm-siv (default), aes256-gcm, chacha20-poly1305, aes128-gcm-siv]"
    )]
    #[getset(get = "pub(crate)")]
    aead_algos: Option<String>,
    /// Ordered MAC algorithms to offer (comma-separated).
    /// Example: `--mac-algos hmac-sha256`
    #[clap(
        long,
        value_name = "ALGOS",
        help = "Ordered MAC algorithms to offer, comma-separated [supported: hmac-sha512 (default), hmac-sha256]"
    )]
    #[getset(get = "pub(crate)")]
    mac_algos: Option<String>,
    /// Ordered KDF algorithms to offer (comma-separated).
    /// Example: `--kdf-algos hkdf-sha512`
    #[clap(
        long,
        value_name = "ALGOS",
        help = "Ordered KDF algorithms to offer, comma-separated [supported: hkdf-sha256 (default), hkdf-sha384, hkdf-sha512]"
    )]
    #[getset(get = "pub(crate)")]
    kdf_algos: Option<String>,
    /// Set of clap argument ids the user actually supplied on the command line
    /// (`ValueSource::CommandLine`), populated by [`Cli::parse_argv`].  This is
    /// the source of truth for "came from the command line": it lets
    /// [`Source::collect`] emit only user-provided values (so clap defaults no
    /// longer clobber the config file / environment) and powers the `ec`
    /// command's provenance column.  Not a real CLI argument.
    #[clap(skip)]
    #[getset(get = "pub(crate)")]
    explicit_args: BTreeSet<String>,
}

impl Cli {
    /// Parse `argv` into a [`Cli`], recording which arguments the user actually
    /// supplied on the command line.
    ///
    /// clap's derived struct cannot distinguish a value the user typed from a
    /// `default_value`, so we parse twice: once into the typed struct and once
    /// into raw [`ArgMatches`], whose [`ValueSource`] reveals the true origin of
    /// each argument.  The resulting [`Cli::explicit_args`] set drives
    /// [`Source::collect`] (so clap defaults no longer clobber the config file or
    /// environment) and the `ec` command's provenance column.
    ///
    /// # Errors
    /// Returns a clap error if `argv` fails to parse.
    pub(crate) fn parse_argv<I, T>(argv: I) -> clap::error::Result<Self>
    where
        I: IntoIterator<Item = T> + Clone,
        T: Into<OsString> + Clone,
    {
        let mut cli = Cli::try_parse_from(argv.clone())?;
        // Fully-qualified: the `command` field's getset getter shadows the
        // inherent `Cli::command()` provided by `CommandFactory`.
        let matches = <Cli as CommandFactory>::command().try_get_matches_from(argv)?;
        cli.explicit_args = explicit_command_line_ids(&matches);
        Ok(cli)
    }
}

/// Collect the ids of all top-level arguments whose value originated from the
/// command line (as opposed to a default value or being unset).
fn explicit_command_line_ids(matches: &ArgMatches) -> BTreeSet<String> {
    matches
        .ids()
        .filter(|id| matches.value_source(id.as_str()) == Some(ValueSource::CommandLine))
        .map(|id| id.as_str().to_string())
        .collect()
}

fn build_algo_table(
    kex: Option<&str>,
    aead: Option<&str>,
    mac: Option<&str>,
    kdf: Option<&str>,
) -> Option<Map<String, Value>> {
    let mut table = Map::new();
    let parse = |s: &str| -> Vec<Value> {
        s.split(',')
            .map(|a| Value::new(None, ValueKind::String(a.trim().to_string())))
            .collect()
    };
    for (key, opt) in [("kex", kex), ("aead", aead), ("mac", mac), ("kdf", kdf)] {
        if let Some(s) = opt {
            let _old = table.insert(
                key.to_string(),
                Value::new(None, ValueKind::Array(parse(s))),
            );
        }
    }
    (!table.is_empty()).then_some(table)
}

impl Source for Cli {
    fn clone_into_box(&self) -> Box<dyn Source + Send + Sync> {
        Box::new((*self).clone())
    }

    fn collect(&self) -> Result<Map<String, Value>, ConfigError> {
        let mut map = Map::new();
        let origin = String::from("command line");
        // Only emit values the user actually typed on the command line.  Without
        // this gate, clap's `default_value`s would be emitted here and override
        // the config file and environment (see `parse_argv` / `explicit_args`).
        let on = |id: &str| self.explicit_args.contains(id);

        if on("config_absolute_path")
            && let Some(config_path) = &self.config_absolute_path
        {
            let _old = map.insert(
                "config_path".to_string(),
                Value::new(Some(&origin), ValueKind::String(config_path.clone())),
            );
        }
        if on("tracing_absolute_path")
            && let Some(tracing_path) = &self.tracing_absolute_path
        {
            let _old = map.insert(
                "tracing_path".to_string(),
                Value::new(Some(&origin), ValueKind::String(tracing_path.clone())),
            );
        }
        if on("private_key_path")
            && let Some(private_key_path) = &self.private_key_path
        {
            let _old = map.insert(
                "private_key_path".to_string(),
                Value::new(Some(&origin), ValueKind::String(private_key_path.clone())),
            );
        }
        if on("public_key_path")
            && let Some(public_key_path) = &self.public_key_path
        {
            let _old = map.insert(
                "public_key_path".to_string(),
                Value::new(Some(&origin), ValueKind::String(public_key_path.clone())),
            );
        }
        if on("server_port") {
            let _old = map.insert(
                "server_port".to_string(),
                Value::new(Some(&origin), ValueKind::U64(u16::into(self.server_port))),
            );
        }
        if on("server_destination")
            && let Some(server_destination) = &self.server_destination
        {
            let _old = map.insert(
                "server_destination".to_string(),
                Value::new(Some(&origin), ValueKind::String(server_destination.clone())),
            );
        }
        if on("predict") {
            let _old = map.insert(
                "predict".to_string(),
                Value::new(Some(&origin), ValueKind::String(self.predict.clone())),
            );
        }
        if on("nat_warmup") {
            let _old = map.insert(
                "nat_warmup".to_string(),
                Value::new(Some(&origin), ValueKind::Boolean(self.nat_warmup)),
            );
        }
        if on("nat_warmup_count") {
            let _old = map.insert(
                "nat_warmup_count".to_string(),
                Value::new(
                    Some(&origin),
                    ValueKind::U64(u32::into(self.nat_warmup_count)),
                ),
            );
        }
        if on("diff_mode") {
            let _old = map.insert(
                "diff_mode".to_string(),
                Value::new(Some(&origin), ValueKind::String(self.diff_mode.clone())),
            );
        }
        if on("legacy_passthrough") {
            let _old = map.insert(
                "legacy_passthrough".to_string(),
                Value::new(Some(&origin), ValueKind::Boolean(self.legacy_passthrough)),
            );
        }
        if let Some(table) = build_algo_table(
            self.kex_algos.as_deref().filter(|_| on("kex_algos")),
            self.aead_algos.as_deref().filter(|_| on("aead_algos")),
            self.mac_algos.as_deref().filter(|_| on("mac_algos")),
            self.kdf_algos.as_deref().filter(|_| on("kdf_algos")),
        ) {
            let _old = map.insert(
                "preferred_algorithms".to_string(),
                Value::new(Some(&origin), ValueKind::Table(table)),
            );
        }
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
    fn test_cli_defaults() -> anyhow::Result<()> {
        let cli = Cli::parse_argv(["moshpit", "user@host"])?;
        assert_eq!(cli.config_absolute_path(), &None);
        assert_eq!(cli.tracing_absolute_path(), &None);
        assert_eq!(cli.private_key_path(), &None);
        assert_eq!(cli.public_key_path(), &None);
        assert_eq!(cli.server_port(), 40404);
        assert_eq!(cli.server_destination().as_deref(), Some("user@host"));
        assert_eq!(cli.predict(), "adaptive");
        assert!(cli.command().is_none());
        // Only the positional was supplied; defaulted flags are not "explicit".
        assert!(cli.explicit_args().contains("server_destination"));
        assert!(!cli.explicit_args().contains("server_port"));
        Ok(())
    }

    #[test]
    fn test_cli_parsing() -> anyhow::Result<()> {
        let cli = Cli::parse_argv([
            "moshpit",
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
        ])?;
        assert_eq!(cli.config_absolute_path().as_deref(), Some("/tmp/config"));
        assert_eq!(cli.tracing_absolute_path().as_deref(), Some("/tmp/trace"));
        assert_eq!(cli.private_key_path().as_deref(), Some("/tmp/priv"));
        assert_eq!(cli.public_key_path().as_deref(), Some("/tmp/pub"));
        assert_eq!(cli.server_port(), 1234);
        assert_eq!(cli.server_destination().as_deref(), Some("admin@10.0.0.1"));
        assert_eq!(cli.predict(), "always");
        assert!(cli.command().is_none());
        Ok(())
    }

    #[test]
    fn test_ec_subcommand_parses() -> anyhow::Result<()> {
        let cli = Cli::parse_argv(["moshpit", "ec"])?;
        assert!(matches!(cli.command(), Some(Commands::Ec { json: false })));
        assert_eq!(cli.server_destination().as_deref(), None);
        Ok(())
    }

    #[test]
    fn test_ec_subcommand_json_flag() -> anyhow::Result<()> {
        let cli = Cli::parse_argv(["moshpit", "ec", "--json"])?;
        assert!(matches!(cli.command(), Some(Commands::Ec { json: true })));
        Ok(())
    }

    #[test]
    fn test_ec_with_global_flags() -> anyhow::Result<()> {
        // Resolution flags must precede the subcommand.
        let cli = Cli::parse_argv(["moshpit", "-c", "/tmp/c", "ec"])?;
        assert_eq!(cli.config_absolute_path().as_deref(), Some("/tmp/c"));
        assert!(matches!(cli.command(), Some(Commands::Ec { .. })));
        Ok(())
    }

    #[test]
    fn test_ec_rejects_destination() {
        // `ec` and a connect destination are mutually exclusive.
        assert!(Cli::parse_argv(["moshpit", "ec", "user@host"]).is_err());
    }

    #[test]
    fn test_connect_still_parses() -> anyhow::Result<()> {
        let cli = Cli::parse_argv(["moshpit", "user@host"])?;
        assert!(cli.command().is_none());
        assert_eq!(cli.server_destination().as_deref(), Some("user@host"));
        Ok(())
    }

    #[test]
    fn test_source_impl() -> anyhow::Result<()> {
        // Explicitly-set values are emitted; defaulted values (e.g. predict) are not.
        let cli = Cli::parse_argv(["moshpit", "-s", "1234", "host"])?;
        let map = cli.collect()?;

        assert!(matches!(
            map.get("server_port")
                .ok_or_else(|| anyhow::anyhow!("\"server_port\" not found in map"))?
                .kind,
            ValueKind::U64(1234)
        ));

        if let ValueKind::String(ref s) = map
            .get("server_destination")
            .ok_or_else(|| anyhow::anyhow!("\"server_destination\" not found in map"))?
            .kind
        {
            assert_eq!(s, "host");
        } else {
            panic!("Expected String");
        }

        // `predict` was not supplied, so it must NOT be emitted (no clap-default
        // pollution that would clobber the config file / environment).
        assert!(!map.contains_key("predict"));
        assert!(!map.contains_key("config_path"));

        let boxed = cli.clone_into_box();
        let map2 = boxed.collect()?;
        if let ValueKind::String(ref s) = map2
            .get("server_destination")
            .ok_or_else(|| anyhow::anyhow!("\"server_destination\" not found in map2"))?
            .kind
        {
            assert_eq!(s, "host");
        } else {
            panic!("Expected String");
        }
        Ok(())
    }

    #[test]
    fn test_source_impl_omits_defaults() -> anyhow::Result<()> {
        // With only the positional supplied, no defaulted flag leaks into the map.
        let cli = Cli::parse_argv(["moshpit", "host"])?;
        let map = cli.collect()?;
        assert!(map.contains_key("server_destination"));
        assert!(!map.contains_key("server_port"));
        assert!(!map.contains_key("predict"));
        assert!(!map.contains_key("diff_mode"));
        Ok(())
    }

    #[test]
    fn test_source_impl_with_options() -> anyhow::Result<()> {
        let cli = Cli::parse_argv([
            "moshpit", "-c", "cfg", "-t", "trc", "-p", "prv", "-k", "pub", "host",
        ])?;
        let map = cli.collect()?;

        if let ValueKind::String(ref s) = map
            .get("config_path")
            .ok_or_else(|| anyhow::anyhow!("\"config_path\" not found in map"))?
            .kind
        {
            assert_eq!(s, "cfg");
        } else {
            panic!("Expected String");
        }

        if let ValueKind::String(ref s) = map
            .get("tracing_path")
            .ok_or_else(|| anyhow::anyhow!("\"tracing_path\" not found in map"))?
            .kind
        {
            assert_eq!(s, "trc");
        } else {
            panic!("Expected String");
        }

        if let ValueKind::String(ref s) = map
            .get("private_key_path")
            .ok_or_else(|| anyhow::anyhow!("\"private_key_path\" not found in map"))?
            .kind
        {
            assert_eq!(s, "prv");
        } else {
            panic!("Expected String");
        }

        if let ValueKind::String(ref s) = map
            .get("public_key_path")
            .ok_or_else(|| anyhow::anyhow!("\"public_key_path\" not found in map"))?
            .kind
        {
            assert_eq!(s, "pub");
        } else {
            panic!("Expected String");
        }
        Ok(())
    }

    #[test]
    fn collect_emits_all_explicit_value_flags() -> anyhow::Result<()> {
        let cli = Cli::parse_argv([
            "moshpit",
            "--predict",
            "always",
            "--nat-warmup",
            "--nat-warmup-count",
            "5",
            "--diff-mode",
            "datagram",
            "--legacy-passthrough",
            "host",
        ])?;
        let map = cli.collect()?;
        assert!(map.contains_key("nat_warmup"));
        assert!(map.contains_key("nat_warmup_count"));
        assert!(map.contains_key("legacy_passthrough"));
        if let ValueKind::String(ref s) = map
            .get("predict")
            .ok_or_else(|| anyhow::anyhow!("\"predict\" not found in map"))?
            .kind
        {
            assert_eq!(s, "always");
        } else {
            panic!("Expected String for predict");
        }
        if let ValueKind::String(ref s) = map
            .get("diff_mode")
            .ok_or_else(|| anyhow::anyhow!("\"diff_mode\" not found in map"))?
            .kind
        {
            assert_eq!(s, "datagram");
        } else {
            panic!("Expected String for diff_mode");
        }
        Ok(())
    }

    #[test]
    fn collect_emits_algo_table() -> anyhow::Result<()> {
        // Surrounding spaces exercise the `trim` in the parse closure.
        let cli = Cli::parse_argv([
            "moshpit",
            "--kex-algos",
            "x25519-sha256, ml-kem-768-sha256",
            "--aead-algos",
            "aes256-gcm-siv",
            "--mac-algos",
            "hmac-sha512",
            "--kdf-algos",
            "hkdf-sha256",
            "host",
        ])?;
        let map = cli.collect()?;
        if let ValueKind::Table(ref table) = map
            .get("preferred_algorithms")
            .ok_or_else(|| anyhow::anyhow!("\"preferred_algorithms\" not found in map"))?
            .kind
        {
            assert!(table.contains_key("kex"));
            assert!(table.contains_key("aead"));
            assert!(table.contains_key("mac"));
            assert!(table.contains_key("kdf"));
        } else {
            panic!("Expected Table for preferred_algorithms");
        }
        Ok(())
    }

    #[test]
    fn test_path_defaults() -> anyhow::Result<()> {
        let cli = Cli::try_parse_from(["moshpit", "-c", "cfg", "-t", "trc", "host"])?;
        assert_eq!(cli.env_prefix(), "MOSHPIT");
        assert_eq!(cli.config_absolute_path().as_deref(), Some("cfg"));
        assert_eq!(cli.default_file_path(), "moshpit");
        assert_eq!(cli.default_file_name(), "moshpit");
        assert_eq!(cli.tracing_absolute_path().as_deref(), Some("trc"));
        assert_eq!(cli.default_tracing_path(), "moshpit/logs");
        assert_eq!(cli.default_tracing_file_name(), "moshpit");
        Ok(())
    }
}
