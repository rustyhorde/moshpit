// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

//! `mp ec` — render the fully-resolved client configuration with the provenance
//! (source) of each value: `config file`, `command line`, `environment`, or
//! `default`.
//!
//! The displayed *values* come from the real merged [`Config`], so they match
//! exactly what the connect path uses.  The *source* of each value is derived
//! independently from three signals and combined with the same precedence the
//! client loader applies (`crate::config::load`): environment overrides command
//! line overrides config file (`env > CLI > file`).
//!
//! Runtime-derived fields are intentionally excluded — they are not sourced from
//! the config file, CLI, or environment and have no meaningful provenance:
//! `mode` and `user` (`#[serde(skip_deserializing)]`, derived at connect time)
//! and `resume_session_uuid` (`#[serde(skip)]`, read from disk per session).

use std::{collections::BTreeSet, io::IsTerminal as _, path::Path};

use libmoshpit::{KexConfig as _, PathDefaults as _};
use serde::Serialize;

use crate::{cli::Cli, config::Config};

/// Where a resolved configuration value came from.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Origin {
    /// Supplied on the command line.
    CommandLine,
    /// Supplied via a `MOSHPIT_*` environment variable.
    Environment,
    /// Read from the TOML config file.
    ConfigFile,
    /// No source provided it; the built-in default applies.
    Default,
}

impl Origin {
    /// The plain-text label shown in the `SOURCE` column / JSON output.
    fn label(self) -> &'static str {
        match self {
            Origin::CommandLine => "command line",
            Origin::Environment => "environment",
            Origin::ConfigFile => "config file",
            Origin::Default => "default",
        }
    }

    /// The label wrapped in an ANSI color for terminal output.
    fn colored(self) -> String {
        use crossterm::style::Stylize as _;
        match self {
            Origin::CommandLine => self.label().cyan().to_string(),
            Origin::Environment => self.label().yellow().to_string(),
            Origin::ConfigFile => self.label().green().to_string(),
            Origin::Default => self.label().dark_grey().to_string(),
        }
    }
}

/// One row of the effective-config listing.
#[derive(Clone, Debug)]
pub(crate) struct EffectiveRow {
    field: String,
    value: String,
    origin: Origin,
}

/// Serializable view of a row for `--json` (renames `origin` → `source`).
#[derive(Serialize)]
struct JsonRow<'a> {
    field: &'a str,
    value: &'a str,
    source: &'a str,
}

/// Combine the three provenance signals using the loader's precedence
/// (`env > CLI > file`, matching `crate::config::load`'s source order).
fn classify(from_env: bool, from_cli: bool, from_file: bool) -> Origin {
    if from_env {
        Origin::Environment
    } else if from_cli {
        Origin::CommandLine
    } else if from_file {
        Origin::ConfigFile
    } else {
        Origin::Default
    }
}

/// Top-level keys (and one nested level, e.g. `preferred_algorithms.kex`)
/// actually present in the TOML config file.  A missing or unparseable file
/// yields an empty set — exactly matching the loader, where an absent file
/// contributes nothing.
fn toml_keys(path: &Path) -> BTreeSet<String> {
    let mut keys = BTreeSet::new();
    let Ok(text) = std::fs::read_to_string(path) else {
        return keys;
    };
    let Ok(table) = text.parse::<toml::Table>() else {
        return keys;
    };
    for (key, value) in &table {
        let _ = keys.insert(key.clone());
        if let toml::Value::Table(sub) = value {
            for sub_key in sub.keys() {
                let _ = keys.insert(format!("{key}.{sub_key}"));
            }
        }
    }
    keys
}

/// Render a value enum (e.g. `DisplayPreference`, `DiffMode`) as its bare
/// serialized token, stripping the JSON string quotes.
fn token<T: Serialize>(value: &T) -> String {
    serde_json::to_string(value).map_or_else(
        |_| "<unserializable>".to_string(),
        |s| s.trim_matches('"').to_string(),
    )
}

/// Display an optional value, or `<unset>` when absent.
fn opt(value: Option<&str>) -> String {
    value.map_or_else(|| "<unset>".to_string(), ToString::to_string)
}

/// Display a string list comma-joined, or `<empty>` when empty.
fn list(value: &[String]) -> String {
    if value.is_empty() {
        "<empty>".to_string()
    } else {
        value.join(", ")
    }
}

/// Shared inputs used to derive each row's provenance.
struct Ctx<'a> {
    cli: &'a Cli,
    toml: &'a BTreeSet<String>,
    prefix: &'a str,
}

impl Ctx<'_> {
    /// Build a single [`EffectiveRow`], computing provenance from the explicit
    /// CLI args, the `MOSHPIT_*` environment, and the config-file keys.  Pass
    /// `None` for any signal that cannot set the field (e.g. no CLI flag).
    fn row(
        &self,
        field: &str,
        value: String,
        clap_id: Option<&str>,
        env_suffix: Option<&str>,
        toml_key: Option<&str>,
    ) -> EffectiveRow {
        let from_env =
            env_suffix.is_some_and(|s| std::env::var_os(format!("{}_{s}", self.prefix)).is_some());
        let from_cli = clap_id.is_some_and(|id| self.cli.explicit_args().contains(id));
        let from_file = toml_key.is_some_and(|k| self.toml.contains(k));
        EffectiveRow {
            field: field.to_string(),
            value,
            origin: classify(from_env, from_cli, from_file),
        }
    }
}

/// Resolve every listed config value alongside its source.
///
/// `config` provides the displayed values (so they match runtime exactly);
/// `config_path` is the resolved config-file location used both as an
/// informational row and to detect which keys the file actually sets.
///
/// Path rows (`config_path`, `tracing_path`) consult only the CLI flag and the
/// default — path resolution never reads the environment.  The
/// `preferred_algorithms.*` rows and the list fields (`send_env`, `send_path`)
/// are not settable via a single env var, so they pass `None` for the env
/// signal.
#[allow(clippy::too_many_lines)] // a flat enumeration of every config field
pub(crate) fn resolve_effective(
    cli: &Cli,
    config: &Config,
    config_path: &Path,
) -> Vec<EffectiveRow> {
    let toml = toml_keys(config_path);
    let prefix = cli.env_prefix();
    let ctx = Ctx {
        cli,
        toml: &toml,
        prefix: &prefix,
    };
    let algos = config.preferred_algorithms();
    let destination = if config.server_destination().is_empty() {
        "<unset>".to_string()
    } else {
        config.server_destination().clone()
    };
    let tracing = serde_json::to_string(config.tracing().file())
        .unwrap_or_else(|_| "<unserializable>".to_string());

    vec![
        ctx.row(
            "config_path",
            config_path.display().to_string(),
            Some("config_absolute_path"),
            None,
            None,
        ),
        ctx.row(
            "tracing_path",
            opt(cli.tracing_absolute_path().as_deref()),
            Some("tracing_absolute_path"),
            None,
            None,
        ),
        ctx.row(
            "server_destination",
            destination,
            Some("server_destination"),
            Some("SERVER_DESTINATION"),
            Some("server_destination"),
        ),
        ctx.row(
            "server_port",
            config.server_port().to_string(),
            Some("server_port"),
            Some("SERVER_PORT"),
            Some("server_port"),
        ),
        ctx.row(
            "private_key_path",
            opt(config.private_key_path().as_deref()),
            Some("private_key_path"),
            Some("PRIVATE_KEY_PATH"),
            Some("private_key_path"),
        ),
        ctx.row(
            "public_key_path",
            opt(config.public_key_path().as_deref()),
            Some("public_key_path"),
            Some("PUBLIC_KEY_PATH"),
            Some("public_key_path"),
        ),
        ctx.row(
            "max_reconnect_backoff_secs",
            config.max_reconnect_backoff_secs().to_string(),
            None,
            Some("MAX_RECONNECT_BACKOFF_SECS"),
            Some("max_reconnect_backoff_secs"),
        ),
        ctx.row(
            "predict",
            token(&config.predict()),
            Some("predict"),
            Some("PREDICT"),
            Some("predict"),
        ),
        ctx.row(
            "nat_warmup",
            config.nat_warmup().to_string(),
            Some("nat_warmup"),
            Some("NAT_WARMUP"),
            Some("nat_warmup"),
        ),
        ctx.row(
            "nat_warmup_count",
            config.nat_warmup_count().to_string(),
            Some("nat_warmup_count"),
            Some("NAT_WARMUP_COUNT"),
            Some("nat_warmup_count"),
        ),
        ctx.row(
            "diff_mode",
            token(&config.diff_mode()),
            Some("diff_mode"),
            Some("DIFF_MODE"),
            Some("diff_mode"),
        ),
        ctx.row(
            "legacy_passthrough",
            config.legacy_passthrough().to_string(),
            Some("legacy_passthrough"),
            Some("LEGACY_PASSTHROUGH"),
            Some("legacy_passthrough"),
        ),
        ctx.row(
            "preferred_algorithms.kex",
            list(&algos.kex),
            Some("kex_algos"),
            None,
            Some("preferred_algorithms.kex"),
        ),
        ctx.row(
            "preferred_algorithms.aead",
            list(&algos.aead),
            Some("aead_algos"),
            None,
            Some("preferred_algorithms.aead"),
        ),
        ctx.row(
            "preferred_algorithms.mac",
            list(&algos.mac),
            Some("mac_algos"),
            None,
            Some("preferred_algorithms.mac"),
        ),
        ctx.row(
            "preferred_algorithms.kdf",
            list(&algos.kdf),
            Some("kdf_algos"),
            None,
            Some("preferred_algorithms.kdf"),
        ),
        ctx.row(
            "send_env",
            list(config.send_env()),
            None,
            None,
            Some("send_env"),
        ),
        ctx.row(
            "send_path",
            list(config.send_path()),
            None,
            None,
            Some("send_path"),
        ),
        ctx.row("tracing", tracing, None, None, Some("tracing")),
    ]
}

/// Longest value rendered in the table before it is elided with `…`.  Long
/// values (e.g. the serialized `tracing` config) would otherwise blow out the
/// column; the full value is always available via `--json`.
const MAX_VALUE_WIDTH: usize = 72;

/// Elide `value` to at most [`MAX_VALUE_WIDTH`] characters, appending `…`.
fn elide(value: &str) -> String {
    if value.chars().count() <= MAX_VALUE_WIDTH {
        value.to_string()
    } else {
        let head: String = value.chars().take(MAX_VALUE_WIDTH - 1).collect();
        format!("{head}…")
    }
}

/// Print the rows as an aligned, colored table.  Color is applied to the
/// `SOURCE` column only when stdout is a TTY, so piped output stays plain.
/// Long values are elided (see [`elide`]); use `--json` for full values.
pub(crate) fn print_table(rows: &[EffectiveRow]) {
    let color = std::io::stdout().is_terminal();
    let values: Vec<String> = rows.iter().map(|r| elide(&r.value)).collect();
    let field_w = rows
        .iter()
        .map(|r| r.field.len())
        .max()
        .unwrap_or(5)
        .max("FIELD".len());
    let value_w = values
        .iter()
        .map(|v| v.chars().count())
        .max()
        .unwrap_or(5)
        .max("VALUE".len());

    println!("{:<field_w$}  {:<value_w$}  SOURCE", "FIELD", "VALUE");
    println!(
        "{:<field_w$}  {:<value_w$}  ------",
        "-".repeat(field_w),
        "-".repeat(value_w),
    );
    for (r, value) in rows.iter().zip(&values) {
        let source = if color {
            r.origin.colored()
        } else {
            r.origin.label().to_string()
        };
        println!("{:<field_w$}  {value:<value_w$}  {source}", r.field);
    }
}

/// Print the rows as a JSON array of `{field, value, source}` objects.
pub(crate) fn print_json(rows: &[EffectiveRow]) {
    let json: Vec<JsonRow<'_>> = rows
        .iter()
        .map(|r| JsonRow {
            field: &r.field,
            value: &r.value,
            source: r.origin.label(),
        })
        .collect();
    match serde_json::to_string_pretty(&json) {
        Ok(text) => println!("{text}"),
        Err(error) => eprintln!("failed to serialize effective config: {error}"),
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{Origin, classify, resolve_effective, toml_keys};
    use crate::{cli::Cli, config::Config};

    #[test]
    fn classify_precedence_is_env_cli_file() {
        // env wins over everything
        assert_eq!(classify(true, true, true), Origin::Environment);
        assert_eq!(classify(true, false, false), Origin::Environment);
        // cli beats file
        assert_eq!(classify(false, true, true), Origin::CommandLine);
        // file when only file
        assert_eq!(classify(false, false, true), Origin::ConfigFile);
        // nothing => default
        assert_eq!(classify(false, false, false), Origin::Default);
    }

    #[test]
    fn toml_keys_missing_file_is_empty() {
        let keys = toml_keys(Path::new("/nonexistent/moshpit-test-config.toml"));
        assert!(keys.is_empty());
    }

    #[test]
    fn resolve_lists_core_fields() -> anyhow::Result<()> {
        let cli = Cli::parse_argv(["moshpit", "host"])?;
        let config = Config::default();
        let rows = resolve_effective(&cli, &config, Path::new("/nonexistent/cfg.toml"));
        let fields: Vec<&str> = rows.iter().map(|r| r.field.as_str()).collect();
        assert!(fields.contains(&"server_port"));
        assert!(fields.contains(&"preferred_algorithms.kex"));
        assert!(fields.contains(&"tracing"));
        assert!(fields.contains(&"config_path"));
        Ok(())
    }
}
