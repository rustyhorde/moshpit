// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

//! `cargo xtask dist <binary>`
//!
//! Generates shell completions (bash, zsh, fish) and a man page for the
//! given moshpit binary.  Each binary's output is written to `dist/<binary>/`.
//!
//! # Usage
//!
//! ```text
//! cargo xtask dist mp
//! cargo xtask dist mps
//! cargo xtask dist mp-keygen
//! ```

use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context as _, Result, bail};
use clap::{Arg, ArgAction, Command};
use clap_complete::{Shell, generate_to};
use clap_mangen::Man;

fn main() -> Result<()> {
    let matches = Command::new("xtask")
        .subcommand_required(true)
        .subcommand(
            Command::new("dist")
                .about("Generate shell completions and man pages for a binary")
                .arg(
                    Arg::new("binary")
                        .required(true)
                        .help("Binary to generate artifacts for (mp, mps, mp-keygen)"),
                ),
        )
        .get_matches();

    match matches.subcommand() {
        Some(("dist", sub)) => {
            let binary = sub.get_one::<String>("binary").expect("required");
            dist(binary)
        }
        _ => bail!("unknown subcommand"),
    }
}

fn dist(binary: &str) -> Result<()> {
    let mut cmd = match binary {
        "mp" => mp_command(),
        "mps" => mps_command(),
        "mp-keygen" => mp_keygen_command(),
        other => bail!("unknown binary '{other}'; expected one of: mp, mps, mp-keygen"),
    };

    let out_dir = PathBuf::from("dist").join(binary);
    fs::create_dir_all(&out_dir)
        .with_context(|| format!("failed to create output directory {}", out_dir.display()))?;

    generate_completions(binary, &mut cmd, &out_dir)?;
    generate_man_page(&cmd, &out_dir)?;
    copy_licenses(&out_dir)?;
    copy_example_config(binary, &out_dir)?;

    println!("Artifacts written to {}", out_dir.display());
    Ok(())
}

fn copy_licenses(out_dir: &Path) -> Result<()> {
    for name in ["LICENSE-MIT", "LICENSE-APACHE"] {
        fs::copy(name, out_dir.join(name))
            .with_context(|| format!("failed to copy {name} to {}", out_dir.display()))?;
    }
    Ok(())
}

fn copy_example_config(binary: &str, out_dir: &Path) -> Result<()> {
    let (pkg, cfg) = match binary {
        "mp" => ("moshpit", "moshpit.toml.example"),
        "mps" => ("moshpits", "moshpits.toml.example"),
        _ => return Ok(()),
    };
    let src = PathBuf::from(format!("packaging/arch/{pkg}/examples/{cfg}"));
    if src.exists() {
        fs::copy(&src, out_dir.join(cfg))
            .with_context(|| format!("failed to copy {}", src.display()))?;
    }
    Ok(())
}

// ── Completion generation ─────────────────────────────────────────────────────

fn generate_completions(binary: &str, cmd: &mut Command, out_dir: &Path) -> Result<()> {
    for shell in [Shell::Bash, Shell::Zsh, Shell::Fish] {
        generate_to(shell, cmd, binary, out_dir).with_context(|| {
            format!(
                "failed to generate {} completions for {binary}",
                shell_name(shell)
            )
        })?;
    }
    Ok(())
}

fn shell_name(shell: Shell) -> &'static str {
    match shell {
        Shell::Bash => "bash",
        Shell::Zsh => "zsh",
        Shell::Fish => "fish",
        _ => "unknown",
    }
}

// ── Man page generation ───────────────────────────────────────────────────────

fn generate_man_page(cmd: &Command, out_dir: &Path) -> Result<()> {
    let man = Man::new(cmd.clone());
    let file_name = format!("{}.1", cmd.get_name());
    let mut file = fs::File::create(out_dir.join(&file_name))
        .with_context(|| format!("failed to create man page file {file_name}"))?;
    man.render(&mut file)
        .with_context(|| format!("failed to render man page {file_name}"))?;
    Ok(())
}

// ── CLI command definitions ───────────────────────────────────────────────────
//
// These mirror the actual Cli structs in moshpit/, moshpits/, and keygen/
// without importing those crates. Keep these in sync with any CLI changes.

/// `mp` — moshpit client
fn mp_command() -> Command {
    Command::new("mp")
        .version(env!("CARGO_PKG_VERSION"))
        .about("Connect to a moshpits server")
        .arg(verbose_arg())
        .arg(quiet_arg())
        .arg(config_absolute_path_arg())
        .arg(tracing_absolute_path_arg())
        .arg(private_key_path_arg())
        .arg(public_key_path_arg())
        .arg(
            Arg::new("server-port")
                .short('s')
                .long("server-port")
                .value_name("PORT")
                .help("The port number of the server to connect to (default: 40404)")
                .default_value("40404"),
        )
        .arg(
            Arg::new("server-destination")
                .value_name("SERVER_DESTINATION")
                .required(true)
                .help("The IP address of the server to connect to (user@address or address)"),
        )
        .arg(
            Arg::new("predict")
                .long("predict")
                .value_name("MODE")
                .value_parser(["adaptive", "always", "never"])
                .default_value("adaptive")
                .help("Local-echo prediction: adaptive (default), always, or never"),
        )
}

/// `mps` — moshpits server
fn mps_command() -> Command {
    Command::new("mps")
        .version(env!("CARGO_PKG_VERSION"))
        .about("Start the moshpits server")
        .arg(verbose_arg())
        .arg(quiet_arg())
        .arg(
            Arg::new("enable-std-output")
                .short('e')
                .long("enable-std-output")
                .action(ArgAction::SetTrue)
                .help("Enable logging to stdout/stderr"),
        )
        .arg(config_absolute_path_arg())
        .arg(tracing_absolute_path_arg())
        .arg(private_key_path_arg())
        .arg(public_key_path_arg())
}

/// `mp-keygen` — key generation tool
fn mp_keygen_command() -> Command {
    Command::new("mp-keygen")
        .version(env!("CARGO_PKG_VERSION"))
        .about("Manage asymmetric key pairs for moshpit")
        .subcommand_required(true)
        .arg(verbose_arg())
        .arg(quiet_arg())
        .subcommand(
            Command::new("generate")
                .about("Generate a new identity public/private key pair")
                .arg(
                    Arg::new("no-passphrase")
                        .short('n')
                        .long("no-passphrase")
                        .action(ArgAction::SetTrue)
                        .help("Skip the passphrase prompt and create an unencrypted key"),
                )
                .arg(
                    Arg::new("output-path")
                        .short('o')
                        .long("output-path")
                        .value_name("PATH")
                        .help("Write keys to this path (skips the interactive path prompt)"),
                )
                .arg(
                    Arg::new("force")
                        .short('f')
                        .long("force")
                        .action(ArgAction::SetTrue)
                        .help("Overwrite existing key files without confirmation"),
                )
                .arg(
                    Arg::new("server")
                        .short('s')
                        .long("server")
                        .action(ArgAction::SetTrue)
                        .help("Generate a server host key (allows unencrypted keys)"),
                )
                .arg(
                    Arg::new("passphrase-stdin")
                        .long("passphrase-stdin")
                        .action(ArgAction::SetTrue)
                        .help("Read passphrase from stdin instead of prompting")
                        .conflicts_with("no-passphrase"),
                )
                .arg(
                    Arg::new("key-type")
                        .short('k')
                        .long("key-type")
                        .value_name("TYPE")
                        .default_value("x25519")
                        .help("Identity key algorithm: x25519 (default), p384, p256; with unstable: mldsa44, mldsa65, mldsa87"),
                ),
        )
        .subcommand(
            Command::new("verify")
                .about("Verify a public key fingerprint against a key file")
                .arg(
                    Arg::new("fingerprint")
                        .value_name("FINGERPRINT")
                        .required(true)
                        .help("The SHA256 fingerprint to verify (e.g. SHA256:S8hOl...)"),
                )
                .arg(
                    Arg::new("key")
                        .short('k')
                        .long("key")
                        .value_name("PATH")
                        .required(true)
                        .help("Path to the public key file"),
                )
                .arg(
                    Arg::new("randomart")
                        .short('r')
                        .long("randomart")
                        .action(ArgAction::SetTrue)
                        .help("Also display the randomart image"),
                ),
        )
        .subcommand(
            Command::new("fingerprint")
                .about("Display the fingerprint of the given public key")
                .arg(
                    Arg::new("public-key")
                        .value_name("PUBLIC_KEY")
                        .required(true)
                        .help("Path to the public key file"),
                ),
        )
}

// ── Shared argument helpers ───────────────────────────────────────────────────

fn verbose_arg() -> Arg {
    Arg::new("verbose")
        .short('v')
        .long("verbose")
        .action(ArgAction::Count)
        .help("Turn up logging verbosity (multiple will turn it up more)")
        .conflicts_with("quiet")
}

fn quiet_arg() -> Arg {
    Arg::new("quiet")
        .short('q')
        .long("quiet")
        .action(ArgAction::Count)
        .help("Turn down logging verbosity (multiple will turn it down more)")
        .conflicts_with("verbose")
}

fn config_absolute_path_arg() -> Arg {
    Arg::new("config-absolute-path")
        .short('c')
        .long("config-absolute-path")
        .value_name("PATH")
        .help("Specify the absolute path to the config file")
}

fn tracing_absolute_path_arg() -> Arg {
    Arg::new("tracing-absolute-path")
        .short('t')
        .long("tracing-absolute-path")
        .value_name("PATH")
        .help("Specify the absolute path to the tracing output file")
}

fn private_key_path_arg() -> Arg {
    Arg::new("private-key-path")
        .short('p')
        .long("private-key-path")
        .value_name("PATH")
        .help("Specify the absolute path to the private key file")
}

fn public_key_path_arg() -> Arg {
    Arg::new("public-key-path")
        .short('k')
        .long("public-key-path")
        .value_name("PATH")
        .help("Specify the absolute path to the public key file")
}
