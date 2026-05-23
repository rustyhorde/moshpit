// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

use std::{io::Cursor, sync::LazyLock};

use clap::{ArgAction, Parser, Subcommand, ValueEnum};
use getset::{CopyGetters, Getters};
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

#[derive(Clone, CopyGetters, Debug, Getters, Parser)]
#[command(author, version, about, long_version = LONG_VERSION.as_str(), long_about = None)]
pub(crate) struct Cli {
    #[clap(
        short,
        long,
        action = ArgAction::Count,
        help = "Turn up logging verbosity",
        conflicts_with = "quiet"
    )]
    #[getset(get_copy = "pub(crate)")]
    verbose: u8,
    #[clap(
        short,
        long,
        action = ArgAction::Count,
        help = "Turn down logging verbosity",
        conflicts_with = "verbose"
    )]
    #[getset(get_copy = "pub(crate)")]
    quiet: u8,
    #[command(subcommand)]
    #[getset(get = "pub(crate)")]
    command: Commands,
}

/// Output format for the socket environment variable printed by `mpa start`.
#[derive(Clone, Copy, Debug, Default, ValueEnum)]
pub(crate) enum ShellKind {
    /// fish: `set -Ux MOSHPIT_AGENT_SOCK <path>`
    #[default]
    Fish,
    /// bash/zsh: `MOSHPIT_AGENT_SOCK=<path>; export MOSHPIT_AGENT_SOCK`
    Bash,
}

#[derive(Clone, Debug, Subcommand)]
pub(crate) enum Commands {
    /// Start the agent daemon (background by default).
    ///
    /// Prints the socket path as a shell assignment to stdout so the caller
    /// can source it:
    ///   mpa start | source              # fish (default)
    ///   eval $(mpa start --shell bash)  # bash/zsh
    ///   mpa start --foreground          # foreground; same output, keeps running
    #[clap(about = "Start the agent daemon")]
    Start {
        /// Override the socket path (default: $XDG_RUNTIME_DIR/moshpit-agent-<uid>.sock
        /// or ~/.mp/agent.sock).
        #[clap(short, long, value_name = "PATH")]
        socket: Option<String>,
        /// Path to the vault file (default: ~/.mp/agent-vault).
        #[clap(long, value_name = "PATH")]
        vault: Option<String>,
        /// Run in the foreground instead of daemonising (daemon is the default).
        #[clap(long, default_value_t = false)]
        foreground: bool,
        /// Shell syntax for the exported environment variable.
        #[clap(long, value_enum, default_value_t = ShellKind::Fish)]
        shell: ShellKind,
        /// Internal: read master passphrase from stdin pipe (used by daemon self-spawn).
        #[clap(long, default_value_t = false, hide = true)]
        passphrase_pipe: bool,
        /// Unlock backend to use (passphrase, fido2, systemd-creds,
        /// ssh-agent-piggyback).  Defaults to the backend compiled into this
        /// binary.
        #[clap(long, value_name = "BACKEND", default_value_t = default_backend())]
        backend: String,
        /// Read the vault master passphrase from stdin instead of prompting
        /// (useful for scripting and non-interactive environments).
        #[clap(long, default_value_t = false)]
        passphrase_stdin: bool,
    },
    /// Add an identity key to the running agent.
    #[clap(about = "Add an identity key to the agent")]
    AddKey {
        /// Path to the private key file.
        #[clap(value_name = "KEY_PATH")]
        key_path: String,
        /// Read the key passphrase from stdin instead of prompting.
        #[clap(long, default_value_t = false)]
        passphrase_stdin: bool,
        /// Suppress the key-selection hint shown when multiple keys are loaded.
        #[clap(long, default_value_t = false)]
        no_hint: bool,
    },
    /// List identities held by the running agent.
    #[clap(about = "List identities held by the agent")]
    List {
        /// Suppress the key-selection hint shown when multiple keys are loaded.
        #[clap(long, default_value_t = false)]
        no_hint: bool,
    },
    /// Remove an identity from the running agent.
    #[clap(about = "Remove an identity from the agent")]
    RemoveKey {
        /// Fingerprint of the key to remove (SHA256:<base64> form).
        #[clap(value_name = "FINGERPRINT")]
        fingerprint: String,
    },
    /// Lock the agent: clear all keys from memory.
    #[clap(about = "Lock the agent (clear keys from memory)")]
    Lock,
    /// Unlock the agent: re-load keys from the vault.
    #[clap(about = "Unlock the agent (reload keys from vault)")]
    Unlock,
    /// Stop the running agent daemon.
    ///
    /// Sends a shutdown request over the socket, then prints the unset command
    /// for the shell so the caller can source it:
    ///   mpa stop | source              # fish (default)
    ///   eval $(mpa stop --shell bash)  # bash/zsh
    #[clap(about = "Stop the agent daemon")]
    Stop {
        /// Override the socket path (default: `$MOSHPIT_AGENT_SOCK` or XDG default).
        #[clap(long, value_name = "PATH")]
        socket: Option<String>,
        /// Shell syntax for the unset command.
        #[clap(long, value_enum, default_value_t = ShellKind::Fish)]
        shell: ShellKind,
    },
}

/// Returns the backend name that matches the compile-time feature set.
/// For multi-backend builds (e.g. the `full` binary) the first match wins.
#[allow(unreachable_code)]
#[cfg_attr(coverage_nightly, coverage(off))]
fn default_backend() -> String {
    #[cfg(feature = "fido2")]
    return "fido2".to_string();
    #[cfg(feature = "systemd-creds")]
    return "systemd-creds".to_string();
    #[cfg(feature = "ssh-agent-piggyback")]
    return "ssh-agent-piggyback".to_string();
    #[cfg(feature = "tpm")]
    return "tpm".to_string();
    #[cfg(feature = "fprintd")]
    return "fprintd".to_string();
    #[cfg(feature = "secret-service")]
    return "secret-service".to_string();
    #[cfg(feature = "macos-keychain")]
    return "macos-keychain".to_string();
    "passphrase".to_string()
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::*;

    #[test]
    fn verify_cli() {
        <Cli as CommandFactory>::command().debug_assert();
    }

    #[test]
    fn start_command_defaults() -> anyhow::Result<()> {
        let cli = Cli::try_parse_from(["mpa", "start"])?;
        assert!(matches!(
            cli.command(),
            Commands::Start {
                socket: None,
                vault: None,
                foreground: false,
                shell: ShellKind::Fish,
                passphrase_pipe: false,
                ..
            }
        ));
        Ok(())
    }

    #[test]
    fn add_key_command() -> anyhow::Result<()> {
        let cli = Cli::try_parse_from(["mpa", "add-key", "/tmp/key"])?;
        match cli.command() {
            Commands::AddKey { key_path, .. } => assert_eq!(key_path, "/tmp/key"),
            _ => panic!("expected AddKey"),
        }
        Ok(())
    }

    #[test]
    fn list_command() -> anyhow::Result<()> {
        let cli = Cli::try_parse_from(["mpa", "list"])?;
        assert!(matches!(cli.command(), Commands::List { .. }));
        Ok(())
    }

    #[test]
    fn lock_unlock_commands() -> anyhow::Result<()> {
        assert!(matches!(
            Cli::try_parse_from(["mpa", "lock"])?.command(),
            Commands::Lock
        ));
        assert!(matches!(
            Cli::try_parse_from(["mpa", "unlock"])?.command(),
            Commands::Unlock
        ));
        Ok(())
    }

    #[test]
    fn stop_command_defaults() -> anyhow::Result<()> {
        let cli = Cli::try_parse_from(["mpa", "stop"])?;
        assert!(matches!(
            cli.command(),
            Commands::Stop {
                socket: None,
                shell: ShellKind::Fish,
            }
        ));
        Ok(())
    }

    #[test]
    fn stop_command_bash_shell() -> anyhow::Result<()> {
        let cli = Cli::try_parse_from(["mpa", "stop", "--shell", "bash"])?;
        assert!(matches!(
            cli.command(),
            Commands::Stop {
                shell: ShellKind::Bash,
                ..
            }
        ));
        Ok(())
    }
}
