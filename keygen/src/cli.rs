// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

use std::{io::Cursor, sync::LazyLock};

use clap::{ArgAction, Parser, Subcommand};
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
    #[command(subcommand)]
    #[getset(get = "pub(crate)")]
    command: Commands,
}

#[derive(Clone, Debug, Subcommand)]
pub(crate) enum Commands {
    #[clap(about = "Generate a new identity public/private key pair")]
    Generate {
        /// Skip the passphrase prompt and create an unencrypted (passwordless) key.
        /// Required when running non-interactively, e.g. as part of a service install.
        #[clap(
            short = 'n',
            long,
            help = "Skip the passphrase prompt and create an unencrypted key",
            default_value_t = false
        )]
        no_passphrase: bool,
        /// Write the private key to this path instead of prompting.
        /// The public key is written alongside it with a `.pub` extension.
        /// Required when running non-interactively (no TTY).
        #[clap(
            short = 'o',
            long,
            help = "Write keys to this path (skips the interactive path prompt)"
        )]
        output_path: Option<String>,
        /// Overwrite existing key files without prompting for confirmation.
        #[clap(
            short = 'f',
            long,
            help = "Overwrite existing key files without confirmation",
            default_value_t = false
        )]
        force: bool,
        /// Generate a server host key (allows unencrypted keys).
        #[clap(
            short = 's',
            long,
            help = "Generate a server host key (allows unencrypted keys)",
            default_value_t = false
        )]
        server: bool,
        /// Read the passphrase from stdin (one line) instead of prompting interactively.
        /// Mutually exclusive with --no-passphrase.
        #[clap(
            long,
            help = "Read passphrase from stdin instead of prompting",
            default_value_t = false,
            conflicts_with = "no_passphrase"
        )]
        passphrase_stdin: bool,
        /// Key algorithm to use for the identity key pair.
        #[clap(
            short = 'k',
            long,
            value_name = "TYPE",
            default_value = "x25519",
            help = "Identity key algorithm: x25519 (default), p384, p256; with unstable: mldsa44, mldsa65, mldsa87"
        )]
        key_type: String,
    },
    #[clap(about = "Verify a public key fingerprint against a key file")]
    Verify {
        #[clap(help = "The SHA256 fingerprint to verify (e.g. SHA256:S8hOl...)")]
        fingerprint: String,
        #[clap(short, long, value_name = "PATH", help = "Path to the public key file")]
        key: String,
        #[clap(
            short,
            long,
            help = "Also display the randomart image",
            default_value_t = false
        )]
        randomart: bool,
    },
    #[clap(about = "Display the fingerprint of the given public key")]
    Fingerprint {
        #[clap(help = "The public key file path")]
        public_key: String,
    },
}

#[cfg(test)]
mod tests {
    use clap::Parser as _;

    use super::{Cli, Commands};

    #[test]
    fn verify_cli() {
        use clap::CommandFactory;
        <Cli as CommandFactory>::command().debug_assert();
    }

    #[test]
    fn verify_generate_command() -> anyhow::Result<()> {
        let args = vec!["moshpit-keygen", "generate"];
        let cli = Cli::try_parse_from(args)?;
        assert!(matches!(
            cli.command(),
            Commands::Generate {
                no_passphrase: false,
                ..
            }
        ));
        assert_eq!(cli.verbose(), 0);
        assert_eq!(cli.quiet(), 0);
        Ok(())
    }

    #[test]
    fn verify_generate_no_passphrase_flag() -> anyhow::Result<()> {
        let args = vec!["moshpit-keygen", "generate", "--no-passphrase"];
        let cli = Cli::try_parse_from(args)?;
        assert!(matches!(
            cli.command(),
            Commands::Generate {
                no_passphrase: true,
                ..
            }
        ));
        Ok(())
    }

    #[test]
    fn verify_generate_no_passphrase_short_flag() -> anyhow::Result<()> {
        let args = vec!["moshpit-keygen", "generate", "-n"];
        let cli = Cli::try_parse_from(args)?;
        assert!(matches!(
            cli.command(),
            Commands::Generate {
                no_passphrase: true,
                ..
            }
        ));
        Ok(())
    }
    #[test]
    fn verify_generate_output_path_flag() -> anyhow::Result<()> {
        let args = vec!["moshpit-keygen", "generate", "--output-path", "/tmp/key"];
        let cli = Cli::try_parse_from(args)?;
        match cli.command() {
            Commands::Generate { output_path, .. } => {
                assert_eq!(output_path.as_deref(), Some("/tmp/key"));
            }
            _ => panic!("Expected Generate command"),
        }
        Ok(())
    }

    #[test]
    fn verify_generate_force_flag() -> anyhow::Result<()> {
        let args = vec!["moshpit-keygen", "generate", "--force"];
        let cli = Cli::try_parse_from(args)?;
        match cli.command() {
            Commands::Generate { force, .. } => {
                assert!(force);
            }
            _ => panic!("Expected Generate command"),
        }
        Ok(())
    }

    #[test]
    fn verify_generate_server_flag() -> anyhow::Result<()> {
        let args = vec!["moshpit-keygen", "generate", "--server"];
        let cli = Cli::try_parse_from(args)?;
        match cli.command() {
            Commands::Generate { server, .. } => {
                assert!(server);
            }
            _ => panic!("Expected Generate command"),
        }
        Ok(())
    }

    #[test]
    fn verify_generate_key_type_flag() -> anyhow::Result<()> {
        // Default is x25519
        let args = vec!["moshpit-keygen", "generate"];
        let cli = Cli::try_parse_from(args)?;
        match cli.command() {
            Commands::Generate { key_type, .. } => {
                assert_eq!(key_type, "x25519");
            }
            _ => panic!("Expected Generate command"),
        }

        // Explicit p384
        let args = vec!["moshpit-keygen", "generate", "--key-type", "p384"];
        let cli = Cli::try_parse_from(args)?;
        match cli.command() {
            Commands::Generate { key_type, .. } => {
                assert_eq!(key_type, "p384");
            }
            _ => panic!("Expected Generate command"),
        }

        // Short flag -k with p256
        let args = vec!["moshpit-keygen", "generate", "-k", "p256"];
        let cli = Cli::try_parse_from(args)?;
        match cli.command() {
            Commands::Generate { key_type, .. } => {
                assert_eq!(key_type, "p256");
            }
            _ => panic!("Expected Generate command"),
        }
        Ok(())
    }

    #[test]
    fn verify_verify_command() -> anyhow::Result<()> {
        let args = vec![
            "moshpit-keygen",
            "verify",
            "--randomart",
            "--key",
            "some_key.pub",
            "SHA256:dummy",
        ];
        let cli = Cli::try_parse_from(args)?;
        match cli.command() {
            Commands::Verify {
                fingerprint,
                key,
                randomart,
            } => {
                assert!(randomart);
                assert_eq!(fingerprint, "SHA256:dummy");
                assert_eq!(key, "some_key.pub");
            }
            _ => panic!("Expected Verify command"),
        }
        Ok(())
    }

    #[test]
    fn verify_fingerprint_command() -> anyhow::Result<()> {
        let args = vec!["moshpit-keygen", "fingerprint", "dummy_path"];
        let cli = Cli::try_parse_from(args)?;
        match cli.command() {
            Commands::Fingerprint { public_key } => {
                assert_eq!(public_key, "dummy_path");
            }
            _ => panic!("Expected Fingerprint command"),
        }
        Ok(())
    }

    #[test]
    fn verify_verbose_quiet_flags() -> anyhow::Result<()> {
        let args = vec!["moshpit-keygen", "-vv", "generate"];
        let cli = Cli::try_parse_from(args)?;
        assert_eq!(cli.verbose(), 2);
        assert_eq!(cli.quiet(), 0);

        let args2 = vec!["moshpit-keygen", "-q", "generate"];
        let cli2 = Cli::try_parse_from(args2)?;
        assert_eq!(cli2.verbose(), 0);
        assert_eq!(cli2.quiet(), 1);
        Ok(())
    }
}
