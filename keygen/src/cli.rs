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
    #[command(subcommand)]
    #[getset(get = "pub(crate)")]
    command: Commands,
}

#[derive(Clone, Debug, Subcommand)]
pub(crate) enum Commands {
    #[clap(about = "Generate a new ed25519 public/private key pair")]
    Generate,
    #[clap(about = "Verify a public key fingerprint or randomart image")]
    Verify {
        #[clap(short, long, help = "Verify randomart", default_value_t = false)]
        randomart: bool,
        #[clap(help = "The signature or randomart to verify")]
        signature: String,
    },
    #[clap(about = "Display the fingerprint of the given public key")]
    Fingerprint {
        #[clap(help = "The public key file path")]
        public_key: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_cli() {
        use clap::CommandFactory;
        <Cli as CommandFactory>::command().debug_assert();
    }

    #[test]
    fn verify_generate_command() {
        let args = vec!["moshpit-keygen", "generate"];
        let cli = Cli::try_parse_from(args).unwrap();
        assert!(matches!(cli.command(), Commands::Generate));
        assert_eq!(cli.verbose(), 0);
        assert_eq!(cli.quiet(), 0);
    }

    #[test]
    fn verify_verify_command() {
        let args = vec!["moshpit-keygen", "verify", "--randomart", "dummy_sig"];
        let cli = Cli::try_parse_from(args).unwrap();
        match cli.command() {
            Commands::Verify {
                randomart,
                signature,
            } => {
                assert!(randomart);
                assert_eq!(signature, "dummy_sig");
            }
            _ => panic!("Expected Verify command"),
        }
    }

    #[test]
    fn verify_fingerprint_command() {
        let args = vec!["moshpit-keygen", "fingerprint", "dummy_path"];
        let cli = Cli::try_parse_from(args).unwrap();
        match cli.command() {
            Commands::Fingerprint { public_key } => {
                assert_eq!(public_key, "dummy_path");
            }
            _ => panic!("Expected Fingerprint command"),
        }
    }

    #[test]
    fn verify_verbose_quiet_flags() {
        let args = vec!["moshpit-keygen", "-vv", "generate"];
        let cli = Cli::try_parse_from(args).unwrap();
        assert_eq!(cli.verbose(), 2);
        assert_eq!(cli.quiet(), 0);

        let args2 = vec!["moshpit-keygen", "-q", "generate"];
        let cli2 = Cli::try_parse_from(args2).unwrap();
        assert_eq!(cli2.verbose(), 0);
        assert_eq!(cli2.quiet(), 1);
    }
}
