//! Error types for the moshpit library.

use clap::error::ErrorKind;
use thiserror::Error;

/// Errors that can occur in moshpit
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum Error {
    /// Incomplete data
    #[error("incomplete data")]
    Incomplete,
    /// Connection Reset by Peer
    #[error("connection reset by peer")]
    ConnectionResetByPeer,
    /// No valid data directory could be found
    #[error("There is no valid data directory")]
    DataDir,
    /// No valid config directory could be found
    #[error("There is no valid config directory")]
    ConfigDir,
    /// Unable to build a valid configuration
    #[error("Unable to build a valid configuration")]
    ConfigBuild,
    /// Unable to load a valid configuration
    #[error("Unable to load a valid configuration")]
    ConfigLoad,
    /// Unable to deserialize configuration
    #[error("Unable to deserialize config")]
    ConfigDeserialize,
    /// Unable to initialize tracing
    #[error("Unable to initialize tracing")]
    TracingInit,
    /// An invalid IP address was provided
    #[error("An invalid IP address was provided")]
    InvalidIpAddress,
    /// An invalid frame was received
    #[error("An invalid frame was received")]
    InvalidFrame,
    /// A key has not been established
    #[error("A key has not been established")]
    KeyNotEstablished,
    /// Decryption failed
    #[error("Decryption failed")]
    DecryptionFailed,
    /// Invalid IP address for server
    #[error("Invalid IP address for server")]
    InvalidServerAddress,
    /// Invalid Moshpits address
    #[error("Invalid Moshpits address")]
    InvalidMoshpitsAddress,
    /// Invalid key exchange state
    #[error("key exchange failed")]
    InvalidKexState,
    /// UUID mismatch
    #[error("UUID mismatch")]
    UuidMismatch,
    /// No valid home directory could be found
    #[error("There is no valid home directory")]
    HomeDir,
    /// Invalid public key file format
    #[error("Invalid public key file format")]
    InvalidPublicKeyFormat,
    /// An invalid key header was found
    #[error("An invalid key header was found")]
    InvalidKeyHeader,
    /// A public key mismatch occurred
    #[error("A public key mismatch occurred")]
    PublicKeyMismatch,
    /// An unsupported AEAD cipher was specified
    #[error("An unsupported AEAD cipher was specified")]
    UnsupportedAeadCipher,
    /// An invalid server destination format was provided
    #[error("An invalid server destination format was provided")]
    InvalidServerDestination,
    /// A frame was received that exceeds the maximum allowed length
    #[error("Frame too large")]
    FrameTooLarge,
    /// A key file was not found or could not be read
    #[error("Key file not found")]
    KeyFileMissing,
    /// A key file is corrupt or has an invalid format
    #[error("Key file is corrupt or has an invalid format")]
    KeyCorrupt,
    /// Public key does not match private key
    #[error("Public key does not match private key")]
    KeyPairMismatch,
    /// The user explicitly rejected the server's host key (TOFU or mismatch prompt)
    #[error("Host key rejected by user")]
    HostKeyRejected,
    /// No common algorithm found during KEX negotiation
    #[error("No common algorithm found during key exchange negotiation")]
    NoCommonAlgorithm,
}

/// Converts an `anyhow::Error` into a suitable exit code or clap message for a CLI application.
#[allow(clippy::needless_pass_by_value)]
#[must_use]
pub fn clap_or_error(err: anyhow::Error) -> i32 {
    let disp_err = || {
        eprintln!("{err:?}");
        1
    };
    match err.downcast_ref::<clap::Error>() {
        Some(e) => match e.kind() {
            ErrorKind::DisplayHelp | ErrorKind::DisplayVersion => {
                println!("{e}");
                0
            }
            ErrorKind::InvalidValue
            | ErrorKind::UnknownArgument
            | ErrorKind::InvalidSubcommand
            | ErrorKind::NoEquals
            | ErrorKind::ValueValidation
            | ErrorKind::TooManyValues
            | ErrorKind::TooFewValues
            | ErrorKind::WrongNumberOfValues
            | ErrorKind::ArgumentConflict
            | ErrorKind::MissingRequiredArgument
            | ErrorKind::MissingSubcommand
            | ErrorKind::InvalidUtf8
            | ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
            | ErrorKind::Io
            | ErrorKind::Format => disp_err(),
            _ => unknown_err_kind(),
        },
        None => disp_err(),
    }
}

// Coverage ignore start: this is a catch-all for future ErrorKinds
#[cfg_attr(coverage_nightly, coverage(off))]
fn unknown_err_kind() -> i32 {
    eprintln!("Unknown ErrorKind");
    1
}

/// Indicates successful execution of a function, returning exit code 0.
#[must_use]
pub fn success((): ()) -> i32 {
    0
}

#[cfg(test)]
mod test {
    use super::{clap_or_error, success};

    use anyhow::{Error, anyhow};
    use clap::{
        Command,
        error::ErrorKind::{self, DisplayHelp, DisplayVersion},
    };

    #[test]
    fn test_success() {
        assert_eq!(success(()), 0);
    }

    #[test]
    fn clap_or_error_is_error() {
        assert_eq!(1, clap_or_error(anyhow!("test")));
    }

    #[test]
    fn clap_or_error_is_help() {
        let mut cmd = Command::new("libmoshpit");
        let error = cmd.error(DisplayHelp, "help");
        let clap_error = Error::new(error);
        assert_eq!(0, clap_or_error(clap_error));
    }

    #[test]
    fn clap_or_error_is_version() {
        let mut cmd = Command::new("libmoshpit");
        let error = cmd.error(DisplayVersion, "1.0");
        let clap_error = Error::new(error);
        assert_eq!(0, clap_or_error(clap_error));
    }

    #[test]
    fn clap_or_error_is_other_clap_error() {
        let mut cmd = Command::new("libmoshpit");
        let error = cmd.error(ErrorKind::InvalidValue, "Some failure case");
        let clap_error = Error::new(error);
        assert_eq!(1, clap_or_error(clap_error));
    }
}
