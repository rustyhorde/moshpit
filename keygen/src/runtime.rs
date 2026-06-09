// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

use std::{
    ffi::OsString,
    fs::{DirBuilder, OpenOptions},
    io::BufRead as _,
    path::{Path, PathBuf},
};

#[cfg(target_family = "unix")]
use std::os::unix::fs::DirBuilderExt;

use anyhow::Result;
use clap::Parser as _;
use dialoguer::{Confirm, Input, Password};
#[cfg(feature = "unstable")]
use libmoshpit::{KEY_ALGORITHM_ML_DSA_44, KEY_ALGORITHM_ML_DSA_65, KEY_ALGORITHM_ML_DSA_87};
use libmoshpit::{
    KEY_ALGORITHM_P256, KEY_ALGORITHM_P384, KEY_ALGORITHM_X25519, KexMode, KeyPair,
    extract_public_key_bytes, fingerprint, randomart, verify_fingerprint,
};

use crate::cli::{Cli, Commands};

#[derive(Clone, Copy)]
enum PassphraseSource {
    Interactive,
    None,
    Stdin,
}

#[cfg_attr(coverage_nightly, coverage(off))]
pub(crate) fn run<I, T>(args: Option<I>) -> Result<()>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    // Parse the command line
    let cli = if let Some(args) = args {
        Cli::try_parse_from(args)?
    } else {
        Cli::try_parse()?
    };

    match cli.command() {
        Commands::Generate {
            no_passphrase,
            passphrase_stdin,
            output_path,
            force,
            server,
            key_type,
        } => {
            let passphrase_source = if *no_passphrase {
                PassphraseSource::None
            } else if *passphrase_stdin {
                PassphraseSource::Stdin
            } else {
                PassphraseSource::Interactive
            };
            generate_keypair(
                passphrase_source,
                output_path.as_deref(),
                *force,
                *server,
                key_type,
            )
        }
        Commands::Verify {
            fingerprint: fp,
            key,
            randomart: show_randomart,
        } => verify_key(fp, key, *show_randomart),
        Commands::Fingerprint { public_key } => display_fingerprint(public_key),
    }
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn prompt_for_path(default_path: &Path) -> Result<String> {
    let key_path_prompt = format!(
        "Enter file in which to save the key ({})",
        default_path.display()
    );
    Ok(Input::new()
        .with_prompt(key_path_prompt)
        .allow_empty(true)
        .interact_text()?)
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn prompt_for_overwrite() -> Result<bool> {
    Ok(Confirm::new()
        .with_prompt("Overwrite?")
        .default(false)
        .wait_for_newline(true)
        .interact()?)
}

fn read_passphrase_from_stdin() -> Result<Option<String>> {
    let mut line = String::new();
    let _ = std::io::stdin().lock().read_line(&mut line)?;
    let passphrase = line.trim_end_matches(['\n', '\r']).to_string();
    Ok(Some(passphrase))
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn prompt_for_passphrase(priv_key_path: &Path) -> Result<Option<String>> {
    let passphrase_prompt = format!("Enter passphrase for \"{}\"", priv_key_path.display());
    let passphrase: String = Password::new()
        .with_prompt(passphrase_prompt)
        .with_confirmation(
            "Enter same passphrase again",
            "Passphrases do not match.  Try again.",
        )
        .allow_empty_password(false)
        .report(false)
        .interact()?;

    Ok(Some(passphrase))
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn generate_keypair(
    passphrase_source: PassphraseSource,
    output_path: Option<&str>,
    force: bool,
    server: bool,
    key_type: &str,
) -> Result<()> {
    // Map CLI key type name to algorithm constant
    let key_alg = match key_type.to_lowercase().as_str() {
        "x25519" => KEY_ALGORITHM_X25519,
        "p384" => KEY_ALGORITHM_P384,
        "p256" => KEY_ALGORITHM_P256,
        #[cfg(feature = "unstable")]
        "mldsa44" | "ml-dsa-44" => KEY_ALGORITHM_ML_DSA_44,
        #[cfg(feature = "unstable")]
        "mldsa65" | "ml-dsa-65" => KEY_ALGORITHM_ML_DSA_65,
        #[cfg(feature = "unstable")]
        "mldsa87" | "ml-dsa-87" => KEY_ALGORITHM_ML_DSA_87,
        other => {
            #[cfg(feature = "unstable")]
            let valid_values = "x25519, p384, p256, mldsa44, mldsa65, mldsa87";
            #[cfg(not(feature = "unstable"))]
            let valid_values = "x25519, p384, p256";
            return Err(anyhow::anyhow!(
                "Unknown key type '{other}'. Valid values: {valid_values}"
            ));
        }
    };

    // Output header
    println!("Generating public/private {key_alg} identity key pair.");

    let mode = if server {
        KexMode::Server("0.0.0.0:0".parse().expect("hardcoded address is valid"))
    } else {
        KexMode::Client
    };

    let (default_priv_key_path, default_pub_key_ext) =
        KeyPair::default_key_path_ext(mode, key_alg)?;

    let priv_key_path_input = if let Some(path) = output_path {
        path.to_string()
    } else {
        prompt_for_path(&default_priv_key_path)?
    };

    let (priv_key_path, pub_key_path) = setup_paths_inner(
        priv_key_path_input,
        &default_priv_key_path,
        default_pub_key_ext,
    )?;

    if force {
        if !check_paths_inner(&priv_key_path, &pub_key_path, || Ok(true))? {
            return Ok(());
        }
    } else if !check_paths_inner(&priv_key_path, &pub_key_path, prompt_for_overwrite)? {
        return Ok(());
    }

    let passphrase_opt = match passphrase_source {
        PassphraseSource::None => None,
        PassphraseSource::Stdin => read_passphrase_from_stdin()?,
        PassphraseSource::Interactive => prompt_for_passphrase(&priv_key_path)?,
    };
    let keypair = KeyPair::generate_key_pair(passphrase_opt.as_ref(), mode, key_alg)?;
    generate_and_write_keys_inner(&priv_key_path, &pub_key_path, &keypair)?;
    Ok(())
}

fn setup_paths_inner(
    input: String,
    default_priv_key_path: &Path,
    default_pub_key_ext: &str,
) -> Result<(PathBuf, PathBuf)> {
    let priv_key_path = if input.is_empty() {
        default_priv_key_path.to_path_buf()
    } else {
        PathBuf::from(input)
    };
    let mut pub_key_path = priv_key_path.clone();
    let _ = pub_key_path.set_extension(default_pub_key_ext);
    if let Some(priv_parent) = priv_key_path.parent() {
        #[cfg(target_family = "unix")]
        {
            DirBuilder::new()
                .mode(0o700)
                .recursive(true)
                .create(priv_parent)?;
        }
        #[cfg(not(target_family = "unix"))]
        {
            DirBuilder::new().recursive(true).create(priv_parent)?;
        }
    }
    Ok((priv_key_path, pub_key_path))
}

fn check_paths_inner<F>(priv_key_path: &Path, pub_key_path: &Path, prompt: F) -> Result<bool>
where
    F: FnOnce() -> Result<bool>,
{
    if priv_key_path.try_exists()? || pub_key_path.try_exists()? {
        println!("{} already exists.", priv_key_path.display());
        prompt()
    } else {
        Ok(true)
    }
}

fn generate_and_write_keys_inner(
    priv_key_path: &Path,
    pub_key_path: &Path,
    keypair: &KeyPair,
) -> Result<()> {
    // Write the private key out to the private key file
    let mut priv_key_file = {
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(priv_key_path)?
        }
        #[cfg(not(unix))]
        {
            OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(priv_key_path)?
        }
    };
    keypair.write_private_key(&mut priv_key_file)?;

    // Write the public key out to the public key file
    let mut pub_key_file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(pub_key_path)?;
    keypair.write_public_key(&mut pub_key_file)?;

    println!(
        "Your identification has been saved in {}",
        priv_key_path.display()
    );
    println!(
        "Your public key has been saved in {}",
        pub_key_path.display()
    );
    println!("The key fingerprint is:");
    println!("{}", keypair.fingerprint()?);
    println!("The key's randomart image is:");
    print!("{}", keypair.randomart());
    Ok(())
}

fn verify_key(fingerprint: &str, key_path: &str, show_randomart: bool) -> Result<()> {
    let public_key_file = OpenOptions::new().read(true).open(key_path)?;
    let key_bytes = extract_public_key_bytes(public_key_file)?;

    // Accept "SHA256:<digest>" or "SHA256:<digest> user@host" — strip prefix and trailing comment
    let digest_part = fingerprint
        .strip_prefix("SHA256:")
        .unwrap_or(fingerprint)
        .split_whitespace()
        .next()
        .unwrap_or(fingerprint);

    if verify_fingerprint(digest_part, &key_bytes) {
        println!("Fingerprint matches. Key is authentic.");
        if show_randomart {
            println!("The key's randomart image is:");
            print!("{}", randomart(&key_bytes));
        }
        Ok(())
    } else {
        Err(anyhow::anyhow!("Fingerprint mismatch. Key does not match."))
    }
}

fn display_fingerprint(public_key_path: &str) -> Result<()> {
    let public_key_file = OpenOptions::new().read(true).open(public_key_path)?;
    let public_key_bytes = extract_public_key_bytes(public_key_file)?;
    println!("{}", fingerprint(&public_key_bytes)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use anyhow::Result;
    use libmoshpit::{KEY_ALGORITHM_X25519, KexMode, KeyPair};

    use super::{
        check_paths_inner, display_fingerprint, generate_and_write_keys_inner,
        setup_paths_inner, verify_key,
    };

    static DIR_COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn get_temp_dir() -> PathBuf {
        let count = DIR_COUNTER.fetch_add(1, Ordering::SeqCst);
        let time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time is before UNIX epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("moshpit_test_{time}_{count}"))
    }

    #[test]
    fn test_setup_paths_inner_empty_input() -> Result<()> {
        let default_path = PathBuf::from("/tmp/dummy_id");
        let (priv_path, pub_path) = setup_paths_inner(String::new(), &default_path, "pub")?;
        assert_eq!(priv_path, default_path);
        assert_eq!(
            pub_path.extension().expect("pub_path has an extension"),
            "pub"
        );
        Ok(())
    }

    #[test]
    fn test_setup_paths_inner_with_input() -> Result<()> {
        let dir = get_temp_dir();
        let input_path = dir.join("my_key");
        let default_path = PathBuf::from("/tmp/dummy_id");

        let (priv_path, pub_path) = setup_paths_inner(
            input_path.to_string_lossy().to_string(),
            &default_path,
            "pub",
        )?;
        assert_eq!(priv_path, input_path);
        assert_eq!(pub_path, dir.join("my_key.pub"));
        assert!(dir.exists());
        Ok(())
    }

    #[test]
    fn test_check_paths_inner_not_exists() -> Result<()> {
        let dir = get_temp_dir();
        let priv_path = dir.join("key");
        let pub_path = dir.join("key.pub");

        let res = check_paths_inner(&priv_path, &pub_path, || Ok(false))?;
        assert!(res);
        Ok(())
    }

    #[test]
    fn test_check_paths_inner_exists_prompt_yes() -> Result<()> {
        let dir = get_temp_dir();
        fs::create_dir_all(&dir)?;
        let priv_path = dir.join("key");
        let pub_path = dir.join("key.pub");
        fs::write(&priv_path, "dummy")?;

        let res = check_paths_inner(&priv_path, &pub_path, || Ok(true))?;
        assert!(res);
        Ok(())
    }

    #[test]
    fn test_check_paths_inner_exists_prompt_no() -> Result<()> {
        let dir = get_temp_dir();
        fs::create_dir_all(&dir)?;
        let priv_path = dir.join("key");
        let pub_path = dir.join("key.pub");
        fs::write(&priv_path, "dummy")?;

        let res = check_paths_inner(&priv_path, &pub_path, || Ok(false))?;
        assert!(!res);
        Ok(())
    }

    #[test]
    fn test_generate_and_write_keys() -> Result<()> {
        let dir = get_temp_dir();
        fs::create_dir_all(&dir)?;
        let priv_path = dir.join("key");
        let pub_path = dir.join("key.pub");

        let secret = "secret".to_string();
        let keypair =
            KeyPair::generate_key_pair(Some(&secret), KexMode::Client, KEY_ALGORITHM_X25519)?;
        generate_and_write_keys_inner(&priv_path, &pub_path, &keypair)?;

        assert!(priv_path.exists());
        assert!(pub_path.exists());

        // Verify fingerprint can be read
        display_fingerprint(pub_path.to_str().expect("pub_path is valid UTF-8"))?;
        Ok(())
    }

    #[test]
    fn test_display_fingerprint_error() {
        let dir = get_temp_dir();
        let missing_file = dir.join("missing.pub");
        let res = display_fingerprint(missing_file.to_str().expect("path is valid UTF-8"));
        assert!(res.is_err());
    }

    #[test]
    fn test_verify_key_match() -> Result<()> {
        let dir = get_temp_dir();
        fs::create_dir_all(&dir)?;
        let priv_path = dir.join("key");
        let pub_path = dir.join("key.pub");

        let server_addr = "0.0.0.0:0".parse().expect("hardcoded address is valid");
        let keypair =
            KeyPair::generate_key_pair(None, KexMode::Server(server_addr), KEY_ALGORITHM_X25519)?;
        generate_and_write_keys_inner(&priv_path, &pub_path, &keypair)?;

        let fp = keypair.fingerprint()?;
        let pub_path_str = pub_path.to_str().expect("valid UTF-8");

        verify_key(&fp, pub_path_str, false)?;
        let fp_no_host = fp
            .split_whitespace()
            .next()
            .expect("fingerprint string has content");
        verify_key(fp_no_host, pub_path_str, false)?;
        verify_key(&fp, pub_path_str, true)?;
        Ok(())
    }

    #[test]
    fn test_verify_key_mismatch() -> Result<()> {
        let dir = get_temp_dir();
        fs::create_dir_all(&dir)?;
        let pub_path = dir.join("key.pub");

        let server_addr = "0.0.0.0:0".parse().expect("hardcoded address is valid");
        let keypair =
            KeyPair::generate_key_pair(None, KexMode::Server(server_addr), KEY_ALGORITHM_X25519)?;
        generate_and_write_keys_inner(&dir.join("key"), &pub_path, &keypair)?;

        let res = verify_key(
            "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            pub_path.to_str().expect("test path is valid UTF-8"),
            false,
        );
        assert!(res.is_err());
        Ok(())
    }

    #[test]
    fn test_verify_key_missing_file() {
        let res = verify_key("SHA256:foo", "/nonexistent/path.pub", false);
        assert!(res.is_err());
    }
}
