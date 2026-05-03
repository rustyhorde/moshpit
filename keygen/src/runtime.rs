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
    path::{Path, PathBuf},
};

#[cfg(target_family = "unix")]
use std::os::unix::fs::DirBuilderExt;

use anyhow::Result;
use clap::Parser as _;
use dialoguer::{Confirm, Input, Password};
use libmoshpit::{KexMode, KeyPair, extract_public_key_bytes, fingerprint};

use crate::cli::{Cli, Commands};

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
            output_path,
            force,
        } => generate_keypair(*no_passphrase, output_path.as_deref(), *force),
        Commands::Verify {
            randomart: _,
            signature: _,
        } => Ok(()),
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
fn generate_keypair(no_passphrase: bool, output_path: Option<&str>, force: bool) -> Result<()> {
    // Output header
    println!("Generating public/private ed25519 key pair.");

    let (default_priv_key_path, default_pub_key_ext) =
        KeyPair::default_key_path_ext(KexMode::Client)?;

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

    let passphrase_opt = if no_passphrase {
        None
    } else {
        prompt_for_passphrase(&priv_key_path)?
    };
    generate_and_write_keys(&priv_key_path, &pub_key_path, passphrase_opt.as_ref())?;
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

fn generate_and_write_keys(
    priv_key_path: &Path,
    pub_key_path: &Path,
    passphrase_opt: Option<&String>,
) -> Result<()> {
    // Generate the key pair
    let keypair = KeyPair::generate_key_pair(passphrase_opt)?;

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

fn display_fingerprint(public_key_path: &str) -> Result<()> {
    let public_key_file = OpenOptions::new().read(true).open(public_key_path)?;
    let public_key_bytes = extract_public_key_bytes(public_key_file)?;
    println!("{}", fingerprint(&public_key_bytes)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static DIR_COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn get_temp_dir() -> PathBuf {
        let count = DIR_COUNTER.fetch_add(1, Ordering::SeqCst);
        let time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("moshpit_test_{time}_{count}"))
    }

    #[test]
    fn test_setup_paths_inner_empty_input() {
        let default_path = PathBuf::from("/tmp/dummy_id");
        let (priv_path, pub_path) = setup_paths_inner(String::new(), &default_path, "pub").unwrap();
        assert_eq!(priv_path, default_path);
        assert_eq!(pub_path.extension().unwrap(), "pub");
    }

    #[test]
    fn test_setup_paths_inner_with_input() {
        let dir = get_temp_dir();
        let input_path = dir.join("my_key");
        let default_path = PathBuf::from("/tmp/dummy_id");

        let (priv_path, pub_path) = setup_paths_inner(
            input_path.to_string_lossy().to_string(),
            &default_path,
            "pub",
        )
        .unwrap();
        assert_eq!(priv_path, input_path);
        assert_eq!(pub_path, dir.join("my_key.pub"));
        assert!(dir.exists());
    }

    #[test]
    fn test_check_paths_inner_not_exists() {
        let dir = get_temp_dir();
        let priv_path = dir.join("key");
        let pub_path = dir.join("key.pub");

        let res = check_paths_inner(&priv_path, &pub_path, || Ok(false)).unwrap();
        assert!(res);
    }

    #[test]
    fn test_check_paths_inner_exists_prompt_yes() {
        let dir = get_temp_dir();
        fs::create_dir_all(&dir).unwrap();
        let priv_path = dir.join("key");
        let pub_path = dir.join("key.pub");
        fs::write(&priv_path, "dummy").unwrap();

        let res = check_paths_inner(&priv_path, &pub_path, || Ok(true)).unwrap();
        assert!(res);
    }

    #[test]
    fn test_check_paths_inner_exists_prompt_no() {
        let dir = get_temp_dir();
        fs::create_dir_all(&dir).unwrap();
        let priv_path = dir.join("key");
        let pub_path = dir.join("key.pub");
        fs::write(&priv_path, "dummy").unwrap();

        let res = check_paths_inner(&priv_path, &pub_path, || Ok(false)).unwrap();
        assert!(!res);
    }

    #[test]
    fn test_generate_and_write_keys() {
        let dir = get_temp_dir();
        fs::create_dir_all(&dir).unwrap();
        let priv_path = dir.join("key");
        let pub_path = dir.join("key.pub");

        let secret = "secret".to_string();
        generate_and_write_keys(&priv_path, &pub_path, Some(&secret)).unwrap();

        assert!(priv_path.exists());
        assert!(pub_path.exists());

        // Verify fingerprint can be read
        display_fingerprint(pub_path.to_str().unwrap()).unwrap();
    }

    #[test]
    fn test_display_fingerprint_error() {
        let dir = get_temp_dir();
        let missing_file = dir.join("missing.pub");
        let res = display_fingerprint(missing_file.to_str().unwrap());
        assert!(res.is_err());
    }
}
