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
        Commands::Generate => generate_keypair(),
        Commands::Verify {
            randomart: _,
            signature: _,
        } => Ok(()),
        Commands::Fingerprint { public_key } => display_fingerprint(public_key),
    }
}

fn generate_keypair() -> Result<()> {
    // Output header
    println!("Generating public/private ed25519 key pair.");

    // Setup and check the key file paths
    let (priv_key_path, pub_key_path) = setup_paths()?;
    if !check_paths(&priv_key_path, &pub_key_path)? {
        return Ok(());
    }

    // Get the optional but highly recommended passphrase
    let passphrase_opt = setup_passphrase(&priv_key_path)?;

    // Generate the key pair
    let keypair = KeyPair::generate_key_pair(passphrase_opt.as_ref())?;

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
                .open(&priv_key_path)?
        }
        #[cfg(not(unix))]
        {
            OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&priv_key_path)?
        }
    };
    keypair.write_private_key(&mut priv_key_file)?;

    // Write the public key out to the public key file
    let mut pub_key_file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&pub_key_path)?;
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

fn setup_paths() -> Result<(PathBuf, PathBuf)> {
    let (default_priv_key_path, default_pub_key_ext) =
        KeyPair::default_key_path_ext(KexMode::Client)?;
    let key_path_prompt = format!(
        "Enter file in which to save the key ({})",
        default_priv_key_path.display()
    );
    let priv_key_path_input: String = Input::new()
        .with_prompt(key_path_prompt)
        .allow_empty(true)
        .interact_text()?;
    let priv_key_path = if priv_key_path_input.is_empty() {
        default_priv_key_path
    } else {
        PathBuf::from(priv_key_path_input)
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

fn check_paths(priv_key_path: &Path, pub_key_path: &Path) -> Result<bool> {
    if priv_key_path.try_exists()? || pub_key_path.try_exists()? {
        println!("{} already exists.", priv_key_path.display());
        Ok(Confirm::new()
            .with_prompt("Overwrite?")
            .default(false)
            .wait_for_newline(true)
            .interact()?)
    } else {
        Ok(true)
    }
}

fn setup_passphrase(priv_key_path: &Path) -> Result<Option<String>> {
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

fn display_fingerprint(public_key_path: &str) -> Result<()> {
    let public_key_file = OpenOptions::new().read(true).open(public_key_path)?;
    let public_key_bytes = extract_public_key_bytes(public_key_file)?;
    println!("{}", fingerprint(&public_key_bytes)?);
    Ok(())
}
