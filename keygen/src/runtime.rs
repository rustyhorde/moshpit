// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

use std::{
    ffi::OsString,
    fs::OpenOptions,
    io::{BufWriter, Write},
    path::PathBuf,
};

use anyhow::Result;
use argon2::{Argon2, PasswordHasher, password_hash::SaltString};
use aws_lc_rs::{
    aead::{AES_256_GCM_SIV, Aad, RandomizedNonceKey},
    agreement::{PrivateKey, X25519},
    cipher::AES_256_KEY_LEN,
    digest::{self, SHA256, SHA512_OUTPUT_LEN},
    encoding::{AsBigEndian, Curve25519SeedBin},
    hkdf::{HKDF_SHA512, Salt},
    rand::fill,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use bishop::{BishopArt, DrawingOptions};
use clap::Parser as _;
use dialoguer::{Input, Password};
use whoami::fallible::{hostname, username};

use crate::cli::Cli;

#[allow(clippy::too_many_lines)]
pub(crate) fn run<I, T>(args: Option<I>) -> Result<()>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    // Parse the command line
    let _cli = if let Some(args) = args {
        Cli::try_parse_from(args)?
    } else {
        Cli::try_parse()?
    };

    let base_dir = dirs2::home_dir()
        .ok_or_else(|| anyhow::anyhow!("Could not determine home directory"))?
        .join(".mp");
    let default_priv_key_path = base_dir.join("id_ed25519");
    let default_pub_key_ext = "pub";
    println!("Generating public/private ed25519 key pair.");
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

    // TODO: Check for presence of existing key files and prompt before overwriting
    //
    // blah already exists.
    // Overwrite (y/n)? y
    let mut passphrase_opt = None;
    loop {
        let passphrase_prompt = format!(
            "Enter passphrase for \"{}\" (empty for no passphrase)",
            priv_key_path.display()
        );
        let first_passphrase: String = Password::new()
            .with_prompt(passphrase_prompt)
            .allow_empty_password(true)
            .interact()?;

        if first_passphrase.is_empty() {
            break;
        }
        let second_passphrase: String = Password::new()
            .with_prompt("Enter same passphrase again")
            .allow_empty_password(true)
            .interact()?;
        if first_passphrase != second_passphrase {
            eprintln!("Passphrases do not match.  Try again.");
            continue;
        }
        passphrase_opt = Some(first_passphrase);
        break;
    }

    let password_hash_opt = if let Some(passphrase) = &passphrase_opt {
        let salt = SaltString::generate();
        let argon2 = Argon2::default();

        Some(
            argon2
                .hash_password(passphrase.as_bytes(), &salt)?
                .to_string(),
        )
    } else {
        None
    };

    let mut priv_key_output = vec![];
    priv_key_output.extend_from_slice(b"moshpit-key-v1");
    let mut pub_key_output = vec![];

    let priv_key = PrivateKey::generate(&X25519)?;
    let public_key = priv_key.compute_public_key()?;

    let key_alg = "X25519";
    let key_alg_len = u32::try_from(key_alg.len())?;
    let key_alg_len_bytes = key_alg_len.to_be_bytes();

    pub_key_output.extend_from_slice(key_alg_len_bytes.as_ref());
    pub_key_output.extend_from_slice(key_alg.as_bytes());

    let priv_key_bytes: Curve25519SeedBin<'_> = priv_key.as_be_bytes()?;
    let mut priv_key_bytes = (priv_key_bytes.as_ref()).to_vec();
    let pub_key_bytes = public_key.as_ref();
    let pub_key_bytes_len = u32::try_from(pub_key_bytes.len())?;

    pub_key_output.extend_from_slice(&pub_key_bytes_len.to_be_bytes());
    pub_key_output.extend_from_slice(pub_key_bytes);

    if let Some((passphrase, password_hash)) = passphrase_opt.zip(password_hash_opt) {
        let cipher = "aes-256-gcm-siv";
        let cipher_len = u32::try_from(cipher.len())?;
        let cipher_len_bytes = cipher_len.to_be_bytes();
        let kdf = password_hash;
        let kdf_len = u32::try_from(kdf.len())?;
        let kdf_len_bytes = kdf_len.to_be_bytes();
        priv_key_output.extend_from_slice(cipher_len_bytes.as_ref());
        priv_key_output.extend_from_slice(cipher.as_bytes());
        priv_key_output.extend_from_slice(kdf_len_bytes.as_ref());
        priv_key_output.extend_from_slice(kdf.as_bytes());
        priv_key_output.extend_from_slice(key_alg_len_bytes.as_ref());
        priv_key_output.extend_from_slice(key_alg.as_bytes());
        priv_key_output.extend_from_slice(&pub_key_bytes_len.to_be_bytes());
        priv_key_output.extend_from_slice(pub_key_bytes);

        // Encrypt the private key bytes with the passphrase
        let key_bytes = passphrase.as_bytes();

        // Extend the passphrase to 32 bytes (256 bits) for AES-256-GCM-SIV
        let mut salt_bytes = [0u8; SHA512_OUTPUT_LEN];
        let salt_bytes_len = u32::try_from(salt_bytes.len())?;
        let salt_bytes_len_bytes = salt_bytes_len.to_be_bytes();
        fill(&mut salt_bytes)?;

        // Extract pseudo-random key from secret keying materials
        let salt = Salt::new(HKDF_SHA512, &salt_bytes);
        let pseudo_random_key = salt.extract(key_bytes);
        let okm_aes = pseudo_random_key.expand(&[b"aead key"], &AES_256_GCM_SIV)?;
        let mut key_bytes = [0u8; AES_256_KEY_LEN];
        okm_aes.fill(&mut key_bytes)?;
        let rnk = RandomizedNonceKey::new(&AES_256_GCM_SIV, &key_bytes)?;
        let nonce = rnk.seal_in_place_append_tag(Aad::empty(), &mut priv_key_bytes)?;
        let nonce_bytes = nonce.as_ref();
        let nonce_bytes_len = u32::try_from(nonce_bytes.len())?;
        let priv_key_bytes_len = u32::try_from(priv_key_bytes.len())?;
        priv_key_output.extend_from_slice(&salt_bytes_len_bytes);
        priv_key_output.extend_from_slice(&salt_bytes);
        priv_key_output.extend_from_slice(&nonce_bytes_len.to_be_bytes());
        priv_key_output.extend_from_slice(nonce_bytes);
        priv_key_output.extend_from_slice(&priv_key_bytes_len.to_be_bytes());
        priv_key_output.extend_from_slice(&priv_key_bytes);
    } else {
        let cipher = "none";
        let cipher_len = u32::try_from(cipher.len())?;
        let cipher_len_bytes = cipher_len.to_be_bytes();
        let kdf = "none";
        let kdf_len = u32::try_from(kdf.len())?;
        let kdf_len_bytes = kdf_len.to_be_bytes();
        priv_key_output.extend_from_slice(cipher_len_bytes.as_ref());
        priv_key_output.extend_from_slice(cipher.as_bytes());
        priv_key_output.extend_from_slice(kdf_len_bytes.as_ref());
        priv_key_output.extend_from_slice(kdf.as_bytes());
        priv_key_output.extend_from_slice(key_alg_len_bytes.as_ref());
        priv_key_output.extend_from_slice(key_alg.as_bytes());
        priv_key_output.extend_from_slice(&pub_key_bytes_len.to_be_bytes());
        priv_key_output.extend_from_slice(pub_key_bytes);
        let priv_key_bytes_len = u32::try_from(priv_key_bytes.len())?;
        priv_key_output.extend_from_slice(&priv_key_bytes_len.to_be_bytes());
        priv_key_output.extend_from_slice(&priv_key_bytes);
    }

    let encoded = STANDARD.encode(&priv_key_output);
    let mut priv_key_file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&priv_key_path)?;
    let mut buf_writer = BufWriter::new(&mut priv_key_file);
    buf_writer.write_all(encoded.as_bytes())?;

    let pub_encoded = STANDARD.encode(&pub_key_output);
    let mut pub_key_file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&pub_key_path)?;
    let mut pub_buf_writer = BufWriter::new(&mut pub_key_file);
    pub_buf_writer.write_all(b"moshpit ")?;
    pub_buf_writer.write_all(pub_encoded.as_bytes())?;
    let username = username().unwrap_or("unknown-user".to_string());
    let hostname = hostname().unwrap_or("unknown-host".to_string());
    pub_buf_writer.write_all(format!(" {username}@{hostname}").as_bytes())?;

    println!(
        "Your identification has been saved in {}",
        priv_key_path.display()
    );
    println!(
        "Your public key has been saved in {}",
        pub_key_path.display()
    );
    println!("The key fingerprint is:");
    let sha256_digest = digest::digest(&SHA256, pub_key_bytes);
    let encoded_digest = STANDARD.encode(sha256_digest.as_ref());
    println!("SHA256:{encoded_digest} {username}@{hostname}");
    println!("The key's randomart image is:");
    let opts1 = DrawingOptions {
        top_text: "X25519 SHA256".to_string(),
        bottom_text: "SHA256".to_string(),
        ..Default::default()
    };
    let mut art = BishopArt::new();
    art.input(pub_key_bytes);
    print!("{}", art.draw_with_opts(&opts1));
    Ok(())
}
