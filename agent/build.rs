// Copyright (c) 2025 moshpit developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

use anyhow::Result;
use vergen_gix::{Build, Cargo, Emitter, Gix, Rustc, Sysinfo};

pub fn main() -> Result<()> {
    println!("cargo:rustc-check-cfg=cfg(coverage_nightly)");
    nightly();

    if std::env::var("CARGO_FEATURE_FIDO2").is_ok() {
        link_fido2();
    }
    Emitter::default()
        .add_instructions(&Build::all_build())?
        .add_instructions(&Cargo::all_cargo())?
        .add_instructions(&Gix::all_git())?
        .add_instructions(&Rustc::all_rustc())?
        .add_instructions(&Sysinfo::all_sysinfo())?
        .emit()
}

fn link_fido2() {
    println!("cargo:rerun-if-env-changed=PKG_CONFIG_PATH");
    let target_env = std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    if target_env == "musl" {
        // Static link for MUSL cross builds; libs are pre-installed in the cross Docker image.
        println!("cargo:rustc-link-search=/usr/local/lib");
        println!("cargo:rustc-link-lib=static=fido2");
        println!("cargo:rustc-link-lib=static=cbor");
        println!("cargo:rustc-link-lib=static=hidapi-hidraw");
        println!("cargo:rustc-link-lib=static=usb-1.0");
        println!("cargo:rustc-link-lib=static=crypto");
        println!("cargo:rustc-link-lib=static=z");
    } else {
        pkg_config::probe_library("libfido2").expect(
            "libfido2 not found; install the libfido2 package (e.g. `sudo pacman -S libfido2`)",
        );
    }
}

#[rustversion::nightly]
fn nightly() {
    println!("cargo:rustc-check-cfg=cfg(nightly)");
    println!("cargo:rustc-cfg=nightly");
}

#[rustversion::not(nightly)]
fn nightly() {
    println!("cargo:rustc-check-cfg=cfg(nightly)");
}
