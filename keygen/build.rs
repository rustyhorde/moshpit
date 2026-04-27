// Copyright (c) 2025 barto developers
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
    Emitter::default()
        .add_instructions(&Build::all_build())?
        .add_instructions(&Cargo::all_cargo())?
        .add_instructions(&Gix::all_git())?
        .add_instructions(&Rustc::all_rustc())?
        .add_instructions(&Sysinfo::all_sysinfo())?
        .emit()
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
