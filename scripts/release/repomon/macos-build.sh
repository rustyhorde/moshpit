#!/bin/sh
# Runs inside a repomon macos-build job (see .repomon/release.toml). Builds
# the native aarch64-apple-darwin mp/mp-keygen binaries (standard +
# unstable) — no mps (the server stays Linux-only) and no mpa (its unlock
# backends are Linux-specific) — and bundles each into its `xtask dist`
# sidecar directory before tarring, matching the former GitHub Actions
# release.yml build-macos job exactly: the tarball contains the binary
# alongside the man page/completions/example config, which is what the
# Homebrew formulas (packaging/homebrew/*.rb.tmpl) expect to unpack flat.
set -eu

cargo xtask dist mp
cargo xtask dist mp-keygen

t=aarch64-apple-darwin

# Standard build
cargo build --release --locked --target "$t" --bin mp --bin mp-keygen
cp "target/$t/release/mp"        dist/mp/mp
cp "target/$t/release/mp-keygen" dist/mp-keygen/mp-keygen
tar -czf mp-aarch64-apple-darwin.tar.gz        -C dist mp
tar -czf mp-keygen-aarch64-apple-darwin.tar.gz -C dist mp-keygen

# Unstable build (post-quantum ML-DSA identity key support) — overwrites
# the binaries in target/ and dist/, dist sidecar artifacts are identical.
cargo build --release --locked --target "$t" --features unstable --bin mp --bin mp-keygen
cp "target/$t/release/mp"        dist/mp/mp
cp "target/$t/release/mp-keygen" dist/mp-keygen/mp-keygen
tar -czf mp-unstable-aarch64-apple-darwin.tar.gz        -C dist mp
tar -czf mp-keygen-unstable-aarch64-apple-darwin.tar.gz -C dist mp-keygen
