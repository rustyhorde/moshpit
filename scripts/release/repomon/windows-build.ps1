# Runs inside a repomon windows-build job (see .repomon/release.toml).
# Builds the native x86_64-pc-windows-msvc mp/mp-keygen binaries (the only
# 2 moshpit binaries ever built for Windows — mps stays Linux-only, mpa is
# Linux-only) and builds an MSI installer for each via `cargo wix` (WiX
# Toolset v3 + cargo-wix — see scripts/release/RUNBOOK.md's one-time
# setup). Unlike barto's bartoc (a Windows service), moshpit/wix/main.wxs
# and keygen/wix/main.wxs are plain CLI-tool installers: no
# util:ServiceConfig, no ACL custom action — just an install directory and
# a PATH entry.
#
# No `cargo xtask dist` step for either MSI — main.wxs pulls the license
# files directly from the crate's own LICENSE-MIT/LICENSE-APACHE.
#
# VERGEN_IDEMPOTENT is set at the repomon job-env level (see
# .repomon/release.toml), not here.

$ErrorActionPreference = "Stop"

cargo build --release --locked --target x86_64-pc-windows-msvc --bin mp --bin mp-keygen
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

# cargo-wix looks for wix\main.wxs relative to the `--package` crate's
# manifest directory by default — moshpit\wix\main.wxs and
# keygen\wix\main.wxs already sit there, so no --include flag is needed.
#
# No -dVersion, no -dCargoTargetBinDir: cargo-wix already injects both the
# `Version` WiX variable (from the `--package` crate's own Cargo.toml
# version) and the `CargoTargetBinDir` WiX variable (computed from
# --target + profile, i.e. target\x86_64-pc-windows-msvc\release) itself.
# Passing either again as an explicit --compiler-arg -d... redeclares the
# same candle variable and fails hard with error CNDL0288 (this broke
# barto's first real repomon Windows release build — see RUNBOOK.md).
#
# No --compiler-arg/--linker-arg -ext WixUtilExtension either: unlike
# bartoc's main.wxs (which needs the util extension for
# util:ServiceConfig), moshpit's/keygen's main.wxs installs a plain binary
# with no service, so nothing here needs it — and cargo-wix's legacy
# (WiX v3) toolset path already passes -ext WixUtilExtension to both
# candle and light unconditionally regardless, so declaring it again would
# fail with error CNDL0125 if main.wxs is ever extended to need it.
cargo wix --package moshpit --no-build --nocapture --target x86_64-pc-windows-msvc `
    --output mp-x86_64-pc-windows-msvc.msi
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

cargo wix --package moshpit-keygen --no-build --nocapture --target x86_64-pc-windows-msvc `
    --output mp-keygen-x86_64-pc-windows-msvc.msi
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Copy-Item target\x86_64-pc-windows-msvc\release\mp.exe        mp-x86_64-pc-windows-msvc.exe
Copy-Item target\x86_64-pc-windows-msvc\release\mp-keygen.exe mp-keygen-x86_64-pc-windows-msvc.exe
