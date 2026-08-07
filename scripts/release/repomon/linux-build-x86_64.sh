#!/bin/sh
# Runs inside the repomon linux-build-x86_64 job (see .repomon/release.toml)
# — one of two jobs that split the Linux musl cross-builds by architecture
# across separate machines. Builds mp/mps/mp-keygen and 8 mpa (moshpit-agent)
# variants for x86_64-unknown-linux-musl, matching the former GitHub Actions
# release.yml `build` job's x86_64 leg — minus the ssh-agent-piggyback-only
# and full source-build PKGBUILD variants no longer individually packaged
# (see scripts/release/RUNBOOK.md's consolidation note). No test suite is
# run here — testing happens on every push via .repomon/ci.toml, not
# redundantly at release time.
#
# The moshpit-cross-x86_64 Docker image bundles static libfido2/libcbor/
# libusb/hidapi/libudev-zero for the FIDO2 unlock backend (see
# docker/Dockerfile.x86_64-unknown-linux-musl and Cross.toml) — plain
# `cross build` against an upstream image (as barto/salus do) isn't enough
# here.
#
# `cross` is bootstrapped here (same install command as the sibling
# projects' `[tool.cargo.cross]`) since this script runs standalone via
# repomon, not through `cargo rake`. Requires Docker already installed on
# this machine (see RUNBOOK.md's one-time setup).
#
# VERGEN_IDEMPOTENT is set at the repomon job-env level (see
# .repomon/release.toml), not here.
set -eu

command -v cross >/dev/null 2>&1 || cargo install cross --force --locked

docker build \
    -t moshpit-cross-x86_64 \
    -f docker/Dockerfile.x86_64-unknown-linux-musl \
    docker/

t=x86_64-unknown-linux-musl

# Standard build: mp, mps, mp-keygen
cross build --release --locked --target "$t" --bin mp --bin mps --bin mp-keygen
cp "target/$t/release/mp"        "mp-$t"
cp "target/$t/release/mps"       "mps-$t"
cp "target/$t/release/mp-keygen" "mp-keygen-$t"

# Unstable build (post-quantum ML-DSA identity key support)
cross build --release --locked --target "$t" --features unstable --bin mp --bin mps --bin mp-keygen
cp "target/$t/release/mp"        "mp-unstable-$t"
cp "target/$t/release/mps"       "mps-unstable-$t"
cp "target/$t/release/mp-keygen" "mp-keygen-unstable-$t"

# mpa — passphrase only (base)
cross build --release --locked --target "$t" --bin mpa
cp "target/$t/release/mpa" "mpa-$t"

# mpa — FIDO2 unlock
cross build --release --locked --target "$t" -p moshpit-agent --features fido2 --bin mpa
cp "target/$t/release/mpa" "mpa-fido2-$t"

# mpa — systemd credentials unlock
cross build --release --locked --target "$t" -p moshpit-agent --features systemd-creds --bin mpa
cp "target/$t/release/mpa" "mpa-systemd-creds-$t"

# mpa — full (all MUSL-portable features: fido2 + systemd-creds + ssh-agent-piggyback)
cross build --release --locked --target "$t" -p moshpit-agent --features fido2,systemd-creds,ssh-agent-piggyback --bin mpa
cp "target/$t/release/mpa" "mpa-full-$t"

# mpa — unstable builds (post-quantum ML-DSA identity key support)
cross build --release --locked --target "$t" -p moshpit-agent --features unstable --bin mpa
cp "target/$t/release/mpa" "mpa-unstable-$t"

cross build --release --locked --target "$t" -p moshpit-agent --features fido2,unstable --bin mpa
cp "target/$t/release/mpa" "mpa-fido2-unstable-$t"

cross build --release --locked --target "$t" -p moshpit-agent --features systemd-creds,unstable --bin mpa
cp "target/$t/release/mpa" "mpa-systemd-creds-unstable-$t"

cross build --release --locked --target "$t" -p moshpit-agent --features fido2,systemd-creds,ssh-agent-piggyback,unstable --bin mpa
cp "target/$t/release/mpa" "mpa-full-unstable-$t"
