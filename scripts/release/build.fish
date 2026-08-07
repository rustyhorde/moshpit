#!/usr/bin/env fish
# Stage: consume the 28 Linux musl binaries (14 binary/feature variants x
# x86_64/aarch64) that dispatch-remote-builds.fish already staged into
# release-assets/ (built by repomon's linux-build-x86_64/linux-build-aarch64
# jobs — see scripts/release/repomon/linux-build-*.sh), generate the xtask
# dist sidecars, and package DEB/RPM via nfpm. Mirrors the old GitHub
# Actions release.yml `build` job, minus the actual cross-compilation, which
# now happens on a repomon linux runner rather than this machine.
#
# Must run after dispatch-remote-builds.fish: that stage is what populates
# release-assets/ with the musl binaries this script's nfpm packaging step
# needs as local files (see packaging/nfpm/*.yaml's `contents[].src`).

source (path dirname (status --current-filename))/lib.fish

cd (rel_repo_root)
or rel_die "not inside the moshpit git repo"

rel_resolve_tag
rel_require_cmd nfpm

rel_log "building release for $RELEASE_TAG (pkgver $RELEASE_PKGVER)"

set -l linux_x86_64_files \
    mp-x86_64-unknown-linux-musl mp-unstable-x86_64-unknown-linux-musl \
    mps-x86_64-unknown-linux-musl mps-unstable-x86_64-unknown-linux-musl \
    mp-keygen-x86_64-unknown-linux-musl mp-keygen-unstable-x86_64-unknown-linux-musl \
    mpa-x86_64-unknown-linux-musl mpa-unstable-x86_64-unknown-linux-musl \
    mpa-fido2-x86_64-unknown-linux-musl mpa-fido2-unstable-x86_64-unknown-linux-musl \
    mpa-systemd-creds-x86_64-unknown-linux-musl mpa-systemd-creds-unstable-x86_64-unknown-linux-musl \
    mpa-full-x86_64-unknown-linux-musl mpa-full-unstable-x86_64-unknown-linux-musl
set -l linux_aarch64_files \
    mp-aarch64-unknown-linux-musl mp-unstable-aarch64-unknown-linux-musl \
    mps-aarch64-unknown-linux-musl mps-unstable-aarch64-unknown-linux-musl \
    mp-keygen-aarch64-unknown-linux-musl mp-keygen-unstable-aarch64-unknown-linux-musl \
    mpa-aarch64-unknown-linux-musl mpa-unstable-aarch64-unknown-linux-musl \
    mpa-fido2-aarch64-unknown-linux-musl mpa-fido2-unstable-aarch64-unknown-linux-musl \
    mpa-systemd-creds-aarch64-unknown-linux-musl mpa-systemd-creds-unstable-aarch64-unknown-linux-musl \
    mpa-full-aarch64-unknown-linux-musl mpa-full-unstable-aarch64-unknown-linux-musl

# Reset build state for idempotency. Does NOT touch release-assets/ — it
# already holds the Linux/macOS/Windows artifacts
# dispatch-remote-builds.fish staged there.
rm -f $linux_x86_64_files $linux_aarch64_files
rm -f dist-mp.tar.gz dist-mps.tar.gz dist-mp-keygen.tar.gz dist-mpa.tar.gz
mkdir -p release-assets

rel_log "collecting repomon linux-build artifacts from release-assets/"
for f in $linux_x86_64_files $linux_aarch64_files
    cp release-assets/$f $f
    or rel_die "expected repomon linux-build artifact release-assets/$f — did dispatch-remote-builds.fish run first?"
end

rel_log "generating dist sidecars (man pages, completions, licenses, example configs)"
for binary in mp mps mp-keygen mpa
    env VERGEN_IDEMPOTENT=1 cargo run --release --locked -p xtask -- dist $binary
    or rel_die "xtask dist failed for $binary"
end

tar -czf dist-mp.tar.gz        -C dist mp
or rel_die "failed to create dist-mp.tar.gz"
tar -czf dist-mps.tar.gz       -C dist mps
or rel_die "failed to create dist-mps.tar.gz"
tar -czf dist-mp-keygen.tar.gz -C dist mp-keygen
or rel_die "failed to create dist-mp-keygen.tar.gz"
tar -czf dist-mpa.tar.gz       -C dist mpa
or rel_die "failed to create dist-mpa.tar.gz"

rel_log "packaging DEB/RPM via nfpm"
# 14 logical packages x {x86_64, "-aarch64"} = 28 nfpm configs, each
# producing both a .deb and a .rpm — see packaging/nfpm/*.yaml.
for cfg in \
    moshpit moshpit-aarch64 moshpit-unstable moshpit-unstable-aarch64 \
    moshpits moshpits-aarch64 moshpits-unstable moshpits-unstable-aarch64 \
    moshpit-keygen moshpit-keygen-aarch64 moshpit-keygen-unstable moshpit-keygen-unstable-aarch64 \
    moshpit-agent moshpit-agent-aarch64 moshpit-agent-unstable moshpit-agent-unstable-aarch64 \
    moshpit-agent-fido2 moshpit-agent-fido2-aarch64 moshpit-agent-fido2-unstable moshpit-agent-fido2-unstable-aarch64 \
    moshpit-agent-systemd-creds moshpit-agent-systemd-creds-aarch64 \
    moshpit-agent-systemd-creds-unstable moshpit-agent-systemd-creds-unstable-aarch64 \
    moshpit-agent-full moshpit-agent-full-aarch64 moshpit-agent-full-unstable moshpit-agent-full-unstable-aarch64
    env VERSION=$RELEASE_PKGVER nfpm package --config "packaging/nfpm/$cfg.yaml" --packager deb --target release-assets/
    or rel_die "nfpm deb packaging failed for $cfg"
    env VERSION=$RELEASE_PKGVER nfpm package --config "packaging/nfpm/$cfg.yaml" --packager rpm --target release-assets/
    or rel_die "nfpm rpm packaging failed for $cfg"
end

cp dist-mp.tar.gz dist-mps.tar.gz dist-mp-keygen.tar.gz dist-mpa.tar.gz release-assets/

rel_log "release-assets/ contents:"
ls -la release-assets
