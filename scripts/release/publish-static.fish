#!/usr/bin/env fish
# Stage: publish the built release-assets/ to a plain static download
# directory on this machine, served at
# https://git.jasonozias.com/dl/moshpit/$RELEASE_TAG/<asset> once the
# one-time nginx wiring (see RUNBOOK.md's one-time setup section) is done.
#
# No secrets, no GitHub Release object — the pacman PKGBUILDs'
# source=/source_x86_64=/source_aarch64= arrays and the Homebrew formulas
# only need a stable, checksummed URL; they don't care what serves it.

source (path dirname (status --current-filename))/lib.fish

cd (rel_repo_root)
or rel_die "not inside the moshpit git repo"

rel_resolve_tag

if rel_is_rc
    rel_log "$RELEASE_TAG is a pre-release tag — nothing to do here"
    exit 0
end

set -l dest /opt/releases/moshpit/$RELEASE_TAG
if not test -d /opt/releases/moshpit
    rel_die "/opt/releases/moshpit does not exist — do the one-time infra setup first (see RUNBOOK.md)"
end

for f in release-assets/dist-mp.tar.gz release-assets/dist-mps.tar.gz \
    release-assets/dist-mp-keygen.tar.gz release-assets/dist-mpa.tar.gz \
    release-assets/mp-x86_64-unknown-linux-musl release-assets/mp-aarch64-unknown-linux-musl \
    release-assets/mp-keygen-x86_64-unknown-linux-musl release-assets/mp-keygen-aarch64-unknown-linux-musl \
    release-assets/mp-aarch64-apple-darwin.tar.gz release-assets/mp-keygen-aarch64-apple-darwin.tar.gz \
    release-assets/mp-x86_64-pc-windows-msvc.exe release-assets/mp-x86_64-pc-windows-msvc.msi \
    release-assets/mp-keygen-x86_64-pc-windows-msvc.exe release-assets/mp-keygen-x86_64-pc-windows-msvc.msi
    test -f $f
    or rel_die "$f not found — run build.fish and dispatch-remote-builds.fish first"
end

rel_log "publishing release-assets/ to $dest"
mkdir -p $dest
or rel_die "failed to create $dest"

for f in release-assets/*
    install -Dm644 $f $dest/(path basename $f)
    or rel_die "failed to install $f to $dest"
end

rel_log "published. Verify with:"
rel_log "  curl -I https://git.jasonozias.com/dl/moshpit/$RELEASE_TAG/dist-mp.tar.gz"
