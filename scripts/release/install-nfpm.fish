#!/usr/bin/env fish
# One-shot installer for nfpm, invoked by Rakefile.toml's `tool.os.nfpm`
# install hook when `nfpm --version` isn't found on PATH. Installs a pinned
# static binary to ~/.local/bin (already on PATH on this host).

source (path dirname (status --current-filename))/lib.fish

set -l nfpm_version 2.43.0
set -l dest ~/.local/bin

mkdir -p $dest

rel_log "installing nfpm $nfpm_version to $dest"
curl -sSL \
    "https://github.com/goreleaser/nfpm/releases/download/v$nfpm_version/nfpm_{$nfpm_version}_Linux_x86_64.tar.gz" \
    | tar -xz -C $dest nfpm
or rel_die "failed to download/extract nfpm"

chmod +x $dest/nfpm
$dest/nfpm --version
