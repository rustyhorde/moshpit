#!/usr/bin/env fish
# Stage: build and publish the signed APT and RPM repositories to
# /opt/releases/moshpit/{apt,rpm}, served at
# https://git.jasonozias.com/dl/moshpit/{apt,rpm} via the existing /dl/
# alias — no nginx.conf changes needed. Replaces the former
# rustyhorde/moshpit-packages GitHub Pages repo.
#
# Rolling repo, not versioned: each run replaces the previous .deb/.rpm in
# the pool with the ones just built. Signed with the "moshpit packages
# <jason.g.ozias@pm.me>" GPG key (see RUNBOOK.md's one-time setup) rather
# than a CI secret. The client-facing moshpit.sources/moshpit.repo are
# tracked in packaging/{apt,rpm}/ and synced into place on every run, so
# they can't silently drift from what's reviewed in git.

source (path dirname (status --current-filename))/lib.fish

cd (rel_repo_root)
or rel_die "not inside the moshpit git repo"

rel_resolve_tag
rel_require_cmd apt-ftparchive
rel_require_cmd createrepo_c
rel_require_cmd gpg

if rel_is_rc
    rel_log "$RELEASE_TAG is a pre-release tag — nothing to do here"
    exit 0
end

# Fingerprint, not the "jason.g.ozias@pm.me" email — see publish-arch.fish
# for why: that email is ambiguous in this machine's keyring against the
# operator's personal key, and gpg silently resolves an ambiguous
# --local-user match instead of erroring.
set -l gpg_user 7452D2FCB49882326B7580E85A25FB9A0E414B67
set -l dest /opt/releases/moshpit
test -d $dest/apt
and test -d $dest/rpm
or rel_die "$dest/{apt,rpm} do not exist — do the one-time package repo setup first (see RUNBOOK.md)"

rel_log "syncing client config files"
cp packaging/apt/moshpit.sources $dest/apt/moshpit.sources
cp packaging/rpm/moshpit.repo $dest/rpm/moshpit.repo

for f in release-assets/*_amd64.deb release-assets/*_arm64.deb \
    release-assets/*.x86_64.rpm release-assets/*.aarch64.rpm
    test -f $f
    or rel_die "$f not found — run build.fish first"
end

rel_log "adding DEB packages to APT pool"
find $dest/apt/pool/main -maxdepth 1 -name '*.deb' -delete
cp release-assets/*_amd64.deb release-assets/*_arm64.deb $dest/apt/pool/main/

rel_log "adding RPM packages to RPM pool"
find $dest/rpm/x86_64 $dest/rpm/aarch64 -maxdepth 1 -name '*.rpm' -delete
cp release-assets/*.x86_64.rpm $dest/rpm/x86_64/
cp release-assets/*.aarch64.rpm $dest/rpm/aarch64/

rel_log "generating APT repo metadata"
# apt-ftparchive's Tree generation writes Packages/Contents straight into
# these dirs but never creates them itself — and silently exits 0 even
# when every write fails with ENOENT, so a missing dir here doesn't trip
# the `or rel_die` below. Pre-create them every run so a fresh/reset
# dists/stable can't leave the repo publishing a signed Release with no
# actual package indices.
mkdir -p $dest/apt/dists/stable/main/binary-amd64 $dest/apt/dists/stable/main/binary-arm64
set -l apt_cache (mktemp -d)
set -l apt_conf (mktemp)
# A `Tree` stanza (not two `BinDirectory "pool/main" { ... }` stanzas, one
# per arch — apt-ftparchive's config keys sections by directory path, so a
# second `BinDirectory "pool/main"` silently overwrites the first and only
# one architecture's Packages file gets generated).
printf '%s\n' \
    'Dir {' \
    "  ArchiveDir \"$dest/apt\";" \
    "  CacheDir \"$apt_cache\";" \
    '};' \
    '' \
    'Default {' \
    '  Packages::Compress ". gzip xz";' \
    '};' \
    '' \
    'TreeDefault {' \
    '  Directory "pool/main";' \
    '};' \
    '' \
    'Tree "dists/stable" {' \
    '  Sections "main";' \
    '  Architectures "amd64 arm64";' \
    '};' \
    > $apt_conf

apt-ftparchive generate $apt_conf
or rel_die "apt-ftparchive generate failed"

apt-ftparchive \
    -o APT::FTPArchive::Release::Origin=moshpit \
    -o APT::FTPArchive::Release::Label=moshpit \
    -o APT::FTPArchive::Release::Suite=stable \
    -o APT::FTPArchive::Release::Codename=stable \
    -o APT::FTPArchive::Release::Architectures="amd64 arm64" \
    -o APT::FTPArchive::Release::Components=main \
    -o APT::FTPArchive::Release::Description="moshpit package repository" \
    release $dest/apt/dists/stable > $dest/apt/dists/stable/Release
or rel_die "apt-ftparchive release failed"

rm -rf $apt_cache
rm -f $apt_conf

gpg --batch --yes --local-user $gpg_user --armor --clearsign \
    -o $dest/apt/dists/stable/InRelease \
    $dest/apt/dists/stable/Release
or rel_die "failed to sign InRelease"

gpg --batch --yes --local-user $gpg_user --armor --detach-sign \
    -o $dest/apt/dists/stable/Release.gpg \
    $dest/apt/dists/stable/Release
or rel_die "failed to sign Release.gpg"

rel_log "generating RPM repo metadata"
for arch in x86_64 aarch64
    createrepo_c --update $dest/rpm/$arch/
    or rel_die "createrepo_c failed for $arch"

    gpg --batch --yes --local-user $gpg_user --armor --detach-sign \
        -o $dest/rpm/$arch/repodata/repomd.xml.asc \
        $dest/rpm/$arch/repodata/repomd.xml
    or rel_die "failed to sign repomd.xml for $arch"
end

rel_log "published. Verify with:"
rel_log "  curl -I https://git.jasonozias.com/dl/moshpit/apt/dists/stable/InRelease"
rel_log "  curl -I https://git.jasonozias.com/dl/moshpit/rpm/x86_64/repodata/repomd.xml"
