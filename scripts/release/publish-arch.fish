#!/usr/bin/env fish
# Stage: build and publish a self-hosted pacman repo to
# /opt/releases/moshpit/arch/{x86_64,aarch64}, served at
# https://git.jasonozias.com/dl/moshpit/arch/$arch via the existing /dl/
# alias — no nginx.conf changes needed. This fully replaces AUR for moshpit
# (no aur-publish stage exists in this pipeline — see RUNBOOK.md).
#
# Rolling repo, not versioned: each run replaces the previous 14 -bin
# packages (moshpit/moshpits/moshpit-keygen x {standard,unstable}, plus
# moshpit-agent built 4 ways x {standard,unstable} — base/fido2/
# systemd-creds/full) in each arch's repo with freshly-built ones,
# mirroring publish-packages.fish's APT/RPM approach. Built locally via
# `makepkg` from the just-refreshed packaging/arch/*/PKGBUILD (see
# update-pkgbuilds.fish) rather than a CI runner. package() only installs
# prebuilt musl binaries (no compilation, no depends/makedepends beyond the
# runtime optdepends — see the PKGBUILDs), so producing the aarch64 package
# doesn't require aarch64 execution: a scratch makepkg.conf per arch
# overrides CARCH, which /etc/makepkg.conf's plain `CARCH="x86_64"`
# assignment would otherwise clobber if only set via an exported env var.
#
# Every package is individually signed at build time (makepkg --sign),
# producing a binary detached <pkgfile>.sig alongside it, in addition to
# repo-add -s signing the database itself — both use the "moshpit packages
# <jason.g.ozias@pm.me>" GPG key already used for the APT/RPM repos (see
# RUNBOOK.md's one-time setup). Package signing (not just the database) is
# required so clients can use the standard `SigLevel = Required` in
# pacman.conf.
#
# Stale package/signature files from prior releases are deleted from each
# arch's destination directory before this run's builds are copied in, so
# the repo never keeps re-publishing old unsigned (or superseded) packages
# alongside the new ones.

source (path dirname (status --current-filename))/lib.fish

cd (rel_repo_root)
or rel_die "not inside the moshpit git repo"

rel_resolve_tag
rel_require_cmd makepkg
rel_require_cmd repo-add
rel_require_cmd gpg

if rel_is_rc
    rel_log "$RELEASE_TAG is a pre-release tag — nothing to do here"
    exit 0
end

set -l gpg_user jason.g.ozias@pm.me
set -l dest /opt/releases/moshpit/arch
test -d $dest/x86_64
and test -d $dest/aarch64
or rel_die "$dest/{x86_64,aarch64} do not exist — do the one-time pacman repo setup first (see RUNBOOK.md)"

set -l repo_root (rel_repo_root)
set -l work $repo_root/scripts/release/.work/arch-build
rm -rf $work
mkdir -p $work

set -l packages \
    moshpit-bin moshpit-unstable-bin \
    moshpits-bin moshpits-unstable-bin \
    moshpit-keygen-bin moshpit-keygen-unstable-bin \
    moshpit-agent-bin moshpit-agent-unstable-bin \
    moshpit-agent-fido2-bin moshpit-agent-fido2-unstable-bin \
    moshpit-agent-systemd-creds-bin moshpit-agent-systemd-creds-unstable-bin \
    moshpit-agent-full-bin moshpit-agent-full-unstable-bin

for arch in x86_64 aarch64
    set -l makepkg_conf $work/makepkg-$arch.conf
    sed "s/^CARCH=.*/CARCH=\"$arch\"/" /etc/makepkg.conf > $makepkg_conf

    rel_log "clearing stale packages/signatures from $dest/$arch"
    find $dest/$arch -maxdepth 1 \( -name '*.pkg.tar.zst' -o -name '*.pkg.tar.zst.sig' \) -delete

    for pkg in $packages
        rel_log "building $pkg for $arch"
        set -l pkgwork $work/$pkg-$arch
        rm -rf $pkgwork
        cp -r $repo_root/packaging/arch/$pkg $pkgwork

        pushd $pkgwork
        makepkg --config $makepkg_conf -f --noconfirm --sign --key $gpg_user
        or rel_die "makepkg failed for $pkg ($arch)"
        popd

        cp $pkgwork/*.pkg.tar.zst $pkgwork/*.pkg.tar.zst.sig $dest/$arch/
    end
end

for arch in x86_64 aarch64
    rel_log "generating pacman repo db for $arch"
    pushd $dest/$arch
    repo-add -s -k $gpg_user moshpit.db.tar.gz *.pkg.tar.zst
    or rel_die "repo-add failed for $arch"
    popd
end

rel_log "published. Verify with:"
rel_log "  curl -I https://git.jasonozias.com/dl/moshpit/arch/x86_64/moshpit.db.tar.gz"
rel_log "  curl -I https://git.jasonozias.com/dl/moshpit/arch/aarch64/moshpit.db.tar.gz"
