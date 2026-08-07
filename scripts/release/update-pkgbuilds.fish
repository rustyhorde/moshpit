#!/usr/bin/env fish
# Stage: refresh the in-tree pacman PKGBUILD checksums + .SRCINFO for the 14
# pre-built packages, and commit the change locally.
#
# All 14 source from the self-hosted static download directory published
# alongside everything else by publish-static.fish — no GitHub involvement
# anywhere in this pipeline. Must run after publish-static.fish: the sha256
# sums computed here are of the exact files just published there, and
# publish-arch.fish's later `makepkg` download step fetches from that same
# URL.
#
# No secrets required. .SRCINFO regeneration runs `makepkg --printsrcinfo`
# directly on this machine (Arch/CachyOS) — no throwaway Docker container
# needed.
#
# Unlike a CI-based job, this does NOT open a PR — the same operator runs
# this script and reviews the diff locally, so it just commits in place on
# whatever branch is currently checked out. It also does NOT push; the
# orchestrator reminds the operator to push it afterward.

source (path dirname (status --current-filename))/lib.fish

cd (rel_repo_root)
or rel_die "not inside the moshpit git repo"

rel_resolve_tag
rel_require_cmd makepkg

if rel_is_rc
    rel_log "$RELEASE_TAG is a pre-release tag — nothing to do here"
    exit 0
end

function _sha256
    sha256sum $argv[1] | awk '{print $1}'
end

# Parallel arrays: pkgname (without -bin) | dist tarball | binary-name prefix
# (matches the `mp[-variant]-<arch>` filenames dispatch-remote-builds.fish
# staged and build.fish copied to the repo root).
set -l pkgs \
    moshpit moshpit-unstable \
    moshpits moshpits-unstable \
    moshpit-keygen moshpit-keygen-unstable \
    moshpit-agent moshpit-agent-unstable \
    moshpit-agent-fido2 moshpit-agent-fido2-unstable \
    moshpit-agent-systemd-creds moshpit-agent-systemd-creds-unstable \
    moshpit-agent-full moshpit-agent-full-unstable
set -l dists \
    dist-mp.tar.gz dist-mp.tar.gz \
    dist-mps.tar.gz dist-mps.tar.gz \
    dist-mp-keygen.tar.gz dist-mp-keygen.tar.gz \
    dist-mpa.tar.gz dist-mpa.tar.gz \
    dist-mpa.tar.gz dist-mpa.tar.gz \
    dist-mpa.tar.gz dist-mpa.tar.gz \
    dist-mpa.tar.gz dist-mpa.tar.gz
set -l prefixes \
    mp mp-unstable \
    mps mps-unstable \
    mp-keygen mp-keygen-unstable \
    mpa mpa-unstable \
    mpa-fido2 mpa-fido2-unstable \
    mpa-systemd-creds mpa-systemd-creds-unstable \
    mpa-full mpa-full-unstable

for i in (seq (count $pkgs))
    set -l pkg $pkgs[$i]
    set -l dist $dists[$i]
    set -l prefix $prefixes[$i]
    set -l dir "packaging/arch/$pkg-bin"

    for f in release-assets/$dist release-assets/$prefix-x86_64-unknown-linux-musl release-assets/$prefix-aarch64-unknown-linux-musl
        test -f $f
        or rel_die "$f not found — run build.fish first"
    end

    set -l dist_sha (_sha256 release-assets/$dist)
    set -l x86_64_sha (_sha256 release-assets/$prefix-x86_64-unknown-linux-musl)
    set -l aarch64_sha (_sha256 release-assets/$prefix-aarch64-unknown-linux-musl)

    rel_log "updating $dir/PKGBUILD"
    sed -i "s/^pkgver=.*/pkgver=$RELEASE_PKGVER/" $dir/PKGBUILD
    sed -i "s/^pkgrel=.*/pkgrel=1/" $dir/PKGBUILD
    # moshpits-bin's first sha256sums entry is followed by a local sidecar
    # file's checksum ('SKIP') — only the dist-tarball entry (first array
    # element) ever changes here, so replace just that element in place
    # rather than the whole array.
    if test $pkg = moshpits; or test $pkg = moshpits-unstable
        sed -i "s/^sha256sums=('[^']*'/sha256sums=('$dist_sha'/" $dir/PKGBUILD
    else
        sed -i "s|^sha256sums=.*|sha256sums=('$dist_sha')|" $dir/PKGBUILD
    end
    sed -i "s|^sha256sums_x86_64=.*|sha256sums_x86_64=('$x86_64_sha')|" $dir/PKGBUILD
    sed -i "s|^sha256sums_aarch64=.*|sha256sums_aarch64=('$aarch64_sha')|" $dir/PKGBUILD
end

for pkg in $pkgs
    set -l dir "packaging/arch/$pkg-bin"
    rel_log "regenerating $dir/.SRCINFO"
    pushd $dir
    makepkg --printsrcinfo > .SRCINFO
    or rel_die "makepkg --printsrcinfo failed for $pkg-bin"
    popd
end

git add packaging/arch/
if not git diff --cached --quiet
    git commit -m "chore(packaging): update PKGBUILDs to v$RELEASE_PKGVER"
    or rel_die "commit failed"
    rel_log "committed PKGBUILD updates — review and push this yourself (git log -1 -p -- packaging/arch)"
else
    rel_log "no PKGBUILD changes to commit"
end
