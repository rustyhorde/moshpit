#!/usr/bin/env fish
# Stage: render packaging/homebrew/{moshpit,moshpit-unstable,moshpit-keygen,
# moshpit-keygen-unstable}.rb.tmpl against the macOS bundles repomon's
# macos-build job scp'd back, and push all 4 to the local
# homebrew-moshpit.git tap. No moshpits formula — mps stays Linux-only and
# macos-build.sh never builds it.
#
# No secrets required — homebrew-moshpit.git is a local bare repo
# (/opt/repos/homebrew-moshpit.git), same as this project's main repo. It's
# served by the existing git-backend nginx block (GIT_PROJECT_ROOT
# /opt/repos already exports every repo under /opt/repos) — no SSH, no
# second host. Users tap it with:
#   brew tap jozias/moshpit https://git.jasonozias.com/homebrew-moshpit.git

source (path dirname (status --current-filename))/lib.fish

cd (rel_repo_root)
or rel_die "not inside the moshpit git repo"

rel_resolve_tag
rel_require_cmd git

if rel_is_rc
    rel_log "$RELEASE_TAG is a pre-release tag — nothing to do here"
    exit 0
end

for f in release-assets/mp-aarch64-apple-darwin.tar.gz \
    release-assets/mp-unstable-aarch64-apple-darwin.tar.gz \
    release-assets/mp-keygen-aarch64-apple-darwin.tar.gz \
    release-assets/mp-keygen-unstable-aarch64-apple-darwin.tar.gz
    test -f $f
    or rel_die "$f not found — run dispatch-remote-builds.fish first"
end

set -l mp_sha (sha256sum release-assets/mp-aarch64-apple-darwin.tar.gz | awk '{print $1}')
set -l mp_unstable_sha (sha256sum release-assets/mp-unstable-aarch64-apple-darwin.tar.gz | awk '{print $1}')
set -l mp_keygen_sha (sha256sum release-assets/mp-keygen-aarch64-apple-darwin.tar.gz | awk '{print $1}')
set -l mp_keygen_unstable_sha (sha256sum release-assets/mp-keygen-unstable-aarch64-apple-darwin.tar.gz | awk '{print $1}')

set -l repo_root (rel_repo_root)

set -l formula_mp (mktemp)
sed -e "s/PKGVER/$RELEASE_PKGVER/g" \
    -e "s/MP_MACOS_SHA256/$mp_sha/g" \
    $repo_root/packaging/homebrew/moshpit.rb.tmpl > $formula_mp

set -l formula_mp_unstable (mktemp)
sed -e "s/PKGVER/$RELEASE_PKGVER/g" \
    -e "s/MP_UNSTABLE_MACOS_SHA256/$mp_unstable_sha/g" \
    $repo_root/packaging/homebrew/moshpit-unstable.rb.tmpl > $formula_mp_unstable

set -l formula_keygen (mktemp)
sed -e "s/PKGVER/$RELEASE_PKGVER/g" \
    -e "s/MP_KEYGEN_MACOS_SHA256/$mp_keygen_sha/g" \
    $repo_root/packaging/homebrew/moshpit-keygen.rb.tmpl > $formula_keygen

set -l formula_keygen_unstable (mktemp)
sed -e "s/PKGVER/$RELEASE_PKGVER/g" \
    -e "s/MP_KEYGEN_UNSTABLE_MACOS_SHA256/$mp_keygen_unstable_sha/g" \
    $repo_root/packaging/homebrew/moshpit-keygen-unstable.rb.tmpl > $formula_keygen_unstable

set -l work $repo_root/scripts/release/.work/homebrew-moshpit
rm -rf $work
mkdir -p (path dirname $work)

rel_log "cloning homebrew-moshpit tap"
git clone /opt/repos/homebrew-moshpit.git $work
or rel_die "homebrew-moshpit clone failed"

cd $work
if git show-ref --quiet refs/remotes/origin/master
    git checkout master
else if git rev-parse HEAD >/dev/null 2>&1
    git checkout -B master
else
    git checkout --orphan master
end

mkdir -p Formula
cp $formula_mp Formula/moshpit.rb
rm -f $formula_mp
cp $formula_mp_unstable Formula/moshpit-unstable.rb
rm -f $formula_mp_unstable
cp $formula_keygen Formula/moshpit-keygen.rb
rm -f $formula_keygen
cp $formula_keygen_unstable Formula/moshpit-keygen-unstable.rb
rm -f $formula_keygen_unstable

git config user.name "Jason Ozias"
git config user.email "jason.g.ozias@pm.me"
git add Formula/
if not git diff-index --quiet HEAD 2>/dev/null
    git commit -m "moshpit v$RELEASE_PKGVER"
    or rel_die "commit failed"
else
    rel_log "no formula changes to commit"
end

rel_retry_push "homebrew-moshpit"
cd $repo_root
rm -rf $work

rel_log "published. Verify with:"
rel_log "  brew tap jozias/moshpit https://git.jasonozias.com/homebrew-moshpit.git"
