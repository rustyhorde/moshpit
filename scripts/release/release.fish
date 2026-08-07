#!/usr/bin/env fish
# Orchestrator for the local moshpit release pipeline. Invoked via
# `cargo rake release` (see the [target.release] entry in Rakefile.toml).
#
# Usage: create and push a vX.Y.Z (or vX.Y.Z-rcN) tag first, then run this
# from the repo root (or let Rakefile.toml run it for you):
#
#   fish scripts/release/bump-version.fish 0.9.5 && git add -u && git commit -m 'chore(deps): version bump for next release'
#   git tag v0.9.5 && git push origin v0.9.5 && git push gh v0.9.5
#   cargo rake release
#
# -rc tags are a build-only dry run: every publish stage after build.fish is
# skipped (cleanup-staging.fish still runs) — see the "Dry-run mode" section
# of RUNBOOK.md. Note this still exercises the repomon Linux/macOS/Windows
# legs in full (build + scp hand-back), unlike a plain "build locally only"
# dry run.
#
# Unlike GitHub Actions, this pipeline needs no `gh release create` step:
# binaries are copied straight to a self-hosted static download directory
# (see publish-static.fish and RUNBOOK.md's one-time setup) rather than
# attached to a release object. It also needs no CI secrets: crates.io
# publishing reads the operator's own `cargo login` token, and package
# signing uses the operator's own GPG key.

source (path dirname (status --current-filename))/lib.fish

cd (rel_repo_root)
or rel_die "not inside the moshpit git repo"

rel_resolve_tag
# Export so every stage script (each a separate `fish` process) inherits
# the same tag/version, rather than re-deriving it from HEAD — a later
# stage (update-pkgbuilds.fish) commits to the current branch, which would
# otherwise move HEAD off the tag before the next stage runs.
set -gx RELEASE_TAG $RELEASE_TAG
set -gx RELEASE_PKGVER $RELEASE_PKGVER
rel_log "releasing $RELEASE_TAG (pkgver $RELEASE_PKGVER)"

set -l here (path dirname (status --current-filename))

fish $here/dispatch-remote-builds.fish
or rel_die "dispatch-remote-builds stage failed"

fish $here/build.fish
or rel_die "build stage failed"

if rel_is_rc
    rel_log "$RELEASE_TAG is a pre-release (-rc) tag — build-only dry run complete (including the repomon Linux/macOS/Windows legs); skipping publish stages"
else
    for stage in publish-static update-pkgbuilds publish-arch publish-packages update-homebrew publish-crates
        fish $here/$stage.fish
        or rel_die "$stage stage failed"
    end

    rel_log "release $RELEASE_TAG complete."
    rel_log "reminder: review and push the packaging commit created by update-pkgbuilds.fish (git log -1 -p -- packaging/arch)"
end

# Runs even for -rcN dry runs (those are the common case for filling up
# staging/ during testing) — best-effort, doesn't fail the release.
fish $here/cleanup-staging.fish
or rel_warn "cleanup-staging stage failed (non-fatal)"
