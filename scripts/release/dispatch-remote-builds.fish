#!/usr/bin/env fish
# Stage: trigger the Linux/macOS/Windows native builds on repomon's
# self-hosted runners (see .repomon/release.toml) by pushing the release
# tag to `origin` (/opt/repos/moshpit.git, repomon-pr-hooked), then wait for
# each job's scp hand-back to land in the staging directory. The Linux leg
# is 2 independent jobs (linux-build-x86_64/-aarch64) that fan out across
# up to 2 repomon linux runners instead of one job building both arches
# sequentially — see scripts/release/RUNBOOK.md.
#
# repomon has no CLI to submit/await a job and no artifact-return channel of
# its own (each job's workspace is deleted right after it finishes, and only
# text logs persist) — so the last step of each repomon job scp's its built
# artifacts to $STAGING_DIR itself, and this script just polls for them.
#
# Runs for -rcN tags too (unlike the publish-* stages): this is exactly how
# you dry-run-verify the repomon leg end to end before cutting a real
# release — see the "Dry-run mode" section of RUNBOOK.md.

source (path dirname (status --current-filename))/lib.fish

cd (rel_repo_root)
or rel_die "not inside the moshpit git repo"

rel_resolve_tag
rel_require_cmd ssh
rel_require_cmd git

set -l staging_root /opt/releases/moshpit/staging
set -l staging_dir $staging_root/$RELEASE_TAG
test -d $staging_root
or rel_die "$staging_root does not exist — do the one-time infra setup first (see RUNBOOK.md)"

mkdir -p $staging_dir
or rel_die "failed to create $staging_dir"

rel_log "pushing $RELEASE_TAG to origin to trigger repomon's linux-build-*/macos-build/windows-build jobs"
# Idempotent: harmless if the tag was already pushed to origin as part of
# the usual multi-remote tag push (gh/origin).
git push origin $RELEASE_TAG
or rel_die "failed to push $RELEASE_TAG to origin"

# 14 binaries per arch: mp/mps/mp-keygen (standard + unstable) plus mpa
# built 4 ways (base/fido2/systemd-creds/full) x (standard + unstable) —
# see .repomon/release.toml's linux-build-* handoff step for the exact list.
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
# macOS/Windows only ship mp + mp-keygen — mps stays Linux-only, mpa is
# Linux-only (its unlock backends are Linux-specific).
set -l macos_files \
    mp-aarch64-apple-darwin.tar.gz mp-unstable-aarch64-apple-darwin.tar.gz \
    mp-keygen-aarch64-apple-darwin.tar.gz mp-keygen-unstable-aarch64-apple-darwin.tar.gz
set -l windows_files \
    mp-x86_64-pc-windows-msvc.exe mp-x86_64-pc-windows-msvc.msi \
    mp-keygen-x86_64-pc-windows-msvc.exe mp-keygen-x86_64-pc-windows-msvc.msi

rel_log "waiting for repomon's linux-build-*/macos-build/windows-build jobs to scp their artifacts into $staging_dir"
rel_log "(watch progress with 'rpmt', or tail ~/.local/share/repomon/logs/moshpit/)"

rel_wait_for_files $staging_dir $linux_x86_64_files $linux_aarch64_files $macos_files $windows_files 2400
or rel_die "timed out waiting for repomon artifacts in $staging_dir — check the repomon daemon/runner logs"

rel_log "collecting repomon artifacts into release-assets/"
# Reset rather than mkdir -p: this is the first stage each pipeline run
# touches release-assets/ (build.fish deliberately doesn't clear it — see
# its own comment). Leftover files from a prior run (an -rcN dry run, or an
# older release) would otherwise sit here indefinitely, since nothing else
# ever prunes them — and publish-packages.fish/publish-static.fish both
# glob/copy release-assets/* wholesale, so stale packages from old
# versions and rc dry-runs would leak into the rolling apt/rpm repo and
# every subsequent static download directory.
rm -rf release-assets
mkdir -p release-assets
for f in $linux_x86_64_files $linux_aarch64_files $macos_files $windows_files
    cp $staging_dir/$f release-assets/
    or rel_die "failed to copy $f from $staging_dir"
end

rel_log "release-assets/ contents:"
ls -la release-assets
