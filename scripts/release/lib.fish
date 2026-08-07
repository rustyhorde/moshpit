#!/usr/bin/env fish
# Shared helpers for scripts/release/*.fish. Sourced, never executed directly.
#
# Fish has no `set -e`; every risky external command in the stage scripts is
# followed by `; or rel_die "..."` instead.

function rel_log
    echo "[release] $argv"
end

function rel_warn
    echo "[release] warning: $argv" >&2
end

function rel_die
    echo "[release] error: $argv" >&2
    exit 1
end

function rel_require_cmd
    type -q $argv[1]
    or rel_die "required command '$argv[1]' not found on PATH"
end

function rel_repo_root
    git rev-parse --show-toplevel
    or rel_die "not inside the moshpit git repository"
end

# Sets RELEASE_TAG / RELEASE_PKGVER from whatever release-shaped tag points
# at HEAD. If a single final (non-RC) tag is present, it wins over any
# leftover -rcN dry-run tags on the same commit. Dies on genuine ambiguity:
# multiple final tags, or multiple RC tags with no final tag to prefer.
#
# If RELEASE_TAG/RELEASE_PKGVER are already set (exported by an orchestrator
# that resolved them once up front), reuse them as-is instead of
# re-deriving from HEAD — later stages (e.g. update-pkgbuilds.fish) commit
# to the current branch, which would otherwise move HEAD off the tag before
# the next stage runs. Running a single stage script standalone in a fresh
# shell still resolves from HEAD as before.
function rel_resolve_tag
    if set -q RELEASE_TAG; and set -q RELEASE_PKGVER
        return 0
    end

    set -l tags (git tag --points-at HEAD | string match -r '^v[0-9].*')
    if test (count $tags) -eq 0
        rel_die "HEAD is not tagged with a vX.Y.Z or vX.Y.Z-rcN tag. Create and push one first: git tag vX.Y.Z && git push origin vX.Y.Z && git push gh vX.Y.Z"
    end

    set -l final_tags
    for t in $tags
        if not string match -qr -- '-rc' $t
            set -a final_tags $t
        end
    end

    if test (count $final_tags) -eq 1
        set -g RELEASE_TAG $final_tags[1]
        if test (count $tags) -gt 1
            rel_log "ignoring leftover RC tag(s) on HEAD in favor of $RELEASE_TAG: "(string join ' ' (string match -v $RELEASE_TAG -- $tags))
        end
    else if test (count $final_tags) -gt 1
        rel_die "HEAD has multiple final release tags ($final_tags); remove the extra one(s) before releasing"
    else if test (count $tags) -eq 1
        set -g RELEASE_TAG $tags[1]
    else
        rel_die "HEAD has multiple RC tags and no final release tag ($tags); remove the extra one(s) before releasing"
    end

    set -g RELEASE_PKGVER (string replace -r '^v' '' -- $RELEASE_TAG)
end

function rel_is_rc
    string match -qr -- '-rc' $RELEASE_TAG
end

# Push the current directory's `master` branch with 3 attempts / 10s backoff.
# $argv[1] is a short description used in log messages.
function rel_retry_push
    set -l desc $argv[1]
    for attempt in 1 2 3
        if git push origin master
            return 0
        end
        if test $attempt -lt 3
            rel_warn "$desc push attempt $attempt failed, retrying in 10s..."
            sleep 10
        else
            rel_die "$desc: all push attempts failed."
        end
    end
end

# Polls $argv[2..] (relative filenames) inside directory $argv[1] until every
# one exists, or $timeout_s (last arg) elapses. Used to wait for the repomon
# macOS/Windows/Linux jobs' scp hand-back — repomon itself has no
# synchronous "wait for job N" API (see dispatch-remote-builds.fish), so
# this is a plain poll loop instead of anything repomon-aware.
#
# Existence-only is safe here *because* every handoff script (linux-
# handoff.sh/macos-handoff.sh/windows-handoff.ps1) scp's to a `.partial`
# suffix and atomically mv's it into the final name only once the transfer
# is complete — a plain `scp foo "$dest"` would create `foo` and start
# streaming into it immediately, letting this poll observe and hand off a
# partially-written file. Don't relax those scripts back to a direct scp
# without also changing this to a size-stability check.
function rel_wait_for_files
    set -l dir $argv[1]
    set -l timeout_s $argv[-1]
    set -l files $argv[2..-2]

    set -l waited 0
    set -l interval 15

    while true
        set -l missing
        for f in $files
            test -f "$dir/$f"
            or set -a missing $f
        end

        if test (count $missing) -eq 0
            return 0
        end

        if test $waited -ge $timeout_s
            rel_warn "timed out after {$timeout_s}s waiting for: $missing"
            return 1
        end

        if test (math "$waited % 60") -eq 0
            rel_log "waiting for repomon artifacts in $dir ("(math "$timeout_s - $waited")"s left): still missing $missing"
        end

        sleep $interval
        set waited (math "$waited + $interval")
    end
end
