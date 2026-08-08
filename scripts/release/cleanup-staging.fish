#!/usr/bin/env fish
# Stage: prune /opt/releases/moshpit/staging/ — the scratch scp landing zone
# dispatch-remote-builds.fish uses to collect each repomon build job's
# artifacts (see RUNBOOK.md). Every release run creates a new
# $RELEASE_TAG-named subdirectory there and nothing else ever removes it,
# so -rcN dry runs in particular pile up fast.
#
# Keeps only the most recent 2 final-release tag directories and the single
# most recent -rcN tag directory (by mtime); everything else under
# staging/ is deleted. Runs unconditionally at the end of release.fish,
# including for -rcN dry runs that skip the publish stages — those are
# exactly what fills this directory up during testing.

source (path dirname (status --current-filename))/lib.fish

set -l staging_root /opt/releases/moshpit/staging
if not test -d $staging_root
    rel_log "$staging_root does not exist — nothing to clean up"
    exit 0
end

set -l keep_final 2
set -l keep_rc 1

# Newest first, by mtime.
set -l sorted (find $staging_root -mindepth 1 -maxdepth 1 -type d -printf '%T@ %p\n' | sort -rn | cut -d' ' -f2-)

set -l final_dirs
set -l rc_dirs
for d in $sorted
    set -l name (path basename $d)
    if string match -qr -- '-rc' $name
        set -a rc_dirs $d
    else
        set -a final_dirs $d
    end
end

set -l to_delete
if test (count $final_dirs) -gt $keep_final
    set -a to_delete $final_dirs[(math $keep_final + 1)..-1]
end
if test (count $rc_dirs) -gt $keep_rc
    set -a to_delete $rc_dirs[(math $keep_rc + 1)..-1]
end

if test (count $to_delete) -eq 0
    rel_log "staging/ cleanup: nothing to prune (keeping "(count $final_dirs)" final + "(count $rc_dirs)" rc tag dir(s))"
    exit 0
end

for d in $to_delete
    rel_log "pruning stale staging dir: $d"
    rm -rf $d
    or rel_warn "failed to remove $d"
end
