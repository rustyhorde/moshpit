#!/usr/bin/env fish
# Stage: publish libmoshpit, moshpit, moshpits, moshpit-keygen, and
# moshpit-agent to crates.io, in dependency order (libmoshpit must land
# first; the other 4 all depend on it by version+path). A straight port of
# the old GitHub Actions release.yml `publish-crates` job into a local
# script; it expects `cargo login` to already be configured with a
# crates.io API token on this machine (there's no CI secret to read it from
# anymore).

source (path dirname (status --current-filename))/lib.fish

cd (rel_repo_root)
or rel_die "not inside the moshpit git repo"

rel_resolve_tag
rel_require_cmd cargo

if rel_is_rc
    rel_log "$RELEASE_TAG is a pre-release tag — nothing to do here"
    exit 0
end

# `cargo publish` blocks until the crate is queryable, but the index can
# still lag for dependents, so retry the dependent publish.
function rel_publish_with_retry --argument-names crate
    for attempt in 1 2 3 4 5
        if cargo publish -p $crate --locked --no-verify
            return 0
        end
        rel_warn "publish of $crate attempt $attempt failed; waiting 30s for the index..."
        sleep 30
    end
    rel_die "all publish attempts for $crate failed."
end

rel_log "publishing libmoshpit"
rel_publish_with_retry libmoshpit

rel_log "publishing moshpit"
rel_publish_with_retry moshpit

rel_log "publishing moshpits"
rel_publish_with_retry moshpits

rel_log "publishing moshpit-keygen"
rel_publish_with_retry moshpit-keygen

rel_log "publishing moshpit-agent"
rel_publish_with_retry moshpit-agent

rel_log "published $RELEASE_TAG to crates.io"
