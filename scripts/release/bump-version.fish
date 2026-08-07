#!/usr/bin/env fish
# One-shot helper: bump every crate's version, then regenerate Cargo.lock.
# Run manually before tagging — not part of the tag-triggered `release`
# target itself.
#
# Unlike barto (which centralizes version in [workspace.package]), moshpit
# gives each of its 6 member crates (agent, keygen, libmoshpit, moshpit,
# moshpits, xtask) its own `version = "..."` line, and every crate that
# depends on libmoshpit pins it by version too
# (`libmoshpit = { version = "...", path = "../libmoshpit" }` in
# agent/keygen/moshpit/moshpits' Cargo.toml). All 6 crates are always
# released in lockstep at the same version, so this bumps all of them plus
# all 4 of those pinned-dependency lines in one pass.
#
# Usage: fish scripts/release/bump-version.fish 0.9.5

source (path dirname (status --current-filename))/lib.fish

cd (rel_repo_root)
or rel_die "not inside the moshpit git repo"

if test (count $argv) -ne 1
    rel_die "usage: bump-version.fish <new-version> (e.g. 0.9.5, no leading 'v')"
end

set -l new_version $argv[1]
if not string match -qr '^[0-9]+\.[0-9]+\.[0-9]+$' -- $new_version
    rel_die "'$new_version' doesn't look like a bare semver (expected X.Y.Z, no leading 'v')"
end

set -l crates agent keygen libmoshpit moshpit moshpits xtask
for crate in $crates
    set -l manifest $crate/Cargo.toml
    test -f $manifest
    or rel_die "$manifest not found"

    rel_log "bumping $manifest to $new_version"
    sed -i "s/^version = \"[0-9][^\"]*\"/version = \"$new_version\"/" $manifest
end

rel_log "bumping libmoshpit path-dependency pins in agent/keygen/moshpit/moshpits"
for crate in agent keygen moshpit moshpits
    sed -i "s/^libmoshpit = { version = \"[0-9][^\"]*\", path = \"..\/libmoshpit\" }/libmoshpit = { version = \"$new_version\", path = \"..\/libmoshpit\" }/" $crate/Cargo.toml
end

rel_log "regenerating Cargo.lock"
cargo update --workspace
or rel_warn "'cargo update --workspace' failed — run 'cargo check' and inspect Cargo.lock manually"

rel_log "bumped all 6 crates to $new_version — review with 'git diff' then commit:"
rel_log "  git add -u && git commit -m 'chore(deps): version bump for next release'"
