#!/bin/sh
# Hands a repomon linux-build-* job's artifacts back to the machine running
# release.fish — repomon has no artifact-return channel of its own (each
# job's workspace is deleted immediately on completion), so this is a plain
# scp to a staging path that dispatch-remote-builds.fish polls, same
# pattern as macos-handoff.sh/windows-handoff.ps1.
#
# Shared by both linux-build-x86_64/linux-build-aarch64 jobs (see
# .repomon/release.toml) — each passes its own binary filenames as
# arguments, since the scp target and logic are identical across jobs and
# only the file list differs.
#
# Each file is scp'd to a `.partial` suffix, then atomically mv'd into its
# final name via a script piped into `ssh ... sh -s`. Plain `scp foo
# "$dest"` creates the destination file and starts streaming into it
# immediately, so dispatch-remote-builds.fish's `test -f`-based poll
# (rel_wait_for_files in lib.fish) can observe and hand off a partially-
# written file if it lands mid-transfer. The rename is a same-filesystem mv
# (atomic), so the poller never sees the final name until every byte has
# landed.
#
# The rename script is piped to `sh -s` over stdin rather than passed as an
# `ssh host "..."` command string — jozias@jasonozias.com's login shell is
# fish, and ssh hands a command-string argument straight to the login
# shell, so POSIX syntax like `set -e` would be misparsed as fish's own
# (incompatible) `set -e VARNAME`. `sh -s` sidesteps the login shell
# entirely.
set -eu

tag=$(git describe --tags --exact-match)
host="jozias@jasonozias.com"
dest_dir="/opt/releases/moshpit/staging/$tag"

for f in "$@"; do
    scp "$f" "$host:$dest_dir/$f.partial"
done

{
    echo "set -e"
    for f in "$@"; do
        printf 'mv -- "%s/%s.partial" "%s/%s"\n' "$dest_dir" "$f" "$dest_dir" "$f"
    done
} | ssh "$host" sh -s
