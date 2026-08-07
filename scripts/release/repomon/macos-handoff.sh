#!/bin/sh
# Hands the macos-build job's artifacts back to the machine running
# release.fish — repomon has no artifact-return channel of its own (each
# job's workspace is deleted immediately on completion), so this is a plain
# scp to a staging path that dispatch-remote-builds.fish polls.
#
# Each file is scp'd to a `.partial` suffix, then atomically mv'd into its
# final name via a script piped into `ssh ... sh -s` — see linux-handoff.sh
# for why.
set -eu

tag=$(git describe --tags --exact-match)
host="jozias@jasonozias.com"
dest_dir="/opt/releases/moshpit/staging/$tag"

files="mp-aarch64-apple-darwin.tar.gz mp-unstable-aarch64-apple-darwin.tar.gz mp-keygen-aarch64-apple-darwin.tar.gz mp-keygen-unstable-aarch64-apple-darwin.tar.gz"

for f in $files; do
    scp "$f" "$host:$dest_dir/$f.partial"
done

{
    echo "set -e"
    for f in $files; do
        printf 'mv -- "%s/%s.partial" "%s/%s"\n' "$dest_dir" "$f" "$dest_dir" "$f"
    done
} | ssh "$host" sh -s
