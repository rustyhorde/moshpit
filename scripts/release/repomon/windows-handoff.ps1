# Hands the windows-build job's artifacts back to the machine running
# release.fish — repomon has no artifact-return channel of its own (each
# job's workspace is deleted immediately on completion), so this is a plain
# scp (Windows OpenSSH client) to a staging path that
# dispatch-remote-builds.fish polls.
#
# Each file is scp'd to a `.partial` suffix, then atomically mv'd into its
# final name — see linux-handoff.sh for why: a plain `scp foo $dest`
# creates the destination file and starts streaming into it immediately,
# so dispatch-remote-builds.fish's `test -f`-based poll can observe and
# hand off a partially-written file if it lands mid-transfer.
#
# The rename script is base64-encoded and passed as a single `ssh
# $remoteHost "echo ... | base64 -d | sh -s"` argument rather than piped to
# ssh's stdin: Windows PowerShell 5.1 (`powershell`, not `pwsh`) mangles
# multi-line content piped to a native process's stdin. Passing a single
# base64 command-line argument sidesteps that pipe entirely, and `echo ...
# | base64 -d | sh -s` is plain enough that it parses correctly under
# jozias@jasonozias.com's login shell (fish) too, unlike POSIX syntax such
# as `set -e` passed directly as an ssh command string.

$ErrorActionPreference = "Stop"

$tag = git describe --tags --exact-match
$remoteHost = "jozias@jasonozias.com"
$destDir = "/opt/releases/moshpit/staging/$tag"

$files = @(
    "mp-x86_64-pc-windows-msvc.exe",
    "mp-x86_64-pc-windows-msvc.msi",
    "mp-keygen-x86_64-pc-windows-msvc.exe",
    "mp-keygen-x86_64-pc-windows-msvc.msi"
)

foreach ($f in $files) {
    scp $f "${remoteHost}:${destDir}/$f.partial"
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

$renameLines = @("set -e")
foreach ($f in $files) {
    $renameLines += "mv -- ""$destDir/$f.partial"" ""$destDir/$f"""
}
$renameScript = ($renameLines -join "`n") + "`n"
$encodedScript = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($renameScript))
ssh $remoteHost "echo $encodedScript | base64 -d | sh -s"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
