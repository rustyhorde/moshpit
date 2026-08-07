# Release runbook

moshpit is released entirely from this machine via `scripts/release/*.fish`,
orchestrated by `cargo rake release` (a `[target.release]` entry in
`Rakefile.toml`). There is no CI involvement: `.github/workflows/` has been
removed entirely. The Linux musl binaries (x86_64/aarch64), the macOS
binary, and the Windows native binary (including MSI installers) all build
on the user's own machines via **repomon**, the self-hosted, git-push-
triggered job runner — see `.repomon/release.toml`. `build.fish` then
packages the Linux artifacts (DEB/RPM via `nfpm`) using the musl binaries
repomon's `linux-build-x86_64`/`linux-build-aarch64` jobs hand back.
Artifacts are published to a self-hosted static download directory, a
self-hosted signed APT/RPM repo, a self-hosted signed pacman repo, and a
self-hosted Homebrew tap — no GitHub Release object, no GitHub-hosted
packages repo (the former `rustyhorde/moshpit-packages`), no GitHub-hosted
Homebrew tap (the former `rustyhorde/homebrew-moshpit`), no AUR (the former
24-package AUR matrix).

This mirrors the pipeline already in use for the sibling `barto`/`salus`
projects, adapted for moshpit's asymmetric binary matrix: `mp`+`mps`+
`mp-keygen`+`mpa` (built 4 ways: base/fido2/systemd-creds/full) on Linux,
`mp`+`mp-keygen` only on macOS and Windows (`mps` — the server — stays
Linux-only for now; `mpa`'s unlock backends are Linux-specific). The AUR
matrix is intentionally **consolidated**, not fully replicated: 14 `-bin`
packages instead of the original 24 (dropped: the never-precompiled
source-build PKGBUILDs, and the `tpm`/`ssh-agent-piggyback`/
`secret-service`/`fprintd` unlock-backend variants, which remain
`// TODO: not yet implemented` stubs in `agent/src/unlock/*.rs`).

## One-time setup

1. **repomon wiring** — **done**: `origin` (`/opt/repos/moshpit.git`)'s
   `post-receive` hook is symlinked to `repomon-pr`, and
   `~/.config/repomon/moshpit.toml` has `[git] url =
   "jozias@jasonozias.com:/opt/repos/moshpit.git"`, telling the repomon
   daemon where to clone the project from.
   - Pushing a `v[0-9]+.[0-9]+.[0-9]+(-.*)?`-shaped tag to `origin` now fans
     out `.repomon/release.toml`'s `linux-build-x86_64`/`linux-build-aarch64`/
     `macos-build`/`windows-build` jobs, plus `.repomon/audit.toml`'s `audit`
     job (it matches release tags too). Every ordinary push fans out
     `.repomon/audit.toml`'s `audit` job; pushes to `master` specifically
     also fan out `.repomon/ci.toml`'s `rake-linux`/`rake-macos`/
     `rake-windows` jobs (`cargo rake most`), while pushes to any *other*
     branch instead fan out `.repomon/test.toml`'s `test-linux`/
     `test-macos`/`test-windows` jobs (the lighter `cargo rake test`).

2. **Docker on both Linux repomon-runner machines** — needed for moshpit's
   custom cross images (`docker/Dockerfile.{x86_64,aarch64}-unknown-linux-musl`,
   which bundle static libfido2/libcbor/libusb/hidapi/libudev-zero for the
   FIDO2 unlock backend). The 2 split `linux-build-*` jobs need up to 2 idle
   `linux`-kind runners checked in simultaneously to actually fan out
   one-per-machine, rather than queuing on one.
   - `scripts/release/repomon/linux-build-*.sh` bootstrap `cross` itself
     (`cargo install cross --force --locked`, matching `Cross.toml`) and
     build the `moshpit-cross-{x86_64,aarch64}` Docker images if not
     already cached — Docker (or Podman) is the one prerequisite `cross`
     can't supply on its own.

3. **WiX Toolset v3 + cargo-wix on the Windows repomon-runner machine** —
   **net-new for moshpit** (unlike barto, which already had WiX authoring to
   convert): `moshpit/wix/main.wxs` and `keygen/wix/main.wxs` are freshly
   authored, minimal (no service install, no ACL custom action — `mp` and
   `mp-keygen` are plain CLI tools, not Windows services), so this should be
   simpler than barto's conversion, but budget for a few dry-run iterations:
   - `choco install wixtoolset -y` — installs WiX Toolset v3 (`candle.exe`/
     `light.exe`). Verify with `Get-Command candle.exe`.
   - `cargo install cargo-wix --locked`. Verify with `cargo wix --version`.
   - Known `cargo-wix` gotchas (hit repeatedly during barto's own migration,
     documented here pre-emptively): don't pass `--compiler-arg -dVersion`
     or `-dCargoTargetBinDir` — `cargo-wix` already injects both from the
     `--package` crate's Cargo.toml version and the `--target`/profile
     respectively; redeclaring either fails with `error CNDL0288`. Don't
     manually add `-ext WixUtilExtension` if `main.wxs` uses the util
     extension — `cargo-wix`'s legacy-toolset (WiX v3) path already passes
     it unconditionally; redeclaring fails with `error CNDL0125`.

4. **Self-hosted pacman repo skeleton** — **done**:
   `/opt/releases/moshpit/arch/{x86_64,aarch64}` exist, owned by `jozias`.
   Also created the rest of the layout at the same time:
   `/opt/releases/moshpit/{staging,apt/pool/main,apt/dists/stable,rpm/x86_64,rpm/aarch64}`,
   matching the layout `barto`/`salus`/`cargo-rake`/`rakemond` already use.
   Tools: `pacman-contrib` (provides `repo-add`), `makepkg` (from
   `base-devel`) — both already installed on this host.

5. **Packages-signing GPG key** — **done**, and reused an existing key
   rather than minting a new `<project>-packages@rustyhorde.com`-style one:
   `moshpit packages <jason.g.ozias@pm.me>` (ed25519, fingerprint
   `7452D2FCB49882326B7580E85A25FB9A0E414B67`), already present in this
   machine's keyring. Its public half is exported to
   `/opt/releases/moshpit/gpg.key`. Back up `~/.gnupg` and the revocation
   certificate somewhere durable if that hasn't already been done — losing
   this key means re-signing under a new key id and updating every
   `.sources`/`.repo`/`pacman.conf` file that references it.

6. **Static download directory, APT/RPM repo skeleton** — **done**, under
   `/opt/releases/moshpit/` on this machine (the same host that serves
   `git.jasonozias.com`). No nginx changes were needed — `/dl/` already
   aliases `/opt/releases/` generically:
   - `/opt/releases/moshpit/staging/` — scratch landing zone for the
     repomon Linux/macOS/Windows jobs' scp hand-back (see
     `dispatch-remote-builds.fish`).
   - `/opt/releases/moshpit/<tag>/` — per-release static download dirs
     (`publish-static.fish`), served at
     `https://git.jasonozias.com/dl/moshpit/<tag>/`.
   - `/opt/releases/moshpit/{apt,rpm}/` — the rolling signed package repo
     (`publish-packages.fish`), served at
     `https://git.jasonozias.com/dl/moshpit/{apt,rpm}/`.
   - `/opt/releases/moshpit/apt/moshpit.sources` and
     `/opt/releases/moshpit/rpm/moshpit.repo` are client config files
     tracked at `packaging/apt/moshpit.sources`/`packaging/rpm/moshpit.repo`
     and synced into place by `publish-packages.fish` on every release.
   - `/opt/releases/moshpit/gpg.key` — the exported public half of the
     packages-signing key, for client-side `curl`.

7. **Homebrew tap** — **done**: a plain bare git repo, served by the
   existing git-backend nginx block (`GIT_PROJECT_ROOT /opt/repos` already
   exports every repo under `/opt/repos`) — no nginx changes at all:
   ```fish
   sudo git init --bare --shared /opt/repos/homebrew-moshpit.git
   sudo chown -R jozias:jozias /opt/repos/homebrew-moshpit.git
   git -C /opt/repos/homebrew-moshpit.git config receive.denyNonFastforwards true
   ```
   Tap URL: `https://git.jasonozias.com/homebrew-moshpit.git`.

8. **Other tools**: `nfpm` (installed automatically by the `[tool.os.nfpm]`
   Rakefile hook if missing — already present at `~/.local/bin/nfpm`),
   `apt-ftparchive`/`createrepo_c`/`gpg`/`docker`/`cross` — all confirmed
   already installed on this host. `cargo-nextest` and `cargo-matrix` must
   additionally be installed on the macOS, Windows, and both Linux
   repomon-runner machines themselves — `.repomon/ci.toml`'s
   `rake-linux`/`rake-macos`/`rake-windows` jobs run `cargo rake most`
   directly, which depends on both.

## Cutting a release

```fish
fish scripts/release/bump-version.fish 0.9.5
git add -u && git commit -m 'chore(deps): version bump for next release'
git tag v0.9.5
git push origin v0.9.5
git push gh v0.9.5
cargo rake release
```

This runs, in order:

1. `dispatch-remote-builds.fish` — pushes the tag to `origin` (harmless if
   already pushed there) to trigger repomon's `linux-build-x86_64`/
   `linux-build-aarch64`/`macos-build`/`windows-build` jobs, then polls
   `/opt/releases/moshpit/staging/<tag>/` until all 4 jobs have scp'd their
   artifacts back, and copies them into a freshly-reset `release-assets/`.
2. `build.fish` — generates the `xtask dist` sidecars for `mp`/`mps`/
   `mp-keygen`/`mpa`, tars 4 dist bundles, and packages `.deb`/`.rpm` for
   all 28 nfpm configs (14 packages x 2 arches) via `nfpm`, adding those
   packages into `release-assets/` alongside the already-staged binaries.
3. `publish-static.fish` — copies `release-assets/` to
   `/opt/releases/moshpit/<tag>/`, served at
   `https://git.jasonozias.com/dl/moshpit/<tag>/<asset>`.
4. `update-pkgbuilds.fish` — computes sha256 sums, updates all 14
   `packaging/arch/*-bin/PKGBUILD`s + `.SRCINFO`, and commits locally (does
   **not** push — review the diff yourself first:
   `git log -1 -p -- packaging/arch`).
5. `publish-arch.fish` — builds all 14 `-bin` packages locally via
   `makepkg` from the just-refreshed PKGBUILDs (one build per arch, using a
   scratch `makepkg.conf` to override `CARCH` rather than real aarch64
   execution, since `package()` only installs a prebuilt binary), signs
   each built package (`makepkg --sign`) in addition to the repo database
   (`repo-add -s`), and publishes the result as a rolling pacman repo to
   `/opt/releases/moshpit/arch/{x86_64,aarch64}`. This is the *only* Arch
   Linux distribution channel — no AUR stage exists in this pipeline.
6. `publish-packages.fish` — rebuilds the signed APT/RPM repo metadata
   (rolling, not versioned) in `/opt/releases/moshpit/{apt,rpm}`.
7. `update-homebrew.fish` — renders
   `packaging/homebrew/{moshpit,moshpit-unstable,moshpit-keygen,moshpit-keygen-unstable}.rb.tmpl`
   against the macOS bundle checksums and pushes all 4 to the local
   `homebrew-moshpit.git` tap. No `moshpits` formula — macOS never builds
   it.
8. `publish-crates.fish` — publishes `libmoshpit` → `moshpit` → `moshpits`
   → `moshpit-keygen` → `moshpit-agent` to crates.io in dependency order,
   using the operator's own `cargo login` credentials.

After it finishes, push the packaging commit it made:

```fish
git push origin master
git push gh master
```

## Dry-run mode (`-rcN` tags)

Tag with an `-rcN` suffix instead — every publish stage **after**
`build.fish` is skipped, but `dispatch-remote-builds.fish` and `build.fish`
themselves still run in full, and `cleanup-staging.fish` still runs at the
end:

```fish
git tag v0.9.5-rc.1
git push origin v0.9.5-rc.1
cargo rake release
```

This is deliberately more thorough than "build locally only": it proves the
*entire* pipeline works except the irreversible publish side effects — the
tag push actually reaching `origin`'s `post-receive` hook and fanning out
all 4 repomon jobs (including the 2 split Linux jobs landing on distinct
machines), each job's build+package steps succeeding on real
macOS/Windows/Linux hardware, the scp hand-back + staging-dir poll
correctly retrieving the resulting artifacts, and the local `nfpm`
packaging of the staged Linux binaries. Use this to validate the wiring
before cutting a real release — especially the first time, and especially
to validate the net-new WiX MSI authoring for `mp`/`mp-keygen`.

## Troubleshooting

- **`dispatch-remote-builds.fish` times out waiting for artifacts** — watch
  live progress with `rpmt` (the repomon TUI), or tail
  `~/.local/share/repomon/logs/moshpit/moshpit-release/`. A missing WiX
  Toolset v3/`cargo-wix` on the Windows runner (see one-time setup step 3),
  or a missing Docker on one of the 2 Linux runners (see one-time setup
  step 2), are the most likely causes the first time this pipeline runs for
  real.
- **`cargo-wix` fails with `CNDL0288`/`CNDL0125`** — see the gotchas listed
  in one-time setup step 3; both are caused by redeclaring a WiX variable
  or extension `cargo-wix` already injects/loads itself.
- **`makepkg` in `publish-arch.fish` can't download sources** — confirm
  `publish-static.fish` ran first in this same release (it must, since
  `update-pkgbuilds.fish` and `publish-arch.fish` both depend on the
  binaries it just published being fetchable from
  `https://git.jasonozias.com/dl/moshpit/<tag>/`).
