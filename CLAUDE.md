# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Development Commands

```bash
# Build everything
cargo build

# Build a specific binary
cargo build --bin mp
cargo build --bin mps
cargo build --bin mp-keygen

# Reproducible release build (matches CI)
VERGEN_IDEMPOTENT=1 cargo build --release --locked

# Run all tests
cargo test

# Run tests for a single crate
cargo test -p libmoshpit

# Run a single test by name
cargo test -p libmoshpit <test_name>

# Lint (deny warnings, all targets)
cargo clippy --all-targets -- -D warnings

# Format check
cargo fmt --check

# Full local verification before pushing (fmt + clippy + tests + docs + coverage).
# Heavy stages are opt-in: --fuzz, --install, --musl/--unstable (MUSL Docker build).
scripts/run_all.fish

# Generate docs
cargo doc --no-deps --open

# Generate shell completions + man pages + licenses (+ example config for mp/mps)
cargo xtask dist mp
cargo xtask dist mps
cargo xtask dist mp-keygen
# Output lands in dist/<binary>/ — this is tarred into dist-<binary>.tar.gz for releases
```

The `cargo xtask` alias is defined in `.cargo/config.toml` and expands to `cargo run -p xtask --`.

### bacon (watch mode)

`bacon.toml` configures common watch-mode jobs. Key keybindings when running `bacon`:
- `c` — clippy on all targets with `-D warnings`
- `p` — pedantic clippy
- Default job is `check` (runs `cargo matrix check`)

## Architecture

### Workspace layout

Five crates:

| Crate | Binary | Purpose |
|-------|--------|---------|
| `libmoshpit` | — | Core library: all protocol logic, crypto, terminal emulation |
| `moshpit` | `mp` | Client: connects to a moshpits server |
| `moshpits` | `mps` | Server: listens, manages PTYs, streams terminal state |
| `keygen` | `mp-keygen` | Key generation, fingerprinting, and verification |
| `xtask` | `xtask` | Build task runner (completions + man pages only) |

All binaries depend on `libmoshpit`. The three application crates have the same internal structure: `cli.rs` (clap args) → `config.rs` (merged config) → `runtime.rs` (async main loop).

### Connection protocol (two phases)

**Phase 1 — TCP key exchange** (`libmoshpit/src/kex/`, `libmoshpit/src/tcp/`):
- Client connects on a configurable TCP port (default 40404)
- Mutual asymmetric key authentication (X25519, P-384, P-256, or ML-DSA) with TOFU on first connect
- Derives a per-session AES-256-GCM-SIV key via Argon2 KDF
- TCP connection closes immediately after key exchange completes

**Phase 2 — UDP terminal transport** (`libmoshpit/src/udp/`):
- Terminal I/O encrypted with AES-256-GCM-SIV + HMAC-SHA-512 per packet
- Ports 50000–59999 (UDP inbound on server)
- NAK-based selective retransmission: 50 ms timeout, max 10 retries
- Server sends full `ScreenState` on reconnect for instant repaint

### Terminal emulation (`libmoshpit/src/term/`)

- `emulator.rs` — VT100 state machine (runs server-side, wraps `vt100` crate)
- `prediction.rs` — Client-side keystroke prediction (adaptive/always/never mode)
- `renderer.rs` — Renders diffs + prediction overlays to ANSI escape sequences

The server tracks the full screen state and sends 50 ms periodic diffs. The client overlays predicted keystrokes locally to eliminate perceived latency.

### Frame encoding (`libmoshpit/src/frames/`)

`Frame` ↔ `bincode-next` serialization ↔ `EncryptedFrame` (AES-256-GCM-SIV). The `MAX_UDP_PAYLOAD` constant caps payload size.

### Crypto

All crypto is through `aws-lc-rs` (no `ring`, no system OpenSSL). Building on Linux requires `cmake` and `gcc` as system packages (they are `makedepends` in the AUR PKGBUILDs). The `VERGEN_IDEMPOTENT=1` env var must be set for reproducible builds (used by the `vergen-gix` build dependency).

## CI Pipeline

CI (`moshpit.yml`) runs rustfmt → clippy (nightly, all platforms) → tests (1.95.0, stable, beta, nightly on Linux/macOS/Windows) → coverage. Clippy runs on nightly and all warnings are errors (`-D warnings`). Tests use the reusable `rustyhorde/workflows` workflow with all features enabled.

The `package-test.yml` workflow simulates a release tarball build by running `--locked` builds against a git archive, catching issues with `Cargo.lock` and `cargo xtask dist` before a real release.

## Release Process

Tagging `v<semver>` triggers `release.yml`, which:
1. Builds static MUSL binaries for `x86_64` via `cross` (cross-rs/cross v0.2.5 in Docker)
2. Runs `cargo xtask dist` natively to generate man pages, completions, licenses, and example configs, then tars them per binary (`dist-mp.tar.gz`, `dist-mps.tar.gz`, `dist-mp-keygen.tar.gz`)
3. Creates a GitHub release with all 3 binaries + 3 dist tarballs + the source tarball
4. Computes SHA256 of every release asset and updates both source and binary PKGBUILDs, opens a PR
5. Publishes to 6 AUR packages: `moshpit-keygen`, `moshpit`, `moshpits` (source/compile) and `moshpit-keygen-bin`, `moshpit-bin`, `moshpits-bin` (binary/pre-compiled)

`Cross.toml` at the workspace root configures `cross` to pass `VERGEN_IDEMPOTENT` into the Docker build container. The source AUR packages compile with glibc natively on Arch; the `-bin` packages install MUSL static binaries and work without Rust/cmake/gcc installed.

## Key Configuration Details

- **Rust edition**: 2024 (all crates)
- **MSRV**: 1.95.0 — when updating `rust-version` in any `Cargo.toml`, also update the required status check names on the `master` branch (GitHub → Settings → Branches → master protection rule). The MSRV check names embed the version string, e.g. `🧪 Test (Linux) 🧪 (ubuntu-latest, 1.95.0, x86_64-unknown-linux-gnu)` — replace the old version with the new one for all three platform variants (Linux × 1, MacOS × 1, Windows × 2 targets).
- **`unstable` feature flag**: Exists in libmoshpit/moshpit/moshpits/keygen but is currently a no-op placeholder
- **Config precedence** (both client and server): env vars > CLI flags > TOML config file. Implemented by `libmoshpit::load` (the `config` crate is last-source-wins, so sources are added file → CLI → env). Each binary's `Cli::collect` emits only values the user actually passed (tracked via `Cli::parse_argv`/`explicit_args`) so clap defaults don't clobber the file/env; fields needing a fallback carry `#[serde(default)]`. The client's config file is optional (`load(..., false)`); the server's is required (`load(..., true)`).
- **Client env prefix**: `MOSHPIT_`; **Server env prefix**: `MOSHPITS_`. Env var names are `<PREFIX>_<FIELD>` with underscores preserved (e.g. `MOSHPIT_SERVER_PORT`, `MOSHPITS_TERM_TYPE`). Nested tables (e.g. `[preferred_algorithms]`) are **not** settable via a single env var — use the TOML table or the dedicated CLI flags.

## Coding Conventions

- **No glob imports**: Always use explicit named imports (`use foo::{Bar, Baz};`). Glob imports (`use foo::*`) hide dependencies and make refactoring harder. This applies everywhere — test modules, production code, and re-exports (`pub use`).
- **Prefer leaf names over FQDNs**: Import a type or function and refer to it by its leaf name (`Bar`) rather than writing it fully qualified inline (`foo::bar::Bar`). Only use a fully-qualified path when a name collision would otherwise occur (e.g. two `Error` types in scope).
- **Gate imports with the code that uses them**: When an import is only needed by code behind a `cfg` (e.g. `#[cfg(target_os = "linux")]`), put the same `cfg` on the `use` if the import isn't used elsewhere. An unconditional `use` for cfg-gated code triggers unused-import warnings on other platforms.
