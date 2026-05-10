# moshpit
An SSH and Mosh inspired tool written in Rust.

## Overview

moshpit is a suite of tools for establishing encrypted, resilient remote terminal sessions:

| Binary | Crate | Role |
|--------|-------|------|
| `mps` | moshpits | Server — listens for incoming connections and spawns PTYs |
| `mp` | moshpit | Client — connects to a running `mps` server |
| `mp-keygen` | moshpit-keygen | Key management — generates and inspects ed25519 key pairs |

Sessions are authenticated with ed25519 key pairs.  TCP is used only for the initial key exchange; once the exchange completes the connection switches to UDP exclusively (ports 50000–59999) for all terminal I/O.  The server tracks full terminal screen state with a server-side vt100 emulator; on reconnect the client receives a single clean screen snapshot and repaints instantly rather than replaying raw scrollback history.

---

## Inspiration & Relation to Mosh

moshpit draws its core motivation from [Mosh (Mobile Shell)](https://mosh.org/), the excellent remote terminal tool created by Keith Winstein and colleagues at MIT.  Mosh demonstrated that a UDP-based transport with graceful handling of packet loss, reordering, and IP roaming could make remote terminal sessions feel dramatically more responsive and reliable than traditional SSH — particularly over high-latency or intermittent connections.  moshpit was created as an exercise in rebuilding that idea from scratch in Rust, exploring different design trade-offs along the way.

### What moshpit shares with Mosh

- **UDP terminal data channel** — terminal I/O is carried over UDP rather than a reliable stream, allowing the session to survive network interruptions without blocking on TCP retransmit timeouts.
- **Resilience to connectivity loss** — both tools keep the session alive across short network outages and IP address changes; the client reconnects automatically without user intervention.
- **Authenticated encryption** — all data on the wire is encrypted and authenticated; neither tool relies on a plain-text transport at any layer.
- **Client / server split** — a lightweight server component (`mps` / `mosh-server`) runs on the remote host and manages the PTY; a client (`mp` / `mosh`) runs locally and drives the terminal.
- **Server-side screen state** — the server maintains a vt100 model of the current PTY screen; on reconnect the client receives a single screen snapshot for an instant, noise-free repaint.
- **Client-side prediction** — keystrokes are echoed locally and cursor movement is predicted to hide round-trip latency; predicted characters are underlined until the server confirms them.

### Where moshpit differs

| Concern | Mosh | moshpit |
|---------|------|---------|
| **Language** | C++ | Rust |
| **Authentication** | Delegated to SSH for the initial handshake; a one-time secret is passed back over SSH | Standalone ed25519 key-pair authentication — no SSH dependency |
| **Transport model** | Pure UDP after setup; Mosh's *State Synchronization Protocol* (SSP) keeps a diff of the full terminal screen state and sends only the latest snapshot | TCP is used solely for the ed25519 key exchange; all terminal I/O runs over UDP after the exchange completes.  NAK-based selective retransmission with an adaptive RTT estimator ensures reliable, ordered delivery; a split data/control channel prevents control frames from being delayed by PTY data backlogs |
| **Reconnect display sync** | SSP sends the latest screen snapshot; client repaints from the diff immediately | Server maintains a `vt100::Parser` tracking the live PTY screen; on reconnect a single `ScreenState` frame delivers `contents_formatted()` bytes for an instant clean repaint.  A 50 ms periodic task also sends `ScreenState` diffs during normal use so the client stays in sync even across network hiccups. |
| **Client-side prediction** | Mosh echoes keystrokes locally and predicts cursor movement to hide latency, underlining characters that have not yet been confirmed by the server | Same — keystrokes are echoed locally, cursor movement is predicted, and unconfirmed characters are underlined until the server output arrives |
| **Encryption** | AES-128-OCB authenticated encryption using a symmetric session key | Key exchange via an ed25519-based handshake; negotiated symmetric encryption on the UDP channel (default: AES-256-GCM-SIV with per-packet HMAC-SHA-512; see [Algorithm negotiation](#algorithm-negotiation)) |
| **Session multiplexing** | One Mosh session per `mosh-server` process | Same — one PTY per `mps` connection |
| **Configuration** | Minimal; primarily driven by command-line options | TOML config files with environment-variable overrides |
| **UDP port range** | 60001–61000 (by default) | 50000–59999 |
| **License** | GPL v3 | Apache 2.0 / MIT (your choice) |

> **Attribution**: the name *moshpit* is a deliberate nod to Mosh, whose design and published research were a direct inspiration for this project.  If you need production-grade, battle-tested remote terminal software, [use Mosh](https://mosh.org/).  moshpit is an independent reimagining with different goals and trade-offs.

---

## Connection model

### Phase 1 — TCP key exchange

The client opens a TCP connection to the server's configured port (default 40404).  The two sides run a mutual ed25519 key-pair authentication and key-exchange protocol over this connection.  Once the handshake completes both halves of the TCP socket are released and the TCP connection is **closed immediately** — it is not kept alive, and is not used for anything after the key exchange.

### Phase 2 — UDP session

All subsequent communication happens exclusively over UDP (server-side port range 50000–59999).  Every frame is encrypted and authenticated using the algorithms negotiated during Phase 1 (default: AES-256-GCM-SIV with per-packet HMAC-SHA-512; see [Algorithm negotiation](#algorithm-negotiation) for the full list of supported ciphers and how to select them).

Reliable, ordered delivery is provided at the application layer using **NAK-based selective retransmission**:

- The **receiver** (`UdpReader`) tracks the highest sequence number seen and maintains a reorder buffer.  Any gap that persists beyond a 20–500 ms adaptive NAK timeout triggers a `Nak` frame — a compact list of missing sequence numbers — sent back to the sender over the same UDP channel.  When a gap opens mid-burst, a `RepaintRequest` is also sent immediately (rather than waiting for the first NAK retry cycle) so the server can deliver a fresh screen snapshot within one RTT.
- The **sender** (`UdpSender`) keeps a sliding retransmit buffer of the 512 most-recently transmitted wire-encoded packets.  When a `Nak` arrives the missing packets are looked up and resent immediately.  The sender uses **two separate outbound channels** — a high-priority control channel (capacity 16) for `Keepalive` and `Shutdown` frames, and a data channel (capacity 256) for PTY diffs and screen states — so control frames are always polled first and bypass any data backlog.
- Each gap is retried up to 4 times (with exponential backoff capped at 800 ms); after the limit is exceeded the gap is abandoned and the session proceeds.
- The NAK timeout adapts to the measured round-trip time using a Jacobson-Karels estimator.  Outlier RTT spikes are clamped to 8× the current estimate rather than discarded, preventing a self-reinforcing loop where aggressive 20 ms NAKs worsen congestion on slow NAT paths.
- Large PTY bursts (more than 10 MTU-sized chunks from a single PTY read, e.g. a full-screen `htop` redraw) are sent with **3× the configured inter-packet pacing delay** to reduce burst loss on stateful NAT devices.

Because retransmission is handled entirely within the UDP layer there is no head-of-line blocking from TCP: a lost packet delays only the frames that depend on it, not the rest of the stream.  Control frames are additionally isolated from data backpressure via the split channel design.

### Reconnection

If the UDP path is interrupted the client automatically reconnects — performing a new TCP key exchange for the same logical session — and the server delivers a single `ScreenState` frame containing the current terminal contents so the display repaints instantly without replaying scrollback history.

### NAT roaming

If the client's IP address or UDP port changes mid-session (e.g. a mobile device switching networks), the server detects the new source address on the first authenticated packet it receives from that address and immediately redirects all subsequent outbound traffic there.  No reconnect or re-authentication is required; the session continues without interruption.

---

## Algorithm negotiation

Both sides exchange algorithm preferences in a `KexInit` frame at the start of the TCP handshake.  The server's preference order wins: the first algorithm the server lists that the client also supports is selected for each category.  All four categories are negotiated independently.

### Supported algorithms

#### Key exchange (KEX)

| Algorithm | Identifier | Default | Pros | Cons |
|-----------|------------|:-------:|------|------|
| X25519 + HKDF-SHA-256 | `x25519-sha256` | ✓ | Fastest DH available; constant-time by construction; tiny 32-byte keys; 128-bit security level | Not NIST/FIPS approved; 128-bit security level (adequate but not the highest margin) |
| NIST P-384 + HKDF-SHA-384 | `p384-sha384` | | 192-bit security level; NIST/FIPS approved; natural pairing with HKDF-SHA-384 | Slower than X25519; larger ephemeral key sizes; unnecessary margin for most deployments |
| NIST P-256 + HKDF-SHA-256 | `p256-sha256` | | FIPS approved; hardware TPM and HSM support; 128-bit security level | Slower than X25519; lower security margin than P-384; no advantage over X25519 outside compliance requirements |

#### Authenticated encryption (AEAD)

| Algorithm | Identifier | Default | Pros | Cons |
|-----------|------------|:-------:|------|------|
| AES-256-GCM-SIV | `aes256-gcm-siv` | ✓ | Nonce-misuse resistant — accidental nonce reuse does not leak plaintext or the authentication key; 256-bit key; fast with AES-NI | Two-pass construction is slightly slower than standard GCM; not as universally deployed as AES-256-GCM; requires AES-NI for peak throughput |
| AES-256-GCM | `aes256-gcm` | | Widely standardized (RFC 5116); fast with AES-NI; 256-bit key; FIPS approved | Nonce reuse is catastrophic — it leaks both plaintext and the Poly1305 authentication key; moshpit generates nonces with CSPRNG so reuse is not expected, but GCM-SIV is safer if any doubt exists |
| ChaCha20-Poly1305 | `chacha20-poly1305` | | Fastest option on CPUs **without** AES hardware acceleration (mobile, embedded, older x86); constant-time by design; immune to AES cache-timing side-channels; recommended for low-power devices | Slower than AES-GCM on hardware with AES-NI (most modern x86-64 and ARM64); not FIPS approved |
| AES-128-GCM-SIV | `aes128-gcm-siv` | | Nonce-misuse resistant; 128-bit key requires less key material and has slightly lighter key setup; fast with AES-NI | Lowest security level of the four (128-bit key vs 256-bit); no practical advantage over `aes256-gcm-siv` on modern hardware |

#### Message authentication (MAC)

These HMAC tags authenticate the wire sequence number and the entire encrypted payload, providing integrity protection before decryption.

| Algorithm | Identifier | Default | Pros | Cons |
|-----------|------------|:-------:|------|------|
| HMAC-SHA-512 | `hmac-sha512` | ✓ | 512-bit (64-byte) tag; highest security margin; SHA-512 is faster than SHA-256 on 64-bit CPUs in most implementations | 64-byte tag adds 32 bytes per packet compared to HMAC-SHA-256 — noticeable overhead on high-packet-rate, bandwidth-constrained links |
| HMAC-SHA-256 | `hmac-sha256` | | 256-bit (32-byte) tag saves 32 bytes per packet; FIPS approved; adequate security for all practical purposes | Lower security margin than HMAC-SHA-512; marginally slower on some 64-bit CPUs due to SHA-256 register pressure |

#### Key derivation (KDF)

The KDF derives the AEAD and HMAC keys from the shared ECDH secret.

| Algorithm | Identifier | Default | Pros | Cons |
|-----------|------------|:-------:|------|------|
| HKDF-SHA-256 | `hkdf-sha256` | ✓ | Fast; widely used; natural security-level match with X25519 and P-256 KEX; output is more than sufficient for all supported ciphers | Lowest output entropy of the three (256-bit — still far more than any supported cipher needs) |
| HKDF-SHA-384 | `hkdf-sha384` | | Matches the 192-bit security level of P-384 KEX; 384-bit internal HMAC | Marginal benefit unless P-384 is used for key exchange; slightly slower than SHA-256 |
| HKDF-SHA-512 | `hkdf-sha512` | | Highest output entropy (512-bit); SHA-512 is fast on 64-bit systems | No practical advantage over SHA-256 for this use case — the derived key length is bounded by the cipher, not the KDF |

#### Recommended pairings

The defaults (`x25519-sha256` / `aes256-gcm-siv` / `hmac-sha512` / `hkdf-sha256`) are a well-balanced choice for most deployments.  Common reasons to deviate:

| Scenario | Suggested override |
|----------|--------------------|
| No AES hardware (mobile, embedded) | `--aead-algos chacha20-poly1305` |
| FIPS / compliance environment | `--kex-algos p256-sha256` or `--kex-algos p384-sha384` |
| Highest security margin (P-384) | `--kex-algos p384-sha384 --kdf-algos hkdf-sha384` |
| Reduce per-packet bandwidth overhead | `--mac-algos hmac-sha256` |

### Configuring algorithm preferences

Use the `--kex-algos`, `--aead-algos`, `--mac-algos`, and `--kdf-algos` flags to override one or more categories.  Unspecified categories use the full default preference list.  Values are comma-separated, most-preferred first.

```bash
# Client: prefer ChaCha20-Poly1305 for AEAD (e.g. no AES-NI on this machine)
mp --aead-algos chacha20-poly1305,aes256-gcm-siv user@192.168.1.10

# Client: request the P-384 key exchange and HMAC-SHA-256 to reduce packet overhead
mp --kex-algos p384-sha384 --mac-algos hmac-sha256 user@192.168.1.10

# Server: prefer P-384 for all connections (overrides client preference ordering)
mps --kex-algos p384-sha384,x25519-sha256,p256-sha256
```

Algorithm preferences can also be set in the TOML config file.  Only the categories you list are overridden; omitted categories fall back to the defaults.

```toml
# Prefer ChaCha20 and reduce MAC overhead — server config
[preferred_algorithms]
aead = ["chacha20-poly1305", "aes256-gcm-siv"]
mac  = ["hmac-sha256", "hmac-sha512"]
```

---

## Current Releases

### libmoshpit
[![Crates.io](https://img.shields.io/crates/v/libmoshpit.svg)](https://crates.io/crates/libmoshpit)
[![Crates.io](https://img.shields.io/crates/l/libmoshpit.svg)](https://crates.io/crates/libmoshpit)
[![Crates.io](https://img.shields.io/crates/d/libmoshpit.svg)](https://crates.io/crates/libmoshpit)

### moshpit
[![Crates.io](https://img.shields.io/crates/v/moshpit.svg)](https://crates.io/crates/moshpit)
[![Crates.io](https://img.shields.io/crates/l/moshpit.svg)](https://crates.io/crates/moshpit)
[![Crates.io](https://img.shields.io/crates/d/moshpit.svg)](https://crates.io/crates/moshpit)

### moshpits
[![Crates.io](https://img.shields.io/crates/v/moshpits.svg)](https://crates.io/crates/moshpits)
[![Crates.io](https://img.shields.io/crates/l/moshpits.svg)](https://crates.io/crates/moshpits)
[![Crates.io](https://img.shields.io/crates/d/moshpits.svg)](https://crates.io/crates/moshpits)

### moshpit-keygen
[![Crates.io](https://img.shields.io/crates/v/moshpit-keygen.svg)](https://crates.io/crates/moshpit-keygen)
[![Crates.io](https://img.shields.io/crates/l/moshpit-keygen.svg)](https://crates.io/crates/moshpit-keygen)
[![Crates.io](https://img.shields.io/crates/d/moshpit-keygen.svg)](https://crates.io/crates/moshpit-keygen)

### CI/CD
[![docs.rs](https://docs.rs/libmoshpit/badge.svg)](https://docs.rs/libmoshpit)
[![codecov](https://codecov.io/gh/rustyhorde/moshpit/branch/master/graph/badge.svg?token=cBXro7o2UN)](https://codecov.io/gh/rustyhorde/moshpit)
[![CI](https://github.com/rustyhorde/moshpit/actions/workflows/moshpit.yml/badge.svg)](https://github.com/rustyhorde/moshpit/actions)

## Security Notice (Pre-Hardening)

This project has not yet completed a formal security hardening phase, external security review, or independent penetration testing.  It may contain security flaws that could lead to data loss, session compromise, privilege misuse, or other unintended behavior.

Use this software at your own risk, especially in internet-facing, production, or high-trust environments.

---

## Installation (Arch Linux / AUR)

All three binaries are available as separate AUR packages.  Install them with any AUR helper (e.g. `yay`, `paru`) or manually with `makepkg`.

| AUR package | Installs | Notes |
|-------------|----------|-------|
| `moshpit-keygen` | `mp-keygen` | No dependencies; install this first if building manually |
| `moshpit` | `mp` (client) | Depends on `moshpit-keygen` |
| `moshpits` | `mps` (server) | Depends on `moshpit-keygen` |

### Install with an AUR helper

```bash
# Install the server (pulls in moshpit-keygen automatically)
yay -S moshpits

# Install the client (pulls in moshpit-keygen automatically)
yay -S moshpit

# Or install both in one go
yay -S moshpits moshpit
```

### Install manually with makepkg

```bash
# 1. Clone and build moshpit-keygen first (shared dependency)
git clone https://aur.archlinux.org/moshpit-keygen.git
cd moshpit-keygen
makepkg -si
cd ..

# 2. Clone and build the server
git clone https://aur.archlinux.org/moshpits.git
cd moshpits
makepkg -si
cd ..

# 3. Clone and build the client
git clone https://aur.archlinux.org/moshpit.git
cd moshpit
makepkg -si
cd ..
```

### Removing packages

```bash
# Remove server and client (keep keygen)
sudo pacman -R moshpits moshpit

# Remove everything including keygen
sudo pacman -Rs moshpits moshpit moshpit-keygen
```

---

## Installation (cargo)

Requires a Rust toolchain (stable, 1.91.1 or later).  Install all three binaries directly from [crates.io](https://crates.io):

```bash
# Key management tool (install first — the others depend on it)
cargo install keygen

# Client
cargo install moshpit

# Server
cargo install moshpits
```

To install a specific version, append `--version <x.y.z>` to any of the commands above.

---

## mp-keygen

`mp-keygen` creates and inspects the ed25519 key pairs used by both the server and client.

### Subcommands

#### `generate`

Interactively generates a new ed25519 public/private key pair.  The tool prompts for an output path and an optional passphrase.

```bash
mp-keygen generate
```

Default key locations (when the default path is accepted at the prompt):

| Key | Default path |
|-----|-------------|
| Private key | `~/.mp/id_ed25519` |
| Public key  | `~/.mp/id_ed25519.pub` |

#### `fingerprint`

Displays the SHA-256 fingerprint of a public key file.

```bash
mp-keygen fingerprint ~/.mp/id_ed25519.pub
```

#### `verify`

Verifies a public key fingerprint string.  Pass `--randomart` to verify a randomart image instead.

```bash
# Verify a fingerprint string
mp-keygen verify "SHA256:..."

# Verify a randomart image
mp-keygen verify --randomart "+--[ED25519 256]--+ ..."
```

### Global flags

| Flag | Short | Description |
|------|-------|-------------|
| `--verbose` | `-v` | Increase log verbosity (repeatable) |
| `--quiet` | `-q` | Decrease log verbosity (repeatable, conflicts with `--verbose`) |

---

## moshpits server (`mps`)

### Quick start

1. Generate a server host key pair (run once):

   ```bash
   # The server uses a separate key stored at ~/.mp/mps_host_ed25519_key[.pub]
   # by default.  You can generate it with mp-keygen using a custom path:
   mp-keygen generate
   # Enter a path such as: /home/user/.mp/mps_host_ed25519_key
   ```

2. Create the config file at `~/.config/moshpits/moshpits.toml` (see [Configuration](#moshpits-configuration) below).

3. Start the server:

   ```bash
   mps
   ```

### Command-line usage

```
mps [OPTIONS]

Options:
  -v, --verbose                        Turn up logging verbosity (repeatable)
  -q, --quiet                          Turn down logging verbosity (repeatable)
  -e, --enable-std-output              Enable logging to stdout/stderr
                                       (not recommended when running as a daemon)
  -c, --config-absolute-path <PATH>    Absolute path to an alternate config file
  -t, --tracing-absolute-path <PATH>   Absolute path to an alternate tracing output file
  -p, --private-key-path <PATH>        Absolute path to the server private key
  -k, --public-key-path <PATH>         Absolute path to the server public key
      --warmup-delay-ms <MILLIS>       Extra delay (ms) after peer discovery before
                                       sending terminal data
      --pacing-delay-us <MICROS>       Min inter-packet delay (µs) between diff chunks
                                       [default: 1000]
      --term-type <TERM>               TERM environment variable for spawned shells
                                       [default: xterm-256color]
      --kex-algos <ALGOS>              Ordered KEX algorithms to prefer, comma-separated
      --aead-algos <ALGOS>             Ordered AEAD algorithms to prefer, comma-separated
      --mac-algos <ALGOS>              Ordered MAC algorithms to prefer, comma-separated
      --kdf-algos <ALGOS>              Ordered KDF algorithms to prefer, comma-separated
  -h, --help                           Print help
  -V, --version                        Print version
```

### Example invocations

```bash
# Start with defaults (reads ~/.config/moshpits/moshpits.toml)
mps

# Start with verbose logging to stderr
mps -vv --enable-std-output

# Use a custom config file
mps --config-absolute-path /etc/moshpits/moshpits.toml

# Use non-default key files
mps --private-key-path /etc/moshpits/host_key \
    --public-key-path  /etc/moshpits/host_key.pub

# Use a different TERM type for specialized environments
mps --term-type screen-256color

# Tune for NAT devices with high warmup delay and packet pacing
mps --warmup-delay-ms 200 --pacing-delay-us 2000

# Prefer P-384 key exchange and ChaCha20 for all sessions
mps --kex-algos p384-sha384,x25519-sha256 --aead-algos chacha20-poly1305,aes256-gcm-siv

# Reduce per-packet overhead by preferring HMAC-SHA-256 (32-byte tag vs 64-byte)
mps --mac-algos hmac-sha256,hmac-sha512
```

### moshpits configuration

**Default config file**: `~/.config/moshpits/moshpits.toml`  
**Environment variable prefix**: `MOSHPITS_` (nested keys separated by `_`, e.g. `MOSHPITS_MPS_PORT=40404`)

```toml
# ~/.config/moshpits/moshpits.toml

# ── Logging ──────────────────────────────────────────────────────────────────
# Base verbosity offset applied to the tracing output file.
# 0 = INFO, positive values increase verbosity, negative decrease it.
verbose = 0
quiet   = 0

# ── Server listen address ─────────────────────────────────────────────────────
[mps]
ip   = "0.0.0.0"   # IP address to listen on
port = 40404       # TCP port to listen on for client connections

# ── Key files ─────────────────────────────────────────────────────────────────
# Defaults to ~/.mp/mps_host_ed25519_key and ~/.mp/mps_host_ed25519_key.pub
# when not set.
# private_key_path = "/path/to/mps_host_ed25519_key"
# public_key_path  = "/path/to/mps_host_ed25519_key.pub"

# ── PTY environment ───────────────────────────────────────────────────────────
# TERM environment variable to set for spawned shells. Default: xterm-256color.
# Matches the VT100/VT220 emulation used by libmoshpit. Required when running
# as a systemd service to prevent ncurses application failures.
term_type = "xterm-256color"

# ── NAT device tuning (optional) ──────────────────────────────────────────────
# Extra delay (ms) after peer discovery before sending bulk terminal data.
# Provides margin for NAT bindings on slow NAT devices when clients use --nat-warmup.
# warmup_delay_ms = 100

# Minimum inter-packet delay (µs) between consecutive diff chunks from the same
# PTY read batch. Spreads back-to-back packets to prevent burst loss on stateful
# NAT devices. Default: 1000 (1 ms). Set to 0 to disable pacing.
# pacing_delay_us = 1000

# ── Algorithm preferences (optional) ─────────────────────────────────────────
# Override the server's preferred algorithm order.  The server's order wins
# during negotiation — the first algorithm from this list that the connecting
# client also supports is selected.  Omitted categories use the built-in defaults.
#
# [preferred_algorithms]
# kex  = ["x25519-sha256", "p384-sha384", "p256-sha256"]
# aead = ["aes256-gcm-siv", "aes256-gcm", "chacha20-poly1305", "aes128-gcm-siv"]
# mac  = ["hmac-sha512", "hmac-sha256"]
# kdf  = ["hkdf-sha256", "hkdf-sha384", "hkdf-sha512"]

# ── Tracing (log output) ──────────────────────────────────────────────────────
# stdout layer — controls the format of log lines written to stderr when
# --enable-std-output is active.
[tracing.stdout]
with_target      = false  # include the Rust module path in each log line
with_thread_ids  = false  # include the thread ID
with_thread_names = false # include the thread name
with_line_number = false  # include the source file line number
with_level       = true   # include the log level (ERROR, WARN, INFO, …)
# directives = "moshpits=debug,libmoshpit=info"  # optional tracing filter

# file layer — controls the format and level of the persistent tracing file.
# Default log file: ~/.config/moshpits/logs/moshpits.log
[tracing.file]
quiet   = 0
verbose = 0

[tracing.file.layer]
with_target      = false
with_thread_ids  = false
with_thread_names = false
with_line_number = false
with_level       = true
# directives = "moshpits=debug"
```

#### Configuration precedence (highest → lowest)

1. Environment variables (`MOSHPITS_*`)
2. Command-line flags
3. Config file values

---

## moshpit client (`mp`)

### Quick start

1. Generate a client key pair (run once):

   ```bash
   mp-keygen generate
   # Accept the default path: ~/.mp/id_ed25519
   ```

2. Add the client's public key to the server's `authorized_keys` file.

   On the **server**, append the contents of the client's `~/.mp/id_ed25519.pub` to `~$TARGET_USER/.mp/authorized_keys` (one key per line):

   ```bash
   # On the client — display the public key to copy
   cat ~/.mp/id_ed25519.pub

   # On the server — create the directory and file with the correct permissions
   mkdir -p ~/.mp && chmod 700 ~/.mp
   echo 'moshpit <base64-key> user@host' >> ~/.mp/authorized_keys
   chmod 600 ~/.mp/authorized_keys
   ```

   The public key line format written by `mp-keygen generate` is:

   ```
   moshpit <base64-encoded-public-key> user@host
   ```

   > **Permission requirements**: `~/.mp` must be mode `0700` and `authorized_keys` must be mode `0600`, otherwise the server will reject the connection.

3. Connect to the server:

   ```bash
   mp 192.168.1.10
   # or with an explicit user
   mp alice@192.168.1.10
   ```

### Command-line usage

```
mp [OPTIONS] <SERVER_DESTINATION>

Arguments:
  <SERVER_DESTINATION>   IP address (or user@address) of the server to connect to

Options:
  -v, --verbose                        Turn up logging verbosity (repeatable)
  -q, --quiet                          Turn down logging verbosity (repeatable)
  -c, --config-absolute-path <PATH>    Absolute path to an alternate config file
  -t, --tracing-absolute-path <PATH>   Absolute path to an alternate tracing output file
  -p, --private-key-path <PATH>        Absolute path to the client private key
  -k, --public-key-path <PATH>         Absolute path to the client public key
  -s, --server-port <PORT>             Server TCP port (default: 40404)
      --predict <MODE>                 Local-echo prediction: adaptive (default),
                                       always, or never
      --nat-warmup                     Send NAT warmup keepalives at UDP session start
      --nat-warmup-count <N>           Number of NAT warmup keepalives to send
                                       [default: 3]
      --kex-algos <ALGOS>              Ordered KEX algorithms to offer, comma-separated
      --aead-algos <ALGOS>             Ordered AEAD algorithms to offer, comma-separated
      --mac-algos <ALGOS>              Ordered MAC algorithms to offer, comma-separated
      --kdf-algos <ALGOS>              Ordered KDF algorithms to offer, comma-separated
  -h, --help                           Print help
  -V, --version                        Print version
```

### Example invocations

```bash
# Connect to a server on the default port (40404)
mp 192.168.1.10

# Connect as a specific user
mp alice@192.168.1.10

# Connect to a non-default port
mp --server-port 50505 192.168.1.10

# Verbose logging, custom key files
mp -vv \
   --private-key-path ~/.mp/work_id_ed25519 \
   --public-key-path  ~/.mp/work_id_ed25519.pub \
   alice@10.0.0.5

# Disable prediction for low-latency LANs
mp --predict never 192.168.1.10

# Enable NAT warmup for problematic NAT devices
mp --nat-warmup --nat-warmup-count 5 192.168.1.10

# Force prediction always on
mp --predict always user@remote-server.com

# Use ChaCha20-Poly1305 when connecting from a device without AES hardware
mp --aead-algos chacha20-poly1305,aes256-gcm-siv user@remote-server.com

# Prefer P-384 and save bandwidth with a smaller MAC tag
mp --kex-algos p384-sha384 --mac-algos hmac-sha256 user@remote-server.com
```
### moshpit configuration

**Default config file**: `~/.config/moshpit/moshpit.toml`  
**Environment variable prefix**: `MOSHPIT_` (e.g. `MOSHPIT_SERVER_PORT=40404`)

```toml
# ~/.config/moshpit/moshpit.toml

# ── Logging ───────────────────────────────────────────────────────────────────
verbose = 0
quiet   = 0

# ── Server connection ─────────────────────────────────────────────────────────
server_port        = 40404          # TCP port of the moshpits server
server_destination = "192.168.1.10" # "ip" or "user@ip"; overridden by the
                                    # positional argument on the command line

# ── Reconnection ──────────────────────────────────────────────────────────────
# Maximum back-off interval between automatic reconnect attempts (seconds).
# Clamped to the range [2, 86400].  Default: 3600 (1 hour).
max_reconnect_backoff_secs = 3600

# ── Key files ─────────────────────────────────────────────────────────────────
# Defaults to ~/.mp/id_ed25519 and ~/.mp/id_ed25519.pub when not set.
# private_key_path = "/home/alice/.mp/id_ed25519"
# public_key_path  = "/home/alice/.mp/id_ed25519.pub"

# ── Local echo prediction ─────────────────────────────────────────────────────
# Control client-side keystroke prediction: adaptive (default), always, or never.
# Adaptive enables prediction on high-latency connections; 'never' disables it.
predict = "adaptive"

# ── NAT traversal (optional) ──────────────────────────────────────────────────
# Send warmup keepalives before UDP session starts to establish NAT bindings.
# Only useful on NAT paths; adds one round-trip of startup latency.
nat_warmup = false
nat_warmup_count = 3  # Number of keepalive frames to send (default: 3)

# ── Algorithm preferences (optional) ─────────────────────────────────────────
# Override the algorithms this client offers during negotiation.  The server's
# preference order wins, but the server can only pick from what you offer here.
# Omitted categories use the built-in defaults.
#
# [preferred_algorithms]
# kex  = ["x25519-sha256", "p384-sha384", "p256-sha256"]
# aead = ["chacha20-poly1305", "aes256-gcm-siv"]  # prefer ChaCha on this device
# mac  = ["hmac-sha256", "hmac-sha512"]            # save 32 bytes per packet
# kdf  = ["hkdf-sha256", "hkdf-sha384", "hkdf-sha512"]

# ── Tracing (log output) ──────────────────────────────────────────────────────
[tracing.stdout]
with_target      = false
with_thread_ids  = false
with_thread_names = false
with_line_number = false
with_level       = true
# directives = "moshpit=debug,libmoshpit=info"

# Default log file: ~/.config/moshpit/logs/moshpit.log
[tracing.file]
quiet   = 0
verbose = 0

[tracing.file.layer]
with_target      = false
with_thread_ids  = false
with_thread_names = false
with_line_number = false
with_level       = true
```

#### Configuration precedence (highest → lowest)

1. Environment variables (`MOSHPIT_*`)
2. Command-line flags
3. Config file values

---

## Troubleshooting

### "Cannot initialize terminal" errors on systemd servers

**Symptom**: When running moshpits as a systemd service, commands like `htop`, `vim`, or `less` fail with:
```
Error opening terminal: unknown.
```

**Cause**: Systemd services run without a controlling terminal, so the `TERM` environment variable is not set. When moshpits spawns shells, it sets `HOME`, `USER`, `LOGNAME`, and `SHELL` but was missing `TERM`, causing ncurses applications to fail.

**Solution**: Use the `term_type` configuration option (default: `xterm-256color`):

```toml
# In ~/.config/moshpits/moshpits.toml
term_type = "xterm-256color"
```

Or via CLI:
```bash
mps --term-type xterm-256color
```

Or via environment variable:
```bash
MOSHPITS_TERM_TYPE=xterm-256color mps
```

The default `xterm-256color` matches the VT100/VT220 terminal emulation used by libmoshpit and works with most ncurses applications. For specialized environments, you can override it with other values like `screen-256color`, `tmux-256color`, or `linux`.

### NAT traversal issues

**Symptom**: Connection hangs after TCP key exchange, no UDP terminal data flows.

**Solution**: Use the `--nat-warmup` option on the client to send keepalive frames before the UDP session starts:

```bash
mp --nat-warmup --nat-warmup-count 5 192.168.1.10
```

On the server, add a warmup delay to give the NAT device time to establish bindings:

```bash
mps --warmup-delay-ms 100
```

For stateful NAT devices that drop bursty packets, enable packet pacing:

```bash
mps --pacing-delay-us 2000
```

### High packet loss on poor networks

**Symptom**: Terminal updates are sluggish or incomplete, especially during full-screen redraws (e.g. `htop`, `vim`).

**Solution**: Increase the pacing delay on the server to spread packets over time:

```bash
mps --pacing-delay-us 5000
```

Or in the config file:
```toml
pacing_delay_us = 5000
```

Note: the server automatically applies **3× the configured pacing delay** for large PTY bursts (more than 10 MTU-sized chunks from a single PTY read), so `htop`-style full-screen redraws are paced more aggressively than small incremental updates without any extra configuration.

### Terminal stalls on high-latency or congested NAT paths

**Symptom**: Occasional multi-second freezes in terminal output, particularly when running high-output programs over a congested or high-latency NAT connection.

**Cause**: If the adaptive NAK timeout converges to its minimum (20 ms) and the connection then experiences a real congestion spike, the aggressive NAK rate can worsen congestion, which in turn appears as more packet loss — a self-reinforcing loop.  The adaptive estimator now clamps outlier RTT spikes rather than discarding them, so the timeout self-heals within a few keepalive intervals, but the symptom may still appear briefly.

**Solution**: If stalls persist, enable packet pacing to reduce burst pressure on the NAT device:

```bash
mps --pacing-delay-us 2000
```

---

## Ports and firewall

| Port range | Protocol | Direction | Purpose |
|-----------|----------|-----------|---------|
| `mps.port` (e.g. 40404) | TCP | Inbound to server | Key exchange only — connection switches to UDP after handshake |
| 50000–59999 | UDP | Inbound to server | Encrypted terminal data |

---

## Developer Liability Disclaimer

To the fullest extent permitted by applicable law, this software is provided "AS IS" and "AS AVAILABLE", without warranties or conditions of any kind, express or implied.  By installing, running, or distributing this software, you assume all risks associated with its use.

The project author and contributors are not liable for any direct, indirect, incidental, special, exemplary, or consequential damages, including but not limited to system damage, data loss, security incidents, service interruption, or loss of profits, arising from use of this project.

If you do not agree with these terms, do not use this software.

---

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your option.
