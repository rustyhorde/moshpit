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
| **Transport model** | Pure UDP after setup; Mosh's *State Synchronization Protocol* (SSP) keeps a diff of the full terminal screen state and sends only the latest snapshot | TCP is used solely for the ed25519 key exchange; all terminal I/O runs over UDP after the exchange completes.  NAK-based selective retransmission ensures reliable, ordered delivery of the raw byte stream |
| **Reconnect display sync** | SSP sends the latest screen snapshot; client repaints from the diff immediately | Server maintains a `vt100::Parser` tracking the live PTY screen; on reconnect a single `ScreenState` frame delivers `contents_formatted()` bytes for an instant clean repaint.  A 50 ms periodic task also sends `ScreenState` diffs during normal use so the client stays in sync even across network hiccups. |
| **Client-side prediction** | Mosh echoes keystrokes locally and predicts cursor movement to hide latency, underlining characters that have not yet been confirmed by the server | Same — keystrokes are echoed locally, cursor movement is predicted, and unconfirmed characters are underlined until the server output arrives |
| **Encryption** | AES-128-OCB authenticated encryption using a symmetric session key | Key exchange via an ed25519-based handshake; symmetric AES-256-GCM-SIV on the UDP channel with per-packet HMAC-SHA-512 authentication |
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

All subsequent communication happens exclusively over UDP (server-side port range 50000–59999).  Every frame is encrypted with AES-256-GCM-SIV and authenticated with a per-packet HMAC-SHA-512.

Reliable, ordered delivery is provided at the application layer using **NAK-based selective retransmission**:

- The **receiver** (`UdpReader`) tracks the highest sequence number seen and maintains a reorder buffer.  Any gap that persists beyond a 50 ms timeout triggers a `Nak` frame — a compact list of missing sequence numbers — sent back to the sender over the same UDP channel.
- The **sender** (`UdpSender`) keeps a sliding retransmit buffer of the 512 most-recently transmitted wire-encoded packets.  When a `Nak` arrives the missing packets are looked up and resent immediately.
- Each gap is retried up to 10 times (with the 50 ms floor doubling each attempt); after the limit is exceeded the gap is abandoned and the session proceeds.

Because retransmission is handled entirely within the UDP layer there is no head-of-line blocking from TCP: a lost packet delays only the frames that depend on it, not the rest of the stream.

### Reconnection

If the UDP path is interrupted the client automatically reconnects — performing a new TCP key exchange for the same logical session — and the server delivers a single `ScreenState` frame containing the current terminal contents so the display repaints instantly without replaying scrollback history.

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
