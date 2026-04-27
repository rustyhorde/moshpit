# moshpit
An SSH and Mosh inspired tool written in Rust.

## Overview

moshpit is a suite of tools for establishing encrypted, resilient remote terminal sessions:

| Binary | Crate | Role |
|--------|-------|------|
| `mps` | moshpits | Server — listens for incoming connections and spawns PTYs |
| `mp` | moshpit | Client — connects to a running `mps` server |
| `mp-keygen` | keygen | Key management — generates and inspects ed25519 key pairs |

Sessions are authenticated with ed25519 key pairs and transported over an encrypted TCP control channel plus a UDP data channel (ports 50000–59999).

---

## Inspiration & Relation to Mosh

moshpit draws its core motivation from [Mosh (Mobile Shell)](https://mosh.org/), the excellent remote terminal tool created by Keith Winstein and colleagues at MIT.  Mosh demonstrated that a UDP-based transport with graceful handling of packet loss, reordering, and IP roaming could make remote terminal sessions feel dramatically more responsive and reliable than traditional SSH — particularly over high-latency or intermittent connections.  moshpit was created as an exercise in rebuilding that idea from scratch in Rust, exploring different design trade-offs along the way.

### What moshpit shares with Mosh

- **UDP terminal data channel** — terminal I/O is carried over UDP rather than a reliable stream, allowing the session to survive network interruptions without blocking on TCP retransmit timeouts.
- **Resilience to connectivity loss** — both tools keep the session alive across short network outages and IP address changes; the client reconnects automatically without user intervention.
- **Authenticated encryption** — all data on the wire is encrypted and authenticated; neither tool relies on a plain-text transport at any layer.
- **Client / server split** — a lightweight server component (`mps` / `mosh-server`) runs on the remote host and manages the PTY; a client (`mp` / `mosh`) runs locally and drives the terminal.

### Where moshpit differs

| Concern | Mosh | moshpit |
|---------|------|---------|
| **Language** | C++ | Rust |
| **Authentication** | Delegated to SSH for the initial handshake; a one-time secret is passed back over SSH | Standalone ed25519 key-pair authentication — no SSH dependency |
| **Transport model** | Pure UDP after setup; Mosh's *State Synchronization Protocol* (SSP) keeps a diff of the full terminal screen state and sends only the latest snapshot | Separate TCP control channel + UDP data channel; NAK-based selective retransmission ensures reliable, ordered delivery of the raw byte stream |
| **Client-side prediction** | Mosh echoes keystrokes locally and predicts cursor movement to hide latency, underlining characters that have not yet been confirmed by the server | No client-side prediction — the server's output is authoritative and is displayed as received |
| **Encryption** | AES-128-OCB authenticated encryption using a symmetric session key | Key exchange via an ed25519-based handshake; symmetric encryption on the UDP channel with per-packet HMAC authentication |
| **Session multiplexing** | One Mosh session per `mosh-server` process | Same — one PTY per `mps` connection |
| **Configuration** | Minimal; primarily driven by command-line options | TOML config files with environment-variable overrides |
| **UDP port range** | 60001–61000 (by default) | 50000–59999 |
| **License** | GPL v3 | Apache 2.0 / MIT (your choice) |

> **Attribution**: the name *moshpit* is a deliberate nod to Mosh, whose design and published research were a direct inspiration for this project.  If you need production-grade, battle-tested remote terminal software, [use Mosh](https://mosh.org/).  moshpit is an independent reimagining with different goals and trade-offs.

---

## Building

```bash
cargo build --release
```

The resulting binaries are in `target/release/`.

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
| `mps.port` (e.g. 40404) | TCP | Inbound to server | Control channel / key exchange |
| 50000–59999 | UDP | Inbound to server | Encrypted terminal data |

---

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your option.
