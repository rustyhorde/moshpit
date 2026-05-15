# moshpit
An SSH and Mosh inspired tool written in Rust.

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

## Overview

moshpit is a suite of tools for establishing encrypted, resilient remote terminal sessions:

| Binary | Crate | Role |
|--------|-------|------|
| `mps` | moshpits | Server — listens for incoming connections and spawns PTYs |
| `mp` | moshpit | Client — connects to a running `mps` server |
| `mp-keygen` | moshpit-keygen | Key management — generates and inspects asymmetric key pairs (X25519, P-384, or P-256) |

Sessions are authenticated with asymmetric key pairs (X25519 by default; P-384 and P-256 are also supported).  TCP is used only for the initial key exchange; once the exchange completes the connection switches to UDP exclusively (ports 50000–59999) for all terminal I/O.  The server tracks full terminal screen state with a server-side vt100 emulator; on reconnect the client receives a single clean screen snapshot and repaints instantly rather than replaying raw scrollback history.

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
| **Authentication** | Delegated to SSH for the initial handshake; a one-time secret is passed back over SSH | Standalone asymmetric key-pair authentication (X25519, P-384, or P-256) — no SSH dependency |
| **Transport model** | Pure UDP after setup; Mosh's *State Synchronization Protocol* (SSP) keeps a diff of the full terminal screen state and sends only the latest snapshot | TCP is used solely for the asymmetric key exchange; all terminal I/O runs over UDP after the exchange completes.  Three selectable diff transport modes: `reliable` (default, NAK-based retransmission with adaptive RTT), `datagram` (fire-and-forget with periodic full-screen recovery), and `statesync` (Mosh-inspired ack-based diffs, no NAKs); see [UDP diff transport modes](#udp-diff-transport-modes) |
| **Reconnect display sync** | SSP sends the latest screen snapshot; client repaints from the diff immediately | Server maintains a `vt100::Parser` tracking the live PTY screen; on reconnect a single `ScreenState` frame delivers `contents_formatted()` bytes for an instant clean repaint.  A 50 ms periodic task also sends `ScreenState` diffs during normal use so the client stays in sync even across network hiccups. |
| **Client-side prediction** | Mosh echoes keystrokes locally and predicts cursor movement to hide latency, underlining characters that have not yet been confirmed by the server | Same — keystrokes are echoed locally, cursor movement is predicted, and unconfirmed characters are underlined until the server output arrives |
| **Encryption** | AES-128-OCB authenticated encryption using a symmetric session key | Key exchange via an asymmetric key-pair handshake (default: X25519); negotiated symmetric encryption on the UDP channel (default: AES-256-GCM-SIV with per-packet HMAC-SHA-512; see [Algorithm negotiation](#algorithm-negotiation)) |
| **Session multiplexing** | One Mosh session per `mosh-server` process | Same — one PTY per `mps` connection |
| **Configuration** | Minimal; primarily driven by command-line options | TOML config files with environment-variable overrides |
| **UDP port range** | 60001–61000 (by default) | 50000–59999 |
| **License** | GPL v3 | Apache 2.0 / MIT (your choice) |

> **Attribution**: the name *moshpit* is a deliberate nod to Mosh, whose design and published research were a direct inspiration for this project.  If you need production-grade, battle-tested remote terminal software, [use Mosh](https://mosh.org/).  moshpit is an independent reimagining with different goals and trade-offs.

---

## Connection model

### Phase 1 — TCP key exchange

The client opens a TCP connection to the server's configured port (default 40404).  The two sides run a mutual asymmetric key-pair authentication and key-exchange protocol over this connection.  Once the handshake completes both halves of the TCP socket are released and the TCP connection is **closed immediately** — it is not kept alive, and is not used for anything after the key exchange.

### Phase 2 — UDP session

All subsequent communication happens exclusively over UDP (server-side port range 50000–59999).  Every frame is encrypted and authenticated using the algorithms negotiated during Phase 1 (default: AES-256-GCM-SIV with per-packet HMAC-SHA-512; see [Algorithm negotiation](#algorithm-negotiation) for the full list of supported ciphers and how to select them).

The client selects a **diff transport mode** during key exchange (via `--diff-mode`; see [UDP diff transport modes](#udp-diff-transport-modes) below).  The mode determines how the server delivers PTY screen diffs and how lost packets are recovered.  All three modes use the same encryption and frame format; only the delivery and recovery strategy differ.

### UDP diff transport modes

#### `reliable` (default)

The server sends incremental PTY diffs as they are produced.  The client tracks sequence numbers, buffers out-of-order frames, and requests retransmission of any gaps via `Nak` frames.

**How it works:**

- The **receiver** (`UdpReader`) maintains a reorder buffer and tracks gaps.  Any gap that persists beyond the adaptive NAK timeout triggers a `Nak` frame — a compact list of missing sequence numbers — sent back to the server.  A `RepaintRequest` is also sent after the first NAK retry (or immediately when the reorder buffer grows large), so the server delivers a fresh full-screen snapshot within one RTT without waiting for retransmit to succeed.
- The **sender** (`UdpSender`) keeps a sliding retransmit buffer of the 512 most-recently transmitted packets.  When a `Nak` arrives the missing packets are resent immediately.  Two separate outbound channels — a high-priority control channel for `Keepalive` and `Shutdown` frames and a data channel for diffs and screen states — ensure control frames always bypass any data backlog.
- Each gap is retried up to 4 times with exponential backoff (initial 50 ms, capped at 800 ms); after the retry limit the gap is abandoned and the session proceeds.
- The NAK timeout adapts continuously to the measured RTT using a Jacobson-Karels estimator (range: 20–500 ms).  Outlier RTT spikes are clamped to 8× the current estimate rather than discarded, preventing the estimator from staying locked at 20 ms and sending aggressive NAKs that worsen congestion.
- Large PTY bursts (more than 10 MTU-sized chunks from a single PTY read, e.g. a full-screen `htop` redraw) are sent with **3× the configured pacing delay** to reduce burst loss on stateful NAT devices.
- The server also runs a proactive watchdog: if it receives ≥10 NAK frames within a 200 ms window it pushes a full `ScreenStateCompressed` immediately, without waiting for an explicit `RepaintRequest` that may itself be lost on a high-loss path.

**Pros:** Lowest bandwidth in steady state (only sends what changed); ordered, lossless delivery; fast per-gap recovery.

**Cons:** Head-of-line blocking — a lost packet stalls all frames with higher sequence numbers until it is retransmitted or the gap is abandoned; retransmit overhead increases sharply on lossy paths.

**Best for:** Low-loss networks — LAN, fibre, stable broadband — where retransmit fires rarely and packet ordering is mostly preserved.

---

#### `datagram`

The server sends incremental PTY diffs with no retransmission.  The client applies diffs as they arrive and ignores gaps entirely.  As the sole recovery mechanism, the server pushes a compressed full-screen snapshot (`ScreenStateCompressed`) every **150 ms**; any accumulated drift is corrected on the next push regardless of what was lost.

**How it works:**

- No NAK frames are generated; no reorder buffer is maintained; incoming frames are delivered immediately in arrival order.
- The server runs a dedicated periodic task that fires every 150 ms, compresses the current `contents_formatted()` snapshot with zstd, and sends it unconditionally.  At a typical compressed screen size of ~3 KB this costs roughly 20 KB/s of extra bandwidth — negligible on any modern link.
- Large initial screen state (or state exceeding the single-datagram limit) is sent as a sequence of `StateChunk` frames (800 B payload each) that the client reassembles.

**Pros:** No head-of-line blocking; the terminal never stalls regardless of loss rate; simple, stateless delivery path.

**Cons:** Higher baseline bandwidth than `reliable` (periodic full-screen pushes even when nothing has changed); a lost diff is visible as a brief glitch for up to 150 ms before the next push corrects it.

**Best for:** High-loss or flaky networks — bursty mobile data, lossy WiFi, satellite links with variable loss — where retransmission would be counterproductive or create congestion feedback loops.

```bash
mp --diff-mode datagram user@192.168.1.10
```

---

#### `statesync`

A Mosh-inspired ack-based delivery mode.  Instead of sending the incremental diff since the *last packet*, the server always sends `contents_diff(ack_state → current)`: the diff from the last state the client **acknowledged** to the current screen.  Each packet is therefore self-contained — a lost packet is automatically covered by the next one sent from the same baseline, with no explicit retransmission needed.

**How it works:**

- The server ticks every **50 ms**.  On each tick it computes `contents_diff(ack_state, current)` and sends a `StateSyncDiff(base_id, diff_id, compressed_diff)` frame if the diff is non-empty.
- The client applies the diff to its local `ack_state`, advances its baseline, and immediately sends a `ClientAck(diff_id)` back to the server.  The server uses incoming `ClientAck` frames to advance its diff baseline so subsequent diffs are as small as possible.
- The server keeps a ring buffer of the 32 most-recently sent states.  When a `ClientAck` arrives, the corresponding entry is looked up to advance the baseline; stale acks are silently discarded.
- If a `StateSyncDiff` arrives with a `base_id` that does not match the client's current `ack_state_seq` (i.e. a packet was lost or arrived out of order), the client discards it and increments a mismatch counter.  After 3 consecutive mismatches the client sends a `RepaintRequest` to trigger a full-state push and reset the baseline.
- Diffs exceeding 900 bytes compressed (e.g. a full alt-screen repaint from `htop`) are replaced with a chunked `ScreenStateCompressed` push rather than a single oversized datagram, preventing NAT fragmentation from stalling the ack pipeline.
- No reorder buffer; no NAK frames; no periodic full-screen pushes in steady state.

**Pros:** Each packet carries maximum useful information — no redundant retransmission; no head-of-line blocking; no periodic bandwidth tax in steady state; bandwidth scales with actual screen change rate rather than loss rate.

**Cons:** Per-packet payload is larger than `reliable` mode (full diff from ack baseline rather than the incremental diff since last packet); latency of each rendered update is bounded by the ack round-trip; desync recovery (3 mismatches → `RepaintRequest`) adds a recovery round-trip on high-loss paths.

**Best for:** Moderate-loss, low-bandwidth links — satellite, weak cellular, metered connections — where bandwidth is precious, each packet should carry maximum useful state, and explicit retransmission is undesirable.

```bash
mp --diff-mode statesync user@192.168.1.10
```

---

#### Choosing a mode

| Condition | Recommended mode |
|-----------|-----------------|
| Low loss, low latency (LAN, fibre, stable broadband) | `reliable` (default) |
| High or bursty loss (lossy WiFi, poor mobile, VPN with drops) | `datagram` |
| Moderate loss, bandwidth-constrained (satellite, weak cellular) | `statesync` |
| High-throughput programs (`htop`, `vim`) over a flaky path | `datagram` |
| Metered / low-bandwidth link, screen changes infrequently | `statesync` |

The mode is requested by the client and honoured by the server for the lifetime of the session.  It can be set on the command line or in the client config file:

```bash
# Command line
mp --diff-mode datagram user@192.168.1.10

# Client config file (~/.config/moshpit/moshpit.toml)
diff_mode = "datagram"   # or "reliable" / "statesync"
```

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
| ML-KEM-768 + HKDF-SHA-256 | `ml-kem-768-sha256` | | Post-quantum KEM from AWS-LC; good default PQ security/performance balance | Larger TCP handshake messages than ECDH; must be supported by both peers |
| ML-KEM-512 + HKDF-SHA-256 | `ml-kem-512-sha256` | | Smaller/faster post-quantum KEM option | Lower security margin than ML-KEM-768/1024 |
| ML-KEM-1024 + HKDF-SHA-256 | `ml-kem-1024-sha256` | | Highest ML-KEM security margin | Largest ML-KEM public key and ciphertext |
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

## Security Notice (Pre-Hardening)

This project has not yet completed a formal security hardening phase, external security review, or independent penetration testing.  It may contain security flaws that could lead to data loss, session compromise, privilege misuse, or other unintended behavior.

Use this software at your own risk, especially in internet-facing, production, or high-trust environments.

---

## Installation (Arch Linux / AUR)

All three binaries are available in three package variants on the AUR.  Install them with any AUR helper (e.g. `yay`, `paru`) or manually with `makepkg`.

| Variant | Packages | Build | ML-DSA keys |
|---------|----------|-------|:-----------:|
| Source (compile locally) | `moshpit-keygen` `moshpit` `moshpits` | `cargo build` from source tarball | — |
| Pre-compiled binary | `moshpit-keygen-bin` `moshpit-bin` `moshpits-bin` | MUSL static binary from GitHub release | — |
| Pre-compiled binary + unstable | `moshpit-keygen-unstable-bin` `moshpit-unstable-bin` `moshpits-unstable-bin` | MUSL static binary built with `--features unstable` | ✓ |

The `-unstable-bin` packages install the same binary names (`mp-keygen`, `mp`, `mps`) and conflict with the other variants — only one variant can be installed at a time.

### Install with an AUR helper

```bash
# Standard pre-compiled binaries (no Rust toolchain required)
yay -S moshpits-bin moshpit-bin

# Pre-compiled binaries with post-quantum ML-DSA identity key support
yay -S moshpits-unstable-bin moshpit-unstable-bin

# Source packages (compiles locally; requires Rust, cmake, gcc)
yay -S moshpits moshpit
```

### Install manually with makepkg

#### Pre-compiled binary packages (`-bin`)

```bash
# 1. Install moshpit-keygen-bin first (provides mp-keygen, no dependencies)
git clone https://aur.archlinux.org/moshpit-keygen-bin.git
cd moshpit-keygen-bin && makepkg -si && cd ..

# 2. Install the server binary
git clone https://aur.archlinux.org/moshpits-bin.git
cd moshpits-bin && makepkg -si && cd ..

# 3. Install the client binary
git clone https://aur.archlinux.org/moshpit-bin.git
cd moshpit-bin && makepkg -si && cd ..
```

#### Unstable binary packages (`-unstable-bin`, includes ML-DSA support)

```bash
# 1. Install moshpit-keygen-unstable-bin first
git clone https://aur.archlinux.org/moshpit-keygen-unstable-bin.git
cd moshpit-keygen-unstable-bin && makepkg -si && cd ..

# 2. Install the server binary with unstable support
git clone https://aur.archlinux.org/moshpits-unstable-bin.git
cd moshpits-unstable-bin && makepkg -si && cd ..

# 3. Install the client binary with unstable support
git clone https://aur.archlinux.org/moshpit-unstable-bin.git
cd moshpit-unstable-bin && makepkg -si && cd ..
```

#### Source packages (compile locally)

```bash
# 1. Clone and build moshpit-keygen first (shared dependency)
git clone https://aur.archlinux.org/moshpit-keygen.git
cd moshpit-keygen && makepkg -si && cd ..

# 2. Clone and build the server
git clone https://aur.archlinux.org/moshpits.git
cd moshpits && makepkg -si && cd ..

# 3. Clone and build the client
git clone https://aur.archlinux.org/moshpit.git
cd moshpit && makepkg -si && cd ..
```

### Removing packages

```bash
# Remove server and client (keep keygen)
sudo pacman -R moshpits moshpit       # or moshpits-bin / moshpits-unstable-bin etc.

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

`mp-keygen` creates and inspects the asymmetric key pairs used by both the server and client.  Three key algorithms are supported by default: X25519, P-384, and P-256. Experimental ML-DSA identity keys are available when built with `--features unstable`.

### Supported identity key algorithms

| Algorithm | Flag value | Default | Notes |
|-----------|------------|:-------:|-------|
| X25519 | `x25519` | ✓ | Fastest; constant-time by construction; 128-bit security level; recommended for most deployments |
| NIST P-384 | `p384` | | 192-bit security level; FIPS/NIST approved; suited for high-security or compliance environments |
| NIST P-256 | `p256` | | 128-bit security level; FIPS/NIST approved; hardware TPM/HSM support on many platforms |
| ML-DSA-44 | `mldsa44` | | Experimental post-quantum signature identity key; requires `--features unstable` |
| ML-DSA-65 | `mldsa65` | | Experimental post-quantum signature identity key; requires `--features unstable` |
| ML-DSA-87 | `mldsa87` | | Experimental post-quantum signature identity key; requires `--features unstable` |

### Subcommands

#### `generate`

Generates a new asymmetric public/private key pair.  By default the tool prompts for an output path and a passphrase; all prompts can be bypassed with flags for non-interactive use.

```bash
mp-keygen generate                                        # X25519 key (default), prompts for path + passphrase
mp-keygen generate --key-type p384                        # P-384 key
mp-keygen generate --key-type p256                        # P-256 key
mp-keygen generate --key-type mldsa65                     # Experimental ML-DSA key when built with --features unstable
mp-keygen generate -n -o ~/.mp/id_x25519                  # Non-interactive: X25519, no passphrase
mp-keygen generate --server -n -o ~/.mp/mps_host_key      # Server host key, no passphrase
```

| Flag | Short | Description |
|------|-------|-------------|
| `--key-type <TYPE>` | `-k` | Identity key algorithm: `x25519` (default), `p384`, `p256`; with `--features unstable`: `mldsa44`, `mldsa65`, `mldsa87` |
| `--no-passphrase` | `-n` | Skip the passphrase prompt; create an unencrypted key |
| `--output-path <PATH>` | `-o` | Write keys to this path (skips the interactive path prompt) |
| `--force` | `-f` | Overwrite existing key files without confirmation |
| `--server` | `-s` | Generate a server host key |

Default key locations when accepting the default path prompt:

| Key | Default path |
|-----|-------------|
| Client private key | `~/.mp/id_ed25519` |
| Client public key  | `~/.mp/id_ed25519.pub` |
| Server private key | `~/.mp/mps_host_ed25519_key` |
| Server public key  | `~/.mp/mps_host_ed25519_key.pub` |

> **Note**: The default file names use the `ed25519` naming convention for historical compatibility.  The actual key algorithm embedded in the file is determined by `--key-type` (default: `x25519`).  All supported identity key algorithms share the same file format and the paths can be freely overridden with `--output-path`.

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
   # Interactive: prompts for path and passphrase
   mp-keygen generate --server

   # Non-interactive (e.g. during service setup):
   mp-keygen generate --server --no-passphrase --output-path ~/.mp/mps_host_ed25519_key

   # Use a P-384 key for a FIPS/compliance environment:
   mp-keygen generate --server --key-type p384 --output-path ~/.mp/mps_host_p384_key
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
                                       [supported: x25519-sha256 (default),
                                       ml-kem-768-sha256, ml-kem-512-sha256,
                                       ml-kem-1024-sha256, p384-sha384,
                                       p256-sha256]
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
# kex  = ["x25519-sha256", "ml-kem-768-sha256", "ml-kem-512-sha256", "ml-kem-1024-sha256", "p384-sha384", "p256-sha256"]
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
   # X25519 (default) — accept the default path: ~/.mp/id_ed25519
   mp-keygen generate

   # Or choose a different algorithm:
   mp-keygen generate --key-type p384
   mp-keygen generate --key-type p256
   ```

2. Add the client's public key to the server's `authorized_keys` file.

   On the **server**, append the contents of the client's public key (e.g. `~/.mp/id_ed25519.pub`) to `~$TARGET_USER/.mp/authorized_keys` (one key per line):

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
      --diff-mode <MODE>               UDP diff transport mode: reliable (default),
                                       datagram, or statesync
      --kex-algos <ALGOS>              Ordered KEX algorithms to offer, comma-separated
                                       [supported: x25519-sha256 (default),
                                       ml-kem-768-sha256, ml-kem-512-sha256,
                                       ml-kem-1024-sha256, p384-sha384,
                                       p256-sha256]
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
   --private-key-path ~/.mp/work_key \
   --public-key-path  ~/.mp/work_key.pub \
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

# Use datagram mode on a lossy mobile connection
mp --diff-mode datagram user@remote-server.com

# Use statesync mode on a satellite / metered link
mp --diff-mode statesync user@remote-server.com
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
# Defaults to ~/.mp/id_ed25519 and ~/.mp/id_ed25519.pub when not set
# (regardless of which --key-type was used to generate the key pair).
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

# ── UDP diff transport mode ───────────────────────────────────────────────────
# Controls how the server delivers PTY screen diffs and recovers from packet loss.
#   reliable   (default) NAK-based retransmission; lowest bandwidth; best on low-loss links
#   datagram             Fire-and-forget + 150 ms full-screen push; best on high-loss links
#   statesync            Ack-based diffs (Mosh-style); best on moderate-loss, low-bandwidth links
# diff_mode = "reliable"

# ── Algorithm preferences (optional) ─────────────────────────────────────────
# Override the algorithms this client offers during negotiation.  The server's
# preference order wins, but the server can only pick from what you offer here.
# Omitted categories use the built-in defaults.
#
# [preferred_algorithms]
# kex  = ["x25519-sha256", "ml-kem-768-sha256", "ml-kem-512-sha256", "ml-kem-1024-sha256", "p384-sha384", "p256-sha256"]
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

## Full Post-Quantum Setup

A fully post-quantum moshpit deployment replaces both authentication and key exchange with quantum-resistant algorithms, eliminating all classical asymmetric cryptography from the protocol.

| Layer | Classical default | Post-quantum replacement |
|-------|------------------|--------------------------|
| Identity keys (authentication) | X25519 | ML-DSA-65 or ML-DSA-87 |
| Key exchange | `x25519-sha256` | `ml-kem-768-sha256` or `ml-kem-1024-sha256` |
| AEAD encryption | `aes256-gcm-siv` | No change — 256-bit keys are quantum-resistant |
| MAC | `hmac-sha512` | No change |
| KDF | `hkdf-sha256` | No change |

**ML-KEM** key exchange is available in all standard builds.  **ML-DSA** identity keys require all three binaries — `mp-keygen`, `mps`, and `mp` — to be built with `--features unstable`.

### Security level reference

Choose a consistent security level for both the identity key and key exchange algorithm:

| NIST level | Identity key | KEX algorithm | Recommended use |
|-----------|-------------|---------------|-----------------|
| 2 / 1 | `mldsa44` | `ml-kem-512-sha256` | Smallest keys; lightest TCP handshake |
| **3 / 3** | **`mldsa65`** | **`ml-kem-768-sha256`** | **Recommended — comparable to AES-192 / P-384** |
| 5 / 5 | `mldsa87` | `ml-kem-1024-sha256` | Maximum margin; largest keys and slowest handshake |

The examples below use **ML-DSA-65 + ML-KEM-768** (NIST level 3).  Substitute `mldsa87` / `ml-kem-1024-sha256` throughout for the level-5 variant.

### Building with ML-DSA support

**From source:**

```bash
cargo build --release \
    --bin mp-keygen --features unstable
cargo build --release \
    --bin mps       --features unstable
cargo build --release \
    --bin mp        --features unstable
```

**From crates.io:**

```bash
cargo install moshpit-keygen --features unstable
cargo install moshpits       --features unstable
cargo install moshpit        --features unstable
```

> **AUR note**: Use the `moshpit-keygen-unstable-bin`, `moshpit-unstable-bin`, and `moshpits-unstable-bin` AUR packages — these are pre-compiled MUSL static binaries built with `--features unstable` and are the easiest way to get ML-DSA support on Arch Linux.  The standard `-bin` packages and the source packages do not include `unstable` support unless you add `--features unstable` to the `cargo build` line in each PKGBUILD manually.

### 1. Generate server and client keys

```bash
# Server host key — ML-DSA-65, no passphrase (service / daemon use)
mp-keygen generate --server \
    --key-type      mldsa65 \
    --no-passphrase \
    --output-path   ~/.mp/mps_host_mldsa65_key

# Client identity key — ML-DSA-65, prompted passphrase
mp-keygen generate \
    --key-type    mldsa65 \
    --output-path ~/.mp/id_mldsa65
```

Verify both fingerprints before proceeding:

```bash
mp-keygen fingerprint ~/.mp/mps_host_mldsa65_key.pub
mp-keygen fingerprint ~/.mp/id_mldsa65.pub
```

### 2. Server setup

#### Config file (`~/.config/moshpits/moshpits.toml`)

```toml
# ~/.config/moshpits/moshpits.toml — full post-quantum server (ML-DSA-65 + ML-KEM-768)

# ── Key files ─────────────────────────────────────────────────────────────────
private_key_path = "/home/user/.mp/mps_host_mldsa65_key"
public_key_path  = "/home/user/.mp/mps_host_mldsa65_key.pub"

# ── Algorithm preferences ─────────────────────────────────────────────────────
# The server's preference order wins during negotiation.  The list below
# prefers ML-KEM variants but still accepts classical algorithms so that
# clients not built with --features unstable can still connect.
[preferred_algorithms]
kex  = ["ml-kem-768-sha256", "ml-kem-1024-sha256", "ml-kem-512-sha256",
        "x25519-sha256", "p384-sha384", "p256-sha256"]
aead = ["aes256-gcm-siv", "aes256-gcm", "chacha20-poly1305", "aes128-gcm-siv"]
mac  = ["hmac-sha512", "hmac-sha256"]
kdf  = ["hkdf-sha256", "hkdf-sha384", "hkdf-sha512"]
```

To **require** ML-KEM and reject classical key exchange entirely, list only ML-KEM algorithms:

```toml
# Strict: reject any client that does not offer an ML-KEM algorithm
[preferred_algorithms]
kex = ["ml-kem-768-sha256", "ml-kem-1024-sha256", "ml-kem-512-sha256"]
```

> **Warning**: A strict ML-KEM-only server will reject connections from clients offering only classical KEX algorithms (X25519, P-384, P-256).

#### Start the server

```bash
# Recommended — reads ~/.config/moshpits/moshpits.toml
mps

# Alternatively, pass everything on the command line
mps --private-key-path ~/.mp/mps_host_mldsa65_key \
    --public-key-path  ~/.mp/mps_host_mldsa65_key.pub \
    --kex-algos        ml-kem-768-sha256,ml-kem-1024-sha256,ml-kem-512-sha256
```

### 3. Authorize the client public key on the server

On the **server**, append the client's public key line to `~$TARGET_USER/.mp/authorized_keys`.  The public key file written by `mp-keygen generate` already contains a correctly formatted line.

```bash
# On the client — display the public key to copy
cat ~/.mp/id_mldsa65.pub
# Output: moshpit <base64-encoded-public-key> user@host

# On the server — create the directory if it does not exist
mkdir -p ~/.mp && chmod 700 ~/.mp

# Append the public key (paste the full line from above)
echo 'moshpit <base64-encoded-public-key> user@host' >> ~/.mp/authorized_keys
chmod 600 ~/.mp/authorized_keys
```

If SSH access to the server is available, copy the key in one step:

```bash
# Copy directly over SSH (run on the client)
ssh user@server "mkdir -p ~/.mp && chmod 700 ~/.mp && cat >> ~/.mp/authorized_keys && chmod 600 ~/.mp/authorized_keys" \
    < ~/.mp/id_mldsa65.pub
```

### 4. Client setup

#### Config file (`~/.config/moshpit/moshpit.toml`)

```toml
# ~/.config/moshpit/moshpit.toml — full post-quantum client (ML-DSA-65 + ML-KEM-768)

# ── Key files ─────────────────────────────────────────────────────────────────
private_key_path = "/home/user/.mp/id_mldsa65"
public_key_path  = "/home/user/.mp/id_mldsa65.pub"

# ── Algorithm preferences ─────────────────────────────────────────────────────
# Offer ML-KEM variants first; the server's preference order determines which
# is actually selected.  Classical algorithms are listed as a fallback for
# servers not running --features unstable builds.
[preferred_algorithms]
kex  = ["ml-kem-768-sha256", "ml-kem-1024-sha256", "ml-kem-512-sha256",
        "x25519-sha256", "p384-sha384", "p256-sha256"]
aead = ["aes256-gcm-siv", "aes256-gcm", "chacha20-poly1305", "aes128-gcm-siv"]
mac  = ["hmac-sha512", "hmac-sha256"]
kdf  = ["hkdf-sha256", "hkdf-sha384", "hkdf-sha512"]
```

#### Connect to the server

```bash
# Recommended — reads ~/.config/moshpit/moshpit.toml for keys and algorithms
mp user@192.168.1.10

# Alternatively, pass everything on the command line
mp --private-key-path ~/.mp/id_mldsa65 \
   --public-key-path  ~/.mp/id_mldsa65.pub \
   --kex-algos        ml-kem-768-sha256,ml-kem-1024-sha256,ml-kem-512-sha256 \
   user@192.168.1.10
```

### Confirming post-quantum algorithms are in use

Enable verbose logging on both sides to see the negotiated algorithm set printed at session start:

```bash
# Server — verbose output to stderr
mps -vv --enable-std-output

# Client — verbose
mp -vv user@192.168.1.10
```

A successful post-quantum session will show `ml-kem-*` for the key exchange algorithm in the negotiation log lines.  If the KEX algorithm falls back to `x25519-sha256` or another classical algorithm, verify that:

1. Both binaries were compiled with `--features unstable`.
2. The server's `kex` preference list includes at least one `ml-kem-*` entry.
3. The client's `kex` offer list includes at least one `ml-kem-*` entry that matches the server's list.

---

## Developer Liability Disclaimer

To the fullest extent permitted by applicable law, this software is provided "AS IS" and "AS AVAILABLE", without warranties or conditions of any kind, express or implied.  By installing, running, or distributing this software, you assume all risks associated with its use.

The project author and contributors are not liable for any direct, indirect, incidental, special, exemplary, or consequential damages, including but not limited to system damage, data loss, security incidents, service interruption, or loss of profits, arising from use of this project.

If you do not agree with these terms, do not use this software.

---

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your option.
