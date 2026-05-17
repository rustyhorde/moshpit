# Algorithm Reference

This document lists every cryptographic algorithm option available to `mp` (client), `mps` (server),
and `mp-keygen`, along with the exact commands needed to generate keys and test each combination
at the command line.

---

## How Negotiation Works

Session algorithms are negotiated SSH-style: the client sends a comma-separated, preference-ordered
list in each category; the server walks through the client's list and picks the **first algorithm it
supports**. This happens independently for each of the four categories below.

If any category has no overlap between client and server lists, the connection fails with
`NoCommonAlgorithm`.

---

## Session Algorithm Categories

Each category has a dedicated CLI flag accepted by both `mp` and `mps`. Pass a comma-separated,
preference-ordered list. Omitting a flag uses the defaults shown below.

### Key Exchange — `--kex-algos`

| Value | Description | Default |
|---|---|:---:|
| `x25519-sha256` | Curve25519 ECDH + HKDF-SHA256 | ✓ |
| `ml-kem-768-sha256` | ML-KEM-768 (FIPS 203) + HKDF-SHA256 | |
| `ml-kem-512-sha256` | ML-KEM-512 (FIPS 203) + HKDF-SHA256 | |
| `ml-kem-1024-sha256` | ML-KEM-1024 (FIPS 203) + HKDF-SHA256 | |
| `p384-sha384` | NIST P-384 ECDH + HKDF-SHA384 | |
| `p256-sha256` | NIST P-256 ECDH + HKDF-SHA256 | |

### AEAD Encryption — `--aead-algos`

| Value | Description | Default |
|---|---|:---:|
| `aes256-gcm-siv` | AES-256-GCM-SIV (nonce-misuse resistant) | ✓ |
| `aes256-gcm` | AES-256-GCM | |
| `chacha20-poly1305` | ChaCha20-Poly1305 (fast without AES-NI) | |
| `aes128-gcm-siv` | AES-128-GCM-SIV | |

### MAC — `--mac-algos`

| Value | Description | Default |
|---|---|:---:|
| `hmac-sha512` | HMAC-SHA512 (64-byte tag) | ✓ |
| `hmac-sha256` | HMAC-SHA256 (32-byte tag) | |

### KDF — `--kdf-algos`

| Value | Description | Default |
|---|---|:---:|
| `hkdf-sha256` | HKDF-SHA256 | ✓ |
| `hkdf-sha384` | HKDF-SHA384 (natural pairing with P-384) | |
| `hkdf-sha512` | HKDF-SHA512 (higher security margin) | |

---

## Identity Key Algorithms (`mp-keygen`)

Identity keys authenticate the client and server during the handshake. They are generated once
with `mp-keygen` and loaded at runtime via `-p` (private key) and `-k` (public key) on both
`mp` and `mps`.

### `mp-keygen generate` flags

| Flag | Description |
|---|---|
| `-k / --key-type TYPE` | Key algorithm (see table below). Default: `x25519` |
| `-s / --server` | Generate a server host key (changes default path; allows unencrypted keys) |
| `-n / --no-passphrase` | Skip passphrase prompt — required for server keys and scripted use |
| `-o / --output-path PATH` | Write keys to `PATH` and `PATH.pub` non-interactively |
| `-f / --force` | Overwrite existing key files without confirmation |

### Supported key algorithms

| `--key-type` value(s) | Algorithm | Requires feature | Client default path | Server default path |
|---|---|:---:|---|---|
| `x25519` *(default)* | Curve25519 ECDH | — | `~/.mp/id_x25519` | `~/.mp/mps_host_x25519_key` |
| `p384` | NIST P-384 ECDH | — | `~/.mp/id_p384` | `~/.mp/mps_host_p384_key` |
| `p256` | NIST P-256 ECDH | — | `~/.mp/id_p256` | `~/.mp/mps_host_p256_key` |
| `mldsa44` or `ml-dsa-44` | ML-DSA-44 (FIPS 204) | `unstable` | `~/.mp/id_ml_dsa_44` | `~/.mp/mps_host_ml_dsa_44_key` |
| `mldsa65` or `ml-dsa-65` | ML-DSA-65 (FIPS 204) | `unstable` | `~/.mp/id_ml_dsa_65` | `~/.mp/mps_host_ml_dsa_65_key` |
| `mldsa87` or `ml-dsa-87` | ML-DSA-87 (FIPS 204) | `unstable` | `~/.mp/id_ml_dsa_87` | `~/.mp/mps_host_ml_dsa_87_key` |

The default filename is derived from the chosen `--key-type` at generation time.  Override with `-o / --output-path` for any custom location.

> **Note:** ML-DSA variants require the binary to be compiled with `--features unstable`.

---

## Key Generation Commands

The examples below write keys to `/tmp/test-keys/` for easy cleanup. Client keys require a
passphrase (the prompt will appear unless automated); server keys use `-n` to skip it.

```bash
mkdir -p /tmp/test-keys

# X25519 (default)
mp-keygen generate -k x25519 -o /tmp/test-keys/client_x25519          # client — prompts for passphrase
mp-keygen generate -k x25519 -s -n -o /tmp/test-keys/server_x25519    # server — no passphrase

# P-384
mp-keygen generate -k p384 -o /tmp/test-keys/client_p384
mp-keygen generate -k p384 -s -n -o /tmp/test-keys/server_p384

# P-256
mp-keygen generate -k p256 -o /tmp/test-keys/client_p256
mp-keygen generate -k p256 -s -n -o /tmp/test-keys/server_p256

# ML-DSA-44  (requires --features pq-dsa-unstable)
mp-keygen generate -k mldsa44 -o /tmp/test-keys/client_mldsa44
mp-keygen generate -k mldsa44 -s -n -o /tmp/test-keys/server_mldsa44

# ML-DSA-65  (requires --features pq-dsa-unstable)
mp-keygen generate -k mldsa65 -o /tmp/test-keys/client_mldsa65
mp-keygen generate -k mldsa65 -s -n -o /tmp/test-keys/server_mldsa65

# ML-DSA-87  (requires --features pq-dsa-unstable)
mp-keygen generate -k mldsa87 -o /tmp/test-keys/client_mldsa87
mp-keygen generate -k mldsa87 -s -n -o /tmp/test-keys/server_mldsa87
```

---

## Connection Test Examples

Each example shows the `mps` server command followed by the `mp` client command. Start `mps`
first; `mp` connects to it.

### Standard (ECDH) identity keys

```bash
# Default everything (x25519-sha256 / aes256-gcm-siv / hmac-sha512 / hkdf-sha256)
mps -p /tmp/test-keys/server_x25519 -k /tmp/test-keys/server_x25519.pub
mp  -p /tmp/test-keys/client_x25519 -k /tmp/test-keys/client_x25519.pub user@host

# ML-KEM-768 KEX
mps --kex-algos ml-kem-768-sha256 \
    -p /tmp/test-keys/server_x25519 -k /tmp/test-keys/server_x25519.pub
mp  --kex-algos ml-kem-768-sha256 \
    -p /tmp/test-keys/client_x25519 -k /tmp/test-keys/client_x25519.pub user@host

# ML-KEM-512 KEX
mps --kex-algos ml-kem-512-sha256 \
    -p /tmp/test-keys/server_x25519 -k /tmp/test-keys/server_x25519.pub
mp  --kex-algos ml-kem-512-sha256 \
    -p /tmp/test-keys/client_x25519 -k /tmp/test-keys/client_x25519.pub user@host

# ML-KEM-1024 KEX
mps --kex-algos ml-kem-1024-sha256 \
    -p /tmp/test-keys/server_x25519 -k /tmp/test-keys/server_x25519.pub
mp  --kex-algos ml-kem-1024-sha256 \
    -p /tmp/test-keys/client_x25519 -k /tmp/test-keys/client_x25519.pub user@host

# P-384 KEX with matching KDF
mps --kex-algos p384-sha384 --kdf-algos hkdf-sha384 \
    -p /tmp/test-keys/server_x25519 -k /tmp/test-keys/server_x25519.pub
mp  --kex-algos p384-sha384 --kdf-algos hkdf-sha384 \
    -p /tmp/test-keys/client_x25519 -k /tmp/test-keys/client_x25519.pub user@host

# P-256 KEX
mps --kex-algos p256-sha256 \
    -p /tmp/test-keys/server_x25519 -k /tmp/test-keys/server_x25519.pub
mp  --kex-algos p256-sha256 \
    -p /tmp/test-keys/client_x25519 -k /tmp/test-keys/client_x25519.pub user@host

# AES-256-GCM AEAD
mps --aead-algos aes256-gcm \
    -p /tmp/test-keys/server_x25519 -k /tmp/test-keys/server_x25519.pub
mp  --aead-algos aes256-gcm \
    -p /tmp/test-keys/client_x25519 -k /tmp/test-keys/client_x25519.pub user@host

# ChaCha20-Poly1305 AEAD
mps --aead-algos chacha20-poly1305 \
    -p /tmp/test-keys/server_x25519 -k /tmp/test-keys/server_x25519.pub
mp  --aead-algos chacha20-poly1305 \
    -p /tmp/test-keys/client_x25519 -k /tmp/test-keys/client_x25519.pub user@host

# AES-128-GCM-SIV AEAD
mps --aead-algos aes128-gcm-siv \
    -p /tmp/test-keys/server_x25519 -k /tmp/test-keys/server_x25519.pub
mp  --aead-algos aes128-gcm-siv \
    -p /tmp/test-keys/client_x25519 -k /tmp/test-keys/client_x25519.pub user@host

# HMAC-SHA256 MAC
mps --mac-algos hmac-sha256 \
    -p /tmp/test-keys/server_x25519 -k /tmp/test-keys/server_x25519.pub
mp  --mac-algos hmac-sha256 \
    -p /tmp/test-keys/client_x25519 -k /tmp/test-keys/client_x25519.pub user@host

# HKDF-SHA384 KDF
mps --kdf-algos hkdf-sha384 \
    -p /tmp/test-keys/server_x25519 -k /tmp/test-keys/server_x25519.pub
mp  --kdf-algos hkdf-sha384 \
    -p /tmp/test-keys/client_x25519 -k /tmp/test-keys/client_x25519.pub user@host

# HKDF-SHA512 KDF
mps --kdf-algos hkdf-sha512 \
    -p /tmp/test-keys/server_x25519 -k /tmp/test-keys/server_x25519.pub
mp  --kdf-algos hkdf-sha512 \
    -p /tmp/test-keys/client_x25519 -k /tmp/test-keys/client_x25519.pub user@host

# No common algorithm — connection failure expected
# (client forces P-384, server only advertises X25519)
mps --kex-algos x25519-sha256 \
    -p /tmp/test-keys/server_x25519 -k /tmp/test-keys/server_x25519.pub
mp  --kex-algos p384-sha384 \
    -p /tmp/test-keys/client_x25519 -k /tmp/test-keys/client_x25519.pub user@host
```

### Experimental ML-DSA identity keys

> Requires binaries compiled with `--features pq-dsa-unstable`.
> Generate keys with the ML-DSA commands shown in the [Key Generation](#key-generation-commands)
> section above.

```bash
# ML-DSA-44 — default session algorithms
mps -p /tmp/test-keys/server_mldsa44 -k /tmp/test-keys/server_mldsa44.pub
mp  -p /tmp/test-keys/client_mldsa44 -k /tmp/test-keys/client_mldsa44.pub user@host

# ML-DSA-44 + ML-KEM-768 KEX
mps --kex-algos ml-kem-768-sha256 \
    -p /tmp/test-keys/server_mldsa44 -k /tmp/test-keys/server_mldsa44.pub
mp  --kex-algos ml-kem-768-sha256 \
    -p /tmp/test-keys/client_mldsa44 -k /tmp/test-keys/client_mldsa44.pub user@host

# ML-DSA-44 + ML-KEM-512 KEX
mps --kex-algos ml-kem-512-sha256 \
    -p /tmp/test-keys/server_mldsa44 -k /tmp/test-keys/server_mldsa44.pub
mp  --kex-algos ml-kem-512-sha256 \
    -p /tmp/test-keys/client_mldsa44 -k /tmp/test-keys/client_mldsa44.pub user@host

# ML-DSA-44 + ML-KEM-1024 KEX
mps --kex-algos ml-kem-1024-sha256 \
    -p /tmp/test-keys/server_mldsa44 -k /tmp/test-keys/server_mldsa44.pub
mp  --kex-algos ml-kem-1024-sha256 \
    -p /tmp/test-keys/client_mldsa44 -k /tmp/test-keys/client_mldsa44.pub user@host

# ML-DSA-65 — default session algorithms
mps -p /tmp/test-keys/server_mldsa65 -k /tmp/test-keys/server_mldsa65.pub
mp  -p /tmp/test-keys/client_mldsa65 -k /tmp/test-keys/client_mldsa65.pub user@host

# ML-DSA-65 + ML-KEM-768 KEX
mps --kex-algos ml-kem-768-sha256 \
    -p /tmp/test-keys/server_mldsa65 -k /tmp/test-keys/server_mldsa65.pub
mp  --kex-algos ml-kem-768-sha256 \
    -p /tmp/test-keys/client_mldsa65 -k /tmp/test-keys/client_mldsa65.pub user@host

# ML-DSA-65 + ML-KEM-512 KEX
mps --kex-algos ml-kem-512-sha256 \
    -p /tmp/test-keys/server_mldsa65 -k /tmp/test-keys/server_mldsa65.pub
mp  --kex-algos ml-kem-512-sha256 \
    -p /tmp/test-keys/client_mldsa65 -k /tmp/test-keys/client_mldsa65.pub user@host

# ML-DSA-65 + ML-KEM-1024 KEX
mps --kex-algos ml-kem-1024-sha256 \
    -p /tmp/test-keys/server_mldsa65 -k /tmp/test-keys/server_mldsa65.pub
mp  --kex-algos ml-kem-1024-sha256 \
    -p /tmp/test-keys/client_mldsa65 -k /tmp/test-keys/client_mldsa65.pub user@host

# ML-DSA-87 — default session algorithms
mps -p /tmp/test-keys/server_mldsa87 -k /tmp/test-keys/server_mldsa87.pub
mp  -p /tmp/test-keys/client_mldsa87 -k /tmp/test-keys/client_mldsa87.pub user@host

# ML-DSA-87 + ML-KEM-768 KEX
mps --kex-algos ml-kem-768-sha256 \
    -p /tmp/test-keys/server_mldsa87 -k /tmp/test-keys/server_mldsa87.pub
mp  --kex-algos ml-kem-768-sha256 \
    -p /tmp/test-keys/client_mldsa87 -k /tmp/test-keys/client_mldsa87.pub user@host

# ML-DSA-87 + ML-KEM-512 KEX
mps --kex-algos ml-kem-512-sha256 \
    -p /tmp/test-keys/server_mldsa87 -k /tmp/test-keys/server_mldsa87.pub
mp  --kex-algos ml-kem-512-sha256 \
    -p /tmp/test-keys/client_mldsa87 -k /tmp/test-keys/client_mldsa87.pub user@host

# ML-DSA-87 + ML-KEM-1024 KEX (fully post-quantum)
mps --kex-algos ml-kem-1024-sha256 \
    -p /tmp/test-keys/server_mldsa87 -k /tmp/test-keys/server_mldsa87.pub
mp  --kex-algos ml-kem-1024-sha256 \
    -p /tmp/test-keys/client_mldsa87 -k /tmp/test-keys/client_mldsa87.pub user@host
```

---

## TOML Config File

The same algorithm preferences can be set in the TOML config file instead of (or alongside) CLI
flags. CLI flags override file settings.

- Client config: `~/.mp/config.toml`
- Server config: `~/.mps/config.toml`

```toml
[preferred_algorithms]
kex  = ["ml-kem-768-sha256", "x25519-sha256"]
aead = ["aes256-gcm-siv"]
mac  = ["hmac-sha512"]
kdf  = ["hkdf-sha256"]
```

Omitted categories fall back to the full supported list in default preference order.
