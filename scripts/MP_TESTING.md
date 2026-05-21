# mp (moshpit client) Local Testing

Two identity paths are covered:

1. **File-based key** — client reads the private key from disk and prompts for the passphrase.
2. **Agent key** — client delegates identity to a running `mpa` agent; no passphrase prompt.

All tests target `127.0.0.1` (loopback) with `mps` running locally, so no remote machine is
needed.

---

## Prerequisites

```fish
cargo build --bin mps
cargo build --bin mp
cargo build --bin mp-keygen
cargo build --bin mpa

# Server host key — server keys are never passphrase-protected
./target/debug/mp-keygen generate --server --no-passphrase \
  --output-path /tmp/test_server_key --force

# Client identity key — must be passphrase-protected
echo "testpass" | ./target/debug/mp-keygen generate --passphrase-stdin \
  --output-path /tmp/test_client_key --force
```

Authorize the client key on the server. `mps` checks `~/.mp/authorized_keys` (must be
`0600`; `~/.mp/` must be `0700`):

```fish
mkdir -p ~/.mp
chmod 700 ~/.mp
cat /tmp/test_client_key.pub >> ~/.mp/authorized_keys
chmod 600 ~/.mp/authorized_keys
```

---

## Part 1 — File-based key (passphrase path)

### Step 1 — Start the server

```fish
./target/debug/mps \
  --private-key-path /tmp/test_server_key \
  --public-key-path /tmp/test_server_key.pub &
```

### Step 2 — Connect with passphrase prompt

On the **first** connect the client TOFU-prompts to trust the server fingerprint; type `y`.
Then enter the key passphrase when prompted.

```fish
./target/debug/mp 127.0.0.1 \
  --private-key-path /tmp/test_client_key \
  --public-key-path /tmp/test_client_key.pub
# Prompt 1: "Trust server SHA256:…? [y/n]" — type y  (first connect only; saved to ~/.mp/known_hosts)
# Prompt 2: "Please enter your private key passphrase" — type testpass
# A shell session opens.  Type exit to disconnect.
```

### Step 3 — Reconnect (no TOFU prompt)

The server fingerprint is now in `~/.mp/known_hosts`, so TOFU is skipped on subsequent
connects. The passphrase is still required on each new `mp` invocation.

```fish
./target/debug/mp 127.0.0.1 \
  --private-key-path /tmp/test_client_key \
  --public-key-path /tmp/test_client_key.pub
# Only passphrase prompt — no TOFU.
```

### Step 4 — Stop the server

```fish
kill (pgrep -f "mps")
```

---

## Part 2 — Agent key (no passphrase prompt)

The agent holds the decrypted private key in memory.  Once the key is loaded, `mp` contacts
the agent over `MOSHPIT_AGENT_SOCK` and signs without prompting.

### Step 1 — Start the agent and load the client key

```fish
read -s -P "Set moshpit-agent master passphrase: " vault_pass
echo $vault_pass | ./target/debug/mpa start \
  --foreground \
  --backend passphrase \
  --passphrase-stdin \
  --vault /tmp/test-client-vault \
  --socket /tmp/test-client-agent.sock &
set -gx MOSHPIT_AGENT_SOCK /tmp/test-client-agent.sock

echo "testpass" | ./target/debug/mpa add-key /tmp/test_client_key --passphrase-stdin
./target/debug/mpa list   # should show the key's fingerprint
```

### Step 2 — Start the server

```fish
./target/debug/mps \
  --private-key-path /tmp/test_server_key \
  --public-key-path /tmp/test_server_key.pub &
```

### Step 3 — Connect via agent (no passphrase prompt)

The public key is fetched from the agent; signing is delegated to the agent.
No passphrase is entered — only the TOFU prompt appears on the very first connect.

```fish
./target/debug/mp 127.0.0.1
# No passphrase prompt — agent provides the identity.
# Client logs: "Agent socket configured — loading identity from moshpit-agent"
# Client logs: "Using agent identity: SHA256:…  (X25519)"
# Type exit to disconnect.
```

### Step 4 — Lock and reconnect (agent locked → passphrase prompt returns)

When the agent is locked, it holds no keys in memory.  `mp` falls back to the file-based
path and re-prompts for the passphrase.

```fish
./target/debug/mpa lock

./target/debug/mp 127.0.0.1
# Agent returns empty — client warns and falls back to key file.
# Client logs: "Agent has no identities with algorithms supported by this client
#               (supported: X25519, P256, P384) — falling back to key file"
# Prompt: "Please enter your private key passphrase" — type testpass
# (--private-key-path and --public-key-path must be provided when falling back to file)
./target/debug/mp 127.0.0.1 \
  --private-key-path /tmp/test_client_key \
  --public-key-path /tmp/test_client_key.pub

./target/debug/mpa unlock    # re-enter vault passphrase when prompted
./target/debug/mpa list      # key reappears

# After unlock, agent path works again without passphrase
./target/debug/mp 127.0.0.1
```

### Step 5 — Stop server and agent

```fish
kill (pgrep -f "mps")
kill (pgrep -f "mpa start")
```

---

## Part 3 — Agent fallback: `unstable` client, non-`unstable` agent

When `mp` is built with `--features unstable` and the agent holds no compatible identities
(e.g. the agent was built without `unstable` and its vault is empty), the client logs a
warning and falls back to the file-based key path.  This is the same fallback exercised
by the lock scenario in Part 2, but triggered by a feature mismatch rather than an explicit
lock.

```fish
cargo build --bin mpa               # no unstable — only X25519/P256/P384 supported
cargo build --bin mp --features unstable
cargo build --bin mp-keygen --features unstable

# Generate an ML-DSA-87 client key; authorize it on the server
echo "testpass" | ./target/debug/mp-keygen generate --passphrase-stdin \
  --output-path /tmp/test_client_mldsa87 --key-type mldsa87 --force
cat /tmp/test_client_mldsa87.pub >> ~/.mp/authorized_keys

# Start the server (plain build is fine for the server side)
./target/debug/mps \
  --private-key-path /tmp/test_server_key \
  --public-key-path /tmp/test_server_key.pub &
```

### Sub-case A — agent not running (socket unreachable)

```fish
set -gx MOSHPIT_AGENT_SOCK /tmp/test-client-agent-missing.sock
# (no agent started — socket does not exist)

./target/debug/mp 127.0.0.1 \
  --private-key-path /tmp/test_client_mldsa87 \
  --public-key-path /tmp/test_client_mldsa87.pub
# Client logs: "Failed to contact agent (…) — falling back to key file"
# Prompt: "Please enter your private key passphrase" — type testpass
# Connection proceeds with the ML-DSA-87 file key.
```

### Sub-case B — agent running (without `unstable`), vault empty

```fish
read -s -P "Set moshpit-agent master passphrase: " vault_pass
echo $vault_pass | ./target/debug/mpa start \
  --foreground \
  --backend passphrase \
  --passphrase-stdin \
  --vault /tmp/test-client-vault-empty \
  --socket /tmp/test-client-agent-empty.sock &
set -gx MOSHPIT_AGENT_SOCK /tmp/test-client-agent-empty.sock

./target/debug/mpa list   # 0 identities

./target/debug/mp 127.0.0.1 \
  --private-key-path /tmp/test_client_mldsa87 \
  --public-key-path /tmp/test_client_mldsa87.pub
# Client logs: "Agent has no identities with algorithms supported by this client
#               (supported: X25519, P256, P384, ML-DSA-44, ML-DSA-65, ML-DSA-87)
#               — falling back to key file"
# Prompt: "Please enter your private key passphrase" — type testpass
# Connection proceeds with the ML-DSA-87 file key.

kill (pgrep -f "mpa start")
```

### Cleanup (Part 3)

```fish
kill (pgrep -f "mps")
rm -f /tmp/test-client-vault-empty /tmp/test-client-agent-empty.sock
rm -f /tmp/test_client_mldsa87 /tmp/test_client_mldsa87.pub
```

---

## Part 4 — Full unstable stack: ML-DSA-87 keys end-to-end

All three binaries (`mps`, `mp`, `mpa`) are built with `--features unstable`.  The server
host key and client identity key are both ML-DSA-87.  The agent holds the client key and
signs on behalf of `mp` — no passphrase prompt after the initial load.

### Step 1 — Build everything with `unstable`

```fish
cargo build --bin mps --features unstable
cargo build --bin mp --features unstable
cargo build --bin mp-keygen --features unstable
cargo build --bin mpa --features unstable
```

### Step 2 — Generate ML-DSA-87 keys

```fish
# Server host key — never passphrase-protected
./target/debug/mp-keygen generate --server --no-passphrase \
  --key-type mldsa87 \
  --output-path /tmp/test_server_key_mldsa87 --force

# Client identity key — must be passphrase-protected
echo "testpass" | ./target/debug/mp-keygen generate --passphrase-stdin \
  --key-type mldsa87 \
  --output-path /tmp/test_client_key_mldsa87 --force
```

### Step 3 — Authorize the client key

```fish
mkdir -p ~/.mp
chmod 700 ~/.mp
cat /tmp/test_client_key_mldsa87.pub >> ~/.mp/authorized_keys
chmod 600 ~/.mp/authorized_keys
```

### Step 4 — Start the agent and load the client key

```fish
read -s -P "Set moshpit-agent master passphrase: " vault_pass
echo $vault_pass | ./target/debug/mpa start \
  --foreground \
  --backend passphrase \
  --passphrase-stdin \
  --vault /tmp/test-client-vault-mldsa87 \
  --socket /tmp/test-client-agent-mldsa87.sock &
set -gx MOSHPIT_AGENT_SOCK /tmp/test-client-agent-mldsa87.sock

echo "testpass" | ./target/debug/mpa add-key /tmp/test_client_key_mldsa87 --passphrase-stdin
./target/debug/mpa list   # should show the ML-DSA-87 key's fingerprint
```

### Step 5 — Start the server

```fish
./target/debug/mps \
  --private-key-path /tmp/test_server_key_mldsa87 \
  --public-key-path /tmp/test_server_key_mldsa87.pub &
```

### Step 6 — Connect via agent (no passphrase prompt)

On the first connect, TOFU-prompt appears for the server's ML-DSA-87 fingerprint; type `y`.
Subsequent connects skip TOFU.  Signing is delegated to the agent throughout.

```fish
./target/debug/mp 127.0.0.1
# Prompt (first connect only): "Trust server SHA256:…? [y/n]" — type y
# No passphrase prompt — agent provides the ML-DSA-87 identity.
# Client logs: "Agent socket configured — loading identity from moshpit-agent"
# Client logs: "Using agent identity: SHA256:…  (ML-DSA-87)"
# Type exit to disconnect.
```

### Step 7 — Lock and reconnect (agent locked → passphrase prompt returns)

```fish
./target/debug/mpa lock

./target/debug/mp 127.0.0.1 \
  --private-key-path /tmp/test_client_key_mldsa87 \
  --public-key-path /tmp/test_client_key_mldsa87.pub
# Agent returns empty — client warns and falls back to key file.
# Client logs: "Agent has no identities with algorithms supported by this client
#               (supported: X25519, P256, P384, ML-DSA-44, ML-DSA-65, ML-DSA-87)
#               — falling back to key file"
# Prompt: "Please enter your private key passphrase" — type testpass

./target/debug/mpa unlock    # re-enter vault passphrase when prompted
./target/debug/mpa list      # ML-DSA-87 key reappears

# After unlock, agent path works again without passphrase
./target/debug/mp 127.0.0.1
```

### Step 8 — Stop server and agent

```fish
kill (pgrep -f "mps")
kill (pgrep -f "mpa start")
```

### Cleanup (Part 4)

```fish
kill (pgrep -f "mps")
kill (pgrep -f "mpa start")
rm -f /tmp/test_server_key_mldsa87 /tmp/test_server_key_mldsa87.pub
rm -f /tmp/test_client_key_mldsa87 /tmp/test_client_key_mldsa87.pub
rm -f /tmp/test-client-vault-mldsa87 /tmp/test-client-agent-mldsa87.sock

# Remove test keys from authorized_keys (edit the file and delete the added lines)
# Remove test server fingerprint from known_hosts (edit ~/.mp/known_hosts)
```

---

## Cleanup

```fish
kill (pgrep -f "mps")
kill (pgrep -f "mpa start")
rm -f /tmp/test_server_key /tmp/test_server_key.pub
rm -f /tmp/test_client_key /tmp/test_client_key.pub
rm -f /tmp/test-client-vault /tmp/test-client-agent.sock

# Remove test keys from authorized_keys (edit the file and delete the added lines)
# Remove test server fingerprint from known_hosts (edit ~/.mp/known_hosts)
```
