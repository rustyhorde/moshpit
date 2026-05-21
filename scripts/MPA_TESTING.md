# mpa (moshpit-agent) Local Testing — Passphrase Backend

## Prerequisites

```fish
cargo build --bin mpa --features unstable
cargo build --bin mp-keygen

# Generate a test key (X25519 by default); client keys require a passphrase
echo "testpass" | ./target/debug/mp-keygen generate --passphrase-stdin \
  --output-path /tmp/test_key --force
# ML-DSA keys also work with --features unstable:
#   cargo build --bin mp-keygen --features unstable
#   echo "testpass" | ./target/debug/mp-keygen generate --passphrase-stdin \
#     --output-path /tmp/test_key --key-type mldsa87 --force
```

---

## Step 1 — First start (fresh vault)

Use `read -s` to collect the passphrase in the foreground shell first, then pipe it
to the agent via `--passphrase-stdin`. This flag makes the agent read its passphrase
from stdin rather than opening a TTY prompt, so the process can be safely backgrounded.
It works the same way whether the vault is new (first start) or already exists (restart).

```fish
read -s -P "Set moshpit-agent master passphrase: " mp
echo $mp | ./target/debug/mpa start \
  --foreground \
  --backend passphrase \
  --passphrase-stdin \
  --vault /tmp/test-agent-vault \
  --socket /tmp/test-agent.sock &
set -gx MOSHPIT_AGENT_SOCK /tmp/test-agent.sock
```

---

## Step 2 — Add a key

```fish
echo "testpass" | ./target/debug/mpa add-key /tmp/test_key --passphrase-stdin
```

## Step 3 — List identities

```fish
./target/debug/mpa list
# Should show the key's fingerprint and comment
```

## Step 4 — Lock and unlock

```fish
./target/debug/mpa lock
./target/debug/mpa list   # should show 0 identities

./target/debug/mpa unlock
./target/debug/mpa list   # should show the key again
```

## Step 5 — Kill, restart, verify vault persistence

```fish
kill (pgrep -f "mpa start")

# Same pattern: collect the passphrase first, then background.
# --passphrase-stdin bypasses the agent's own "Enter ..." prompt here too.
# Enter the same passphrase you chose in step 1.
read -s -P "Enter moshpit-agent master passphrase: " mp
echo $mp | ./target/debug/mpa start \
  --foreground \
  --backend passphrase \
  --passphrase-stdin \
  --vault /tmp/test-agent-vault \
  --socket /tmp/test-agent.sock &
set -gx MOSHPIT_AGENT_SOCK /tmp/test-agent.sock

./target/debug/mpa list   # same key should reappear
```

---

## Feature mismatch: agent with ML-DSA keys, client without `unstable`

This exercises the `ListSupportedIdentities` protocol path: the agent holds an ML-DSA key
the client cannot use, so the client must skip it and fall back to a classical key.

```fish
cargo build --bin mpa --features unstable
cargo build --bin mp               # no unstable — only X25519/P256/P384 supported
cargo build --bin mp-keygen --features unstable

# Generate an X25519 key and an ML-DSA-87 key; client keys require a passphrase
echo "testpass" | ./target/debug/mp-keygen generate --passphrase-stdin \
  --output-path /tmp/test_x25519 --force
echo "testpass" | ./target/debug/mp-keygen generate --passphrase-stdin \
  --output-path /tmp/test_mldsa87 --key-type mldsa87 --force
```

Start the agent with both keys loaded:

```fish
read -s -P "Set moshpit-agent master passphrase: " mp
echo $mp | ./target/debug/mpa start \
  --foreground \
  --backend passphrase \
  --passphrase-stdin \
  --vault /tmp/test-agent-vault-mismatch \
  --socket /tmp/test-agent-mismatch.sock &
set -gx MOSHPIT_AGENT_SOCK /tmp/test-agent-mismatch.sock

echo "testpass" | ./target/debug/mpa add-key /tmp/test_x25519 --passphrase-stdin
echo "testpass" | ./target/debug/mpa add-key /tmp/test_mldsa87 --passphrase-stdin
./target/debug/mpa list
# Shows both keys: test_x25519 (X25519) and test_mldsa87 (ML-DSA-87)
```

Connect with the non-unstable client:

```fish
# mp will call list_supported_identities(["X25519","P256","P384"])
# Agent returns only the X25519 key; ML-DSA-87 is filtered out.
# Client logs: "Using agent identity: SHA256:... (X25519)"
./target/debug/mp <server>
```

Connect with the unstable-enabled client (should prefer ML-DSA-87):

```fish
cargo build --bin mp --features unstable
# Client calls list_supported_identities(["X25519","P256","P384","ML-DSA-44","ML-DSA-65","ML-DSA-87"])
# Agent returns both keys; client sorts by strength and picks ML-DSA-87.
# Client logs: "Using agent identity: SHA256:... (ML-DSA-87)"
./target/debug/mp <server>
```

All-ML-DSA agent, non-unstable client (no usable key — expected error):

```fish
./target/debug/mpa lock
./target/debug/mpa unlock   # re-enter passphrase
# Remove the classical key first, leaving only ML-DSA-87
./target/debug/mpa remove-key <fingerprint-of-classical-key>
./target/debug/mpa list     # only ML-DSA-87 remains

# Non-unstable mp should error:
# error: Agent has no identities with algorithms supported by this client
#        — run `mpa add-key <path>` with a compatible key (supported: X25519, P256, P384)
./target/debug/mp <server>
```

Cleanup:

```fish
kill (pgrep -f "mpa start")
rm -f /tmp/test-agent-vault-mismatch /tmp/test-agent-mismatch.sock
rm -f /tmp/test_x25519 /tmp/test_x25519.pub /tmp/test_mldsa87 /tmp/test_mldsa87.pub
```

---

## Feature mismatch: client with `unstable`, agent without — file key fallback

When the client is built with `--features unstable` but the agent is not, the client
advertises ML-DSA algorithms the agent cannot hold. If the agent has no compatible key to
return (empty vault or socket unreachable), the client falls back to the file-based key path
and prompts for the passphrase rather than failing outright.

```fish
cargo build --bin mpa               # no unstable — only X25519/P256/P384 supported
cargo build --bin mp --features unstable
cargo build --bin mp-keygen --features unstable

# Generate an ML-DSA-87 key file; client keys require a passphrase
echo "testpass" | ./target/debug/mp-keygen generate --passphrase-stdin \
  --output-path /tmp/test_mldsa87_client --key-type mldsa87 --force
```

### Sub-case A — agent socket set but agent is not running

```fish
set -gx MOSHPIT_AGENT_SOCK /tmp/test-agent-fallback.sock
# (no agent started — socket does not exist)

# mp logs: "Failed to contact agent … — falling back to key file"
# then prompts: "Please enter your private key passphrase"
# Enter "testpass" — connection proceeds with the ML-DSA-87 file key.
./target/debug/mp <server>
```

### Sub-case B — agent running (without `unstable`), vault empty, MOSHPIT_AGENT_SOCK set

```fish
read -s -P "Set moshpit-agent master passphrase: " mp
echo $mp | ./target/debug/mpa start \
  --foreground \
  --backend passphrase \
  --passphrase-stdin \
  --vault /tmp/test-agent-vault-fallback \
  --socket /tmp/test-agent-fallback.sock &
set -gx MOSHPIT_AGENT_SOCK /tmp/test-agent-fallback.sock

# Agent is running but has no keys loaded — list returns empty.
./target/debug/mpa list   # shows 0 identities

# mp logs: "Agent has no identities with algorithms supported by this client
#           (supported: X25519, P256, P384) — falling back to key file"
# then prompts: "Please enter your private key passphrase"
# Enter "testpass" — connection proceeds with the ML-DSA-87 file key.
./target/debug/mp <server>
```

Cleanup:

```fish
kill (pgrep -f "mpa start")
rm -f /tmp/test-agent-vault-fallback /tmp/test-agent-fallback.sock
rm -f /tmp/test_mldsa87_client /tmp/test_mldsa87_client.pub
```

---

## Cleanup

```fish
kill (pgrep -f "mpa start")
rm -f /tmp/test-agent-vault /tmp/test-agent.sock /tmp/test_key /tmp/test_key.pub
```

---

## Non-interactive use (`--passphrase-stdin`)

`--passphrase-stdin` accepts the master passphrase on stdin (one line, no confirmation
prompt). This is also useful for scripting:

```fish
echo "my-passphrase" | ./target/debug/mpa start \
  --foreground \
  --backend passphrase \
  --passphrase-stdin \
  --vault /tmp/test-agent-vault \
  --socket /tmp/test-agent.sock &
set -gx MOSHPIT_AGENT_SOCK /tmp/test-agent.sock
```
