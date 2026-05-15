#!/usr/bin/env fish
#
# Moshpit key-type test harness.
#
# Layout:
#   ┌─────────────────────────────┐
#   │        TOP (this script)    │
#   ├──────────────┬──────────────┤
#   │  CENTER-LEFT │ CENTER-RIGHT │
#   │  (mps log)   │  (mp log)   │
#   ├──────────────┬──────────────┤
#   │ BOTTOM-LEFT  │ BOTTOM-RIGHT │
#   │    (mps)     │    (mp)      │
#   └──────────────┴──────────────┘
#
# Builds debug binaries with unstable, generates all keys automatically,
# then walks through every (or selected) connection-test scenario.

set -g SCRIPT_DIR  (cd (dirname (status --current-filename)) && pwd)
set -g REPO_DIR    (cd $SCRIPT_DIR/.. && pwd)
set -g KEYS_DIR    /tmp/test-keys
set -g LOGS_DIR    "$SCRIPT_DIR/logs"
set -g AUTH_KEYS   "$HOME/.mp/authorized_keys"
set -g MPS_CONF    "scripts/mps-test.toml"
set -g MP_CONF     "scripts/mp-test.toml"
set -g MP_BIN      "$REPO_DIR/target/debug/mp"
set -g MPS_BIN     "$REPO_DIR/target/debug/mps"
set -g KEYGEN_BIN  "$REPO_DIR/target/debug/mp-keygen"
set SESSION_NAME   moshpit-keytest

# Parallel arrays tracking results for the final summary.
set -g RESULT_LABELS
set -g RESULT_STATUSES

# ── Bootstrap: always run inside our named session ───────────────────────────

if not set -q TMUX; or test (tmux display-message -p '#S') != $SESSION_NAME
    tmux kill-session -t $SESSION_NAME 2>/dev/null
    tmux new-session -d -s $SESSION_NAME -x 220 -y 50 -c $REPO_DIR
    tmux send-keys -t "$SESSION_NAME:0" "fish $SCRIPT_DIR/test-keys.fish" Enter
    if set -q TMUX
        tmux switch-client -t $SESSION_NAME
    else
        tmux attach-session -t $SESSION_NAME
    end
    exit 0
end

# ── Layout ───────────────────────────────────────────────────────────────────
#
# Build five panes via four sequential splits.  Pane indices are deterministic
# in a fresh single-window session (left-to-right, top-to-bottom):
#
#   0.0 → top          (this script)
#   0.1 → center-left  (mps log tail)
#   0.2 → center-right (mp  log tail)
#   0.3 → bottom-left  (mps)
#   0.4 → bottom-right (mp)

tmux split-window -v -d -t "$SESSION_NAME:0.0"   # → [0:top, 1:bottom]
tmux split-window -v -d -t "$SESSION_NAME:0.1"   # → [0:top, 1:mid, 2:bottom]
tmux split-window -h -d -t "$SESSION_NAME:0.1"   # → [0:top, 1:mid-L, 2:mid-R, 3:bottom]
tmux split-window -h -d -t "$SESSION_NAME:0.3"   # → [0:top, 1:mid-L, 2:mid-R, 3:bot-L, 4:bot-R]

set -g LOG_LEFT     "$SESSION_NAME:0.1"
set -g LOG_RIGHT    "$SESSION_NAME:0.2"
set -g BOTTOM_LEFT  "$SESSION_NAME:0.3"
set -g BOTTOM_RIGHT "$SESSION_NAME:0.4"

set -l WIN_H (tmux display-message -p '#{window_height}')
tmux resize-pane -t "$SESSION_NAME:0.0" -y (math "floor($WIN_H * 0.50)")
tmux resize-pane -t "$SESSION_NAME:0.1" -y (math "floor($WIN_H * 0.25)")
tmux select-pane -t "$SESSION_NAME:0.0"

# ── Log directory + tails ────────────────────────────────────────────────────

mkdir -p $LOGS_DIR
set -g TODAY     (date +%Y-%m-%d)
set -g LOG_MPS   "$LOGS_DIR/mps.log.$TODAY"
set -g LOG_MP    "$LOGS_DIR/mp.log.$TODAY"
touch $LOG_MPS $LOG_MP

tmux send-keys -t $LOG_LEFT  "tail -F $LOG_MPS" Enter
tmux send-keys -t $LOG_RIGHT "tail -F $LOG_MP"  Enter

# ── Helper functions ─────────────────────────────────────────────────────────

function send_to
    tmux send-keys -t $argv[1] $argv[2] Enter
end

function clear_pane
    tmux send-keys -t $argv[1] C-c
    sleep 0.3
    tmux send-keys -t $argv[1] "clear" Enter
end

# Add a client public key to ~/.mp/authorized_keys.
# Creates the directory and file with correct permissions if they don't exist.
function add_client_key
    set -l pub_file "$KEYS_DIR/client_$argv[1].pub"
    mkdir -m 700 -p "$HOME/.mp"
    if not test -f $AUTH_KEYS
        touch $AUTH_KEYS
        chmod 600 $AUTH_KEYS
    end
    cat $pub_file >> $AUTH_KEYS
    printf '\n' >> $AUTH_KEYS
    echo "    → added to $AUTH_KEYS"
end

# Remove all test client public keys from ~/.mp/authorized_keys.
# Reads each .pub file still present in KEYS_DIR and filters out its line.
function remove_client_keys
    if not test -f $AUTH_KEYS
        return
    end
    set -l tmp     (mktemp)
    set -l scratch (mktemp)
    cp $AUTH_KEYS $tmp
    for kt in x25519 p384 p256 mldsa44 mldsa65 mldsa87
        set -l pub_file "$KEYS_DIR/client_$kt.pub"
        if test -f $pub_file
            grep -vxFf $pub_file $tmp > $scratch 2>/dev/null; or true
            cp $scratch $tmp
        end
    end
    cp $tmp $AUTH_KEYS
    chmod 600 $AUTH_KEYS
    rm -f $tmp $scratch
    echo "  ✓ Test client keys removed from $AUTH_KEYS"
end

function show_summary
    set -l n (count $RESULT_LABELS)
    test $n -eq 0; and return
    set -l line (string repeat -n 60 ═)
    echo ""
    echo $line
    printf "  %s\n" "Test Summary"
    echo $line
    for i in (seq $n)
        if test $RESULT_STATUSES[$i] = pass
            set_color green
            printf "  ✓  "
            set_color normal
        else
            set_color red
            printf "  ✗  "
            set_color normal
        end
        echo $RESULT_LABELS[$i]
    end
    echo $line
end

function cleanup
    echo ""
    echo "═══ Cleaning up ═══"
    remove_client_keys
    rm -rf $KEYS_DIR
    echo "  ✓ $KEYS_DIR removed."
end

function exit_with_failure
    show_summary
    cleanup
    exit 1
end

function banner
    set -l line (string repeat -n 60 ═)
    echo ""
    echo $line
    printf "  %s\n" $argv[1]
    echo $line
end

function ask_pass
    read -P "[$argv[1]] Did the test PASS? [y/N] " ans
    set -l a (string lower -- (string trim -- $ans))
    if test "$a" = y -o "$a" = yes
        return 0
    end
    return 1
end

function ask_expected_fail
    read -P "[$argv[1]] Did the connection FAIL as expected? [y/N] " ans
    set -l a (string lower -- (string trim -- $ans))
    if test "$a" = y -o "$a" = yes
        return 0
    end
    return 1
end

# run_test LABEL EXPECT_FAIL MPS_CMD MP_CMD
function run_test
    set -l label       $argv[1]
    set -l expect_fail $argv[2]
    set -l mps_cmd     $argv[3]
    set -l mp_cmd      $argv[4]

    banner $label
    if test $expect_fail -eq 1
        echo "  NOTE: connection failure is EXPECTED for this test."
        echo ""
    end
    echo "  MPS: $mps_cmd"
    echo "  MP:  $mp_cmd"
    echo ""

    send_to $BOTTOM_LEFT  $mps_cmd
    sleep 1
    send_to $BOTTOM_RIGHT $mp_cmd

    echo "  ↑ mps in bottom-left · mp in bottom-right"
    echo "    Log output in center panes.  Stop both (Ctrl-C) when done, then answer below."
    echo ""

    set -l passed 0
    if test $expect_fail -eq 1
        if ask_expected_fail $label
            set passed 1
        end
    else
        if ask_pass $label
            set passed 1
        end
    end

    clear_pane $BOTTOM_LEFT
    clear_pane $BOTTOM_RIGHT

    set -g -a RESULT_LABELS $label
    if test $passed -eq 1
        set -g -a RESULT_STATUSES pass
        echo "  ✓ PASS"
        return 0
    else
        set -g -a RESULT_STATUSES fail
        echo "  ✗ FAIL — aborting."
        return 1
    end
end

# ── Test Definitions ─────────────────────────────────────────────────────────
#
# Five parallel arrays, one element per test (25 total):
#   ALL_LABELS       — display description (no number prefix)
#   ALL_EXPECT_FAIL  — 1 = failure is expected, 0 = should connect
#   ALL_KEYS         — identity key type  (x25519 | p384 | p256 | mldsa44 | …)
#   ALL_MPS_FLAGS    — extra flags for mps (empty string = none)
#   ALL_MP_FLAGS     — extra flags for mp  (empty string = none)

set -g ALL_LABELS
set -g ALL_EXPECT_FAIL
set -g ALL_KEYS
set -g ALL_MPS_FLAGS
set -g ALL_MP_FLAGS

# def_test LABEL EXPECT_FAIL KEY MPS_FLAGS MP_FLAGS
function def_test
    set -g -a ALL_LABELS      "$argv[1]"
    set -g -a ALL_EXPECT_FAIL "$argv[2]"
    set -g -a ALL_KEYS        "$argv[3]"
    set -g -a ALL_MPS_FLAGS   "$argv[4]"
    set -g -a ALL_MP_FLAGS    "$argv[5]"
end

# ── Standard ECDH identity key tests (x25519 key pair) ───────────────────────
def_test "Default (x25519-sha256 / aes256-gcm-siv / hmac-sha512 / hkdf-sha256)" \
    0 x25519 "" ""
def_test "ML-KEM-768 KEX" \
    0 x25519 "--kex-algos ml-kem-768-sha256" "--kex-algos ml-kem-768-sha256"
def_test "ML-KEM-512 KEX" \
    0 x25519 "--kex-algos ml-kem-512-sha256" "--kex-algos ml-kem-512-sha256"
def_test "ML-KEM-1024 KEX" \
    0 x25519 "--kex-algos ml-kem-1024-sha256" "--kex-algos ml-kem-1024-sha256"
def_test "P-384 KEX + HKDF-SHA384 KDF" \
    0 x25519 "--kex-algos p384-sha384 --kdf-algos hkdf-sha384" \
             "--kex-algos p384-sha384 --kdf-algos hkdf-sha384"
def_test "P-256 KEX" \
    0 x25519 "--kex-algos p256-sha256" "--kex-algos p256-sha256"
def_test "AES-256-GCM AEAD" \
    0 x25519 "--aead-algos aes256-gcm" "--aead-algos aes256-gcm"
def_test "ChaCha20-Poly1305 AEAD" \
    0 x25519 "--aead-algos chacha20-poly1305" "--aead-algos chacha20-poly1305"
def_test "AES-128-GCM-SIV AEAD" \
    0 x25519 "--aead-algos aes128-gcm-siv" "--aead-algos aes128-gcm-siv"
def_test "HMAC-SHA256 MAC" \
    0 x25519 "--mac-algos hmac-sha256" "--mac-algos hmac-sha256"
def_test "HKDF-SHA384 KDF" \
    0 x25519 "--kdf-algos hkdf-sha384" "--kdf-algos hkdf-sha384"
def_test "HKDF-SHA512 KDF" \
    0 x25519 "--kdf-algos hkdf-sha512" "--kdf-algos hkdf-sha512"
def_test "No common algorithm — server=x25519-sha256 client=p384-sha384" \
    1 x25519 "--kex-algos x25519-sha256" "--kex-algos p384-sha384"

# ── ML-DSA-44 ─────────────────────────────────────────────────────────────────
def_test "ML-DSA-44 — default session algorithms" \
    0 mldsa44 "" ""
def_test "ML-DSA-44 + ML-KEM-768 KEX" \
    0 mldsa44 "--kex-algos ml-kem-768-sha256" "--kex-algos ml-kem-768-sha256"
def_test "ML-DSA-44 + ML-KEM-512 KEX" \
    0 mldsa44 "--kex-algos ml-kem-512-sha256" "--kex-algos ml-kem-512-sha256"
def_test "ML-DSA-44 + ML-KEM-1024 KEX" \
    0 mldsa44 "--kex-algos ml-kem-1024-sha256" "--kex-algos ml-kem-1024-sha256"

# ── ML-DSA-65 ─────────────────────────────────────────────────────────────────
def_test "ML-DSA-65 — default session algorithms" \
    0 mldsa65 "" ""
def_test "ML-DSA-65 + ML-KEM-768 KEX" \
    0 mldsa65 "--kex-algos ml-kem-768-sha256" "--kex-algos ml-kem-768-sha256"
def_test "ML-DSA-65 + ML-KEM-512 KEX" \
    0 mldsa65 "--kex-algos ml-kem-512-sha256" "--kex-algos ml-kem-512-sha256"
def_test "ML-DSA-65 + ML-KEM-1024 KEX" \
    0 mldsa65 "--kex-algos ml-kem-1024-sha256" "--kex-algos ml-kem-1024-sha256"

# ── ML-DSA-87 ─────────────────────────────────────────────────────────────────
def_test "ML-DSA-87 — default session algorithms" \
    0 mldsa87 "" ""
def_test "ML-DSA-87 + ML-KEM-768 KEX" \
    0 mldsa87 "--kex-algos ml-kem-768-sha256" "--kex-algos ml-kem-768-sha256"
def_test "ML-DSA-87 + ML-KEM-512 KEX" \
    0 mldsa87 "--kex-algos ml-kem-512-sha256" "--kex-algos ml-kem-512-sha256"
def_test "ML-DSA-87 + ML-KEM-1024 KEX (fully post-quantum)" \
    0 mldsa87 "--kex-algos ml-kem-1024-sha256" "--kex-algos ml-kem-1024-sha256"

set -g TOTAL_TESTS (count $ALL_LABELS)

# ── Build ────────────────────────────────────────────────────────────────────

banner "Building debug binaries (unstable)"
echo "  Repo: $REPO_DIR"
echo ""

cd $REPO_DIR
for pkg in moshpit moshpits moshpit-keygen
    echo "  cargo build -p $pkg --features unstable"
    cargo build -p $pkg --features unstable
    or begin
        echo "  Build failed for $pkg — aborting."
        exit 1
    end
end

echo ""
echo "  ✓ mp:       $MP_BIN"
echo "  ✓ mps:      $MPS_BIN"
echo "  ✓ mp-keygen: $KEYGEN_BIN"

# ── Key Generation (fully automatic) ─────────────────────────────────────────

banner "Generating all key pairs → $KEYS_DIR"
mkdir -p $KEYS_DIR

for kt in x25519 p384 p256 mldsa44 mldsa65 mldsa87
    echo ""
    echo "  ── $kt ──"

    echo "    client key → $KEYS_DIR/client_$kt  (passphrase: test)"
    echo "test" | $KEYGEN_BIN generate -k $kt --passphrase-stdin -f -o "$KEYS_DIR/client_$kt"
    or begin
        echo "  ✗ Client keygen failed for $kt — aborting."
        exit_with_failure
    end
    add_client_key $kt

    echo "    server key → $KEYS_DIR/server_$kt"
    $KEYGEN_BIN generate -k $kt -s -n -f -o "$KEYS_DIR/server_$kt"
    or begin
        echo "  ✗ Server keygen failed for $kt — aborting."
        exit_with_failure
    end
end

echo ""
echo "  ✓ All keys written to $KEYS_DIR"
echo "  ✓ Client public keys registered in $AUTH_KEYS"

# ── Test Selection ────────────────────────────────────────────────────────────

banner "Test Selection"

# Print the full test table.
set -l tbl_line (string repeat -n 74 ─)
echo ""
echo "  $tbl_line"
printf "  %3s  %-64s  %s\n" " # " "Description" "Note"
echo "  $tbl_line"
for i in (seq $TOTAL_TESTS)
    set -l note ""
    if test "$ALL_EXPECT_FAIL[$i]" = 1
        set note "EXPECT FAIL"
    end
    printf "  %3d  %-64s  %s\n" $i "$ALL_LABELS[$i]" "$note"
end
echo "  $tbl_line"
echo ""
echo "  Enter a single test number, a comma-separated list (e.g. 1,3,13),"
echo "  or 'all' to run every test."
echo ""

# Loop until a valid selection is entered.
set -g SELECTED_TESTS
while true
    read -P "  Selection: " raw_sel
    set -l sel (string lower -- (string trim -- $raw_sel))

    if test "$sel" = all
        set -g SELECTED_TESTS (seq $TOTAL_TESTS)
        break
    end

    set -l parts (string split "," -- $sel)
    set -l valid 1
    set -l parsed

    for part in $parts
        set -l n (string trim -- $part)
        if not string match -qr '^[0-9]+$' -- $n
            echo "  ✗ '$n' is not a valid number — try again."
            set valid 0
            break
        end
        if test $n -lt 1 -o $n -gt $TOTAL_TESTS
            echo "  ✗ $n is out of range (1–$TOTAL_TESTS) — try again."
            set valid 0
            break
        end
        if not contains -- $n $parsed
            set -a parsed $n
        end
    end

    if test $valid -eq 1 -a (count $parsed) -gt 0
        # Sort numerically and store.
        set -g SELECTED_TESTS (for n in $parsed; echo $n; end | sort -n)
        break
    else if test $valid -eq 1
        echo "  ✗ No tests selected — try again."
    end
end

set -l n_sel (count $SELECTED_TESTS)
echo ""
echo "  Running $n_sel of $TOTAL_TESTS tests:"
for i in $SELECTED_TESTS
    printf "    %3d  %s\n" $i "$ALL_LABELS[$i]"
end

# ── Connection Tests ──────────────────────────────────────────────────────────

banner "Connection Tests ($n_sel selected)"
echo "  mps starts first, then mp connects after 1 s."
echo "  Stop both panes (Ctrl-C) when done, then answer pass/fail here."
echo "  Logs: $LOGS_DIR"
echo ""
read -P "  Press Enter to begin..." _begin

set -g MPS_BASE "$MPS_BIN -c $MPS_CONF --tracing-absolute-path $LOGS_DIR/mps.log"
set -g MP_BASE  "$MP_BIN  -c $MP_CONF  --tracing-absolute-path $LOGS_DIR/mp.log -s 40406"

for i in $SELECTED_TESTS
    set -l key    $ALL_KEYS[$i]
    set -l mflag  $ALL_MPS_FLAGS[$i]
    set -l pflag  $ALL_MP_FLAGS[$i]
    set -l label  (printf "[%02d/%02d]  %s" $i $TOTAL_TESTS "$ALL_LABELS[$i]")

    set -l this_mps "$MPS_BASE $mflag -p $KEYS_DIR/server_$key -k $KEYS_DIR/server_$key.pub"
    set -l this_mp  "$MP_BASE $pflag -p $KEYS_DIR/client_$key -k $KEYS_DIR/client_$key.pub 127.0.0.1"

    run_test "$label" "$ALL_EXPECT_FAIL[$i]" "$this_mps" "$this_mp"
    or begin; exit_with_failure; end
end

# ── Done ─────────────────────────────────────────────────────────────────────

banner "All $n_sel selected tests passed ✓"
show_summary
cleanup
exit 0
