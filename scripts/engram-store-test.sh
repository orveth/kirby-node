#!/usr/bin/env bash
# Kirby durable-mind-state Chunk-2 LIVE multi-relay e2e (design doc §16): stand up a
# 3-relay nerve set, then drive the real NIP-AE `EngramStore` through the ignored
# integration test `engram_live_multi_relay_round_trip`, which proves end to end:
#   - SET -> GET round-trips the value (NIP-44 self-encrypted, self-decrypted);
#   - RM tombstones it -> GET reads ABSENT (LWW drops the tombstoned head);
#   - a second SET + LS lists the live slug and omits the tombstoned one;
#   - the write reaches the relay set and K-of-N (majority) acks.
# Then a K-OF-N phase: kill ONE relay and re-run -- the write still reaches 2/3 (>= the
# majority K=2) and reads still union from the survivors, proving partial-relay tolerance.
#
# Like the nerve presence round-trip, this needs running relays, so it lives OUTSIDE the
# default `cargo test` gate (the test is `#[ignore]`d). The encrypt-to-self / K_self
# determinism / LWW-reconcile LOGIC is covered network-free by the `engram` unit tests.
#
# Run INSIDE the dev shell (cargo + the relay binary):
#   nix develop --command bash scripts/engram-store-test.sh
#
# Tunables via env: PORT_BASE (first relay port; 3 consecutive), KEEP (1 = keep work dir).
set -euo pipefail

PORT_BASE="${PORT_BASE:-7790}"
KEEP="${KEEP:-0}"
PORTS=("$PORT_BASE" "$((PORT_BASE + 1))" "$((PORT_BASE + 2))")

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d -t kirby-engram-XXXXXX)"

declare -A RELAY_PID=()

cleanup() {
  set +e
  for p in "${!RELAY_PID[@]}"; do
    [ -n "${RELAY_PID[$p]}" ] && kill "${RELAY_PID[$p]}" 2>/dev/null
  done
  wait 2>/dev/null
  if [ "$KEEP" = "1" ]; then echo "[test] work dir kept: $WORK"; else rm -rf "$WORK"; fi
}
trap cleanup EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }

# --- locate the relay binary (PATH, else build from the flake) ---------------
RELAY_BIN="$(command -v nostr-rs-relay || true)"
if [ -z "$RELAY_BIN" ]; then
  echo "[test] nostr-rs-relay not on PATH; building it (nix build .#relay-bin)..."
  RELAY_BIN="$(nix build --no-link --print-out-paths "$ROOT#relay-bin")/bin/nostr-rs-relay"
fi
echo "[test] relay binary: $RELAY_BIN"

# --- start a relay on a port -------------------------------------------------
start_relay() {
  local port="$1"
  local data="$WORK/relay-$port"
  mkdir -p "$data"
  cat > "$WORK/relay-$port.toml" <<EOF
[info]
name = "kirby-engram-test-relay-$port"
[database]
data_directory = "$data"
[network]
address = "127.0.0.1"
port = $port
[authorization]
nip42_auth = false
[limits]
messages_per_sec = 0
EOF
  RUST_LOG=warn "$RELAY_BIN" --config "$WORK/relay-$port.toml" >"$WORK/relay-$port.log" 2>&1 &
  RELAY_PID[$port]=$!
  # Wait for the TCP port to accept connections.
  for i in $(seq 1 50); do
    if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then exec 3>&- 3<&-; return 0; fi
    kill -0 "${RELAY_PID[$port]}" 2>/dev/null || { cat "$WORK/relay-$port.log" >&2; fail "relay $port exited early"; }
    sleep 0.2
  done
  fail "relay $port did not open"
}

echo "[test] === starting 3 relays (the nerve set, N=3) ==="
for p in "${PORTS[@]}"; do start_relay "$p"; echo "[test] relay up on ws://127.0.0.1:$p"; done

RELAYS="ws://127.0.0.1:${PORTS[0]},ws://127.0.0.1:${PORTS[1]},ws://127.0.0.1:${PORTS[2]}"

run_round_trip() {
  local phase="$1"
  echo "[test] === $phase: KIRBY_ENGRAM_RELAYS=$RELAYS ==="
  KIRBY_ENGRAM_RELAYS="$RELAYS" \
    ( cd "$ROOT" && cargo test -p kirby-node --test memory_engram \
        engram_live_multi_relay_round_trip -- --ignored --nocapture ) \
    || fail "$phase: live multi-relay round-trip failed"
  echo "[test] OK: $phase passed."
}

# Phase 1: all 3 relays up -- full write/read/LWW/tombstone round-trip + K-of-N (3/3).
run_round_trip "phase 1 (all 3 relays up)"

# Phase 2: kill ONE relay -- the write still reaches 2/3 (>= majority K=2) and reads
# still union from the survivors. Proves partial-relay (K-of-N) tolerance.
echo "[test] === killing relay ${PORTS[2]} (K-of-N tolerance: 2/3 remain >= K=2) ==="
kill "${RELAY_PID[${PORTS[2]}]}" 2>/dev/null; wait "${RELAY_PID[${PORTS[2]}]}" 2>/dev/null || true
RELAY_PID[${PORTS[2]}]=""
run_round_trip "phase 2 (one relay down, 2/3 up)"

echo
echo "PASS: EngramStore live multi-relay e2e (round-trip + LWW + tombstone + K-of-N tolerance)."
