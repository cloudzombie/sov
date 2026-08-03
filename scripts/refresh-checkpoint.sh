#!/usr/bin/env bash
# Refresh the mainnet assumevalid anchor in chain/crates/rpc/src/daemon.rs.
#
# WHY THIS EXISTS
# ---------------
# The baked anchor is a bootstrap for a node with NO history. It has gone stale
# four times (5000 -> 6800 -> 8300 -> 12800 -> 14336), and each time refreshing it
# was a hand-edit: query a relay, cross-check the hash on another, count the depth,
# paste the pair, write the comment. A chore done by hand is a chore that gets
# skipped, so it is a script.
#
# A running node ALSO maintains its own anchor now (see
# `Blockchain::adopt_local_finalized_checkpoint` and the `assumevalid.dat` written
# under the data dir), and an operator can pass one via the node config's
# `checkpoints` list. This script is the third leg: keeping the value that ships in
# the binary current, so a genuinely fresh node starts close to the tip.
#
# It is deliberately conservative. It refuses to pin anything it cannot confirm
# IDENTICAL on at least two independent relays, and refuses anything shallower than
# the depth below.
#
# Usage:
#   scripts/refresh-checkpoint.sh            # propose + print the patch, no write
#   scripts/refresh-checkpoint.sh --write    # apply it to daemon.rs
set -euo pipefail

cd "$(dirname "$0")/.."

DAEMON=chain/crates/rpc/src/daemon.rs
# Relays that answer RPC FROM OUTSIDE. sgp1 (143.198.219.31) was destroyed on
# 2026-07-31 (it had drifted onto a minority fork and was poisoning every fresh
# sync); leaving it here made curl exit 7 abort this whole script under
# `set -euo pipefail`, so the refresh failed SILENTLY and the anchor went stale.
#
# CAUTION: fra1 (164.92.141.24) binds its RPC to LOOPBACK — correct posture, but it
# means only ONE relay answers publicly, so the two-independent-confirmations rule
# below can no longer be satisfied from outside and this script will (honestly)
# refuse. Until a second public relay exists, confirm the second opinion by hand:
#   ssh root@164.92.141.24 "curl -s --max-time 8 -X POST http://127.0.0.1:8645 \
#     -H 'content-type: application/json' \
#     --data '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"sov_getBlockByHeight\",\"params\":{\"height\":<CAND>}}'"
# and pin only if that hash is IDENTICAL to sfo3's. That is how the 15872 anchor
# was cross-checked.
RELAYS=(137.184.83.91 164.92.141.24)
# How far below the live tip to pin. Two orders of magnitude past the
# 6-confirmation finality bar — roughly a day of blocks at the 2.5-minute target.
MIN_DEPTH=512
# Round the pinned height down to a multiple of this, so anchors land on tidy,
# quotable numbers (as every previous one has).
ROUND_TO=512

WRITE=0
[ "${1:-}" = "--write" ] && WRITE=1

rpc() { # rpc <relay> <method> <params-json>
  # `|| true`: an unreachable relay is an ORDINARY outcome here (a droplet is down,
  # or binds RPC to loopback) and must not abort the script via `set -e`. The caller
  # already treats an empty reply as "no answer" and the two-confirmation rule below
  # is what actually decides whether anything gets pinned. Without this, one dead
  # relay turned a refresh into a silent exit 7 and the anchor rotted unnoticed.
  curl -s --max-time 10 -X POST "http://$1:8645" \
    -H 'content-type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$2\",\"params\":$3}" 2>/dev/null || true
}

# 1. Live tip, from whichever relay answers first.
TIP=""
for r in "${RELAYS[@]}"; do
  TIP="$(rpc "$r" sov_getHeight '{}' | sed -n 's/.*"result":[[:space:]]*\([0-9]*\).*/\1/p')"
  [ -n "$TIP" ] && break
done
[ -n "$TIP" ] || { echo "refresh-checkpoint: no relay answered — cannot propose an anchor" >&2; exit 1; }

# 2. The candidate height: buried at least MIN_DEPTH, rounded down.
CAND=$(( (TIP - MIN_DEPTH) / ROUND_TO * ROUND_TO ))
[ "$CAND" -gt 0 ] || { echo "refresh-checkpoint: chain too short to pin (tip $TIP)" >&2; exit 1; }

NEWEST="$(awk '/const MAINNET_CHECKPOINTS/,/^\];/' "$DAEMON" \
  | grep -oE '^[[:space:]]+[0-9]+,$' | tr -d ' ,' | sort -n | tail -1)"
if [ -n "${NEWEST:-}" ] && [ "$CAND" -le "$NEWEST" ]; then
  echo "refresh-checkpoint: nothing to do — anchor $NEWEST already at/above candidate $CAND (tip $TIP)"
  exit 0
fi

# 3. The hash, confirmed IDENTICAL on at least two independent relays. One relay is
#    a claim; two that agree is evidence. Never pin on one.
AGREE=0
HASH=""
SOURCES=""
for r in "${RELAYS[@]}"; do
  H="$(rpc "$r" sov_getBlockByHeight "{\"height\":$CAND}" \
    | sed -n 's/.*"hash":"\([0-9a-f]\{64\}\)".*/\1/p' | head -1)"
  [ -n "$H" ] || continue
  if [ -z "$HASH" ]; then
    HASH="$H"
  elif [ "$H" != "$HASH" ]; then
    echo "refresh-checkpoint: RELAYS DISAGREE at height $CAND ($HASH vs $H from $r) — refusing to pin" >&2
    exit 1
  fi
  AGREE=$(( AGREE + 1 ))
  SOURCES="$SOURCES $r"
done
if [ "$AGREE" -lt 2 ]; then
  echo "refresh-checkpoint: only $AGREE relay(s) confirmed height $CAND — need 2 independent confirmations. Refusing." >&2
  exit 1
fi

DEPTH=$(( TIP - CAND ))
TODAY="$(date -u +%Y-%m-%d)"
ENTRY="    // Pinned $TODAY at tip $TIP (this block is ~$DEPTH deep — far past finality).
    // Hash confirmed IDENTICAL on $AGREE independent relays:$SOURCES.
    // Generated by scripts/refresh-checkpoint.sh. A stale anchor is a SLOWNESS, not
    // an outage: verification runs off the P2P thread (see chain/crates/rpc/src/p2p.rs),
    // so a fresh node above its anchor keeps its peers while it catches up.
    (
        $CAND,
        \"$HASH\",
    ),"

echo "tip           : $TIP"
echo "candidate     : $CAND (depth $DEPTH)"
echo "hash          : $HASH"
echo "confirmed by  :$SOURCES"
echo
echo "$ENTRY"

if [ "$WRITE" -eq 1 ]; then
  python3 - "$DAEMON" "$ENTRY" <<'PY'
import sys
path, entry = sys.argv[1], sys.argv[2]
src = open(path).read()
start = src.index("const MAINNET_CHECKPOINTS")
end = src.index("\n];", start) + 1
assert entry not in src, "entry already present"
open(path, "w").write(src[:end] + entry + "\n" + src[end:])
PY
  ( cd chain && cargo fmt )
  echo
  echo "WROTE $DAEMON — review the diff, then run scripts/release-gate.sh."
else
  echo
  echo "(dry run — re-run with --write to apply)"
fi
