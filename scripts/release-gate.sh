#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# release-gate.sh — the HARDENED pre-release gate.
#
# Nothing gets tagged, pushed, or published unless this exits 0. It is the single
# source of truth for "is this tree fit to be a release", run identically on a
# developer's machine and in CI (release.yml calls it before building artifacts).
#
# The crown jewel is a DOUBLE-LOCK on genesis consensus:
#
#   Lock 1 — PIN INTEGRITY: the canonical mainnet/testnet genesis hashes must
#            still be the exact constants pinned in the source. You cannot quietly
#            edit the pin to make a changed genesis "pass".
#   Lock 2 — BUILD-TO-PIN: the genesis block, rebuilt from the chain spec, must
#            hash byte-for-byte to those same constants. You cannot change genesis
#            and keep the pin.
#
# Together: mainnet genesis is immutable. There is no rollback, ever — the network
# is live. On top of that it runs the full CI check surface locally (fmt, clippy
# -D warnings, the whole workspace test suite, the verification/KAT suite, the
# reproducible-build attestation, and the supply-chain audit) so a green gate here
# means a green CI there.
#
# Usage:
#   scripts/release-gate.sh              # verify only (exit 0 = CLEARED)
#   scripts/release-gate.sh --cut vX.Y.Z # verify, then tag + push on success
#
# Environment-dependent checks (wasm target, cargo-deny, reproducible build) are
# ATTEMPTED and, if their tooling is absent locally, reported as a LOUD SKIP — never
# silently passed — because CI runs them unconditionally. Use --strict to turn any
# such skip into a hard failure (this is what CI uses).
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

# The immutable, canonical genesis hashes. These are the network's identity.
# NEVER change these — a change here is a new, incompatible chain, not a release.
readonly MAINNET_GENESIS="cb0272ff88e64c18cde0257f7fae1c8236b02651f10cc7a02456fd682ee2e72d"
readonly TESTNET_GENESIS="4d7d9123a489f4fd29486da3d66a6c20b04953cb886dee847662e11af293da15"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

STRICT=0
CUT_TAG=""
while [ $# -gt 0 ]; do
  case "$1" in
    --strict) STRICT=1 ;;
    --cut) CUT_TAG="${2:-}"; shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done

# ── output helpers ───────────────────────────────────────────────────────────
if [ -t 1 ]; then
  BOLD=$'\033[1m'; RED=$'\033[31m'; GRN=$'\033[32m'; YEL=$'\033[33m'; DIM=$'\033[2m'; RST=$'\033[0m'
else
  BOLD=""; RED=""; GRN=""; YEL=""; DIM=""; RST=""
fi
STEP=0
fail() { echo "${RED}${BOLD}✗ GATE FAILED:${RST} $*" >&2; exit 1; }
ok()   { echo "${GRN}✓${RST} $*"; }
skip() {
  if [ "$STRICT" = "1" ]; then fail "$* (—strict: no skips allowed in CI)"; fi
  echo "${YEL}⁃ SKIP:${RST} $* ${DIM}(CI runs this unconditionally)${RST}"
}
banner() { STEP=$((STEP+1)); echo; echo "${BOLD}[$STEP] $*${RST}"; }

echo "${BOLD}══════════════════════════════════════════════════════════════${RST}"
echo "${BOLD}  SOV RELEASE GATE — hardened pre-release verification${RST}"
echo "${BOLD}══════════════════════════════════════════════════════════════${RST}"
echo "${DIM}root: $ROOT${RST}"
echo "${DIM}rust: $(rustc --version 2>/dev/null || echo 'MISSING')${RST}"
echo "${DIM}git:  $(git rev-parse --short HEAD 2>/dev/null || echo '?') on $(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo '?')${RST}"

command -v cargo >/dev/null || fail "cargo not found on PATH"

# ── 0. clean tree (a release must build from committed source) ───────────────
# We fail on any uncommitted change to a TRACKED file (staged or not) — that is
# exactly what would differ from the tag's source. Untracked files never enter a
# tag, so they are reported but do not block (e.g. a local scratch dir).
banner "Tracked source is fully committed"
if ! git diff --quiet || ! git diff --cached --quiet; then
  git status --short --untracked-files=no
  fail "uncommitted changes to tracked files — commit or stash before releasing"
fi
UNTRACKED="$(git ls-files --others --exclude-standard)"
if [ -n "$UNTRACKED" ]; then
  echo "${DIM}note: untracked files present (not part of the release):${RST}"
  printf '%s\n' "$UNTRACKED" | sed 's/^/  · /'
fi
ok "every tracked file is committed"

# ── 1. GENESIS PIN INTEGRITY (double-lock #1) ────────────────────────────────
banner "Genesis pin integrity — the canonical hashes are unchanged in source"
PIN_FILE="chain/crates/rpc/src/daemon.rs"
grep -qF "$MAINNET_GENESIS" "$PIN_FILE" \
  || fail "MAINNET genesis pin $MAINNET_GENESIS not found in $PIN_FILE — the pin was altered"
grep -qF "$TESTNET_GENESIS" "$PIN_FILE" \
  || fail "TESTNET genesis pin $TESTNET_GENESIS not found in $PIN_FILE — the pin was altered"
ok "mainnet pin present: ${DIM}$MAINNET_GENESIS${RST}"
ok "testnet pin present: ${DIM}$TESTNET_GENESIS${RST}"

# ── 2. GENESIS BUILDS TO PIN (double-lock #2), byte-for-byte ─────────────────
banner "Genesis rebuilds byte-for-byte to the pinned hashes"
GEN_OUT="$( cd chain && cargo test -p sov-rpc --release -- --nocapture --test-threads=1 \
  mainnet_genesis_builds_and_is_frozen \
  testnet_1_frozen_genesis_is_byte_for_byte_deterministic \
  genesis_hash_pin_is_enforced 2>&1 )" || { echo "$GEN_OUT"; fail "frozen-genesis tests did not pass"; }
# Belt-and-suspenders: confirm the value the test itself PRINTED equals the pin.
PRINTED="$(printf '%s\n' "$GEN_OUT" | sed -n 's/.*MAINNET GENESIS HASH = \([0-9a-f]\{64\}\).*/\1/p' | head -1)"
if [ -n "$PRINTED" ] && [ "$PRINTED" != "$MAINNET_GENESIS" ]; then
  fail "rebuilt mainnet genesis $PRINTED != pinned $MAINNET_GENESIS"
fi
printf '%s\n' "$GEN_OUT" | grep -qE "test result: ok" || fail "frozen-genesis tests reported no success"
ok "mainnet genesis rebuilds to the pin (byte-for-byte)"
ok "testnet genesis rebuilds to the pin (byte-for-byte)"
ok "pin-enforcement mechanism itself is tested and live"

# ── 3. formatting ────────────────────────────────────────────────────────────
banner "Formatting (cargo fmt --check)"
( cd chain && cargo fmt --all -- --check ) || fail "formatting drift — run 'cargo fmt --all'"
ok "no formatting drift"

# ── 4. clippy, warnings are errors ───────────────────────────────────────────
banner "Clippy (deny warnings)"
( cd chain && cargo clippy --workspace --all-targets -- -D warnings ) || fail "clippy found issues"
ok "clippy clean under -D warnings"

# ── 5. the whole workspace test suite ────────────────────────────────────────
banner "Workspace tests (cargo test --workspace)"
( cd chain && cargo test --workspace ) || fail "workspace tests failed"
ok "every workspace test passed"

# ── 6. verification + cross-impl KAT ─────────────────────────────────────────
banner "Verification suite (invariants · model-check · conformance · KAT)"
( cd chain && cargo test -p sov-verify ) || fail "verification/KAT suite failed"
ok "consensus invariants + cross-impl KAT vectors hold"

# ── 6b. key-generation collisions + randomness ───────────────────────────────
# Runs the wallet pipeline (OS entropy → BIP-39 → seed → hybrid key → account) for
# a batch of fresh wallets and proves ZERO collisions plus a statistical randomness
# battery (monobit · byte χ² · Shannon entropy · serial correlation) on the RAW
# entropy that seeds them — so a biased/stuck RNG can never ship in a release.
banner "Key pipeline (collision-free + randomness battery)"
( cd chain && cargo run --quiet -p sov-rpc --bin sov-selfcheck -- keys --count 3000 ) \
  || fail "key-generation self-check failed (collision or randomness battery)"
ok "wallet keys: zero collisions + entropy battery passed"

# ── 6c. the SOV Station desktop app (node/) ──────────────────────────────────
# node/ is a SEPARATE cargo workspace — the chain-workspace fmt/clippy/test steps
# above DO NOT touch it. That blind spot is exactly how "sov-testnet not built"
# shipped (a broken node-start path, on mainnet). Gate the shipped app the same as
# the chain: fmt · clippy -D · its tests (incl. the self-contained-node-setup guard).
banner "SOV Station app (node/): fmt · clippy · tests"
( cd node && cargo fmt --all -- --check ) || fail "node app: formatting drift — run 'cargo fmt' in node/"
cargo clippy --manifest-path node/Cargo.toml --all-targets -- -D warnings || fail "node app: clippy issues"
cargo test --manifest-path node/Cargo.toml || fail "node app: tests failed"
ok "sov-station app builds, lints, and tests clean"

# ── 6d. the external-mining bridge (tools/sov-stratum/) ─────────────────────
# sov-stratum is a SEPARATE cargo workspace. It is the first practical path for
# outside RandomX hashpower, so letting it bypass the gate would turn a
# decentralization improvement into an unverified mining surface.
banner "Stratum bridge (tools/sov-stratum/): fmt · clippy · tests"
cargo fmt --manifest-path tools/sov-stratum/Cargo.toml --all -- --check \
  || fail "sov-stratum: formatting drift"
cargo clippy --manifest-path tools/sov-stratum/Cargo.toml --all-targets -- -D warnings \
  || fail "sov-stratum: clippy issues"
cargo test --manifest-path tools/sov-stratum/Cargo.toml \
  || fail "sov-stratum: tests failed"
ok "sov-stratum bridge builds, lints, and tests clean"

# ── 7. wasm contracts (mirror CI's `contracts` job exactly) ──────────────────
# Scoped to chain/contracts — the no_std guest crate — NOT the whole workspace.
# A workspace-wide wasm build pulls in std-only deps (getrandom without `js`) that
# never ship in a contract; CI builds only the guest, and so do we.
banner "WASM contracts (wasm32 clippy + release build)"
if rustup target list --installed 2>/dev/null | grep -q wasm32-unknown-unknown; then
  ( cd chain/contracts \
      && cargo clippy --target wasm32-unknown-unknown -- -D warnings \
      && cargo build --target wasm32-unknown-unknown --release ) \
    || fail "wasm contracts (clippy/build) failed"
  ok "wasm guest contracts clippy-clean + release build"
else
  skip "wasm32-unknown-unknown target not installed"
fi

# ── 8. reproducible-build attestation ────────────────────────────────────────
banner "Reproducible build (bit-for-bit binary attestation)"
if [ -x scripts/reproducible-build.sh ]; then
  scripts/reproducible-build.sh || fail "reproducible-build attestation failed"
  ok "release binaries are bit-for-bit reproducible"
else
  skip "scripts/reproducible-build.sh not executable"
fi

# ── 9. supply-chain audit ────────────────────────────────────────────────────
banner "Supply chain (cargo-deny: advisories + bans)"
# Mirror CI EXACTLY: `check advisories bans` against chain/Cargo.toml + chain/deny.toml.
# (Not licenses/sources — CI does not gate on those, and neither do we.)
if command -v cargo-deny >/dev/null; then
  ( cd chain && cargo deny check advisories bans ) || fail "cargo-deny found advisories/bans"
  ok "no known advisories or banned deps"
else
  skip "cargo-deny not installed"
fi

# ── 9b. cargo-audit (RustSec) — audit SOV-M004 ───────────────────────────────
# The documented advisory policy is `cargo audit --deny warnings`; run it ALONGSIDE
# cargo-deny so the two advisory gates can never silently disagree again. cargo-audit
# honors chain/.cargo/audit.toml for the reviewed unmaintained-crate waivers.
banner "Dependency advisories (cargo-audit --deny warnings)"
if ! command -v cargo-audit >/dev/null; then
  cargo install cargo-audit --locked >/dev/null 2>&1 || fail "could not install cargo-audit"
fi
( cd chain && cargo audit --deny warnings ) || fail "chain cargo-audit found advisories (see chain/.cargo/audit.toml)"
( cd tools/sov-stratum && cargo audit --deny warnings ) \
  || fail "sov-stratum cargo-audit found advisories (see tools/sov-stratum/.cargo/audit.toml)"
ok "cargo-audit: chain + sov-stratum clean under their reviewed waiver sets"

# ── cleared ──────────────────────────────────────────────────────────────────
echo
echo "${GRN}${BOLD}══════════════════════════════════════════════════════════════${RST}"
echo "${GRN}${BOLD}  ✓ CLEARED FOR RELEASE${RST}"
echo "${GRN}${BOLD}══════════════════════════════════════════════════════════════${RST}"
echo "  mainnet genesis ${DIM}$MAINNET_GENESIS${RST} ${GRN}FROZEN${RST}"
echo "  testnet genesis ${DIM}$TESTNET_GENESIS${RST} ${GRN}FROZEN${RST}"
echo "  version $(grep -m1 '^version' node/Cargo.toml | cut -d'"' -f2)"

# ── optional: cut the tag on success ─────────────────────────────────────────
if [ -n "$CUT_TAG" ]; then
  case "$CUT_TAG" in
    v[0-9]*) : ;;
    *) fail "--cut tag must look like vX.Y.Z (got '$CUT_TAG')" ;;
  esac
  # VERSION GUARD: the tag MUST equal node/Cargo.toml's version — that is what SOV
  # Station displays (CARGO_PKG_VERSION). Cutting a tag while it is stale ships an app
  # whose in-app version lies (the v0.1.93/0.1.91 mismatch). Refuse it here, and the
  # release workflow's gate re-checks it so a bare `git tag` can't sneak past either.
  CARGO_VER="$(grep -m1 '^version' node/Cargo.toml | cut -d'"' -f2)"
  [ "$CUT_TAG" = "v$CARGO_VER" ] || fail "version mismatch: node/Cargo.toml is $CARGO_VER but --cut is $CUT_TAG. Bump node/Cargo.toml to ${CUT_TAG#v} (refresh node/Cargo.lock), commit, then re-cut."
  echo
  echo "${BOLD}Cutting release $CUT_TAG …${RST}"
  git tag -a "$CUT_TAG" -m "Release $CUT_TAG (release-gate: genesis frozen, all checks green)"
  git push origin "$(git rev-parse --abbrev-ref HEAD)"
  git push origin "$CUT_TAG"
  ok "tagged and pushed $CUT_TAG — the release workflow will build + publish artifacts"
fi
