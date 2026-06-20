#!/usr/bin/env bash
# Reproducible-build verification (Phase 7, p7-i7).
#
# Builds the SOV release binaries twice, into two separate target directories,
# and asserts the resulting executables are byte-for-byte (SHA-256) identical.
# Determinism comes from: a committed Cargo.lock (`--locked`), single codegen
# unit + `panic = abort` (release profile), path remapping, and a fixed
# SOURCE_DATE_EPOCH — so the build does not embed machine-specific paths or
# timestamps.
#
# Scope (honest): this proves determinism on a *fixed toolchain*. Full
# cross-machine binary attestation additionally requires pinning the exact Rust
# toolchain (rust-toolchain.toml) and ideally a container image; see
# chain/docs/reproducible-builds.md.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT/chain"

# Strip machine-specific paths from the artifacts so two checkouts in different
# directories still produce identical bytes.
export RUSTFLAGS="--remap-path-prefix=$ROOT=/sov --remap-path-prefix=$HOME=/home -C debuginfo=0"
export SOURCE_DATE_EPOCH=1700000000

BINS=(sov-node sov-miner sov-katgen)

build_into() {
  local dir="$1"
  # The shipped binaries (and their full dependency graph) — the attestable
  # artifacts. Building these is sufficient for binary attestation and far faster
  # than the whole workspace (which includes test-only crates).
  CARGO_TARGET_DIR="$dir" cargo build --release --locked -p sov-node -p sov-rpc >/dev/null
}

TMP1="$(mktemp -d)"
TMP2="$(mktemp -d)"
trap 'rm -rf "$TMP1" "$TMP2"' EXIT

echo "Reproducible-build check: building twice..."
build_into "$TMP1"
build_into "$TMP2"

# Pick a SHA-256 tool (coreutils on Linux/CI, BSD shasum on macOS).
sha() { if command -v sha256sum >/dev/null; then sha256sum "$1" | awk '{print $1}'; else shasum -a 256 "$1" | awk '{print $1}'; fi; }

status=0
for bin in "${BINS[@]}"; do
  a="$TMP1/release/$bin"
  b="$TMP2/release/$bin"
  if [[ ! -f "$a" || ! -f "$b" ]]; then
    echo "MISSING  $bin (expected at $a)"
    status=1
    continue
  fi
  h1="$(sha "$a")"
  h2="$(sha "$b")"
  if [[ "$h1" == "$h2" ]]; then
    echo "OK    $bin  $h1"
  else
    echo "DIFFER $bin  $h1 != $h2"
    status=1
  fi
done

if [[ $status -eq 0 ]]; then
  echo "All binaries reproduced bit-for-bit."
else
  echo "Reproducibility check FAILED." >&2
fi
exit $status
