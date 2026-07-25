#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# verify-artifact-version.sh — make the BUILT ARTIFACT prove its version.
#
# `release.yml` bakes the tag into the binaries (`SOV_BUILD_VERSION` → `SOV_VERSION`,
# and `node/Cargo.toml` → `CARGO_PKG_VERSION`). Baking it is not proof: the rust-cache
# once served a stale build object and a `v0.1.93` release advertised `sov/v0.1.89`.
# This script is run on EVERY platform build job, against the exact binary that is
# about to be published, and requires the artifact's own version output to equal the
# tag. If it does not, the job fails and nothing is published.
#
# Modes:
#   station  <sov-station-binary> <vX.Y.Z>
#       EXECUTES the binary: `sov-station --version` must print exactly
#       `sov-station X.Y.Z` — the same CARGO_PKG_VERSION the app's status bar shows.
#
#   no-describe <binary> <vX.Y.Z>
#       For a published binary with no version surface of its own (`sov-testnet`): it
#       must at least carry NO git-describe version string, i.e. it was built from the
#       tag like everything else in the release.
#
#   embedded <binary> <vX.Y.Z>
#       Inspects the compiled-in version strings of any SOV binary:
#         · the tag literal `vX.Y.Z` must be present;
#         · NO git-describe-shaped version (`vX.Y.Z-<n>-g<hash>` / `…-dirty`) may be
#           present — that shape only exists if the build fell back to `git describe`
#           instead of the tag, which is exactly the v0.1.93/v0.1.89 failure;
#         · every P2P agent literal `sov/vX.Y.Z` must equal `sov/<tag>` — that string
#           is what peers see on the wire.
#
#   plist    <Info.plist> <vX.Y.Z>
#       macOS bundle keys: CFBundleShortVersionString and CFBundleVersion must both be
#       the release version (X.Y.Z) — that is what Finder and "About" show.
#
#   daemon   <bin-dir> <vX.Y.Z>
#       The strongest check for the headless node: BOOTS the freshly built `sov-rpcd`
#       (via the freshly built `sov-testnet` operator helper) on an isolated, otherwise
#       unused port, asks it `sov_version` over JSON-RPC, and requires the answer to
#       equal the tag exactly — the daemon reporting its own version, live, from the
#       bytes that are about to ship. The node is torn down afterwards.
#
# Exit codes: 0 = the artifact proves the tag, 1 = it does not, 2 = bad usage.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

if [ -t 1 ]; then
  BOLD=$'\033[1m'; RED=$'\033[31m'; GRN=$'\033[32m'; RST=$'\033[0m'
else
  BOLD=""; RED=""; GRN=""; RST=""
fi
fail() { echo "${RED}${BOLD}✗ ARTIFACT VERSION:${RST} $*" >&2; exit 1; }
ok()   { echo "${GRN}✓${RST} $*"; }
usage() { sed -n '2,44p' "$0" | sed 's/^# \{0,1\}//'; exit 2; }

# Ports for the `daemon` probe. Deliberately NOT the defaults (8645/9645): a developer
# or CI runner may already have a real node there, and querying someone else's node
# would "verify" the wrong binary. Overridable for parallel runs.
RPC_PORT="${SOV_VERIFY_RPC_PORT:-28645}"
P2P_PORT="${SOV_VERIFY_P2P_PORT:-29645}"
BOOT_TIMEOUT_SECS="${SOV_VERIFY_BOOT_TIMEOUT:-90}"

require_tag_shape() {
  case "$1" in
    v[0-9]*.[0-9]*.[0-9]*) : ;;
    *) fail "expected a tag of the form vX.Y.Z, got '$1'" ;;
  esac
}

# ── mode: station — execute the app and read its own version line ────────────
mode_station() {
  local bin="$1" tag="$2"
  require_tag_shape "$tag"
  [ -f "$bin" ] || fail "binary not found: $bin"
  local want="sov-station ${tag#v}" got rc
  set +e
  got="$("$bin" --version 2>&1)"; rc=$?
  set -e
  if [ "$rc" != "0" ]; then
    fail "could not run '$bin --version' (exit $rc). A published artifact that cannot
      report its own version is not publishable. Output:
      $got"
  fi
  got="$(printf '%s' "$got" | tr -d '\r')"
  if [ "$got" != "$want" ]; then
    fail "the built SOV Station reports '$got' but the release tag is '$tag'
      (expected exactly '$want'). The app would DISPLAY the wrong version.
      This means node/Cargo.toml's version and the tag disagree in the shipped
      binary — do not publish. Rebuild from a commit where they match."
  fi
  ok "sov-station --version → '$got' (matches tag $tag)"
}

# A `git describe` string (`vX.Y.Z-<n>-g<hash>`, optionally `-dirty`) can only appear in
# a SOV binary if the build ignored SOV_BUILD_VERSION and fell back to describing the
# checkout. That is precisely how a v0.1.93 release shipped `sov/v0.1.89`, so its mere
# presence disqualifies the artifact — no interpretation required.
check_no_describe() {
  local bin="$1" tag="$2" describe
  describe="$(LC_ALL=C grep -aoE 'v[0-9]+\.[0-9]+\.[0-9]+(-[0-9]+-g[0-9a-f]{7,})?-dirty|v[0-9]+\.[0-9]+\.[0-9]+-[0-9]+-g[0-9a-f]{7,}' "$bin" | sort -u || true)"
  if [ -n "$describe" ]; then
    fail "$(basename "$bin") contains git-describe version string(s):
$(printf '%s\n' "$describe" | sed 's/^/        /')
      The build did NOT use the tag (SOV_BUILD_VERSION) — it fell back to
      \`git describe\`, so the daemon would advertise that string instead of '$tag'.
      This is the exact v0.1.93-ships-sov/v0.1.89 failure. Do not publish."
  fi
}

# ── mode: no-describe — for published binaries with no version surface ───────
# `sov-testnet` (the operator helper) links the node library but reports no version of
# its own — the version constants are optimised out of it. It is still PUBLISHED, so it
# gets the check that does apply: no stale git-describe build may ship under a tag.
mode_no_describe() {
  local bin="$1" tag="$2"
  require_tag_shape "$tag"
  [ -f "$bin" ] || fail "binary not found: $bin"
  check_no_describe "$bin" "$tag"
  ok "$(basename "$bin"): no git-describe fallback (no version surface of its own)"
}

# ── mode: plist — the macOS bundle's own version keys ───────────────────────
# Finder, Gatekeeper and every "About" dialog read these, not the executable. Both keys
# must be the release version in Apple's numeric form (X.Y.Z — no leading `v`).
mode_plist() {
  local plist="$1" tag="$2"
  require_tag_shape "$tag"
  [ -f "$plist" ] || fail "Info.plist not found: $plist"
  command -v plutil >/dev/null 2>&1 || fail "plutil not available — cannot verify $plist"
  local want="${tag#v}" key got
  for key in CFBundleShortVersionString CFBundleVersion; do
    got="$(plutil -extract "$key" raw -o - "$plist" 2>/dev/null || true)"
    [ "$got" = "$want" ] || fail "$plist: $key is '$got', expected '$want' (tag $tag).
      macOS shows this number — the bundle must not claim a different version than the
      binary inside it."
  done
  ok "$(basename "$(dirname "$plist")")/Info.plist: both version keys are $want"
}

# ── mode: embedded — the compiled-in version strings ─────────────────────────
mode_embedded() {
  local bin="$1" tag="$2"
  require_tag_shape "$tag"
  [ -f "$bin" ] || fail "binary not found: $bin"

  # 1. No git-describe fallback may have leaked in.
  check_no_describe "$bin" "$tag"

  # 2. Every P2P agent literal must be the tag.
  local agents bad
  agents="$(LC_ALL=C grep -aoE 'sov/v[0-9]+\.[0-9]+\.[0-9]+' "$bin" | sort -u || true)"
  if [ -n "$agents" ]; then
    bad="$(printf '%s\n' "$agents" | grep -v -x -F "sov/$tag" || true)"
    [ -z "$bad" ] || fail "$(basename "$bin") carries P2P agent string(s) that are not
      'sov/$tag':
$(printf '%s\n' "$bad" | sed 's/^/        /')
      Peers would see the wrong version on the wire. Do not publish."
    ok "$(basename "$bin"): P2P agent literal is sov/$tag"
  fi

  # 3. The tag literal itself must be present.
  LC_ALL=C grep -aoE 'v[0-9]+\.[0-9]+\.[0-9]+' "$bin" | sort -u | grep -q -x -F "$tag" \
    || fail "$(basename "$bin") does not contain the tag literal '$tag' — the version
      baked into it is not the version being released. Do not publish."
  ok "$(basename "$bin"): tag literal $tag present, no git-describe fallback"
}

# ── mode: daemon — boot the real binary and ask it over RPC ─────────────────
rpc_version() {
  local port="$1" body
  body="$(curl -s -m 5 -X POST -H 'content-type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"sov_version","params":[]}' \
    "http://127.0.0.1:${port}/" 2>/dev/null)" || return 1
  printf '%s' "$body" | sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p'
}

# Tear the probe node down and remove its scratch directory. Set by `mode_daemon`
# before the node is started; a no-op if it never was.
PROBE_TESTNET=""
PROBE_WORK=""
probe_cleanup() {
  [ -n "$PROBE_TESTNET" ] && "$PROBE_TESTNET" down --out "$PROBE_WORK/net" >/dev/null 2>&1
  [ -n "$PROBE_WORK" ] && rm -rf "$PROBE_WORK"
  return 0
}

mode_daemon() {
  local dir="$1" tag="$2"
  require_tag_shape "$tag"
  local exe="" rpcd testnet
  case "$(uname -s 2>/dev/null || echo unknown)" in MINGW*|MSYS*|CYGWIN*) exe=".exe" ;; esac
  # Absolute paths: the probe cds into its scratch directory (sov-rpcd resolves a
  # relative data_dir against its CWD), so a relative bin-dir would stop resolving.
  [ -d "$dir" ] || fail "bin directory not found: $dir"
  dir="$(cd "$dir" && pwd)"
  rpcd="$dir/sov-rpcd$exe"; testnet="$dir/sov-testnet$exe"
  [ -x "$rpcd" ]    || fail "sov-rpcd not found/executable at $rpcd"
  [ -x "$testnet" ] || fail "sov-testnet (operator helper) not found/executable at $testnet"

  # The port MUST be free: if anything answers there we could end up interrogating a
  # DIFFERENT node and "proving" a version this artifact never had.
  set +e
  curl -s -m 2 "http://127.0.0.1:${RPC_PORT}/" >/dev/null 2>&1
  local probe_rc=$?
  set -e
  [ "$probe_rc" = "7" ] || fail "something is already listening on 127.0.0.1:${RPC_PORT}
      (curl exit $probe_rc, expected 7 = connection refused). Refusing to probe — the
      answer could come from another node. Set SOV_VERIFY_RPC_PORT to a free port."

  # The teardown runs from an EXIT trap, i.e. AFTER this function's locals are gone —
  # so the paths it needs are globals. (Getting this wrong once left a probe node
  # running and poisoned the next run's port.)
  PROBE_TESTNET="$testnet"
  PROBE_WORK="$(mktemp -d)"
  trap probe_cleanup EXIT
  local work="$PROBE_WORK"

  "$testnet" gen --miners 1 --policy test --pow sha256d \
      --base-rpc "$RPC_PORT" --base-p2p "$P2P_PORT" --out "$work/net" >/dev/null \
    || fail "could not generate the throwaway probe network"
  ( cd "$work" && "$testnet" up --out "$work/net" >/dev/null ) \
    || fail "could not start the freshly built sov-rpcd for the version probe"

  local waited=0 got=""
  while [ "$waited" -lt "$BOOT_TIMEOUT_SECS" ]; do
    got="$(rpc_version "$RPC_PORT" || true)"
    [ -n "$got" ] && break
    sleep 1; waited=$((waited+1))
  done
  [ -n "$got" ] || fail "the freshly built sov-rpcd did not answer sov_version within
      ${BOOT_TIMEOUT_SECS}s on 127.0.0.1:${RPC_PORT} — cannot prove its version.
      Node log:
$(sed 's/^/        /' "$work/net/node-1/node.log" 2>/dev/null | tail -20)"

  if [ "$got" != "$tag" ]; then
    fail "the freshly built sov-rpcd reports version '$got', but the release tag is
      '$tag'. That string is what every peer sees (\`sov/$got\`) and what
      \`sov_version\`/\`sov_getPeerInfo\` return. Do not publish."
  fi
  ok "sov-rpcd answered sov_version → '$got' live over RPC (matches tag $tag)"
}

[ $# -ge 1 ] || usage
case "$1" in
  station)  [ $# -eq 3 ] || usage; mode_station  "$2" "$3" ;;
  no-describe) [ $# -eq 3 ] || usage; mode_no_describe "$2" "$3" ;;
  plist)    [ $# -eq 3 ] || usage; mode_plist    "$2" "$3" ;;
  embedded) [ $# -eq 3 ] || usage; mode_embedded "$2" "$3" ;;
  daemon)   [ $# -eq 3 ] || usage; mode_daemon   "$2" "$3" ;;
  -h|--help|help) usage ;;
  *) echo "unknown mode: $1" >&2; usage ;;
esac
