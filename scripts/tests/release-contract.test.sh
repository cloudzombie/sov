#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# release-contract.test.sh — prove the release version contract guards FIRE.
#
# A guard that has never been observed to fail is not a guard. This suite drives
# `scripts/version-contract.sh` and `scripts/verify-artifact-version.sh` through every
# failure path they exist to catch, using throwaway git repositories (with a real
# `file://` remote, so the remote-tag / remote-main checks run for real), a stubbed
# `gh`, and synthetic binaries. No network, no cargo, no mainnet — runs in ~seconds on
# a laptop and in CI (`.github/workflows/ci.yml` → job `release-contract`).
#
#   ./scripts/tests/release-contract.test.sh
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CONTRACT="$ROOT/scripts/version-contract.sh"
ARTIFACT="$ROOT/scripts/verify-artifact-version.sh"

PASS=0
FAILED=0
CASE=""

if [ -t 1 ]; then
  BOLD=$'\033[1m'; RED=$'\033[31m'; GRN=$'\033[32m'; DIM=$'\033[2m'; RST=$'\033[0m'
else
  BOLD=""; RED=""; GRN=""; DIM=""; RST=""
fi

# Run a command, capturing combined output; assert the exit code and (optionally) that
# the output contains a substring. Every negative case asserts on the MESSAGE too, so a
# guard cannot pass the test by failing for an unrelated reason.
expect() {
  local want_rc="$1" want_text="$2"; shift 2
  local out rc
  out="$("$@" 2>&1)"; rc=$?
  if [ "$rc" != "$want_rc" ]; then
    echo "${RED}✗ $CASE${RST}: expected exit $want_rc, got $rc"
    printf '%s\n' "$out" | sed 's/^/      /'
    FAILED=$((FAILED+1)); return
  fi
  if [ -n "$want_text" ] && ! printf '%s' "$out" | grep -qF -- "$want_text"; then
    echo "${RED}✗ $CASE${RST}: output did not contain '$want_text'"
    printf '%s\n' "$out" | sed 's/^/      /'
    FAILED=$((FAILED+1)); return
  fi
  echo "${GRN}✓${RST} $CASE"
  [ "$want_rc" = "0" ] || echo "${DIM}    guard fired: $(printf '%s' "$out" | grep -m1 -F -- "$want_text" | sed 's/^ *//')${RST}"
  PASS=$((PASS+1))
}

# ── fixtures ────────────────────────────────────────────────────────────────
# A throwaway repo with a real file:// remote and a `node/Cargo.toml` version source.
make_repo() {
  local base version="$1"
  base="$(mktemp -d)"
  git init -q --bare "$base/remote.git"
  git init -q -b main "$base/work"
  mkdir -p "$base/work/node"
  printf '[package]\nname = "sov-station"\nversion = "%s"\nedition = "2021"\n' "$version" \
    > "$base/work/node/Cargo.toml"
  (
    cd "$base/work" || exit 1
    git config user.email t@t.test; git config user.name test
    git config commit.gpgsign false
    git add -A && git commit -qm "initial"
    git remote add origin "file://$base/remote.git"
    git push -q origin main
  )
  printf '%s\n' "$base"
}

# A stubbed `gh`: `found` = a release exists, `notfound` = it does not, `error` = the
# API/auth broke (the fail-closed case).
stub_gh() {
  local dir="$1" mode="$2"
  mkdir -p "$dir"
  cat > "$dir/gh" <<EOF
#!/usr/bin/env bash
case "$mode" in
  found)    echo "release v-stub"; exit 0 ;;
  notfound) echo "release not found" >&2; exit 1 ;;
  error)    echo "gh: could not authenticate to github.com" >&2; exit 4 ;;
esac
EOF
  chmod +x "$dir/gh"
  printf '%s\n' "$dir"
}

# PATH with every directory that provides `gh` removed — genuine absence, not a stub.
path_without_gh() {
  local out="" d
  local IFS=:
  for d in $PATH; do
    [ -n "$d" ] || continue
    [ -x "$d/gh" ] && continue
    out="${out:+$out:}$d"
  done
  printf '%s\n' "$out"
}

# A synthetic "binary": the version literals a real build would bake, embedded in
# binary-ish noise, so the string extraction is exercised the way it is on a real ELF
# (long NUL-separated blobs, adjacent literals glued together).
make_fake_binary() {
  local path="$1"; shift
  {
    printf '\177ELF\002\001\001\000'
    printf 'some.symbol\000'
    for s in "$@"; do printf '%s' "$s"; printf 'blocks.log\000mempool.dat\000'; done
    printf '\000\000rustc 1.97.0\000'
  } > "$path"
}

echo "${BOLD}release version contract — guard tests${RST}"

# ══ RULE 1 — the tag must equal the single version source ═══════════════════
BASE="$(make_repo 0.1.99)"; GH="$(stub_gh "$BASE/bin" notfound)"
CASE="precut: tag that matches node/Cargo.toml + current main is accepted"
expect 0 "version contract holds" env PATH="$GH:$PATH" bash -c "cd '$BASE/work' && '$CONTRACT' precut v0.1.99"

CASE="RULE 1: tag != node/Cargo.toml version is refused"
expect 1 "!= node/Cargo.toml version '0.1.99'" \
  env PATH="$GH:$PATH" bash -c "cd '$BASE/work' && '$CONTRACT' precut v0.2.0"

CASE="RULE 1: a malformed tag is refused"
expect 1 "is not of the form vX.Y.Z" \
  env PATH="$GH:$PATH" bash -c "cd '$BASE/work' && '$CONTRACT' precut release-1"

# ══ RULE 2 — a released version is spent: no reuse, no moving ═══════════════
CASE="RULE 2: refuses a tag that already exists LOCALLY"
( cd "$BASE/work" && git tag -a v0.1.99 -m x ) >/dev/null 2>&1
expect 1 "already exists LOCALLY" \
  env PATH="$GH:$PATH" bash -c "cd '$BASE/work' && '$CONTRACT' precut v0.1.99"

CASE="RULE 2: the refusal tells the operator to bump the patch, not rewrite"
expect 1 "FIX FORWARD: bump the patch version" \
  env PATH="$GH:$PATH" bash -c "cd '$BASE/work' && '$CONTRACT' precut v0.1.99"

CASE="RULE 2: refuses a tag that exists only on the REMOTE"
( cd "$BASE/work" && git push -q origin v0.1.99 && git tag -d v0.1.99 ) >/dev/null 2>&1
expect 1 "already exists on origin" \
  env PATH="$GH:$PATH" bash -c "cd '$BASE/work' && '$CONTRACT' precut v0.1.99"

CASE="RULE 2: refuses when a GitHub Release already exists for the version"
BASE2="$(make_repo 0.1.99)"; GH_FOUND="$(stub_gh "$BASE2/bin" found)"
expect 1 "a GitHub Release already exists" \
  env PATH="$GH_FOUND:$PATH" bash -c "cd '$BASE2/work' && '$CONTRACT' precut v0.1.99"

CASE="RULE 2: with gh absent the remote-tag check still refuses reuse (loud note)"
NOGH="$(path_without_gh)"
( cd "$BASE2/work" && git tag -a v0.1.99 -m x && git push -q origin v0.1.99 && git tag -d v0.1.99 ) >/dev/null 2>&1
expect 1 "already exists on origin" \
  env PATH="$NOGH" bash -c "cd '$BASE2/work' && '$CONTRACT' precut v0.1.99"

CASE="RULE 2 (CI): refuses to build a tag that already has a GitHub Release"
BASE3="$(make_repo 0.1.99)"; GH_FOUND3="$(stub_gh "$BASE3/bin" found)"
SHA3="$( cd "$BASE3/work" && git rev-parse HEAD )"
( cd "$BASE3/work" && git tag -a v0.1.99 -m x && git push -q origin v0.1.99 ) >/dev/null 2>&1
expect 1 "would re-publish a" \
  env PATH="$GH_FOUND3:$PATH" bash -c "cd '$BASE3/work' && '$CONTRACT' verify-tag-push v0.1.99 $SHA3"

CASE="RULE 2 (CI): accepts a first publication of a tag at main's head"
GH_NF3="$(stub_gh "$BASE3/bin-nf" notfound)"
expect 0 "version contract holds" \
  env PATH="$GH_NF3:$PATH" bash -c "cd '$BASE3/work' && '$CONTRACT' verify-tag-push v0.1.99 $SHA3"

CASE="RULE 2 (CI): refuses when the tag on the remote MOVED to another commit"
( cd "$BASE3/work" && git commit -q --allow-empty -m second && git push -q origin main \
  && git tag -f -a v0.1.99 -m moved >/dev/null && git push -q -f origin v0.1.99 ) >/dev/null 2>&1
expect 1 "the tag MOVED" \
  env PATH="$GH_NF3:$PATH" bash -c "cd '$BASE3/work' && '$CONTRACT' verify-tag-push v0.1.99 $SHA3"

CASE="RULE 2 (CI): refuses a tag the remote does not have at all"
BASE4="$(make_repo 0.1.99)"; GH_NF4="$(stub_gh "$BASE4/bin" notfound)"
SHA4="$( cd "$BASE4/work" && git rev-parse HEAD )"
expect 1 "is not on origin" \
  env PATH="$GH_NF4:$PATH" bash -c "cd '$BASE4/work' && '$CONTRACT' verify-tag-push v0.1.99 $SHA4"

CASE="RULE 2 (CI): --require-gh fails CLOSED when gh cannot answer"
GH_ERR4="$(stub_gh "$BASE4/bin-err" error)"
expect 1 "failing" \
  env PATH="$GH_ERR4:$PATH" bash -c "cd '$BASE4/work' && '$CONTRACT' verify-tag-push v0.1.99 $SHA4 --require-gh"

CASE="RULE 2 (CI): --require-gh fails when gh is not installed at all"
expect 1 "gh CLI is required" \
  env PATH="$NOGH" bash -c "cd '$BASE4/work' && '$CONTRACT' verify-tag-push v0.1.99 $SHA4 --require-gh"

# ══ RULE 3 — releases come only from the CURRENT head of origin/main ════════
CASE="RULE 3: refuses a cut from a feature branch"
BASE5="$(make_repo 0.1.99)"; GH5="$(stub_gh "$BASE5/bin" notfound)"
( cd "$BASE5/work" && git checkout -q -b feature/x && git commit -q --allow-empty -m wip ) >/dev/null 2>&1
expect 1 "current branch is 'feature/x'" \
  env PATH="$GH5:$PATH" bash -c "cd '$BASE5/work' && '$CONTRACT' precut v0.1.99"

CASE="RULE 3: refuses a cut from a local main that is BEHIND origin/main"
BASE6="$(make_repo 0.1.99)"; GH6="$(stub_gh "$BASE6/bin" notfound)"
(
  cd "$BASE6/work" || exit 1
  git commit -q --allow-empty -m "someone else's commit" && git push -q origin main
  git reset -q --hard HEAD~1          # local main is now stale
) >/dev/null 2>&1
expect 1 "is not the head of origin/main" \
  env PATH="$GH6:$PATH" bash -c "cd '$BASE6/work' && '$CONTRACT' precut v0.1.99"

CASE="RULE 3: a stale local main is named an ANCESTOR (release would omit commits)"
expect 1 "ANCESTOR of main" \
  env PATH="$GH6:$PATH" bash -c "cd '$BASE6/work' && '$CONTRACT' precut v0.1.99"

CASE="RULE 3: refuses a cut from a local main with UNPUSHED commits"
BASE7="$(make_repo 0.1.99)"; GH7="$(stub_gh "$BASE7/bin" notfound)"
( cd "$BASE7/work" && git commit -q --allow-empty -m unpushed ) >/dev/null 2>&1
expect 1 "is not the head of origin/main" \
  env PATH="$GH7:$PATH" bash -c "cd '$BASE7/work' && '$CONTRACT' precut v0.1.99"

CASE="RULE 3 (CI): refuses building a tag on an ANCESTOR of origin/main"
BASE8="$(make_repo 0.1.99)"; GH8="$(stub_gh "$BASE8/bin" notfound)"
OLD8="$( cd "$BASE8/work" && git rev-parse HEAD )"
(
  cd "$BASE8/work" || exit 1
  git tag -a v0.1.99 -m x "$OLD8" && git push -q origin v0.1.99
  git commit -q --allow-empty -m "main moved on" && git push -q origin main
) >/dev/null 2>&1
expect 1 "ANCESTOR of main" \
  env PATH="$GH8:$PATH" bash -c "cd '$BASE8/work' && '$CONTRACT' verify-tag-push v0.1.99 $OLD8"

# ══ ARTIFACT SELF-REPORT ════════════════════════════════════════════════════
FIX="$(mktemp -d)"
CASE="artifact: a correctly-baked binary passes the embedded check"
make_fake_binary "$FIX/good" "sov/v0.1.99" "v0.1.99"
expect 0 "tag literal v0.1.99 present" "$ARTIFACT" embedded "$FIX/good" v0.1.99

CASE="artifact: a git-describe fallback (the v0.1.93→sov/v0.1.89 bug) is refused"
make_fake_binary "$FIX/describe" "sov/v0.1.97" "v0.1.97-16-g7dce59b"
expect 1 "contains git-describe version string" "$ARTIFACT" embedded "$FIX/describe" v0.1.99

CASE="artifact: a '-dirty' build is refused"
make_fake_binary "$FIX/dirty" "v0.1.99-dirty"
expect 1 "contains git-describe version string" "$ARTIFACT" embedded "$FIX/dirty" v0.1.99

CASE="artifact: a wrong P2P agent string is refused"
make_fake_binary "$FIX/agent" "sov/v0.1.89" "v0.1.99"
expect 1 "carries P2P agent string(s) that are not" "$ARTIFACT" embedded "$FIX/agent" v0.1.99

CASE="artifact: a binary missing the tag literal is refused"
make_fake_binary "$FIX/missing" "some.other.string"
expect 1 "does not contain the tag literal" "$ARTIFACT" embedded "$FIX/missing" v0.1.99

CASE="artifact: no-describe accepts a tag-built helper with no version surface"
make_fake_binary "$FIX/helper" "some.other.string"
expect 0 "no git-describe fallback" "$ARTIFACT" no-describe "$FIX/helper" v0.1.99

CASE="artifact: no-describe refuses a helper built from a describe fallback"
expect 1 "contains git-describe version string" "$ARTIFACT" no-describe "$FIX/describe" v0.1.99

CASE="artifact: station --version matching the tag passes"
printf '#!/usr/bin/env bash\necho "sov-station 0.1.99"\n' > "$FIX/station-ok"; chmod +x "$FIX/station-ok"
expect 0 "matches tag v0.1.99" "$ARTIFACT" station "$FIX/station-ok" v0.1.99

CASE="artifact: station reporting a DIFFERENT version than the tag is refused"
printf '#!/usr/bin/env bash\necho "sov-station 0.1.89"\n' > "$FIX/station-bad"; chmod +x "$FIX/station-bad"
expect 1 "would DISPLAY the wrong version" "$ARTIFACT" station "$FIX/station-bad" v0.1.99

CASE="artifact: a station binary that cannot report its version is refused"
printf '#!/usr/bin/env bash\necho boom >&2; exit 3\n' > "$FIX/station-broken"; chmod +x "$FIX/station-broken"
expect 1 "could not run" "$ARTIFACT" station "$FIX/station-broken" v0.1.99

CASE="artifact: a missing binary is refused (never silently skipped)"
expect 1 "binary not found" "$ARTIFACT" station "$FIX/does-not-exist" v0.1.99

# The macOS bundle keys (`plist` mode) need Apple's plutil; on Linux the mode is not
# used — the macOS job is the only place a bundle exists — so the case is SKIPPED loudly
# rather than faked.
if command -v plutil >/dev/null; then
  write_plist() {
    cat > "$1" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleName</key><string>SOV Station</string>
  <key>CFBundleVersion</key><string>$2</string>
  <key>CFBundleShortVersionString</key><string>$3</string>
</dict></plist>
PLIST
  }
  CASE="artifact: a bundle whose version keys are the tag passes"
  write_plist "$FIX/good.plist" 0.1.99 0.1.99
  expect 0 "both version keys are 0.1.99" "$ARTIFACT" plist "$FIX/good.plist" v0.1.99

  CASE="artifact: the hardcoded CFBundleVersion 0.1.0 is refused"
  write_plist "$FIX/stale.plist" 0.1.0 0.1.99
  expect 1 "CFBundleVersion is '0.1.0'" "$ARTIFACT" plist "$FIX/stale.plist" v0.1.99

  CASE="artifact: a bundle short version with a leading 'v' is refused"
  write_plist "$FIX/vprefix.plist" 0.1.99 v0.1.99
  expect 1 "CFBundleShortVersionString is 'v0.1.99'" "$ARTIFACT" plist "$FIX/vprefix.plist" v0.1.99
else
  echo "  (skipped macOS bundle-plist cases: plutil unavailable on this host)"
fi

CASE="artifact: the daemon probe refuses a port that is already answering"
mkdir -p "$FIX/bin"; : > "$FIX/bin/sov-rpcd"; : > "$FIX/bin/sov-testnet"
chmod +x "$FIX/bin/sov-rpcd" "$FIX/bin/sov-testnet"
if command -v python3 >/dev/null; then
  python3 -m http.server 28777 --bind 127.0.0.1 >/dev/null 2>&1 &
  SRV=$!
  sleep 1
  expect 1 "already listening" \
    env SOV_VERIFY_RPC_PORT=28777 "$ARTIFACT" daemon "$FIX/bin" v0.1.99
  kill "$SRV" 2>/dev/null
  wait "$SRV" 2>/dev/null
else
  echo "  (skipped port-collision case: python3 unavailable)"
fi

CASE="artifact: the daemon probe refuses a missing sov-rpcd"
expect 1 "sov-rpcd not found" "$ARTIFACT" daemon "$FIX" v0.1.99

echo
if [ "$FAILED" = "0" ]; then
  echo "${GRN}${BOLD}✓ all $PASS release-contract guard tests passed${RST}"
  exit 0
fi
echo "${RED}${BOLD}✗ $FAILED of $((PASS+FAILED)) release-contract guard tests FAILED${RST}"
exit 1
