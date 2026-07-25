#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# version-contract.sh — the RELEASE VERSION CONTRACT, in one enforceable place.
#
# SOV has ONE version source: `node/Cargo.toml`'s `version`. Everything a release
# claims must equal it — the tag, the daemon's reported version (`SOV_VERSION`, baked
# by the release workflow from the tag), and the number SOV Station displays
# (`CARGO_PKG_VERSION`). A release that says one thing and ships another is how a
# `v0.1.93` tag once shipped a binary advertising `sov/v0.1.89`.
#
# This script is the shared implementation of the three structural rules, so the
# developer path (`scripts/release-gate.sh --cut`) and the CI path
# (`.github/workflows/release.yml` → job `gate`) enforce the SAME logic and cannot
# drift apart:
#
#   RULE 1 — TAG MATCHES THE SOURCE. The tag is exactly `v<node/Cargo.toml version>`.
#   RULE 2 — VERSIONS ARE NEVER REUSED, TAGS NEVER MOVE. A version that has been
#            released is spent forever: if the tag exists locally, on the remote, or a
#            GitHub Release exists for it, the release is refused. Fix forward — bump
#            the patch version and cut a NEW tag. Never rewrite a published version.
#   RULE 3 — RELEASES COME FROM CURRENT `main`. The released commit must be exactly
#            the head of `origin/main`. An ancestor of main is refused too: it would
#            publish a release that OMITS commits main already has.
#
# Usage:
#   version-contract.sh precut          vX.Y.Z   # before a tag is created (dev path)
#   version-contract.sh verify-tag-push vX.Y.Z <sha>  # after a tag push (CI path)
#   version-contract.sh source-version                # print node/Cargo.toml's version
#
# Options (both check modes):
#   --remote NAME   git remote to consult            (default: origin)
#   --main NAME     the release branch               (default: main)
#   --require-gh    `gh` MUST be available and able to answer (CI uses this); without
#                   it, a missing `gh` is a loud note — the remote-tag check already
#                   makes a reused version impossible, since every published GitHub
#                   Release has its tag on the remote.
#
# Exit codes: 0 = contract holds, 1 = contract violated, 2 = bad usage.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

REMOTE="origin"
MAIN_BRANCH="main"
REQUIRE_GH=0

if [ -t 1 ]; then
  BOLD=$'\033[1m'; RED=$'\033[31m'; GRN=$'\033[32m'; YEL=$'\033[33m'; RST=$'\033[0m'
else
  BOLD=""; RED=""; GRN=""; YEL=""; RST=""
fi

fail() { echo "${RED}${BOLD}✗ VERSION CONTRACT:${RST} $*" >&2; exit 1; }
ok()   { echo "${GRN}✓${RST} $*"; }
note() { echo "${YEL}⁃${RST} $*"; }
usage() {
  sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'
  exit 2
}

# ── the single version source ────────────────────────────────────────────────
# `node/Cargo.toml` — SOV Station's manifest. Its `version` is what the app shows
# (CARGO_PKG_VERSION); the tag and the baked daemon version are derived from it.
readonly VERSION_SOURCE="node/Cargo.toml"

repo_root() {
  git rev-parse --show-toplevel 2>/dev/null || fail "not inside a git repository"
}

source_version() {
  local root file
  root="$(repo_root)"
  file="$root/$VERSION_SOURCE"
  [ -f "$file" ] || fail "version source $VERSION_SOURCE not found at $file"
  local ver
  ver="$(grep -m1 '^version' "$file" | cut -d'"' -f2)"
  [ -n "$ver" ] || fail "could not read a version from $VERSION_SOURCE"
  printf '%s\n' "$ver"
}

# ── RULE 1 — tag shape + tag == the single version source ────────────────────
check_tag_matches_source() {
  local tag="$1" ver
  case "$tag" in
    v[0-9]*.[0-9]*.[0-9]*) : ;;
    *) fail "tag '$tag' is not of the form vX.Y.Z" ;;
  esac
  ver="$(source_version)"
  if [ "$tag" != "v$ver" ]; then
    fail "tag '$tag' != $VERSION_SOURCE version '$ver'.
      $VERSION_SOURCE is the SINGLE version source — SOV Station displays it and the
      daemon bakes the tag as SOV_VERSION, so a mismatch ships a binary that lies.
      FIX: set $VERSION_SOURCE version = '${tag#v}', refresh node/Cargo.lock, commit
      to $MAIN_BRANCH, then cut the tag."
  fi
  ok "tag $tag == $VERSION_SOURCE version $ver (the single version source)"
}

# ── RULE 2 helpers — has this version already been released? ─────────────────
# A GitHub Release for the tag. `gh release view` exits 0 when it exists; a genuine
# "not found" is the only non-zero we accept — anything else (auth failure, API
# outage) FAILS CLOSED rather than being read as "no release".
github_release_exists() {
  local tag="$1" out rc
  if ! command -v gh >/dev/null 2>&1; then
    if [ "$REQUIRE_GH" = "1" ]; then
      fail "gh CLI is required here (--require-gh) but is not installed"
    fi
    note "gh CLI not installed — skipping the GitHub-Release check.
      (The remote-tag check below still makes a reused version impossible: every
       published release has its tag on the remote.)"
    return 1
  fi
  set +e
  out="$(gh release view "$tag" 2>&1)"; rc=$?
  set -e
  if [ "$rc" = "0" ]; then
    return 0
  fi
  case "$out" in
    *"release not found"*|*"Release not found"*|*"not found"*|*"HTTP 404"*) return 1 ;;
    *)
      if [ "$REQUIRE_GH" = "1" ]; then
        fail "could not determine whether a GitHub Release exists for $tag — failing
      closed rather than assuming it does not. gh said:
      $out"
      fi
      note "gh could not answer for $tag (not authenticated?); relying on the
      remote-tag check. gh said: $out"
      return 1 ;;
  esac
}

# Resolve a tag on the remote to the COMMIT it points at (peeling annotated tags).
# Prints nothing when the remote has no such tag.
remote_tag_commit() {
  local tag="$1" lines peeled plain
  lines="$(git ls-remote --tags "$REMOTE" "refs/tags/$tag" "refs/tags/$tag^{}" 2>/dev/null || true)"
  peeled="$(printf '%s\n' "$lines" | awk -v t="refs/tags/$tag^{}" '$2==t {print $1}' | head -1)"
  plain="$(printf '%s\n' "$lines" | awk -v t="refs/tags/$tag" '$2==t {print $1}' | head -1)"
  # An annotated tag's `^{}` line is the commit; a lightweight tag has only the plain
  # line, which already IS the commit.
  if [ -n "$peeled" ]; then printf '%s\n' "$peeled"; elif [ -n "$plain" ]; then printf '%s\n' "$plain"; fi
}

remote_main_head() {
  local sha
  sha="$(git ls-remote "$REMOTE" "refs/heads/$MAIN_BRANCH" 2>/dev/null | awk '{print $1}' | head -1)"
  [ -n "$sha" ] || fail "could not read $REMOTE/$MAIN_BRANCH — is the remote reachable?"
  printf '%s\n' "$sha"
}

reuse_advice() {
  local tag="$1"
  printf '%s' "A released version is SPENT — it is never re-cut, re-pointed, or deleted:
      downstream operators, the SHA256SUMS/cosign provenance, and every node that
      already reports '$tag' pin it to specific bytes.
      FIX FORWARD: bump the patch version in $VERSION_SOURCE (e.g. ${tag} → next patch),
      refresh node/Cargo.lock, commit to $MAIN_BRANCH, then cut that NEW tag with
      scripts/release-gate.sh --cut vX.Y.Z. Do NOT delete or move '$tag'."
}

# ── RULE 2 (dev path) — the tag must not exist anywhere yet ──────────────────
check_tag_unused() {
  local tag="$1" remote_sha
  if git rev-parse -q --verify "refs/tags/$tag" >/dev/null 2>&1; then
    fail "tag '$tag' already exists LOCALLY (points at $(git rev-parse --short "refs/tags/$tag")).
      $(reuse_advice "$tag")"
  fi
  remote_sha="$(remote_tag_commit "$tag")"
  if [ -n "$remote_sha" ]; then
    fail "tag '$tag' already exists on $REMOTE (points at ${remote_sha:0:12}).
      $(reuse_advice "$tag")"
  fi
  if github_release_exists "$tag"; then
    fail "a GitHub Release already exists for '$tag' — that version is published.
      $(reuse_advice "$tag")"
  fi
  ok "version $tag has never been released (no local tag, no remote tag, no release)"
}

# ── RULE 2 (CI path) — the pushed tag must be new AND must not have moved ────
check_tag_push_is_first_publication() {
  local tag="$1" sha="$2" remote_sha
  if github_release_exists "$tag"; then
    fail "a GitHub Release already exists for '$tag' — this build would re-publish a
      version that is already out in the world.
      $(reuse_advice "$tag")"
  fi
  remote_sha="$(remote_tag_commit "$tag")"
  [ -n "$remote_sha" ] || fail "tag '$tag' is not on $REMOTE — refusing to build a
      release for a tag the remote does not have."
  if [ "$remote_sha" != "$sha" ]; then
    fail "tag '$tag' on $REMOTE points at ${remote_sha:0:12}, but this build is for
      ${sha:0:12} — the tag MOVED. $(reuse_advice "$tag")"
  fi
  ok "'$tag' is a first publication and still points at ${sha:0:12} on $REMOTE"
}

# ── RULE 3 — the released commit is the CURRENT head of origin/main ─────────
# Head-equality, not ancestry: `git merge-base --is-ancestor` would accept a commit
# main has already moved past, i.e. a release that silently OMITS commits that are on
# main. Exact head equality is the only check that makes "this release == what main
# says today" true.
check_is_main_head() {
  local sha="$1" head
  head="$(remote_main_head)"
  if [ "$sha" != "$head" ]; then
    local relation
    if git cat-file -e "${sha}^{commit}" 2>/dev/null && git cat-file -e "${head}^{commit}" 2>/dev/null; then
      if git merge-base --is-ancestor "$sha" "$head" 2>/dev/null; then
        relation="an ANCESTOR of $MAIN_BRANCH — main has moved on, so this release would OMIT commits main already has"
      else
        relation="not on $MAIN_BRANCH at all (a feature branch or a detached commit)"
      fi
    else
      relation="of undetermined relation to $MAIN_BRANCH (this checkout does not have both commits)"
    fi
    fail "release commit ${sha:0:12} is not the head of $REMOTE/$MAIN_BRANCH (${head:0:12}).
      It is $relation.
      Releases are cut ONLY from the current head of $MAIN_BRANCH, so the published
      artifacts equal what $MAIN_BRANCH says.
      FIX: merge/push your work to $MAIN_BRANCH, check it out, pull, then re-cut."
  fi
  ok "release commit ${sha:0:12} is the current head of $REMOTE/$MAIN_BRANCH"
}

# Dev-path variant: also insist we are actually ON the release branch, so `--cut`
# cannot push a feature branch's HEAD under a release tag.
check_local_branch_is_main() {
  local branch
  branch="$(git rev-parse --abbrev-ref HEAD)"
  [ "$branch" = "$MAIN_BRANCH" ] || fail "current branch is '$branch', not '$MAIN_BRANCH'.
      Releases are cut from $MAIN_BRANCH only. FIX: merge the work to $MAIN_BRANCH,
      \`git checkout $MAIN_BRANCH && git pull\`, then re-cut."
  ok "on branch $MAIN_BRANCH"
}

# ── entry point ──────────────────────────────────────────────────────────────
[ $# -ge 1 ] || usage
MODE="$1"; shift

POSITIONAL=()
while [ $# -gt 0 ]; do
  case "$1" in
    --remote) REMOTE="${2:-}"; shift ;;
    --main)   MAIN_BRANCH="${2:-}"; shift ;;
    --require-gh) REQUIRE_GH=1 ;;
    -*) echo "unknown option: $1" >&2; usage ;;
    *) POSITIONAL+=("$1") ;;
  esac
  shift
done

case "$MODE" in
  source-version)
    source_version
    ;;
  precut)
    [ "${#POSITIONAL[@]}" -eq 1 ] || usage
    TAG="${POSITIONAL[0]}"
    echo "${BOLD}Release version contract — pre-cut checks for $TAG${RST}"
    check_tag_matches_source "$TAG"
    check_local_branch_is_main
    check_is_main_head "$(git rev-parse HEAD)"
    check_tag_unused "$TAG"
    ok "${BOLD}version contract holds — $TAG is a legal, new release from current $MAIN_BRANCH${RST}"
    ;;
  verify-tag-push)
    [ "${#POSITIONAL[@]}" -eq 2 ] || usage
    TAG="${POSITIONAL[0]}"; SHA="${POSITIONAL[1]}"
    echo "${BOLD}Release version contract — tag-push checks for $TAG @ ${SHA:0:12}${RST}"
    check_tag_matches_source "$TAG"
    check_tag_push_is_first_publication "$TAG" "$SHA"
    check_is_main_head "$SHA"
    ok "${BOLD}version contract holds — building $TAG from current $MAIN_BRANCH${RST}"
    ;;
  -h|--help|help) usage ;;
  *) echo "unknown mode: $MODE" >&2; usage ;;
esac
