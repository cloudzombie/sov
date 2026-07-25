# The SOV release version contract (runbook)

_Added 2026-07-25. Read before cutting any release._

A mis-versioned release is a lie about what is running on a live post-quantum reserve
network. It has happened once: the `v0.1.93` tag shipped a binary that advertised
`sov/v0.1.89` (the rust-cache served a stale build object, and `git describe` filled in
the version). This document states the contract that makes it **structurally
impossible** — not a convention, not a checklist item, but four rules enforced by code
in two places that cannot drift apart.

## The rules

1. **ONE version source: `node/Cargo.toml`.** Its `version` is what SOV Station displays
   (`CARGO_PKG_VERSION`), and the tag is exactly `v<that version>`. The release workflow
   bakes the tag into the daemon as `SOV_VERSION` (`SOV_BUILD_VERSION` → the P2P agent
   string `sov/vX.Y.Z`, `sov_version`, `sov_getPeerInfo`). Everything the software says
   about itself traces back to that one line.
2. **Tags are created ONLY by the documented path**: `scripts/release-gate.sh --cut
   vX.Y.Z`. Never `git tag` by hand — but a hand tag does not slip through either: the
   release workflow's `gate` job re-checks every rule, and every build job `needs: gate`.
3. **Versions are NEVER reused, tags NEVER move.** A released version is spent forever.
   If something is wrong with `vX.Y.Z`, the fix is `vX.Y.Z+1` — never a re-cut, never a
   moved or deleted tag. Downstream operators, the `SHA256SUMS` + cosign provenance, and
   every node already reporting that string pin it to specific bytes.
4. **Releases come only from the CURRENT head of `origin/main`.** Not a feature branch,
   not a stale local `main`, not an older commit that main has moved past. The check is
   **head equality**, deliberately not ancestry: a tag on an ancestor of main would
   publish a release that OMITS commits main already has.

## Where each rule is enforced

| Rule | Developer path (`scripts/release-gate.sh --cut`) | CI path (`.github/workflows/release.yml` → `gate`) |
|---|---|---|
| 1 — tag == version source | `version-contract.sh precut` + the gate's own guard | "Version guard" step + `version-contract.sh verify-tag-push` |
| 2 — no reuse / no moving | `precut`: refuses a tag that exists locally, on the remote, or that already has a GitHub Release | `verify-tag-push`: refuses if a GitHub Release exists, if the remote tag is missing, or if it points anywhere but this commit |
| 3 — current `main` only | `precut`: must be ON `main`, and HEAD must equal `origin/main` | `verify-tag-push`: the tag's commit must equal `origin/main`'s head; the ref must be a **tag** (no `workflow_dispatch` off a branch) |
| 4 — the artifact proves it | — (binaries are built in CI) | `verify-artifact-version.sh` in **every** build job, before staging |

Both paths call the SAME script — `scripts/version-contract.sh` — so they cannot drift.
`--require-gh` (CI only) makes an unanswerable GitHub API **fail closed**: an
unreachable API is never read as "no release exists".

## The artifact must prove its version (not just claim it)

Baking the version in is not proof; that is exactly what failed in v0.1.93. Every
platform job runs `scripts/verify-artifact-version.sh` against the binary it is about to
publish, **before** staging, so a mis-versioned build is never even packaged:

- **Windows / macOS (`sov-station`)** — `station`: executes `sov-station --version` and
  requires exactly `sov-station X.Y.Z` (the same `CARGO_PKG_VERSION` the status bar
  shows). `embedded`: the in-process daemon's baked version must be the tag —
  the P2P agent literal must be `sov/vX.Y.Z` and **no** `git describe`-shaped string
  (`vX.Y.Z-<n>-g<hash>`, `-dirty`) may be present.
- **Linux (`sov-rpcd`)** — `embedded`, plus `daemon`: the freshly built daemon is
  **booted on an isolated port and asked `sov_version` over JSON-RPC**; the answer must
  equal the tag. That string is what peers see on the wire. (The probe refuses to run if
  anything is already listening on its port — otherwise it could interrogate a different
  node and "prove" a version this artifact never had.)
- **macOS bundle (`Info.plist`)** — `plist`: `CFBundleShortVersionString` and
  `CFBundleVersion` must both be the release version (Apple's numeric `X.Y.Z`). Finder
  and the About panel read these, not the executable.
- **Linux (`sov-testnet`)** — `no-describe`. The operator helper links the node library
  but has no version surface of its own (the constants are optimised out), so it gets the
  check that does apply: it must not be a stale git-describe build. **Stated plainly so
  nobody mistakes it for a full version assertion.**

## The guards are tested, not trusted

`scripts/tests/release-contract.test.sh` drives every refusal path — reused version,
tag already released, tag moved on the remote, cut from a feature branch, cut from a
stale/unpushed `main`, tag on an ancestor of main, gh unavailable/unanswerable, a binary
reporting the wrong version, a binary that cannot report one at all, a describe fallback,
a wrong agent string, a busy probe port. It uses throwaway git repos with real `file://`
remotes, a stubbed `gh`, and synthetic binaries: no network, no cargo, seconds to run.
It runs in CI on every push (`ci.yml` → `release-contract`) and again in the release
`gate` job. A guard nobody has watched fail is not a guard.

## Cutting a release (the whole procedure)

```bash
# 1. Bump the ONE version source and refresh the lock, on main.
#    node/Cargo.toml: version = "X.Y.Z"   (then: cargo check --manifest-path node/Cargo.toml)
git checkout main && git pull            # main must be current
git commit -am "release(vX.Y.Z): bump version"
git push origin main

# 2. Cut. This runs the full gate (genesis double-lock, fmt/clippy/tests, KAT,
#    reproducible build, supply chain) and the version contract, then tags + pushes.
scripts/release-gate.sh --cut vX.Y.Z

# 3. CI takes over: gate (contract re-checked against the real remote) → builds
#    (each artifact proves its version) → signed, attested publish.
```

If the gate refuses, **read the refusal** — each one names the exact fix. The one answer
that is never correct is deleting or moving a tag.

## Known holes (honest disclosure)

- `sov-testnet` ships without a version surface of its own; it is only checked for a
  describe fallback (above). Giving it a `--version` would need a change in
  `chain/crates/rpc`, which is out of scope for release tooling.
- `sov-rpcd` has no `--version` flag either — hence the live-RPC probe, which is
  stronger anyway (it is the daemon reporting itself), but it does cost a node boot in
  the Linux job. Same reason it is not a CLI flag: adding one touches a chain crate.
- FIXED here, recorded for history: the macOS `.app` used to hardcode
  `CFBundleVersion = 0.1.0` on every release, and set `CFBundleShortVersionString` to
  the tag WITH its `v` (not Apple's numeric form). Both keys now come from the tag and
  are asserted by `verify-artifact-version.sh plist`.
