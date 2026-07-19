# SOV v0.1.94 — Version consistency, tunable mining duty, and the Phase-2 signing foundation

> **All additive / node-local. No consensus rule changes, no activation.** Genesis
> `cb0272ff88e64c18cde0257f7fae1c8236b02651f10cc7a02456fd682ee2e72d` stays byte-identical and the
> `sov-verify` KAT reproduces byte-for-byte. A mixed fleet of v0.1.93 and v0.1.94 nodes runs
> together with zero fork risk — every change takes effect per-node the instant it runs the binary.
> Reviewed by a max-rigor Fable audit: no critical or high findings.

## What's in it

### 1. Version broadcasting is now CONSISTENT and guarded
v0.1.93 shipped two mismatched version strings — SOV Station displayed `0.1.91` (the app version in
`node/Cargo.toml` was never bumped) and the node daemon advertised `sov/v0.1.89` in its P2P handshake
(the rust-cache served an rpc build baked from a stale `git describe`). Both are now structurally
impossible to ship again:
- `node/Cargo.toml` → `0.1.94` (SOV Station shows `CARGO_PKG_VERSION`).
- The release workflow bakes `SOV_BUILD_VERSION = <tag>` so `build.rs` embeds the release tag into
  `SOV_VERSION` — the P2P agent string, `sov_version`, and `sov_getPeerInfo` — with no git-describe
  or cache drift.
- The release **gate fails** unless `tag == node/Cargo.toml` version; every build job `needs: gate`,
  so a mismatched tag (cut via `release-gate.sh` **or** a bare `git tag`) blocks the whole release.

Result: app, daemon, RPC, and handshake all broadcast the same tag version.

### 2. Tunable mining duty cycle — multi-core miners mine ~2× harder
The miner grinds a time slice then sleeps a comparable span — a flat ~50% duty on **one** core — so a
2-vCPU box under-used its hardware and left a core idle (the effective network hashrate read ~half of
what the hardware could do; the block explorer's `getnetworkhashps` was correct, the miners were just
throttled).
- New `NodeConfig.mining_duty_pct` (`10..=100`, or unset). **Unset = adaptive:** ~90% on a
  multi-core host (networking has the other cores), ~50% single-core (never starves peer
  connections). `duty=50` reproduces the old behavior exactly; `duty=100` pegs the mining core.
- The yield-sleep runs OFF the node lock (no priority inversion — the documented peer-drop fix),
  now `(100−duty)/duty` of the grind slice instead of a flat equal sleep.
- Applies to the headless daemon (droplets) and SOV Station on macOS/Windows, which auto-raise to
  ~90% on multi-core desktops.

Consensus-neutral: difficulty retargets to the resulting real hashrate; block cadence is unchanged.

### 3. `sov_getSigningDomain` — the Phase-2 tx-domain signing foundation (dormant)
A read-only RPC that reports the network signing domain a client should bind a new
transaction/intent signature to (`chainId` + genesis, or null). While the miner-signaled tx-domain
hard fork is dormant (its live state) it returns `active:false`/null, so clients sign the legacy
(un-bound) way — byte-identical. This is what the Phase-2 signers (SDK, wallet, Station, conformance,
tx-cannon) will read to switch to bound signing when the fork eventually activates.

## Cloud fleet
Rolling the v0.1.94 Linux node binary to the mainnet miners corrects the `sov/v0.1.89` broadcast to
`sov/v0.1.94` **and** applies the ~90% mining duty (raising the network hashrate on the 2-vCPU
droplets). Pure mining needs only the binary swap — see the ops runbook.

## Not in this release (by design)
The **tx-domain hard fork stays dormant** — no activation height is set. Its activation is the
committed target for **v0.1.95** (Phase-2 client signing → grace-window gate → a concrete activation
height on a generous horizon → whole-fleet upgrade → audit → activate), tracked in
`notes/activation-tx-domain.md`.
