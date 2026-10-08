# SOV — STATUS (master anchor)

_Last updated: **2026-10-08** for the Rust quantum hardening release preparation.
Network/fleet observations below remain dated 2026-08-06 and were not reverified
in this session._

_(Previous update was 2026-07-21 at v0.1.97. It sat stale through thirteen releases and described
an already-activated fork as pending — flagged as item E1 in `consensus-open-list.md` on
2026-07-27 and unfixed for ten days. If you are reading this at the end of a session and it is
more than one release behind, fix it now; that is the whole job of this file.)_

## Current Rust Station checkpoint — 2026-10-08

- Source is being prepared as **v0.2.15** at the owner's request for a `main`
  push and platform releases. See [release-v0.2.15.md](release-v0.2.15.md).
- Protocol-3 peer authentication binds the full hybrid transport transcript and
  account identity. Mainnet/rehearsal peer admission requires hybrid keys and a
  coordinated operator upgrade.
- Scheduled legacy retirement covers secondary authority paths. Station preserves
  imported legacy keys and provides explicit reviewed migration to hybrid keys.
  V1 recovery binds recipient, chain, genesis and nonce once retirement activates.
- New pool-v2 creation and broadcast are quarantined because the current unmasked
  proof trace does not establish privacy. Historical verification remains.
- Mainnet PQ retirement remains **unarmed**; existing genesis and deployment
  schedules are preserved. An isolated fresh rehearsal verifies retirement at 48,
  sunset at 64 and cold replay. No claim of full post-quantum security is made.
- All 170 active Station tests passed (one intentional ignore), with relevant
  runtime, proof, transport, RPC and replay checks plus Clippy. The complete
  release gate and platform workflow must pass before publication is complete.

## Previous Station UI checkpoint — 2026-10-01

- The existing local production window reports **v0.2.13**. Source baseline:
  `29e7a11`; UI branch: `codex/station-next-gen-ui`. The development package is
  **v0.2.14**, with a separate **v0.2.14-preview** application. No release was
  cut, published or installed over the existing app.
- Eight workspace destinations and six wallet tasks are preserved. Public XUS,
  v1-owned shielded XUS and live-v2-owned shielded XUS have separate readouts.
  Send, fee auction, replacement, offline signing, both pool workflows,
  receiving, identity, backups, assets, swaps, vaults, node/mining and blocks
  are indexed in [station-ui-feature-map.md](station-ui-feature-map.md).
- Transaction reviews pin wallet/account, selected network, RPC, route, amount
  and bid. Pending history can refresh through another node on the **same chain**;
  a fresh replacement review uses that node, while original RPC metadata remains
  recorded. Another network cannot settle or replace the old payment.
- Native preview uses disposable data, synthetic balances, active-v2 and active
  fee-auction fixtures. Real signing, proof generation, broadcasting, node
  launch and mining are disabled there. The running production wallet/node,
  real keys, stored chain and genesis were not changed.
- Validation: Station suite **160 passed, 0 failed, 1 ignored**; see the daily
  checkpoint for build/lint and native inspection evidence and limitations.
- **Release follow-up:** the owner subsequently requested a GitHub release and
  confirmed **main only, no release branch**. The tested UI commit is now on
  local `main`. The subsequent 2026-10-08 release request supersedes that target
  with **v0.2.15**. See [release-v0.2.14.md](release-v0.2.14.md) for the earlier
  preparation. No tag existed at that checkpoint.
- **Next action:** run the ordinary release/integration gates, publish from
  current `origin/main`, and verify the GitHub build/publish results.
  Do not treat preview balances or scans as live-chain evidence.

See [2026-10-01.md](2026-10-01.md) for this session. Fleet state and current live
node version need a separate fresh check before acting on the historical tracks.

## Previous network checkpoint — 2026-08-06

Mainnet LIVE (genesis `cb0272ff…e72d`, FROZEN). Release at that checkpoint **v0.2.10** (`eb51cd6`,
2026-08-02). Live tip **18715** as of 2026-08-06. Three activations are **Active on the live
chain** — tx-domain and fee-auction at h11520, the post-quantum shielded pool (bit 2) at h15552.
A fourth, `tx-timestamp` (bit 3), was armed in v0.2.6 and its signaling window has **closed** —
see the urgent track below, because the fleet was never upgraded to match.

## Live activation state (verified from the chain, 2026-08-06)

| bit | deployment | start | Active at | state |
|---|---|---|---|---|
| 0 | `tx-domain` | 10944 | **11520** | Active |
| 1 | `fee-auction` | 10944 | **11520** | Active |
| 2 | `shielded-v2` (PQ pool) | 14976 | **15552** | Active |
| 3 | `tx-timestamp` | 17280 | **18432** | **Active — and the cloud fleet does not know it. See A1** |

Source: `sov_getDeployments` + `sov_getSigningDomain` on the sfo3 relay, and
`mainnet_deployments()` at `chain/crates/rpc/src/daemon.rs:1221`.

**The v0.1.98/tx-domain Phase-2 signer blocker that older versions of this file described as open
is CLOSED.** The live relay answers `sov_getSigningDomain` with `active: true`.

## Sibling repositories (NOT in this tree)

Guarded by the `repository-boundaries` CI job — re-adding any of their paths fails CI:

- **XUS Miner** — https://github.com/cloudzombie/xus-miner (no SOV source dependency; compatibility
  via the documented RPC/Stratum contract).
- **SOV TX Cannon** — https://github.com/cloudzombie/sov-tx-cannon. Signs REAL transactions, so it
  uses `sov-rpc`/`sov-crypto`/`sov-types`/`sov-primitives` as git dependencies **pinned to a
  release TAG**. A chain change reaches it only when that pin is deliberately bumped there.
- **SOV Red Team** — https://github.com/cloudzombie/sov-redteam. Tracks `branch = "main"`, not a
  tag: it exists to catch a consensus regression the day it lands, and its CI runs the full
  gauntlet daily against this repo's `main`. **Deliberate and load-bearing** — the harness must NOT
  live in the same commit as the code it attacks, or an inconvenient VULNERABLE verdict could be
  edited away in the same change that caused it. `redteam-gui/` moved there in v0.2.8; this
  monorepo now carries **zero** red-team code.

## Golden rules (do not break)

- Genesis `cb0272ff88e64c18cde0257f7fae1c8236b02651f10cc7a02456fd682ee2e72d` NEVER changes.
- Consensus changes ship **dormant** behind a miner-signaled activation; turning them on is a
  **separate, coordinated, explicitly-approved** step — never a countdown wired in casually.
  **See A1: arming without a fleet-upgrade plan is how bit 3 got into its current state.**
- Every phase gate re-proves the `sov-verify` KAT byte-for-byte + genesis pins before shipping.
- This is mainnet post-quantum reserve cash. Conservative pace, honest disclosure, prove-don't-claim.
- **Releases follow the version contract** — ONE version source (`node/Cargo.toml`), tags only via
  `scripts/release-gate.sh --cut vX.Y.Z`, versions NEVER re-used, tags NEVER moved, releases only
  from the current head of `origin/main`, and every artifact proves its own version before it is
  published. See [release-version-contract.md](release-version-contract.md).

---

## NEXT RELEASE

**v0.2.11 is drafted** — see [release-v0.2.11.md](release-v0.2.11.md). Focus: node memory (so the
fleet can upgrade at all), P2P/relay/sync hardening, and Station private-balance chips. NO
consensus change, nothing armed, genesis frozen. Its release-blocking item is A1b below; its
highest-value item is a **second public relay** (A2).

## OPEN TRACKS (each with its exact NEXT ACTION)

### A1. ★ FLEET IS BEHIND THE CHAIN — a latent split behind bit 3 (URGENT)

**State (CONFIRMED from the chain + the code, 2026-08-06 — full working in
[2026-08-06.md](2026-08-06.md)):**

- **Both** droplets run the identical pre-0.2.6 binary (`sha256 2969de29…`), emit
  `version_bits = 7`, and their `sov_getDeployments` carries only three deployments. A v0.2.6+
  node cannot omit `tx-timestamp`.
- Bit-3 signaling, counted over every block in each window (9/10 of 288 needs **≥260**):
  `[17568,17856)` = 239 (fails), `[17856,18144)` = **260 — met by exactly one block**.
- Timeout is 18144, the same boundary. `next_state()` (`governance/src/lib.rs:459`) checks the
  **threshold before the timeout**, so it went LockedIn at 18144, then **Active at 18432**.

So `tx-timestamp` has been **Active for ~280 blocks** on every v0.2.6+ node, while both cloud
nodes do not know the deployment exists. They would reject an `Action::Timestamped` tx and
therefore **any block containing one** — a chain split with the fleet on the losing side. Untriggered
only because nobody has sent one.

**Exposure is LOWER than it first appears.** `Timestamped` is an **opt-in** outermost envelope
(like `Tipped`), not something applied to every tx — and **no client can construct one**: there is
no construction site in the Rust wallet, Station (`node/src`), or the TS SDK (which only *reads*
`timing` off receipts). Confirmed on-chain: both droplets agree at tip 18721 and recent blocks
carry 0 transactions. Triggering the split would take deliberately writing new client code. Real,
worth closing, **not urgent**.

**NEXT ACTION — BLOCKED on A1b below.** The v0.2.10 upgrade was attempted on 2026-08-06 and
**rolled back**: it cannot start on the 2 GB box. Do not retry until the startup OOM is fixed.

### A1b. ★ v0.2.10 cannot start on a 2 GB node (BLOCKS the fleet upgrade)

**State:** attempted on sfo3 2026-08-06 with the checksum-verified CI artifact
(`sha256 340e5858…`). OOM-killed ~21 s into startup **before emitting any log line**, restart loop
to counter 5, **public RPC down**, rolled back to `2969de29…` (now stable: 898 MB flat, 0
restarts, mining, serving). Failed binary kept at `/usr/local/bin/sov-rpcd.v0210.failed`.

**Not the RandomX dataset and not the v0.2.9 light-mode guard** — the guard correctly demoted to
light (1.65 GB available < the 2.6 GB `FAST_DATASET_MIN_AVAIL_BYTES`) and the process never
reached mining. The cost is in the **startup chain-replay path**, most plausibly v0.2.7's
`BlockImporter`/verifier rework. fra1 was deliberately not attempted: it would pick **fast** mode
(~3.5 GB available > 2.6 GB threshold) and allocate the 2 GB dataset on top of the higher
baseline, on a 4 GB box already at 3.4 GB RSS. Neither box has swap.

**This is not a fleet problem — no 2 GB node can run current SOV**, which is a fresh-node
accessibility regression.

**NEXT ACTION:** reproduce locally against a mainnet-sized store, measure peak startup RSS across
v0.2.5 → v0.2.10, and bound the startup replay allocation. Interim mitigations if an upgrade is
needed sooner: add a swapfile (free, reversible, absorbs a ~21 s spike) and/or set
`"mine": false` on sfo3 (~20 H/s of ~1100; its relay role is what matters).

### A1c. Pay the DigitalOcean bill

Raised by the owner 2026-08-06. Both droplets were running and SSH-reachable, so nothing is
suspended yet. sfo3 is the network's **only public RPC** *and* a miner, so a suspension is an
immediate outage — unlike A1, which is dormant. sgp1 is already gone. **This now outranks the
fleet upgrade.**

**Process fix owed:** bits 0/1/2 each got an `activation-*.md` runbook. Bit 3 was armed in v0.2.6
on 2026-07-30 and its whole signaling window opened and closed with no runbook, no fleet upgrade,
and no note. Arming should not be possible without a written activation plan.

### A2. Assumevalid anchor is stale again — the next release is already blocked

**State:** anchor **15872**, tip **18715** → lag **2843**, over the `CP_MAX_LAG` of 2000
(`scripts/release-gate.sh:190`). The gate will refuse `--cut`, exactly as it refused v0.2.10 on
2026-08-02. The guard is working; the *refresh* is what keeps rotting.

`scripts/refresh-checkpoint.sh` was repaired in `9eee9d9` (it used to abort silently on the
destroyed sgp1 relay under `set -euo pipefail`), but its **two-independent-relay confirmation
cannot complete automatically** — fra1 binds RPC to loopback, so only sfo3 answers publicly.

**NEXT ACTION:** refresh to ~18400 before attempting any release (`scripts/refresh-checkpoint.sh
--write`, completing the second confirmation by hand via fra1 over SSH). **Then stand up a second
publicly reachable relay** so this stops needing a human every time — that is the actual fix.

### A3. Consensus open list — see [consensus-open-list.md](consensus-open-list.md)

Compiled 2026-07-27 after v0.2.2 and **now partly out of date** (its A1/A2/E1 are closed; its
section C predates bit 2 actually going live). Still open and worth ranking by:

- **C5 / PQV2-07 — `MAX_BLOCK_WEIGHT` is not enforced on the block path.** It appears only in
  comments outside `types/weight.rs`; block production does not accumulate weight and import does
  not recompute it. Mempool admission is weight-aware, the block path is not. This is the only
  Medium that is a *missing enforcement* rather than a sizing or claims question.
- **C1/C2/C4 need re-adjudication now that bit 2 is Active** — they were written as
  *pre-arming* gates (anchor-ring eviction, tree exhaustion, replay-ordering). They are now
  live-chain properties, not gates. Re-read them against the shipped state.
- **D1** O(N) reorg/recommit · **D2** multisig rework (owner-flagged poor, back-burnered) ·
  **D3** xUSD oracle deviation bound · **D4** HTLC preimage pricing · **D5** RPC rate limiting.

### A4. Fresh-node sync — the structural fix shipped, the validation did not

**State:** v0.2.7 (`435c603`) moved verification off the P2P thread and moved the Station chain
store out of `$TMPDIR`. See [fresh-sync-p2p-starvation.md](fresh-sync-p2p-starvation.md).

**Still open, from that note's own honest-limits section:**
- Verification is still **single-threaded and sequential**; parallel/batched RandomX is the
  obvious next win and is not implemented.
- **No real fresh-node mainnet resync has ever been run.** All numbers are from a simulated-cost
  regression test.
- The Station `$TMPDIR` → `~/.sov-station` migration is unit-tested but has **never run against
  the owner's real ~63 MB store**.

**NEXT ACTION:** run one genuine fresh-node mainnet resync and record the wall-clock. It is the
only thing that converts this track from "believed fixed" to "proven fixed".

### A5. Pool mining — stratum + `sov_getBlockTemplate`

**State (corrected 2026-08-08 — the previous entry here was wrong):** Phases 1–2 built in v0.1.92
(`sov_getBlockTemplate`/`sov_submitBlock` + TemplateCache; `tools/sov-stratum` bridge, 2,483 LOC,
53 tests). **Phase 3 IS BUILT** — `tools/sov-sharechain`, 1,824 LOC, 36 tests, in CI: share DAG,
heaviest-work fork choice, uncle credit, bounded PPLNS window, exact payouts, the
block-must-pay-the-window rule, LWMA share retarget, gossip wire format + socket loop.
**Phase 4 (multi-output coinbase) CAN BE STRUCK** — the sharechain pays the window with ordinary
transfers that spend the same block's coinbase (`apply_coinbase` runs before `apply_transactions`),
so **no hard fork is needed for a non-custodial pool**.

**THE BLOCKER:** `sov-stratum` and `sov-sharechain` are **not wired together** (neither depends on
the other), so the bridge still pays the whole coinbase to one `--coinbase` account — i.e.
custodial, the exact thing the sharechain abolishes. Also open: `sov_submitHeader` (B3, additive,
would cut pool bandwidth), no TLS on the stratum port, no miner auth/ban scoring.

**NEXT ACTION:** the workstream, with the hosting question answered (the pool is P2Pool-style —
there is no central server, and it must NOT go on the explorer or sfo3 droplets):
[pool-public-launch.md](pool-public-launch.md).

### A6. xUSD stablecoin

**State:** consensus layer landed (additive, genesis-frozen); oracle acct `96abb938…`.
**NEXT ACTION:** RPC + Mint/Burn GUI page + liquidations + deploy the oracle feed.

### A7. Standing roadmap (not active)

Light client/SPV, efficient sync, end-to-end atomic swap (ZEC sighash unproven), external audit
(including the pending QROM analysis accepted as an arming prerequisite in
[audit-scope-pq-pool.md](audit-scope-pq-pool.md) §9).

---

## Recently shipped

- **v0.2.10** (2026-08-02, `eb51cd6`) — Station: shield affordability checked before ~25 s of STARK
  proving, no double-fire on a second click, reversible recipient overwrite.
- **v0.2.9** (2026-08-02, `a3351b4`) — RandomX **light mode** on low-RAM hosts (the droplet OOM;
  the old `Err` fallback was unreachable on Linux because the OOM killer fires first), per-wallet
  shielded pool views, and honest pool-v2 confirmations (a pending tx no longer reads as "failed",
  which had been prompting double-spent nonces).
- **v0.2.8** (2026-07-31, `734e330`) — the P2P self-fork pair: **#39** sync-strike deadlock (fork
  recovery) + **#40** peerless solo-mining (fork creation). Plus fail-closed RNG health self-test
  and the red-team extraction. Closes the sgp1 fork-poisoning incident.
- **anchor 15872** (2026-08-02, `9eee9d9`) — plus the repair of a refresh script that had been
  failing **silently** since sgp1 was destroyed.
- **v0.2.7** (2026-07-31) — fresh-node sync: durable chain store + verification off the P2P thread.
- **v0.2.6** (2026-07-30) — tx-timestamp receipts; **armed bit 3** (see A1).
- **v0.2.5** (2026-07-28) — armed shielded-v2 (bit 2), now Active at h15552.
- **v0.1.99** (2026-07-22) — armed bits 0/1, Active at h11520.

Full detail for the 07-31 → 08-02 run: [2026-08-02.md](2026-08-02.md). This session:
[2026-08-06.md](2026-08-06.md).
