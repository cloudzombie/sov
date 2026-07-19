# Runbook — FULL stratum + `getBlockTemplate` pool-mining activation

_Owner track for taking SOV from "solo mining only" to "production decentralized pool
mining." Source of truth for status: the v0.1.92 release doc
(`.github/RELEASE-0.1.92.md`) — this runbook is the operational overlay._

## Where we are (built vs pending)

| Phase | What | Status | Consensus surface |
|------|------|--------|-------------------|
| **1** | `sov_getBlockTemplate` + `sov_submitBlock` RPC + `TemplateCache` (node stays authoritative; submit re-seals + re-validates via `import_block`) | **BUILT v0.1.92** | **None** (RPC onto existing producer + validated import) |
| **2** | `tools/sov-stratum` — RandomX **Monero-dialect** Stratum bridge (login/job/submit, blob⇄header splice, vardiff, local share validation, connection cap) | **BUILT v0.1.92** | **None** (relays a nonce the node re-seals) |
| **3** | Decentralized **sharechain + PPLNS** payouts (option b, sharechain-enforced under the frozen single-recipient coinbase) | **SCOPED, not built** | **None** (separate P2P chain; SOV sees ordinary `Transfer`s) |
| **4** | Payout-consensus decision: keep (b), or fork to **multi-output coinbase** (a) | **DISCLOSED, not shipped** | **(a) = hard fork, activation-gated** |

Genesis-safe through Phase 3; only Phase 4(a) is a fork, and it is quarantined behind a
miner-signaled activation exactly like the tx-domain fork.

## The activation path (concrete)

### A. Operational bring-up of Phases 1–2 (no new code required)
This is the "turn on what's already built" step — solo-pool / single-operator first.
1. Run a SOV node (`sov-rpcd`) with the RPC reachable to the bridge (loopback or LAN;
   keep it OFF the public internet — `sov_submitBlock` is powerful).
2. Run `tools/sov-stratum` pointed at that node's RPC; it polls `sov_getBlockTemplate`,
   serves Monero-dialect Stratum jobs, validates shares locally, and calls
   `sov_submitBlock` on a network-target hit.
3. Point a RandomX miner (xmrig or the native worker) at the bridge.
4. **Prove before trusting:** confirm an accepted network-target share becomes a real
   imported block (check the node height + the coinbase credit). Run the acceptance on a
   throwaway/dev context first, never first on mainnet money.
5. **Honest caveat to verify, not assume:** stock `xmrig` blob compatibility is claimed
   but NOT yet demonstrated end-to-end (see v0.1.92 doc §2 "honest xmrig caveat"). Do a
   real xmrig connect + accepted-share test and record the result here before advertising it.

**Open question for this step:** do we bring up a single-operator pool now (fast, custodial
payout by the operator), or wait for Phase 3 so payouts are trustless from day one? Default
per the v0.1.92 recommendation: build Phase 3 so the first public pool is non-custodial.

### B. Phase 3 — build the sharechain (the real "decentralized pool")
New **additive** crate `tools/sov-sharechain/` (or `chain/crates/sharechain/` only if
first-class types warrant it — additive either way; consensus crates never edited).
Reuses existing pieces (no new crypto in the trust path):
- **Transport:** `sov-network` (Noise/ML-KEM) on its own logical channel.
- **Seal:** `sov-pow` `pow_seal` — a share and a block are the same RandomX computation at
  different targets.
- **Retarget:** `sov-mining` LWMA-1 tuned to ~10s share interval.
- **Payout:** plain `Transfer` actions the STF already executes (option b) — no new action.

A **share** = a `sov_getBlockTemplate` candidate meeting a share target + sharechain metadata
(finder payout account, prev-share, uncles, implied PPLNS window). When a share ALSO meets the
network target, the SOV block it carries **must embed the PPLNS payout transfers** for the
window; the sharechain validity rule rejects it otherwise — that is where trustless payout is
enforced.

**Required tests (prove-don't-claim):** deterministic PPLNS window (same history ⇒ identical
weights on every peer); a network-target share embedding WRONG payouts is rejected (cheating-finder
test); uncle inclusion earns proportional weight; sharechain LWMA holds the interval under swinging
hashrate; heaviest-share-work reorg drops an orphan branch. Genesis/KAT untouched (SOV sees only
ordinary blocks with ordinary `Transfer`s).

### C. Phase 4 — the ONLY consensus fork (optional, later)
Upgrade payout from "enforced-by-sharechain-rule" (b) to "atomic-in-coinbase" (a =
multi-output coinbase). This is a **coordinated hard fork**: new coinbase encoding + STF
verification, miner-signaled activation, cross-impl KAT vectors (Rust node + TS second client).
**Default: stay on (b)** — zero consensus change, working, non-custodial. Only do (a) if
finder-withholding proves a real problem. Belongs with the coordinated-fork bundle, not shipped
casually.

## Interaction with the tx-domain hard fork (IMPORTANT — do not miss)

- Phases 1–3 are **orthogonal** to the tx-domain fork: they move block *templates* and *shares*,
  not transaction signing. A template's transactions are validated by the node's consensus like
  any other block, so once the tx-domain fork is active the node/producer already require
  domain-bound signatures — the bridge/sharechain need no signing changes.
- BUT the pool operator's node MUST be on a binary that enforces the tx-domain rule correctly
  (v0.1.93+); a pool running an un-upgraded node post-activation would build/relay invalid
  templates. **Coordinate the two rollouts:** upgrade pool nodes in the same wave as everyone else.
- The **PPLNS payout transfers** the sharechain embeds are ordinary `Transfer`s signed by... the
  producer? No — payouts are coinbase-adjacent transfers the block producer includes; confirm the
  signing/authorization path for embedded payout transfers is compatible with the domain rule
  before Phase 3 ships near activation. **OPEN ITEM to design in Phase 3.**

## Genesis discipline
Everything Phases 1–3 is additive: new RPC, new standalone crates, read-only accessors. No change
to any block/header/tx encoding, state root, emission, difficulty, chain spec, or KAT vector.
`sov-verify` KAT + genesis pins must be green at every phase gate. Only Phase 4(a) is a fork.

## Immediate next actions (pick with the user)
1. [ ] End-to-end acceptance of Phases 1–2 on a dev/throwaway context (accepted share → imported
   block → coinbase credit); record the xmrig-compat result.
2. [ ] Decide: single-operator bring-up now, or build Phase 3 first (default: Phase 3 first).
3. [ ] If Phase 3: scaffold `tools/sov-sharechain/` + the 5 required tests above.
4. [ ] Resolve the OPEN ITEM: how embedded PPLNS payout transfers are signed/authorized under the
   tx-domain rule, so Phase 3 and the fork activation don't collide.
