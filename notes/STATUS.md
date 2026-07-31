# SOV — STATUS (master anchor)

_Last updated: 2026-07-21. Update at the end of every session._

## One-line state

Mainnet LIVE (genesis `cb0272ff…e72d`, FROZEN). Current release **v0.1.97** — accurate live
hashrate (30-block window, display-only). v0.1.96 = the DEFINITIVE cold-sync fix (size-capped
`GetBlocks` batches; fresh nodes stuck at 7168 → fixed; all 3 seeds deployed). **v0.1.95 was
SKIPPED as a release** — its tx-domain activation plan now folds into **v0.1.98** (see below).
No consensus behavior has changed on the live chain. Nothing is armed.

## Sibling repositories (NOT in this tree)

Three tools have been extracted to standalone repositories and are guarded by the
`repository-boundaries` CI job here — re-adding any of their paths fails CI:

- **XUS Miner** — https://github.com/cloudzombie/xus-miner (no SOV source dependency at all;
  compatibility via the documented RPC/Stratum contract).
- **SOV TX Cannon** — https://github.com/cloudzombie/sov-tx-cannon (was `tools/tx-cannon`). It
  signs REAL transactions, so it still uses the real chain crates — `sov-rpc`, `sov-crypto`,
  `sov-types`, `sov-primitives` — as **git dependencies pinned to a release TAG**, not copies.
  A chain change reaches it only when that pin is deliberately bumped there; changes on this
  branch cannot break its build, and it never modifies this repository.
- **SOV Red Team** — https://github.com/cloudzombie/sov-redteam (was `chain/crates/redteam`).
  The adversarial harness. Unlike the two above, it tracks `branch = "main"` rather than a
  release tag: it exists to catch a consensus regression the day it lands, and its CI runs the
  full gauntlet daily against this repo's `main`, so a broken defense shows up as a red build
  over there instead of a surprise on release day. **This is deliberate and load-bearing** —
  the harness must NOT live in the same commit as the code it attacks, or an inconvenient
  VULNERABLE verdict could be edited away in the same change that caused it.
  `redteam-gui/` stays here (it is a desktop app, not the engine) and consumes the harness by
  **git**, never by path; CI enforces that too, because a `../chain/...` path dep would also be
  a second, non-unifying source of `sov-crypto`.

## Golden rules (do not break)

- Genesis `cb0272ff88e64c18cde0257f7fae1c8236b02651f10cc7a02456fd682ee2e72d` NEVER changes.
- Consensus changes ship **dormant** behind a miner-signaled activation; turning them on is a
  **separate, coordinated, explicitly-approved** step — never a countdown wired in casually.
- Every phase gate re-proves the `sov-verify` KAT byte-for-byte + genesis pins before shipping.
- This is mainnet post-quantum reserve cash. Conservative pace, honest disclosure, prove-don't-claim.
- **Releases follow the version contract** — ONE version source (`node/Cargo.toml`), tags only via
  `scripts/release-gate.sh --cut vX.Y.Z`, versions NEVER re-used, tags NEVER moved, releases only
  from the current head of `origin/main`, and every artifact proves its own version before it is
  published. See [release-version-contract.md](release-version-contract.md).

---

## OPEN TRACKS (each with its exact NEXT ACTION)

### 1. v0.1.98 ACTIVATION (tx-domain fork + fee-auction mempool) — see [activation-v0198.md](activation-v0198.md)
**★ v0.1.95 SKIPPED — its tx-domain activation now bundles with the new fee-priority mempool +
v2 tx envelope into ONE coordinated v0.1.98 activation** (both touch the tx envelope/signing;
one flag day, not two). Full plan + backtest/verification method in `activation-v0198.md`.
**Blocker (unchanged): Phase-2 client signing is NOT done** — only `node/src/gui.rs` references it;
SDK, Rust wallet, conformance, TX Cannon (external repo) still pending. A tx-domain flag day is impossible until
all 5 signers query `sov_getSigningDomain` + `sign_in`. **NEXT: land fee-priority mempool
Layer-1 (policy-only, genesis-safe) + finish the Phase-2 signers.**

#### 1a. tx-domain hard fork — reference (carried into v0.1.98)
**State:** v0.1.93 shipped DORMANT (commit `25b3b5d`, tag `v0.1.93`). Full machinery present +
tested; `tx_domain_deployment` defaults `None` → byte-identical, inactive.
**NEXT ACTION:** **Phase-2 client signing** (v0.1.94, additive/dormant). Foundation DONE: the
read-only `sov_getSigningDomain` RPC (returns `active:false`/null while dormant) — landed +
tested. **Remaining: the 5 client signers query it and call `sign_in(domain)`** — TS SDK, Rust
wallet, SOV Station, conformance, TX Cannon (external repo).
See [activation-tx-domain.md](activation-tx-domain.md).
**★ FIRM TARGET — v0.1.95 = THE tx-domain ACTIVATION RELEASE. Do NOT defer / leave for later
(user directive 2026-07-19).** v0.1.95 must SET the activation height and ship the whole safe
activation, in this order (all IN the v0.1.95 line):
  1. Phase-2 client signing complete (5 signers query `sov_getSigningDomain` → `sign_in`).
  2. Grace-window gate refinement (accept legacy OR bound in `[H_a, H_a+G)` so there's no cliff).
  3. Wire the concrete activation height into the mainnet config (a GENEROUS horizon — days, not
     the vetoed ~10h/250-block rush; height = tip + wide margin, set at release time).
  4. Fleet on v0.1.95 (every node + wallet + tool) confirmed BEFORE the height.
  5. Fable audit of the activation change.
**Blocking dependency (still true):** the height cannot go live until Phase-2 clients sign the new
way and are deployed everywhere, or the flag day rejects every legacy-signed tx. So v0.1.95 bundles
Phase-2 + grace-window + the height together — that's what "implement the activation height for
0.1.95" means done safely.

### 2. Pool mining — stratum + `sov_getBlockTemplate`
**State:** Phases 1–2 BUILT in v0.1.92 (`sov_getBlockTemplate`/`sov_submitBlock` RPC + TemplateCache;
`tools/sov-stratum` RandomX Monero-dialect bridge, vardiff, share validation). Both additive, zero
consensus surface. Phase 3 (sharechain/PPLNS) SCOPED, not built. Phase 4 (multi-output coinbase
fork) disclosed, not shipped.
**NEXT ACTION:** decide operational bring-up vs. building Phase 3 sharechain first. See
[activation-pool-mining.md](activation-pool-mining.md) for the full runbook.

### 3. xUSD stablecoin
**State:** consensus layer landed (additive, genesis-frozen); oracle acct `96abb938…`.
**NEXT ACTION (pending):** RPC + Mint/Burn GUI page + liquidations + deploy the oracle feed.

### 4. Standing roadmap (not active this week)
Light client/SPV, efficient sync, PQ shielded pool, end-to-end atomic swap (ZEC sighash unproven),
external audit. Tracked in `~/.claude/.../memory/` (see `v0186-program.md`).

---

## Recently shipped
- **release version contract** (2026-07-25, branch `feat/release-version-contract`, PR open) —
  reused/moved tags refused, release-from-current-main enforced in both the gate and CI, and every
  published artifact asserted to self-report the tag; 35 guard tests in CI. See
  [release-version-contract.md](release-version-contract.md) + [2026-07-25.md](2026-07-25.md).
- **v0.1.93** (2026-07-19) — dormant cross-network replay hard fork; also hardened a macOS-flaky
  p2p sync test. All CI-equivalent gates green locally before push.
- **v0.1.92** (2026-07-19) — pool-mining groundwork (Phases 1–2).
- **v0.1.91** — SOV Station connect/sync without mining; mining a Mining-tab toggle.
- **v0.1.90** — Codex-audit ship-now security hardening.
