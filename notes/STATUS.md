# SOV — STATUS (master anchor)

_Last updated: 2026-07-19. Update at the end of every session._

## One-line state

Mainnet LIVE (genesis `cb0272ff…e72d`, FROZEN). Current release **v0.1.93** — ships the
cross-network replay hard fork **DORMANT**. No consensus behavior has changed on the live
chain. Nothing is armed.

## Golden rules (do not break)

- Genesis `cb0272ff88e64c18cde0257f7fae1c8236b02651f10cc7a02456fd682ee2e72d` NEVER changes.
- Consensus changes ship **dormant** behind a miner-signaled activation; turning them on is a
  **separate, coordinated, explicitly-approved** step — never a countdown wired in casually.
- Every phase gate re-proves the `sov-verify` KAT byte-for-byte + genesis pins before shipping.
- This is mainnet post-quantum reserve cash. Conservative pace, honest disclosure, prove-don't-claim.

---

## OPEN TRACKS (each with its exact NEXT ACTION)

### 1. tx-domain hard fork — cross-network ("ghost chain") replay
**State:** v0.1.93 shipped DORMANT (commit `25b3b5d`, tag `v0.1.93`). Full machinery present +
tested; `tx_domain_deployment` defaults `None` → byte-identical, inactive.
**NEXT ACTION:** **Phase-2 client signing** (v0.1.94, additive/dormant). Foundation DONE: the
read-only `sov_getSigningDomain` RPC (returns `active:false`/null while dormant) — landed +
tested. **Remaining: the 5 client signers query it and call `sign_in(domain)`** — TS SDK, Rust
wallet, SOV Station, conformance, tx-cannon. See [activation-tx-domain.md](activation-tx-domain.md).
**Then (NOT yet, in order):** grace-window gate refinement → confirm all nodes/clients on v0.1.94
→ Fable audit of `25b3b5d` → schedule activation on a GENEROUS horizon (NOT ~250 blocks / 10h) →
miners signal / flag day.
**Blocking dependency:** you cannot schedule activation until Phase-2 clients sign the new way and
are deployed everywhere, or the flag day rejects every legacy-signed transaction.

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
- **v0.1.93** (2026-07-19) — dormant cross-network replay hard fork; also hardened a macOS-flaky
  p2p sync test. All CI-equivalent gates green locally before push.
- **v0.1.92** (2026-07-19) — pool-mining groundwork (Phases 1–2).
- **v0.1.91** — SOV Station connect/sync without mining; mining a Mining-tab toggle.
- **v0.1.90** — Codex-audit ship-now security hardening.
