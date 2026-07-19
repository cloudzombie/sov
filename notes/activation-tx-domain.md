# Runbook — tx-domain hard fork (cross-network replay) activation

_Closes "ghost chain" cross-network signature replay by binding each tx/intent signature to
`{chain_id, genesis}`. Shipped DORMANT in v0.1.93 (`25b3b5d`). Reference:
`.github/RELEASE-0.1.93.md`, memory `v0193-tx-domain-fork.md`._

## What is live now
- Full machinery present + tested; `tx_domain_deployment` defaults `None` in production →
  signing bytes byte-identical to pre-v0.1.93. **The chain is unaffected. Nothing is armed.**
- Proven at push: `sov-verify` KAT reproduces byte-for-byte; genesis `cb0272ff` pins hold.

## Why it is a HARD fork (and why timing must be generous)
Post-activation, a node enforces the bound preimage: a legacy-signed tx is **rejected**, and an
un-upgraded node **rejects** a correctly-bound tx (so it forks off). Therefore:
- Every **node** must be on the activation binary BEFORE the flag day.
- Every **signer** (wallet/SDK/tools) must sign the bound way BEFORE the flag day.
- **A ~250-block (~10h) countdown is NOT acceptable** for a hard fork on reserve mainnet.
  Decision 2026-07-19: do NOT wire a short-horizon activation. Generous horizon only, after all
  prerequisites are provably met + explicit go.

## The safe activation order (do NOT reorder)
1. **Phase-2 client signing** (v0.1.94, additive/DORMANT) — every signer becomes domain-aware.
   Design: a read-only RPC `sov_getSigningDomain` returns the node's resolved signing domain
   (`chainId` + genesis, or null) for the next height. Each client queries it and calls
   `sign_in(Some(domain))` when non-null, else `sign()`. While dormant the RPC returns
   `active:false`/null → clients sign legacy → byte-identical behavior.
   - [x] **`sov_getSigningDomain` RPC** — landed + tested (`get_signing_domain_reports_dormant_by_default`)
   Clients to update:
   - [ ] TS SDK (`sdk/`) — the KAT second client
   - [ ] Rust wallet (`chain/crates/wallet`)
   - [ ] SOV Station (`node/`)
   - [ ] `tools/conformance`
   - [ ] `tools/tx-cannon`
2. **Grace-window gate refinement** (v0.1.94 consensus, still DORMANT) — so there is no sharp
   cliff: for a height range `[H_a, H_a+G)` the node accepts EITHER legacy OR bound signatures;
   `≥ H_a+G` bound-only (full replay protection). Removes the boundary problem where an in-flight
   legacy tx would be rejected exactly at `H_a`. This is a refinement of the enforcement logic,
   safe to change while dormant (pre-activation still byte-identical).
3. **Confirm the fleet** — every node + wallet + tool on the activation binary, verified via
   `sov_getDeployments` and manual roll-call.
4. **Fable adversarial audit** of `25b3b5d` (+ the grace-window change) — independent check.
   (Built by the assistant while Fable was rate-limited; resets ~2:40am America/Chicago 2026-07-19.)
5. **Schedule** — only then wire a concrete activation on a generous horizon (days, not hours),
   with an explicit go from the owner.
6. **Activate** — height/flag-day or miner-signaling to `Active` at a window boundary.

## Design reference (already implemented, dormant)
- Preimage: `tag ‖ 0x00 ‖ chain_id ‖ 0x00 ‖ genesis(32) ‖ borsh` — `tag` = `sov:tx:v1` /
  `sov:intent:v1`. `SigningDomain::frame` in `chain/crates/primitives/src/signing_domain.rs`.
- tx id is UNCHANGED (hash of bare borsh) → KAT byte-for-byte; only the signature binds.
- Gate: `BlockContext.tx_domain` → `apply_transaction` + intent settlement (runtime);
  `Block::all_signatures_valid_in` at `validate_candidate` import; mempool admission
  (`Mempool.domain`, refreshed by the node on tip advance). `Blockchain::resolved_tx_domain`.

## Immediate next action
Build **Phase-2 client signing** (step 1) — additive, dormant, activates nothing. Start with the
`sov_getSigningDomain` RPC, then the SDK (second client), then the Rust signers.
