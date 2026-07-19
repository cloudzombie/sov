# Runbook — tx-domain hard fork (cross-network replay) activation

> ★★★ FIRM TARGET (user directive 2026-07-19): **v0.1.95 IS THE ACTIVATION RELEASE — set the
> activation height in v0.1.95. NO leaving it for later.** v0.1.95 must deliver the full, SAFE
> activation: Phase-2 client signing → grace-window gate → a concrete activation height in the
> mainnet config (GENEROUS horizon, days — not the vetoed ~10h rush) → whole fleet on v0.1.95 →
> Fable audit → activate. The height cannot precede Phase-2 (else the flag day breaks all txs), so
> v0.1.95 bundles them. Do the safe order below; just do it IN the v0.1.95 line, not "someday".


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

## Cloud-miner + operator checklist AT ACTIVATION (do it WITH the user)

### A. Every mining node (cloud droplets + home rig + laptop) — BINARY UPGRADE only
Pure mining needs NO "signing command": the coinbase is part of the block state transition, not a
signed transaction, so it is untouched by the fork. The node just needs the activation binary so it
validates the new signature rule.
1. SSH to each droplet (per `~/.claude` `do-node-ops` runbook): pull/build the activation release
   (v0.1.94+), replace the `sov-rpcd` binary, `systemctl restart`.
2. Confirm it re-syncs and, via `sov_getDeployments`, that it sees the `tx-domain` deployment.
3. Do the home rig + laptop the same way. **All nodes must be upgraded BEFORE the activation
   height** or an un-upgraded node forks off / builds invalid templates.

### B. Sweeping / sending from a cloud miner via sov-station — AUTOMATIC after Phase-2
There is deliberately NO manual "sign the miners" command. After Phase-2:
1. Import the miner key into sov-station (raw 64-hex seed from
   `~/Desktop/keys/sov-cloud-miner-<region>.txt`).
2. Enter recipient + amount → **Send**. Station calls `sov_getSigningDomain` and signs bound (post-
   activation) or legacy (before) automatically — no command to type. Identical UX to today.
3. If ever sweeping via a script/CLI instead of the GUI, that path must also query
   `sov_getSigningDomain` and `sign_in(domain)` — same rule (Phase-2 covers tx-cannon/conformance).

## Immediate next action
Build **Phase-2 client signing** (step 1) — additive, dormant, activates nothing. `sov_getSigningDomain`
RPC is DONE; next the SDK (second client), then the Rust signers (wallet, Station, conformance, tx-cannon).
