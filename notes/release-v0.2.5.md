# SOV v0.2.5 — release notes

**This release ARMS a consensus feature on mainnet.** It schedules the
post-quantum shielded pool (`shielded-v2`, signal **bit 2**) for miner-signaled
activation, and enables the PQ send path in SOV Station once that activation
resolves. Genesis
`cb0272ff88e64c18cde0257f7fae1c8236b02651f10cc7a02456fd682ee2e72d` remains
frozen. Behavior is **byte-identical to v0.2.4 until the activation height** —
the only immediate change is that a mainnet 0.2.5 node now stamps
`version_bits = 0b111` (it signals readiness for bit 2 in addition to bits 0/1).

## What v0.2.5 does

1. **Schedules the `shielded-v2` bit-2 deployment on mainnet.**
   - Registered next to the live `tx-domain` (bit 0) and `fee-auction` (bit 1)
     deployments in the release-pinned mainnet preset
     (`mainnet_deployments()` in `chain/crates/rpc/src/daemon.rs`).
   - **Parameters match bits 0/1 exactly:** `period = 288`, `threshold = 9/10`
     (90%), `lockinontimeout = false`. The min-activation guard and timeout use
     the identical offsets bits 0/1 used (`start + 288`, `start + 3·288`).
   - **Start height: `14_976`** (`MAINNET_SHIELDED_V2_START_HEIGHT`, a single
     named constant the coordinator can adjust). This is a `52 · 288` window
     boundary, chosen ~1,316 blocks (~2.3 days at the 2.5-min target) above the
     ~13,660 mainnet head at the time this release was cut, so the whole fleet
     can be running 0.2.5 and signaling bit 2 **before** the signaling window
     opens. Timeout height `15_840`; min-activation `15_264`.
   - **Cadence** (with ≥90% signaling): `Started` at 14,976 → `LockedIn` at
     15,264 → `Active` at **15,552** — the same two-period lag bits 0/1 had.
   - **Adds bit 2 to the mainnet signal mask** (`0b11` → `0b111`), so blocks a
     0.2.5 node mines broadcast the bit-2 readiness vote. Old nodes record the
     bit and do not enforce it.

2. **Wires `shielded_v2_active` to the deployment, per-branch.** The
   executor/import gate (`BlockContext::shielded_v2_active`, and the
   `FeatureInactive` gate in `chain/crates/runtime/src/execution.rs`) resolves
   over the block's **own parent-branch** committed signals via
   `Blockchain::branch_shielded_v2_active` → `shielded_v2_active_with` →
   `deployment_active_at` — the SAME shared evaluation `fee-auction` uses
   (`fee_auction_active_with` → `deployment_active_at`), so upgraded and
   non-upgraded nodes agree on whether the rule applies to any given block on any
   branch. (This wiring already existed in the tree; 0.2.5 arms the schedule that
   drives it.) Until Active, `Action::ShieldedV2` stays a hard,
   block-invalidating reject.

3. **Un-gates Station's PQ send path.** SOV Station's shield-v2 / de-shield-v2 /
   private-v2-send controls (`node/src/gui.rs`) are shown and enabled only when
   the connected node reports `shielded-v2` **Active** — read from
   `sov_getShieldedV2Info.active`, which the node derives from
   `chain.shielded_v2_active(height)` (the identical consensus resolution
   `sov_getDeployments` reports). While dormant/unknown the section is hidden and
   the pool chip shows an honest "not yet active" state. The backend
   (`require_v2_live`) re-checks the same flag before spending ~25 s proving, and
   the `v2_allows` guard gates every money-moving control on `pool_active`, so
   Station never builds a v2 transaction before activation — it does **not**
   bypass the consensus gate. (This dynamic gating was already implemented; no
   artificial dormant hard-off existed to remove.)

## Payload it carries

- The **depth-32** pool-v2 note-commitment tree.
- All **six audit Mediums** (PQV2-01 … PQV2-07 as landed on the pre-arming
  branch).
- The pool-v2 lifecycle: shield, de-shield (per-window drain limiter), and
  fully-private v2→v2 send, carrier-bound to `{chain_id, genesis}` (PQV2-06
  cross-network replay protection) and to `{signer, nonce}`.

## Honest status (the arming bar)

- **Activation is miner-signaled and requires the fleet running 0.2.5.** If
  fewer than 90% of blocks in a 288-block window at/after height 14,976 signal
  bit 2, the deployment does not lock in and the pool stays dormant (and the
  schedule ultimately `Fail`s at the timeout, since `lockinontimeout = false`).
- **The external circuit audit and QROM analysis remain accepted-pending.**
  Arming is the owner's explicit, coordinated decision after the six Mediums and
  the depth-32 upgrade landed; it is not a claim that the external review is
  complete.
- Once Active, `Action::ShieldedV2` executes the full pool-v2 path and the
  `MAX_BLOCK_WEIGHT` bound (PQV2-07) begins to be enforced — both arrive
  atomically under the same bit-2 deployment.

## Upgrading

Drop-in from v0.2.4. Existing balances, pool-v1 shielded notes, and chain data
are unaffected; no resync. A node that has not upgraded keeps validating (it
records bit 2 but does not signal it, and cannot spend into pool v2). To
participate in activation, miners must run 0.2.5 before height 14,976 so their
blocks signal bit 2.

## Proof

- Consensus KAT (`sov-verify::kat_vectors_are_reproduced_byte_for_byte`) stays
  green — the preset is mainnet-only, so dev/test/KAT chains are untouched.
- Mainnet replay (`chain/crates/rpc/tests/mainnet_replay.rs`) still reproduces
  every historical state root: all real history precedes height 14,976, so the
  v2 sub-state stays exactly absent.
- New activation test
  (`sov-chain::miner_signaled_shielded_v2_activates_and_a_bundle_executes`)
  mirrors the fee-auction activation test: a node signals bit 2; with ≥threshold
  signaling over the window `shielded-v2` reaches Active and a real carrier-bound
  shield **executes** (value enters the pool, supply conserved); before Active it
  is still `FeatureInactive` (producer excludes it, a smuggled block fails to
  import).
