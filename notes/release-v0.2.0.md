# SOV v0.2.0 — release notes

**What this release IS:** the v0.1.99 consensus line, plus the completed first
workstream of the post-quantum shielded program (W1) and the live-VM end-to-end
harness (W8), both landed as additive, dormant code.

**What this release is NOT — read this before assuming otherwise:** v0.2.0 does
**not** ship a usable post-quantum shielded pool. The `shielded-pq` crate is in
the tree and its STARK spend circuit is real and tested, but it is **not wired
into consensus**: there is no `ShieldedV2` action, no pool-v2 state, no
turnstile, no anchor tree, and no wallet, RPC, CLI, or GUI pathway. You cannot
send, receive, or hold a v2 shielded note with this build. Workstreams W2
(consensus wiring), W3 (keys/HD/wallet scan), W4 (RPC/CLI/KAT/SDK/conformance)
and W5 (Station dual-pool GUI) are unstarted, and the external audit that the
v0.2.0 program names as a prerequisite for a shipping PQ pool has not happened.

## Consensus

**No consensus change from v0.1.99.** Genesis remains
`cb0272ff88e64c18cde0257f7fae1c8236b02651f10cc7a02456fd682ee2e72d`, frozen and
unaltered. A v0.2.0 node validates byte-identically to a v0.1.99 node; it is a
drop-in replacement and introduces no fork, no new deployment bit, and no new
block or transaction rule.

The two deployments armed by v0.1.99 — `tx-domain` (bit 0) and `fee-auction`
(bit 1) — activated on mainnet at height **11520**, one signaling period after
locking in at 11232. That activation is a property of the running chain, not of
this release; v0.1.99 nodes and v0.2.0 nodes enforce it identically.

## What landed

- **`chain/crates/shielded-pq` (W1)** — the post-quantum spend circuit:
  Winterfell STARK over Rescue-Prime commitments with a depth-20 Merkle tree,
  PRF nullifiers, ML-KEM-768 note encryption, and ML-DSA-65 carrier spend
  authorization. Amounts are private in-circuit (4-in/4-out, 61-bit range
  checks). Deserialization is panic-free and fuzzed, behind a `proof_version`
  gate. **Dormant: not reachable from any consensus path.**
- **`tools/e2e-vm` (W8)** — the live end-to-end harness. Boots a real
  multi-node isolated testnet (genesis `c53be5ab`, deliberately not mainnet) and
  proves genesis determinism, mesh formation and late-join sync, mining,
  the full shielded-v1 lifecycle with exact pool deltas, restart-replay survival
  from a cold boot, and cross-node conformance. Pool-v2 steps report
  SKIP-with-reason until W2 lands.

## Upgrading

Drop-in from v0.1.99. No data migration, no resync, no configuration change.
Existing Orchard (v1) shielded notes are unaffected and remain fully spendable —
this release adds no restriction to pool v1.

Nodes still on v0.1.96 or earlier should upgrade: the `tx-domain` grace window,
during which both old-form and chain-bound signatures are accepted, ends at
approximately height **11808**. After that, transactions signed without the
chain domain are rejected. This is a client requirement; no funds are at risk
and nothing becomes unspendable — an un-upgraded wallet simply cannot transact
until it is upgraded.

## Version contract

`node/Cargo.toml` is the single version source. The release tag equals it
exactly, the release gate refuses any mismatch, and `SOV_BUILD_VERSION` bakes
the tag into the daemon so the P2P agent string, `sov_version`, and
`sov_getPeerInfo` all report the same version the tag claims.
