# Consensus — the complete open list

**Compiled 2026-07-27, after v0.2.2.** Every item below was verified against the
tree or the live chain at compile time, not recalled. Each says what it is, why
it matters, and what "done" means.

Ordering is by *urgency to users*, not by severity label.

---

## A. LIVE — degrading real users right now

### A1. The assumevalid checkpoint is STALE (act now)

- Highest baked checkpoint: **8300**. Live mainnet height: **13,019**.
- A fresh node fast-syncs to 8300, then re-runs RandomX for **~4,700 blocks**.

That is the exact, already-documented failure mode: CPU-bound validation starves
the P2P thread, peers time out, the node drops every connection and loops on 0
peers. It is why the anchor was moved 5000 → 6800 → 8300 before. It has rotted
again, further than any previous time.

**Done means:** anchor pinned near tip (confirmed byte-identical on all three
relays first, at a depth well past finality), *plus* a guard so it cannot rot
silently again — a test or release-gate check that fails when
`tip - highest_checkpoint` exceeds a threshold. Refreshing without the guard
just schedules the next occurrence.

### A2. assumevalid is height-gated, not ancestry-gated (HIGH, pre-existing)

The PoW-skip below a checkpoint trusts *height*, not *ancestry*. A fresh node
can be fed a fabricated sub-checkpoint branch carrying no valid PoW. Found in an
earlier internal audit; never fixed.

**Done means:** the skip applies only to blocks proven to descend from a pinned
checkpoint hash. Consensus-sensitive — wants a careful change and a test that
feeds a fake branch and asserts rejection.

---

## B. getBlockTemplate / mining surface

### B1. Template shape — COMPLETE

17 fields, including `versionBits`, `blob`, `nonceOffset`, `powKey`,
`minTimestampMs`. Nothing missing for stratum or solo mining.

### B2. `header.hash` — DONE (v0.2.2)

Both block-returning RPCs (`getBlockByHeight`, `getBlockByHash`) go through
`block_with_hash`, so the id a client round-trips is always present.

### B3. No header-only submit

Only `sov_submitBlock` exists; stratum round-trips whole blocks. A
`sov_submitHeader` (header + nonce against a cached template) would cut pool
bandwidth materially. **Additive, no consensus surface.**

### B4. Pool mining phases 3–4 not built

Phase 3 (sharechain/PPLNS) is scoped, not built. Phase 4 (multi-output coinbase)
is **a hard fork** — disclosed, not shipped, and should not be bundled with
anything else.

---

## C. PQ pool v2 — the five audit Mediums

These gate **arming bit 2**. They do not gate a release; the pool ships dormant.
Full detail in `pq-pool-v2-audit-response.md`.

- **C1 / PQV2-03** — one saturated block can evict the entire 128-entry anchor
  ring, invalidating in-flight spends. Needs retention defined in *blocks*, or
  the ring sized for worst-case insertions across the confirmation horizon.
- **C2 / PQV2-04** — the depth-20 commitment tree can be economically exhausted.
- **C3 / PQV2-05** — "128-bit post-quantum" is a **classical** list-decoding
  bound. Either restate the claim precisely or commission a QROM analysis. This
  is a claims-accuracy issue and must be settled before any public security
  statement.
- **C4 / PQV2-06** — cross-network replay protection depends on an activation
  ordering consensus does not enforce.
- **C5 / PQV2-07** — **verified open:** `MAX_BLOCK_WEIGHT` appears only in
  comments outside `types/weight.rs`. Block production does not accumulate
  weight and import does not recompute it. Mempool admission is weight-aware as
  of v0.2.2; the block path is not.

Plus **PQV2-08** (regression-check drift), a test-quality item.

---

## D. Older consensus debt, still open

- **D1. O(N) reorg / recommit.** Long-standing; cost grows with chain length.
- **D2. Multisig.** Owner-flagged as poor and back-burnered. A rework should
  precede any further multisig-adjacent consensus work.
- **D3. Oracle deviation bound** (xUSD) — unbounded feed movement.
- **D4. HTLC preimage pricing.**
- **D5. RPC rate limiting.**

(The P2P inbox cap from the same audit round was closed in the v0.2.2 line.)

---

## E. Process

### E1. `notes/STATUS.md` is stale and actively misleading

It still describes the v0.1.98 tx-domain activation as open and blocked on
Phase-2 signers. Both `tx-domain` and `fee-auction` **activated at height
11520**, the grace window closed, and v0.2.2 has shipped since. A status file
that describes a fork as pending after it activated is worse than no status
file.

---

## Suggested order

1. **A1** — live, users hitting it, and the fix is small. Do the guard with it.
2. **A2** — HIGH severity, and it is about *fresh nodes trusting the wrong
   chain*, which is the worst class of bug we still carry.
3. **E1** — ten minutes, stops the next person being misled.
4. **C5** — the only Medium that is a *missing enforcement* rather than a
   sizing/claims question, so it is the one most likely to bite.
5. Everything else by appetite.
