# PQ pool v2 — response to the Codex audit (2026-07-26)

Audit report: `notes/pq-pool-v2-e2e-audit-report.md`
Audited commit: `dc14751` / branch state `418641d`
Disposition given: **NO-GO for bit-2 activation or a full-green release tag**

That disposition still stands. This file records, finding by finding, what has
been fixed and what has not — so nobody has to infer it from the diff.

**Standing fact that makes all of this safe to change:** pool v2 rides BIP-9
signal bit 2, which is DEFINED and UNARMED on every canonical network. No chain
has ever executed a v2 spend. Consensus digests in this pool can therefore still
be changed freely. After arming, every one of them is a hard fork.

## PQV2-01 — nullifiers not unique per note occurrence (High) — **FIXED**

Confirmed independently before fixing: a failing test stranded 1,000,000 grains.

The audit was right and our own soundness argument was wrong. §5 of
`chain/docs/pq-shielded-soundness.md` had checked only whether one note could
yield two nullifiers, and asserted `(nsk, rho)` was "the same pair that
determines the commitment". It is not — the commitment also binds the value. The
unexamined direction was the dangerous one: two notes colliding onto one
nullifier, where spending either permanently strands the other.

Fix: `NF = merge_d(NF, nsk, rho; leaf_position)`, with the position bound into
sponge capacity element 2 (the slot domain separation already uses at element 1,
so no extra permutation). In-circuit, a new accumulator column reconstructs the
position from the SAME path bits that route the Merkle hash, so position and
membership cannot disagree; it is asserted zero at each segment start.

- trace width 31 -> 32, one new transition constraint (129)
- adversarial vectors assert WHICH constraint rejects, both for a seeded
  accumulator and for a position divorced from the path
- soundness doc §5 rewritten, including the error it previously contained
- cost: proof 96,586 -> 98,494 bytes (+2.0%), verify 970 -> 1,005 us; security
  level unchanged (FRI parameters untouched)

The audit also asked for tests covering identical commitments at two positions
and spending either occurrence — both are now covered, and both occurrences are
independently spendable, which is the correct accounting.

## PQV2-02 — E2E release gate produced a false green (High) — **FIXED**

Two separate defects; both addressed.

1. *The gate counted skips as success.* The harness exited on the failure count
   alone, so it printed `GREEN` / exit 0 while skipping all six v2 steps. Added
   `--require-complete`, under which any skip is fatal, and replaced the verdict
   line: GREEN only when every step ran, AMBER when skips are tolerated, RED
   under the release gate. Verified: the identical run that printed GREEN/exit 0
   now exits **1** with 6 skips.

2. *The six v2 steps did not exist.* They are implemented and live now —
   `shielded-v1-never-stranded-across-pool-v2`, `shield-v2`, `z-send-v2`,
   `unshield-v2`, `v1-to-v2-migration`, `reorg-with-v2-state` — driving real
   STARK proofs through real consensus. The rehearsal preset
   (`sov-e2e-` chain-id namespace ONLY) now arms bit 2 one window after
   `tx-domain`, so the harness proves DORMANCY first (a v2 shield must be
   refused outright) and then drives a genuine BIP-9 activation.

   Mainnet is matched first in `baked_deployments` and schedules no
   `shielded-v2` deployment at all; a test asserts no canonical chain id
   (`sov-mainnet`, `sov-testnet-1`, `sov-dev`, `sov-test`) can arm bit 2.

**Still open from this finding:** nothing in `scripts/` or `.github/` invokes
the harness, so the five-node suite is not yet a required release job. That
wiring is the remaining half of "make it a gate".

## Found during remediation, NOT in the audit — carrier binding (High)

The audit did not catch this, and neither did any test at any layer: the
pool-v2 transaction path did not work at all.

`build_shield` / `build_spend` signed `bundle_digest(...)`. Consensus
(`verify_carrier_auth`) requires a signature over
`carrier_sighash(digest, {signer, nonce})`. Every bundle the wallet built was
therefore rejected with `CarrierAuth` — no v2 shield, send or de-shield could
ever have been mined.

Why every layer missed it is the lesson worth keeping:

- the CLI's `require_v2_active` refuses while bit 2 is dormant, which happens
  BEFORE a bundle is ever built — so live CLI checks only ever exercised the
  dormancy guard and the cross-pool address refusal;
- `chain/crates/runtime/src/shielded_v2.rs`, the whole 8-stage consensus
  verifier, had ZERO tests;
- the only two v2 execution tests both assert a v2 action is REJECTED;
- the E2E harness skipped all six v2 steps and still reported green.

**Every layer tested that pool v2 is refused. No layer tested that it works.**

Fixed with `authorize_for_carrier`, applied at submit time in both clients.
The runtime module now has 8 tests, including the first that proves a v2
transaction is ACCEPTED, plus double-spend, replay/theft, unknown anchor,
insufficient balance, and byte-mutation-fails-closed.

## Medium findings — **OPEN**

None of these are fixed. They are stated here so they are not lost.

- **PQV2-03** — one saturated block can evict the whole anchor window. Needs
  anchor retention defined in block units, or the ring sized for worst-case
  insertions across the confirmation horizon, plus an E2E test that spends
  against a pre-block root after maximum insertions.
- **PQV2-04** — the depth-20 commitment tree can be economically exhausted.
- **PQV2-05** — 128-bit *end-to-end post-quantum* security is not established.
  The 128 figure is a classical list-decoding bound. Either restate the claim
  precisely or commission a QROM analysis. This is a claims-accuracy issue and
  should be settled before any public security statement.
- **PQV2-06** — cross-network replay protection depends on an activation
  ordering consensus does not enforce.
- **PQV2-07** — the declared proof-verification block weight is not enforced by
  block production or import. Mempool admission is weight-aware as of the
  v0.2.2 branch, but import-side accumulation and recomputation are not.
- **PQV2-08** — security/performance regression checks have drifted.

## Bar for arming bit 2

Unchanged and not met: every Medium resolved or explicitly accepted in writing,
the five-node suite wired as a required job and green with **zero** skips, and
the external circuit audit (`notes/audit-scope-pq-pool.md`) completed with its
findings closed. Pool v2 ships DORMANT in v0.2.2 regardless.
