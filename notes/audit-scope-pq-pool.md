# External security audit — scope of work

**Subject:** SOV post-quantum shielded pool (pool v2) — STARK spend circuit and
consensus integration
**Requested by:** SOV (cloudzombie/sov)
**Status of this document:** scope for solicitation. No engagement exists.

---

## 1. Why this audit exists

SOV is a live proof-of-work chain (mainnet running since 4 July 2026, genesis
`cb0272ff88e64c18cde0257f7fae1c8236b02651f10cc7a02456fd682ee2e72d`, frozen).
Its existing shielded pool is Orchard/Halo2 — sound, but its soundness rests on
the discrete-log assumption and its privacy is vulnerable to harvest-now-
decrypt-later. Pool v2 replaces both with hash-based and lattice primitives.

The pool is **not live**. It rides BIP-9 signal bit 2, which is defined and NOT
armed; there is no height on any chain at which a v2 spend can execute. This
audit is a **hard gate before the arming release exists** — the project's own
release contract states that arming without it is not permitted.

The chain carries real value. A soundness break in this circuit is unbounded
inflation or theft of shielded funds, not a bug.

## 2. What we are actually worried about

Stated plainly, so the engagement targets it rather than restating our tests:

1. **An under-constrained AIR.** The failure mode is not a Rust defect — it is a
   constraint we did not write, letting a prover produce a valid proof of a
   false statement: value created from nothing, or a note spent by someone who
   does not own it. This is absence-of-code and it is the single highest-value
   finding available.
2. **Parameter soundness.** Our own documentation says 127 bits *conjectured*,
   and explicitly "less under proven FRI bounds" — a figure nobody has derived.
   We want that number computed, not accepted.
3. **Binding gaps.** Every public input must be bound such that it cannot be
   reshaped around a signature or proof. A prior external audit of this project
   found exactly this class (transactions carried no chain/genesis binding,
   permitting cross-network replay); we expect that lens applied here.
4. **Consensus integration.** A sound circuit wired in unsoundly is equally
   fatal: anchor handling, nullifier double-spend across blocks and reorg
   branches, the value turnstile, and denial-of-service via verification cost.

## 3. In scope

### 3.1 Circuit and cryptography — `chain/crates/shielded-pq/` (~5,700 LOC)

| file | LOC | what it is |
|---|---|---|
| `air.rs` | 679 | the AIR: 31-column trace, length 1024, 4-in/4-out |
| `prover.rs` | 560 | proof generation and `ProofOptions` |
| `state.rs` | 854 | commitment frontier, 128-anchor ring, nullifier set |
| `scan.rs` | 1065 | wallet-side trial-decapsulation note detection |
| `hd.rs` | 373 | HD derivation of spend + KEM keys from one phrase |
| `wire.rs` / `proof_frame.rs` | 610 | bundle encoding, `proof_version` gate |
| `bundle.rs` / `carrier.rs` | 447 | bundle digest, spend authorization |
| `encrypt.rs` | 218 | ML-KEM-768 note encryption |
| `tree.rs` | 209 | depth-20 Rescue-Prime Merkle tree |

Primitives: **winterfell** STARK (FRI, Blake3), **Rescue-Prime** (`Rp64_256`)
commitments, Goldilocks field with quadratic extension, **ML-KEM-768** (fips203)
note encryption, **ML-DSA-65** (fips204) spend authorization.

Current proof options: **42 FRI queries, blowup factor 8, 16 bits of grinding,
quadratic field extension.** Bundle ~55 KB; prove ~25 ms, verify ~0.66 ms.

Specific questions we want answered, not merely reviewed:

- Is **every** one of the 4 input slots constrained to genuine tree membership,
  or can a slot be given a free pass?
- Is the **value balance** constrained in both directions (no mint, no burn),
  including for dummy notes?
- Do the **61-bit range checks** bind every value? (Range is 61 rather than 64
  because the Goldilocks prime is below 2^64 and four u64 values must sum
  without wrap — we want this reasoning checked, not assumed.)
- Is the **owner tag** constrained so a note's *sender* cannot spend it? An
  earlier internal review caught precisely this; we want independent confirmation
  the fix is complete.
- Is the **nullifier** uniquely determined by the note, with no freedom for a
  prover to produce two distinct nullifiers for one note (double-spend) or
  collide two notes onto one (censorship)?
- **Derive the real soundness level** under proven FRI bounds, and state what
  parameter changes reach a written 128-bit target.

### 3.2 Consensus integration — `chain/crates/{runtime,state,types}`

Execution and verification wiring: anchor-ring membership, nullifier
double-spend within a bundle, within a block, across blocks, and across reorg
branches; the pool-value turnstile (cannot go negative); value balance to the
transparent leg; the de-shield drain limiter; transaction and block weight
accounting; and the dormancy gate that must keep every v2 action a hard,
block-invalidating reject while bit 2 is unarmed.

### 3.3 Denial of service / liveness

Worst-case verification cost for a block saturated with v2 bundles, measured
against our weakest production node. A pool that cannot verify inside the block
interval stalls the chain — for us this is a soundness-class risk, not a
performance note.

## 4. Out of scope

The Orchard/Halo2 pool v1 (already shipped), the PoW and difficulty algorithm,
P2P transport, the desktop wallet UI, and the existing transparent ledger —
except where they interact with pool v2.

## 5. What we will provide

- Full repository access, and a written **soundness argument per constraint**
  with every public input's binding justified.
- A proven-versus-conjectured table for all security claims.
- The threat model (`chain/docs/pq-shielded-design.md`), the program contract
  with its pinned design decisions, and every internal adversarial audit report
  including the findings already fixed.
- A reproducible build, benchmarks, and a live multi-node test harness
  (`tools/e2e-vm`) that boots a real isolated chain.

We would rather the engagement spend its hours attacking the circuit than
orienting itself.

## 6. Deliverables

1. Written report: findings with severity, reproduction, and recommended fix.
2. An explicit statement on **AIR soundness and completeness** — not only "no
   bugs found", but what was proven and what was not.
3. The **derived soundness level** in bits under proven bounds, with the
   parameter set required to reach 128.
4. A re-review of fixes.
5. Permission to publish the report.

## 7. Qualification we care about

Demonstrated STARK and AIR experience specifically — not general smart-contract
auditing. Tooling that detects under-constrained circuits is directly relevant.
Familiarity with winterfell, Plonky/Starky, or comparable AIR-based systems is
the discriminator.

## 8. Commercial

Timeline, cost, and scheduling to be proposed. We are pre-arming and not under
release pressure: correctness matters more to us than speed. The pool ships
dormant regardless of audit timing.

**Contact:** cloudzombie/sov maintainer.
