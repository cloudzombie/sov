# PQ Shielded Pool ("pool v2") — Design & Prototype Increment

**Status: PROTOTYPE in tree (`chain/crates/shielded-pq`, crate
`sov-shielded-pq`). NOT wired into consensus. Nothing here is in the trust
path, and nothing here enters it before external audit and parameter
review.** This document updates the posture stated in
[`quantum-posture.md`](quantum-posture.md): the shielded-pool exposure moves
from *"disclosed gap, research track"* to *"prototype in tree"*. The
disclosure there remains normative — Orchard privacy is still
harvest-now-decrypt-later (HNDL) exposed, and this prototype does not change
that for any data already on chain.

## 1. Threat model

The live shielded pool (`sov-shielded`) is Zcash Orchard/Halo2 on the Pallas
curve. Against a cryptographically relevant quantum computer (CRQC):

- **HNDL privacy break.** Orchard note encryption is ECDH-based; recorded
  ciphertexts are decryptable once a CRQC exists. Amounts, recipients and
  linkages of *past* shielded activity become public retroactively. No code
  change can fix data already published.
- **Proof-system soundness break.** Halo2's soundness rests on discrete log;
  a CRQC can forge membership/spend proofs. SOV's supply survives this (the
  conservation turnstile and de-shield drain limiter are consensus-level and
  hash-based — Theorems 5/34), but in-pool theft at a bounded rate becomes
  possible.

Pool v2's goal: a shielded pool whose **soundness and privacy both rest on
hash and lattice assumptions only** — no elliptic curves anywhere in the
trust path.

## 2. The v2 primitive stack, and why each piece is PQ

| Component | Primitive | Why PQ |
|---|---|---|
| Note commitments | Rescue-Prime (`Rp64_256`, winter-crypto) over the Goldilocks field | Hash-based hiding/binding; Grover only halves margins |
| Commitment tree | Depth-20 Merkle over the same hash | Same |
| Nullifiers | PRF `nf = H(nsk, rho)`; ownership via `owner_tag = H(nsk, 0)` | Same |
| Spend proof | STARK (winterfell): FRI + Merkle commitments over Blake3 | Transparent (no trusted setup), hash-based soundness; no pairing/DLOG |
| Note encryption | ML-KEM-768 (FIPS 203, `fips203`) + ChaCha20-Poly1305 | Lattice KEM — the same pair the P2P transport already ships |
| Spend authorization | ML-DSA-65 (FIPS 204, `fips204`) | Lattice signature — the same crate the transparent layer's hybrid keys use |

Deliberate reuse: `fips203`/`fips204`/`chacha20poly1305`/`blake3` are already
in the workspace's trust surface. The only genuinely new dependency is the
winterfell STARK stack (pure Rust, MIT, Meta-origin, actively maintained).

## 3. What this increment PROVES vs what remains

### Proven in-circuit (one winterfell AIR, 21×256 trace, 69 constraints)

For public inputs `(root, nf, value)` the prover knows `nsk`, `rho`, and a
Merkle path such that:

1. `owner_tag = merge(nsk, 0)` — spending requires the nullifier secret, not
   merely knowledge of the note opening (senders cannot spend what they sent);
2. `cm = merge(merge([value,0,0,0], owner_tag), rho)` — the commitment opens
   to the public value;
3. `cm` is a leaf of the depth-20 tree under `root` (Rescue-Prime Merkle
   path, path bits proven binary);
4. `nf = merge(nsk, rho)` — the revealed nullifier is THE nullifier of that
   note (same `nsk`/`rho` registers across all four equations).

All 27 Rescue-Prime permutations (3 commitment/tag + 20 tree levels + 1
nullifier + padding) are executed inside the trace with full round
constraints (degree-7 forward/backward Rescue round identity against the
upstream `ARK1`/`ARK2`/`MDS`/`INV_MDS` constants; a unit test pins our sponge
byte-for-byte to `Rp64_256::merge`).

### Explicitly NOT proven (prototype-unproven, checked natively or deferred)

- **Value conservation is transparent, not zero-knowledge.** Spent values
  are PUBLIC inputs; output notes travel with their openings and the bundle
  verifier recomputes commitments and checks
  `sum(inputs) = sum(outputs) + fee` natively. Amount privacy is therefore
  NOT provided by this increment (recipient/linkage privacy of *who owns
  what in the tree* is).
- **No in-circuit range check** on values (public inputs; the native
  verifier bounds them by `MAX_NOTE_VALUE`).
- **Spend authorization is a carrier ML-DSA-65 signature** over the bundle
  digest, not an in-circuit key check — same carrier-auth model as today's
  design.
- **No per-use hash domain separation** beyond structure (commitment vs tree
  node use the same `merge`); production adds explicit domain tags in the
  capacity.
- **Winterfell deserialization robustness**: a malformed proof header can
  panic (assert) inside `Proof::from_bytes`/options validation rather than
  return an error — must be hardened (catch or pre-validate) before any
  consensus exposure.
- Fixed single-spend circuit shape (one input per proof; bundles carry N
  proofs). Batching/aggregation and a variable-arity circuit are future work.

### Remaining road to a real pool v2

1. Value-hiding conservation in-circuit (Pedersen-style hash commitments to
   values with in-circuit sum check + range proofs — all over the same hash).
2. In-circuit spend authorization (or a PQ signature-over-proof binding that
   removes the carrier-sig malleability surface).
3. Output-note integrity in-circuit (prove output commitments well-formed
   without revealing openings).
4. Encrypted-note well-formedness/scannability decisions (out-of-band vs
   proven).
5. Aggregation (one proof per bundle; recursive or batched FRI).
6. Parameter/toolchain audit: Rescue-Prime instance security margins, FRI
   soundness parameters (currently 42 queries × blowup 8 + 16-bit grinding,
   quadratic extension — 127 bits conjectured, less under *proven* FRI
   bounds), winterfell itself.

## 4. Measured performance (Apple Silicon dev machine, release build)

One spend proof (depth-20 membership + nullifier + commitment opening):

- **prove: ~21 ms**, **verify: ~0.22 ms**, **proof size: ~35 KB**,
  127-bit conjectured security (Blake3 carrier).

For comparison, an Orchard action proof is ~2 KB but curve-based. ~35 KB per
spend is the honest cost of hash-based soundness at these parameters;
aggregation is the lever that makes it block-practical.

## 5. Dual-pool migration plan

The Orchard pool continues unchanged — v2 is **additive**, exactly like every
consensus-adjacent change since genesis (`cb0272ff…` FROZEN):

1. **Dormant landing.** A future `Action::ShieldedV2(...)` variant, byte-gated
   behind a deployment/activation signal (the same miner-signaled,
   genesis-safe pattern as the tx-domain fork). Pre-activation the variant is
   rejected everywhere; serialization of existing types is untouched.
2. **Separate state.** V2 keeps its own commitment tree, nullifier set, and
   value pool with its own conservation turnstile and its own de-shield drain
   limiter — a v2 proof bug can never mint SOV nor touch the Orchard pool.
3. **Migration is user-driven:** v1 → de-shield to transparent → shield into
   v2. (A direct v1→v2 bridge circuit is possible later but is NOT required
   and NOT planned for the first activation.) Users who want their *future*
   activity out of the HNDL window migrate; past chain data remains exposed,
   as `quantum-posture.md` states — that is unfixable by construction.
4. **Sunset (eventually, optional):** once v2 is audited and liquid,
   governance can freeze new v1 shielding while keeping v1 de-shield open
   indefinitely.

## 6. Production-readiness criteria (the honest bar)

Pool v2 does NOT ship to consensus until ALL of:

- External audit of the circuit (AIR soundness — completeness AND soundness
  of every constraint), the native verifier, and the migration/state code.
- Independent parameter review: Rescue-Prime instance, FRI parameters under
  proven (not conjectured) soundness bounds, Goldilocks-field security
  margins with the quadratic extension.
- The winterfell dependency pinned + reviewed (or replaced by an audited
  prover), and its deserialization panic-hardened.
- Value-hiding conservation in-circuit (§3 item 1) — a shielded pool with
  public amounts is not an acceptable end state.
- Proof-size/throughput budget accepted: at ~35 KB/spend, a 2 MB blockspace
  budget carries ~55 spends/block unaggregated; either aggregation lands or
  the budget is explicitly ratified.
- KATs frozen and cross-checked from a second implementation (same bar as
  the transparent layer's KAT discipline).

Until then this crate is a measuring stick and a forcing function — real
proofs, real numbers, honestly labeled.
