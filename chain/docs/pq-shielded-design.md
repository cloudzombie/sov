# PQ Shielded Pool ("pool v2") — Design & Prototype Increment

**Status: consensus-grade CIRCUIT in tree (`chain/crates/shielded-pq`,
crate `sov-shielded-pq`) — v0.2.0 program slices S1a (in-circuit value
privacy, 4-in/4-out) and S1b (full domain separation) landed. NOT wired
into consensus. Nothing here is in the trust path, and nothing here enters
it before external audit and parameter review (v0.2.0 ships it DORMANT
behind BIP-9 bit 2; see `notes/v0.2.0-program.md`).** This document updates the posture stated in
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
| Note commitments | Domain-separated Rescue-Prime (`Rp64_256`, winter-crypto) over the Goldilocks field | Hash-based hiding/binding; Grover only halves margins |
| Commitment tree | Depth-20 Merkle over the same hash (own domain) | Same |
| Nullifiers | PRF `nf = H_NF(nsk, rho)`; ownership via `owner_tag = H_TAG(nsk, 0)` | Same |
| Spend proof | STARK (winterfell): FRI + Merkle commitments over Blake3 | Transparent (no trusted setup), hash-based soundness; no pairing/DLOG |
| Note encryption | ML-KEM-768 (FIPS 203, `fips203`) + ChaCha20-Poly1305 | Lattice KEM — the same pair the P2P transport already ships |
| Spend authorization | ML-DSA-65 (FIPS 204, `fips204`) | Lattice signature — the same crate the transparent layer's hybrid keys use |

Deliberate reuse: `fips203`/`fips204`/`chacha20poly1305`/`blake3` are already
in the workspace's trust surface. The only genuinely new dependency is the
winterfell STARK stack (pure Rust, MIT, Meta-origin, actively maintained).

## 3. What the circuit PROVES vs what remains

### Proven in-circuit (one winterfell AIR, 31×1024 trace, 129 transition constraints)

One proof covers a whole **4-in/4-out bundle** (D2; unused slots are
in-circuit dummies). Public inputs — the COMPLETE set, nothing else leaks:

| public input | meaning |
|---|---|
| `anchors[4]` | per-input tree root (zero digest for dummy slots; inputs may use different anchors, D5 — anchor-RING acceptance is the native verifier's job) |
| `nullifiers[4]` | per-input revealed nullifier (zero for dummies) |
| `input_dummy[4]` / `output_dummy[4]` | public dummy flags (leak the bundle's arity ≤ 4 and nothing else) |
| `output_commitments[4]` | per-output note commitment (zero for dummies) |
| `transparent_in` / `transparent_out` | the two unsigned halves of the signed net transparent value balance |
| `fee_grains` | transparent fee |

For those publics the prover knows witnesses such that (all hashes
domain-separated Rescue-Prime merges, domains in `src/domains.rs`):

1. **Per real input**: `owner_tag = H_TAG(nsk, 0)` (ownership — senders
   cannot spend what they sent); `cm = H_C2(H_C1([v,0,0,0], owner_tag), rho)`
   with the value `v` a PRIVATE witness; `cm` is a depth-20 Merkle leaf
   under that input's public anchor (path bits proven binary); the revealed
   nullifier is `H_NF(nsk, rho)` with the same `nsk`/`rho` registers across
   all equations.
2. **Per real output**: the public commitment opens to a hidden
   `(value, owner_tag, rho)` — output-commitment integrity in-circuit,
   values private.
3. **Dummy slots**: value proven ZERO (asserted on the committed value
   register); the dummy's nullifier hash runs under a DISTINCT domain
   (`DUMMY_NF`) so it can never collide with a real nullifier; its
   Merkle/nullifier rows are unconstrained junk that the verifier never
   surfaces (dummy anchors/nullifiers/commitments are the zero digest by
   convention, enforced natively).
4. **61-bit range check on every value** (8 registers): MSB-first
   double-and-add bit decomposition, every bit boolean-constrained, the
   accumulator asserted to start at 0 and constrained to land exactly on
   the value register.
5. **Value conservation IN-CIRCUIT and value-hiding** (D1):
   `Σ v_in + t_in = Σ v_out + t_out + fee` over the private registers with
   only the three transparent legs public.

**Field-arithmetic soundness of the sum (D3, adjusted):** Goldilocks
`p = 2^64 − 2^32 + 1` is smaller than 2^64, so sums of four full u64s CAN
wrap `p` — a "64-bit" range check would be unsound here. Values are
therefore range-checked to **61 bits** (`MAX_NOTE_VALUE = 2^61 − 1`, still
~2^10 × total supply) and the public legs are bounded `≤ MAX_NOTE_VALUE`
natively before verification; both sides of the identity are then integers
`< 6·2^61 < p`, so field equality is integer equality. The full argument
lives in `src/note.rs` (with a numeric test).

All Rescue-Prime permutations (4×24 input cycles + 4×2 output cycles +
padding) are executed inside the trace with full round constraints
(degree-7 forward/backward Rescue round identity against the upstream
`ARK1`/`ARK2`/`MDS`/`INV_MDS` constants; a unit test pins our sponge
byte-for-byte to `Rp64_256::merge` at the reserved domain 0). Injection
rows stamp each phase's DOMAIN into sponge capacity element 1, so the
domain separation is itself constraint-enforced.

Every constraint family has a NEGATIVE test that breaks it and observes
REJECT (`tests/kat.rs`): wrong value sum, out-of-range value (a fully
consistent 2^61 forgery), non-boolean range-check digit, dummy with nonzero
value, wrong anchor, tampered nullifier/output commitment, flipped dummy
flags, wrong Merkle path, foreign note, flipped/truncated proof bytes.
Witness-side tests assert the EXACT violated constraint index in debug and
full prover→verifier rejection in release.

### Domain separation (S1b)

Every hash use has a distinct, named domain in ONE module
(`src/domains.rs`): in-circuit Rescue domains (owner-tag, commit-stage-1,
commit-stage-2, merkle-node, nullifier, dummy-nullifier; capacity-element
tagging, domain 0 reserved for the upstream pin) and blake3 `derive_key`
domains (nsk, rho, auth-keygen, auth-sign, note-AEAD, detection-tag,
bundle-digest, test). A test proves cross-domain outputs differ for
identical inputs, for every pair, in both families. Note ciphertexts now
carry the D7 4-byte detection checksum
(`blake3_derive_key(detect, shared_secret)[..4]`), checked before any AEAD
work so wallet trial-decapsulation scanning stays ~µs per foreign note.

### Total deserialization + proof_version gate (S1c) — hardened

The D15 BLOCKER (a malformed proof header could PANIC inside
`winterfell::Proof::from_bytes` — in consensus, a remote crash DoS from
any peer) is closed. All bundle/proof deserialization is now TOTAL: every
malformed input returns a typed `Err`, never panics, never aborts.

- **Audited upstream hazards** (winterfell 0.13.1, documented in
  `src/proof_frame.rs`): `ProofOptions::new` / `PartitionOptions::new` /
  `TraceInfo` asserts reachable from `read_from` (a one-byte option-header
  corruption panics — reproduced by the
  `raw_winterfell_decode_panics_on_corrupt_option_header` evidence test),
  a `2^trace_length_byte` overflow, and `Vec::with_capacity(len)` on
  attacker-declared vint lengths up to `u64::MAX` in the query sections
  (at best a catchable "capacity overflow" panic, at worst an uncatchable
  allocation abort).
- **Catch-free pre-validator** (`proof_frame::validate_proof_frame`):
  before winterfell sees any bytes, the full proof layout is walked with a
  total bounds-checked cursor — size cap (128 KiB), the proof context
  byte-pinned to the canonical context an honest prover emits for this
  circuit + public dummy pattern (killing every header assert path), every
  declared section length checked against the bytes actually present
  (killing the allocation paths), unique-query count bounded, trailing
  bytes rejected. `prover::decode_proof` is the single decode entry point;
  it additionally wraps the winterfell decode in `catch_unwind` as a LAST
  line of defense (typed `DecodePanic`, asserted unreachable by the fuzz
  targets).
- **proof_version gate (D6)**: the v1 bundle wire format (`src/wire.rs`)
  starts with a `proof_version` byte; v0.2.0 = 1; any other version is a
  clean typed reject (`WireError::UnknownProofVersion`), never a panic,
  never a silent skip. The codec is total AND canonical (strict flags,
  canonical digest encodings, exact lengths, no trailing bytes):
  `encode(decode(b)) == b` for every accepted `b`. New wire KATs pinned
  (publics header, canonical context bytes, note-ciphertext encoding) —
  these are NEW pins, not re-pins: the bundle had no wire format before
  S1c.
- **Fuzzed** (`fuzz/` sub-crate, libFuzzer via cargo-fuzz on nightly,
  curated seed corpus committed): 60 s per target on the dev machine,
  ZERO crashes/panics/leaks — `fuzz_bundle_decode` 2,428,702 execs,
  `fuzz_proof_decode` 1,024,107 execs, `fuzz_note_ciphertext_decode`
  8,633,735 execs. A deterministic structured-random hammer
  (`random_and_mutated_inputs_never_panic`, ~12k inputs) lives
  permanently in `cargo test` for toolchains without nightly.

### Explicitly NOT proven (deferred, with owners)

- **Spend authorization is a carrier ML-DSA-65 signature** over the full
  public-input set + output ciphertexts (D4), not an in-circuit key check.
  In-circuit spend auth is a future proof_version (pinned trade-off).
- **Dummy flags are public**: bundle arity (≤ 4 per side) is visible.
  Values, owners, and linkages are not.
- **Parameter review to a written 128-bit target** (S1d, pending): current
  FRI parameters are 42 queries × blowup 8 + 16-bit grinding, quadratic
  extension — 127 bits conjectured, less under proven FRI bounds.
- Global nullifier double-spend tracking, the anchor ring, turnstile, and
  drain limiter are consensus state (W2) — the bundle verifier here takes
  the valid-anchor set as an argument and leaves state to the caller.

### Remaining road to a real pool v2

1. ~~Value-hiding conservation in-circuit~~ — **DONE (S1a, proven
   in-circuit with negative tests).**
2. ~~Output-note integrity in-circuit~~ — **DONE (S1a).**
3. ~~Proof deserialization hardening + fuzz~~ — **DONE (S1c: total
   decoders, proof_version gate, fuzzed with zero crashes).** Parameter
   review (S1d) remains pending.
4. In-circuit spend authorization (future proof_version, per D4).
5. Consensus wiring, keys/addresses, wallet, RPC/CLI/KAT/SDK, Station (W2–W5).
6. Aggregation (recursive or batched FRI) if throughput demands it.

## 4. Measured performance (Apple Silicon dev machine, release build)

One 4-in/4-out bundle proof (4× depth-20 membership + nullifiers +
commitment openings, 8× 61-bit range checks, hidden-value conservation):

- **prove: ~25 ms**, **verify: ~0.7 ms**, **proof size: 55,054 bytes**,
  127-bit conjectured security (Blake3 carrier).

(The earlier single-note prototype was ~21 ms / ~0.22 ms / ~35.5 KB — the
bundle circuit carries 4 inputs + 4 outputs in ONE proof, so per-spend cost
went DOWN.) An Orchard action proof is ~2 KB but curve-based; ~55 KB per
bundle is the honest cost of hash-based soundness at these parameters.

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
  prover). (Its deserialization is panic-hardened as of S1c — total
  pre-validated decode + fuzz evidence; the audit still owns confirming
  it.)
- Proof-size/throughput budget accepted: at ~55 KB per 4-in/4-out bundle,
  a 2 MB blockspace budget carries ~36 bundles (up to 144 spends) per block
  unaggregated; D10 owns the size-cap audit.
- KATs frozen and cross-checked from a second implementation (same bar as
  the transparent layer's KAT discipline).

Until then this crate is a measuring stick and a forcing function — real
proofs, real numbers, honestly labeled.
