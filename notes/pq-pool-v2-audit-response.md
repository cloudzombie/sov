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

3. *It was not a gate.* Nothing in `scripts/` or `.github/` invoked the harness
   at all, so it could not block anything. `release.yml` now carries an `e2e`
   job that runs the five-node matrix with `--require-complete`, and every
   build job `needs: [gate, e2e]` — so a tag cannot produce artifacts unless
   the suite ran with zero failures AND zero skips. The job also re-reads the
   emitted report and fails if any step is not `pass`, because the report is
   the artifact humans read and it must agree with the exit code.

   It runs on the release path rather than every push because it mines a real
   chain to a real activation height (~25 minutes) — not a per-commit cost, but
   exactly what a tag should have to earn.

**Status:** verified GREEN end to end — 15 steps, 0 failed, 0 skipped, exit 0
under `--require-complete`, with the full pool-v2 lifecycle (shield, private
send, de-shield, v1->v2 migration) driven through real STARK proofs and real
consensus on a live five-node chain.

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
  should be settled before any public security statement. **RESTATED +
  QROM-SCOPED — see the resolution below.**
- **PQV2-06** — cross-network replay protection depends on an activation
  ordering consensus does not enforce. **FIXED** — see the resolution below.
- **PQV2-07** — the declared proof-verification block weight is not enforced by
  block production or import. Mempool admission is weight-aware as of the
  v0.2.2 branch, but import-side accumulation and recomputation are not.
- **PQV2-08** — security/performance regression checks have drifted.

## PQV2-06 — cross-network replay, resolution (2026-07-28) — **FIXED**

**The vector.** A pool-v2 bundle's only network-independent binding was the
carrier ML-DSA-65 signature over
`carrier_sighash(scheme ‖ len(signer) ‖ signer ‖ nonce ‖ bundle_digest)` — it
bound `{signer, nonce}` and the bundle contents, but NOT the network. The STARK
proof binds note math, also network-independent. So the whole
`Action::ShieldedV2 { bundle }` was network-agnostic. The ONLY thing stopping a
cross-network replay was the *carrier transaction's own signature* being
chain-bound — which is true only once the `tx-domain` fork reaches `Bound`
mode. `carrier.rs` even documented this dependency in prose. Nothing in
consensus requires `tx-domain` to be active before/with `shielded-v2`: that is
the unenforced activation ORDERING the finding names.

Worked scenario: networks A (`sov-mainnet`, genesis `GA`) and B
(`sov-testnet-1`, genesis `GB`), both with `shielded-v2` Active but `tx-domain`
still `Legacy` (or in its `Grace` window, where a legacy carrier signature is
accepted). `usa.reserve.sov` builds a shield/de-shield on A, carrier-bound to
`{usa.reserve.sov, nonce N}`, carrier tx legacy-signed. The identical
transaction bytes are submitted to B: the carrier signature verifies under B's
legacy preimage (same implicit id from the same pubkey, nonce N available on B),
the ML-DSA carrier auth verifies (signer+nonce match; no network in the
preimage), the STARK verifies. Where B's pool holds the referenced anchor (a
fork of A, or a parallel-funded pool) the bundle executes on B — a de-shield
drains B's pool; a shield mints B-side notes. Protection existed only because
someone assumed `tx-domain` would be `Bound` first.

**The fix (intrinsic, not ordering-dependent).** The carrier sighash now folds
this chain's identity into the signed message:

```text
sighash = blake3_derive_key(B3_CARRIER_BINDING,
    scheme(2) ‖ len(chain_id) ‖ chain_id ‖ genesis(32)
              ‖ len(signer) ‖ signer ‖ nonce ‖ bundle_digest)
```

- `chain/crates/shielded-pq/src/carrier.rs` — `CarrierContext` gains
  `chain_id: &[u8]` and `genesis: &[u8; 32]`; `carrier_sighash` binds them
  (injective: both variable fields length-prefixed, all else fixed-width). The
  scheme byte moves `1 → 2` (`SCHEME_DOMAIN_SIGNER_NONCE`); the old
  `{signer,nonce}`-only scheme is retired (it never authorized a bundle on any
  chain — bit 2 is dormant everywhere — so nothing is stranded). `bundle_digest`
  and its KATs are UNCHANGED: the network binding wraps, it does not replace.
- `chain/crates/runtime/src/shielded_v2.rs` — `verify_bundle_for_carrier` takes
  a `&SigningDomain` and builds the `CarrierContext` from it. The domain is the
  chain's own `{chain_id, genesis}`, sourced from the chain identity (a new
  always-populated `BlockContext::chain_domain`, `Blockchain::chain_domain()`),
  NOT from `tx_domain` mode — so the guard holds whatever `tx-domain` has or has
  not done. This is the key point: the protection is now self-sufficient and no
  activation-ordering invariant is required or assumed.
- `chain/crates/rpc` — `sov_getChainDomain` (always available, unlike the
  activation-gated `sov_getSigningDomain`) + `RpcClient::chain_domain()`; the
  `sov-wallet` v2 submit path binds bundles to it. The e2e harness drives v2
  through this CLI, so it exercises the real binding.

**The proof it was real.** A consensus-layer test,
`a_bundle_valid_on_network_a_is_refused_on_network_b` (in `shielded_v2.rs`),
builds a bundle authorized for network A and imports the identical bytes under
network B's domain (differing chain id) and under a fork's domain (same id,
different genesis). Temporarily reverting the network binding in
`carrier_sighash` makes this test FAIL with the replay accepted
(`Ok(V2Effects { … shield_in: 500000000 grains … })`); with the fix it
hard-rejects both with `ShieldedV2Error::CarrierAuth`. Companion unit tests
added in `carrier.rs` and `wallet.rs`.

**Why it is safe while dormant.** Bit 2 is UNARMED on every canonical chain, so
no `Action::ShieldedV2` has ever been accepted and no carrier signature is
frozen in any history — the sighash is free to change. `chain_domain` is read
only on the (dormant) v2 path, so no historical/current block outcome changes:
the consensus KAT vectors reproduce byte-for-byte
(`sov-verify` `kat_vectors_are_reproduced_byte_for_byte` green) and the genesis
hash is untouched. After arming, this binding is part of the hard fork.

**Verification (real output).**
- `cargo test -p sov-shielded-pq -p sov-runtime` — green (runtime lib incl. the
  11 `shielded_v2::tests`; shielded-pq lib + `kat` 23/23 + security/verify-cost).
- Pre-fix vs post-fix on the replay test: `FAILED` (replay accepted) → `ok`.
- `cargo fmt --check` and `cargo clippy --all-targets -D warnings` clean on
  `sov-shielded-pq`, `sov-runtime`, `sov-chain`, `sov-rpc`.
- `sov-verify` KAT byte-for-byte green (dormancy/byte-identity).
- The five-node E2E was NOT run in this environment (it mines a real chain to a
  real activation height, ~25 min); the CLI build path it drives is wired and
  compiles.

## PQV2-04 — depth-20 tree exhaustion, resolution (2026-07-28) — **boundary FIXED; capacity UPGRADED to depth 32 (code-complete, pending external audit)**

The finding has two halves. One is a correctness bug and is fixed; the other was
a capacity/sizing limit that pricing could not solve. As of this session BOTH
are resolved in code: the tree is deepened to the horizon-safe depth 32 in a
re-derived, re-proven STARK spend circuit. The depth upgrade is code-complete and
carries the same "pending the external audit that gates arming" caveat as the
rest of pool v2 — it is no longer an open prerequisite blocking the circuit work,
only the audit.

**Update (depth-32 upgrade, 2026-07-28).** `TREE_DEPTH` is now
`HORIZON_SAFE_TREE_DEPTH` = **32** (asserted equal at compile time). The spend
circuit was re-derived so the Merkle-verify segment proves a full 32-deep
authentication path: `INPUT_SEGMENT_ROWS`, `root_row`, `nf_row` and
`TRACE_LENGTH` are now DERIVED symbolically from `TREE_DEPTH` (no depth literals;
compile-time guards pin the geometry), the trace grew 1024 → **2048** rows, and
every proof/param KAT was regenerated from freshly MEASURED values. The circuit
is proven to actually CONSTRAIN the deep path by a negative test
(`spend_circuit_constrains_the_full_32_deep_path`): a proof over a tampered
level-28 node — a level that exists only because depth is 32 — does not verify
under the honest anchor, while an honest 32-deep spend does. Measured deltas
(release, Apple Silicon): proof **98,494 → 107,453 bytes**; verify median
**~0.9 → 1.60 ms** (16 ms weight budget still ~10× over); prove ~68 ms; proven
classical soundness unchanged at **128 bits** (`>=128` floor green). All KAT
changes are explained by the depth increase and nothing else (see the per-KAT
justifications in code); the trailing constraint-count vint in the canonical
context byte-string is IDENTICAL, confirming the deeper path added trace ROWS via
masked reuse of the same constraints, not any new constraint. Everything remains
DORMANT: bit 2 UNARMED, no v2 action executes, the non-v2 consensus KAT
(`sov-verify`) stays green.

**Half 1 — the `root()` / capacity boundary bug — FIXED (already on `main`).**
The depth-20 frontier is an O(depth) encoding of "one ommer per set bit of
`size`". At exactly `size == 2^20` every low bit is zero, so the frontier walk
would return the EMPTY-tree root for a FULL tree — a full-pool anchor colliding
with the empty-pool anchor. Fixed by capping usable capacity at
`MAX_V2_NOTES = MAX_TREE_LEAVES = 2^20 − 1` (the final leaf slot is deliberately
unusable), with a compile-time guard `MAX_V2_NOTES < 2^TREE_DEPTH`. Both mutators
(`append_commitment`, `apply`) reject the insertion that would reach exact
capacity with a typed `TreeFull`, mutating nothing. This landed in
`fix(pool-v2 consensus): the frontier CANNOT hold 2^20 notes` (commit `d999ebd`)
and is proven — not by an early refusal — by
`frontier_matches_the_reference_tree_at_full_capacity` (release-only), which
appends `2^20 − 1` REAL leaves and asserts the frontier root equals the
reference tree's root at full capacity, is NOT the empty root, and that one more
append is `TreeFull`. Re-verified this session: **1 passed** in 68 s.

**Half 2 — economic/growth exhaustion — QUANTIFIED; pricing floor pinned; the
real fix is a deeper tree (out of scope here) and it GATES arming.**

*The number, traced from code (post-activation, mainnet schedule):*
- Fee model: `fee = gas_for(action) × gas_price`, paid transparently from the
  carrier (the in-circuit fee leg is pinned to zero in proof_version 1), to the
  miner (not burned). `gas_price` mainnet = **10 grains/gas**
  (`MiningPolicy::mainnet_like`). `GRAINS_PER_SOV = 10^8`.
- `gas_for(ShieldedV2) = INTRINSIC_GAS (21,000) + SHIELDED_V2_VERIFY_GAS
  (500,000) + bundle.len()·16 (+ hybrid envelope if a PQ carrier)`.
- Each bundle appends at most `NUM_SLOTS = 4` real output commitments (leaves).
- Conservative per-bundle floor (fixed terms only, ignoring bundle bytes and a
  possible V1 carrier's zero envelope): `521,000 gas × 10 = 5,210,000 grains =
  0.0521 XUS`; per commitment `0.013 XUS`.
- Filling `2^20 − 1` leaves needs `⌈1,048,575 / 4⌉ = 262,144` bundles ⇒
  **≥ ~13,657 XUS** in fees at the floor, **~39,000 XUS** counting the ~60 KB of
  bundle bytes each tx carries.
- Rate/time floor: block weight bounds a block to
  `MAX_V2_COMMITMENTS_PER_BLOCK = 160` commitments, so the fill also takes
  `⌈1,048,575 / 160⌉ = 6,554` consecutive blocks ≈ **11.4 days** the attacker
  must WIN the blockspace auction against all other traffic.

*Verdict.* The attacker's gain is pure griefing (fees enrich miners; funds are
never lost — holders can still de-shield out), and the floor is not trivial, so
the tree is not *cheaply* bricked. But depth-20 is a **prototype** capacity: it
is exhaustible for a bounded, finite one-time cost (~13.6k–39k XUS + ~11 days),
AND by honest growth alone (1.05M notes is months-to-a-few-years of real
adoption). Pricing cannot fix honest exhaustion, and inflating gas to price the
attack out would distort legitimate use. The robust fix is a **deeper tree**:
sizing capacity from the issuance/confirmation horizon
(`MAX_V2_COMMITMENTS_PER_BLOCK × ~20 years of blocks ≈ 6.7×10^8` leaves ⇒ depth
~30) gives Orchard-parity depth **32** (`HORIZON_SAFE_TREE_DEPTH`), 4.29×10^9
leaves, >6× headroom.

*The depth change, now SHIPPED (reserve-grade).* Raising `TREE_DEPTH` was a STARK
**spend-circuit** re-derivation, not a constant bump: the AIR trace row-map used
to bake the Merkle path length into fixed literals. That is now gone — the row
map is derived from `TREE_DEPTH` symbolically:
`INPUT_SEGMENT_ROWS = (3 + TREE_DEPTH + 1)·CYCLE_LENGTH`,
`root_row = input_base + (3 + TREE_DEPTH)·CYCLE_LENGTH − 1`,
`nf_row` at `(4 + TREE_DEPTH)·…`, and `TRACE_LENGTH = ACTIVE_ROWS.next_power_of_two()`,
each pinned by a `const _: () = assert!(…)` so no literal can silently assume the
old depth again. Depth 32 pushed the input segment 24 → 36 cycles and doubled the
trace 1024 → 2048; every proof KAT and the *measured* verify-cost basis behind
`SHIELDED_V2_VERIFY_WEIGHT` were regenerated from real measurements. Soundness of
the extended path is not assumed but tested (the level-28 tamper negative test).
This is a deliberate, re-proven change to the trust path; it still awaits the
same **external audit** as the rest of pool v2 before bit 2 is armed.

*What this PR implements.* (1) `TREE_DEPTH` 20 → 32 with the whole AIR/prover
row-map re-derived symbolically and guarded. (2) The economic floor re-pinned at
the new depth: `pool_v2_exhaustion_has_a_pinned_fee_floor` now shows filling the
tree costs ~55.9M XUS — **more than the entire ~21M-XUS money supply (~2.6×)**, so
exhaustion is economically impossible, not merely expensive; and
`filling_the_tree_takes_decades_of_saturated_blocks` shows ~26.8M blocks ≈ **127
years** of sustained saturation (was 6,554 blocks / ~11 days at depth 20). (3)
The boundary is proven algebraically (a literal 2^32 fill is infeasible):
`capacity_boundary_is_exact_for_real_appends_at_the_real_depth` and
`a_state_at_full_capacity_never_reports_the_empty_root` (real append at a faked
`MAX_V2_NOTES − 1` plus the `size == 2^depth` collision argument), plus the
exhaustive small-depth frontier↔reference equivalence and a many-thousand-append
deep-prefix pin at the real depth. (4) `TREE_DEPTH == HORIZON_SAFE_TREE_DEPTH`
asserted at compile time — the "prototype depth" era is over.

*Why it is safe while dormant.* Bit 2 is UNARMED on every canonical chain
(`shielded_v2_is_dormant_everywhere` green), so no v2 action executes and no
`Action::ShieldedV2` has ever been accepted — there is no historical v2 proof to
preserve, so re-deriving every v2 KAT is free. The non-v2 consensus KAT
(`sov-verify::kat_vectors_are_reproduced_byte_for_byte`) is untouched and green:
genesis and the transparent path are unaffected.

**Status:** boundary FIXED and proven; economics now horizon-safe; the depth
upgrade to `HORIZON_SAFE_TREE_DEPTH` = 32 is **code-complete and re-proven**,
pending the same external audit as the rest of pool v2. PQV2-04 is therefore
**resolved in code** — no longer a circuit-work blocker on the arming bar, only
the audit remains.

## PQV2-05 — "128-bit post-quantum" claim, resolution (2026-07-28) — **RESTATED; QROM analysis SCOPED-AND-PENDING (accepted in writing)**

The finding is a claims-accuracy issue, and this is the claims-accuracy fix. No
crypto was changed, no QROM proof was fabricated. `proof_options()` and the FRI
parameters are byte-for-byte unchanged; this is documentation and comment text
plus one relabeled table, no behavior/consensus/digest change.

**The overstatement, precisely.** The tree derives 128 "proven" soundness bits
for the shipped parameters (64 FRI queries, blowup 16, 16 bits grinding, cubic
extension over Goldilocks). "Proven" there meant *proven vs conjectured* FRI
soundness — the unconditional Johnson/list-decoding bound rather than the
capacity conjecture. Both are **classical** bounds. Nowhere did the tree
distinguish that classical soundness figure from a post-quantum (QROM) one, so
"128-bit PROVEN" read as if it were an established post-quantum guarantee. It is
not.

**What is genuinely established PQ (NOT downgraded).** Kept exactly as true:
the hybrid ML-DSA-65 (FIPS 204) spend authorization and hybrid ML-KEM-768
(FIPS 203) note encryption (`chain/docs/quantum-posture.md`), and the fact that
the proof rests on hashes only (Rescue-Prime + Blake3) with **no Shor-breakable
number-theoretic assumption** — a real advantage over the curve-based v1 pool.
That removes the catastrophic total break.

**What was overstated and is now precise.** Using only hash primitives does not
by itself yield a *quantified* post-quantum soundness level. Two gaps, neither
assigned a number (the finding explicitly warned against asserting one we cannot
back): (1) the QROM soundness of the Fiat-Shamir-transformed FRI/STARK at these
parameters has not been analyzed; (2) a quantum adversary gets Grover-type
speedups against the 16-bit grinding (→ at most ~8 bits) and against the
hash-based commitments (Grover preimage / BHT collision), eroding margins by an
amount we do not quantify here.

**Where it was restated (every occurrence found and corrected):**
- `chain/crates/shielded-pq/src/prover.rs` — `proof_options()` docstring: table
  columns relabeled "conjectured (classical)" / "proven (classical)"; the
  headline is now "128 bits of proven CLASSICAL soundness"; the old one-liner
  "Soundness rests on hashes only: no number-theoretic assumption a quantum
  adversary could break" is expanded into an explicit "what 128 is and is NOT"
  block naming the QROM gap and the Grover erosion, and keeping the genuine
  no-Shor-target advantage.
- `chain/crates/shielded-pq/src/lib.rs` — the "128-bit parameter review (S1d)"
  bullet now states the 128 is a classical FRI bound and QROM soundness is a
  separate pending analysis.
- `chain/docs/pq-shielded-soundness.md` — §10 opens with a "every number here is
  a CLASSICAL bound" note; §8 gains item 8.7 (post-quantum soundness NOT
  established, with the two gaps).
- `chain/docs/quantum-posture.md` — the STARK-pool paragraph now names pool v2
  and states plainly that hash-only primitives remove the Shor break but do not
  establish a post-quantum soundness *level*; no "128-bit post-quantum" claim is
  warranted until the QROM analysis is done.
- test comments (`tests/security_level.rs`, `tests/decode_hardening.rs`) that
  said "128-bit PROVEN security" now say "PROVEN CLASSICAL soundness (not
  post-quantum)".

No user-facing surface (Station GUI, CLI help, explorer, release notes, README)
was found to make a "128-bit post-quantum" claim about pool v2 — the release
notes correctly describe the pool only as "dormant and incomplete". So the
claim lived entirely in the crate docs/comments and the two design docs, all
corrected above.

**The QROM analysis is scoped, not done.** `notes/audit-scope-pq-pool.md` §9
now specifies exactly what a post-quantum soundness analysis of the spend proof
must cover before any public "post-quantum secure" claim or before arming bit 2:
QROM Fiat-Shamir soundness (round-by-round / state-restoration) at the shipped
parameters, Grover erosion of grinding, Grover/BHT erosion of the hash
commitments, the QROM query model for challenge derivation, and a single
reconciled bit figure with the parameter set that reaches a written
post-quantum target (or a precise statement of why one cannot yet be asserted).

**Disposition (explicit written acceptance — one of the two allowed ways to
clear a Medium per this doc).** PQV2-05 is cleared as a *claims-accuracy* Medium:
the overstated claims are restated conservatively and correctly across the tree.
The underlying **QROM analysis is ACCEPTED as scoped-and-pending** and is added
to the arming bar below: no public "post-quantum secure" statement about pool v2,
and no arming of bit 2, until `audit-scope-pq-pool.md` §9 is completed with a
derived post-quantum soundness level (or an explicit finding that it cannot be
asserted, with the gap named). The classical parameter review (S1d) remains a
separate pending slice; this finding does not close it and does not claim to.

**Why it is safe while dormant.** Docs, comments, and one relabeled table only —
no code path, constant, FRI parameter, gas value, or digest changed.
`proof_options()` is byte-identical, so every proof KAT and the consensus KATs
reproduce unchanged. Bit 2 is UNARMED on every canonical chain.

**Verification (real output).** `cargo build --workspace` green (documentation/
comment-only changes; see the PR body / agent report for the tail). `cargo fmt
--check` clean on the touched crate.
## PQV2-08 — regression checks have drifted, resolution (2026-07-28) — **FIXED**

*The finding.* The pool-v2 security/performance regression guards had drifted off
the parameters actually shipped, and several security-critical surfaces had no
regression pin at all. A silent parameter change could therefore regress proven
security (128 → as low as 75 bits) or the proof size / weight derivation with **no
failing test** while the pool is dormant.

*Drift inventory and evidence (each verified by running the tests, not guessed):*

1. **Mislabeled security report** (`tests/security_level.rs`). The report line read
   `"42 queries, blowup 8, 16 grinding, quadratic ext"` while the code below it
   measured the SHIPPED options via `proof_options()`. Evidence: the measured
   output is `conjectured 128 / proven(ldr) 128`, which is the **64q / blowup 16 /
   cubic** row of the sweep — the quadratic/8/42 set measures 127/75. The label
   described the OLD set. → relabeled to the real parameters.

2. **No floor pin on the security level** (`security_level.rs`). The reporting test
   asserted *nothing* ("asserting a target would move the goalposts"). That reasoning
   is wrong for a *floor*: the entire 42q→64q / quadratic→cubic evolution existed to
   raise **proven** security 75→128. A silent revert would drop proven security to 75
   with every test still green. → added `assert!(conjectured.bits() >= 128)` and
   `assert!(proven.ldr_bits() >= 128)` (measured today: 128 / 128). A `>=` floor can
   only catch a downward regression, never bless a change.

3. **Proof parameters not build-time-guarded** (`src/prover.rs`). `proof_options()`
   inlined `64, 16, 16, Cubic` as bare literals — a runtime-only fact. → extracted
   `FRI_NUM_QUERIES=64`, `FRI_BLOWUP_FACTOR=16`, `FRI_GRINDING_BITS=16`,
   `FRI_EXTENSION_DEGREE=3` with `const _: () = assert!(…)` build-time guards (same
   structural discipline as the PQV2-03 anchor-ring floor). Proven by experiment: a
   one-line edit to `42` fails the BUILD with `evaluation panicked: FRI query count
   moved off 64` — not a test nobody ran.

4. **Claimed-but-absent proof-size pin** (`tests/verify_cost.rs` + `tests/kat.rs`).
   `verify_cost.rs` stated the exact proof size "is pinned by the KAT suite" — but
   **no such pin existed**; only the loose `<= MAX_PROOF_LEN` bound was checked, so a
   parameter/winterfell change could move the size (and the weight/gas derivation)
   unnoticed. → added `kat_proof_size_pinned` pinning the deterministic proof length
   to **98494 bytes** (measured; STARK proofs are Fiat-Shamir-deterministic, so this
   is a true known-answer, not a machine-dependent number), and corrected the stale
   `verify_cost.rs` reference. Also corrected the `prover.rs` doc table (it claimed
   94.3 KB; the shipped `prove_bundle` output is 96.2 KB / 98494 B — a stale figure
   from before the PQV2-01 width 31→32 growth).

5. **No byte-KAT on the carrier network binding** (`src/carrier.rs`, PQV2-06). Every
   carrier test re-derived the sighash through the same code, so they were mutually
   self-consistent: a silent change to the preimage layout, the scheme byte, or the
   `B3_CARRIER_BINDING` domain would keep them ALL green while changing the authorized
   message. → added `carrier_sighash_byte_kat_pinned`, pinning the exact sighash for a
   fixed input and asserting `SCHEME_DOMAIN_SIGNER_NONCE == 2`.

*Already-covered surfaces (left as-is):* the note-commitment / tree-root / nullifier /
owner-tag digest KATs (`kat.rs`), the canonical proof-context KAT already carrying the
`40 10 10 03` = 64/16/16/cubic option bytes with justification (`decode_hardening.rs`),
the PQV2-01 leaf-position double-spend vectors, and the PQV2-03 tree-exhaustion const
floor (`state.rs`) all already pin their respective invariants.

*No KAT/security constant was re-blessed to make a test pass.* The one changed constant
is the corrected report LABEL (drift 1); every added pin was captured from a freshly
measured, deterministic value and justified above. No consensus behavior, gas, digest,
or activation state changed — only the guards around them. Bit 2 remains UNARMED.

## Bar for arming bit 2

Unchanged and not met: every Medium resolved or explicitly accepted in writing,
the five-node suite wired as a required job and green with **zero** skips, and
the external circuit audit (`notes/audit-scope-pq-pool.md`) completed with its
findings closed. Pool v2 ships DORMANT in v0.2.2 regardless.

PQV2-04 (depth) — **RESOLVED IN CODE (2026-07-28), audit-pending.** The
note-commitment tree is now the horizon-safe depth 32
(`TREE_DEPTH == HORIZON_SAFE_TREE_DEPTH`), a re-derived and re-proven STARK
spend circuit (trace 1024 → 2048, all row-map constants derived from
`TREE_DEPTH`, all KATs regenerated from measured values, the deep path proven
constrained by a negative test). Filling the tree now costs more than the entire
money supply and would take ~127 years of saturation, so honest-growth and
griefing exhaustion are both off the table. This is no longer a circuit-work
blocker on arming — it folds into the SAME external circuit audit already
required above; bit 2 stays UNARMED until that audit closes.

Added by PQV2-05: **no public "post-quantum secure" statement about pool v2, and
no arming of bit 2, until the QROM / post-quantum soundness analysis scoped in
`notes/audit-scope-pq-pool.md` §9 is completed** — a derived post-quantum
soundness level (with the parameter set reaching a written PQ target), or an
explicit written finding that it cannot yet be asserted with the blocking gap
named. The classical 128-bit figure alone does not satisfy this bar.
