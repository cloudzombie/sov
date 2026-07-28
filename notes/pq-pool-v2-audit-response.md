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
  should be settled before any public security statement.
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

## Bar for arming bit 2

Unchanged and not met: every Medium resolved or explicitly accepted in writing,
the five-node suite wired as a required job and green with **zero** skips, and
the external circuit audit (`notes/audit-scope-pq-pool.md`) completed with its
findings closed. Pool v2 ships DORMANT in v0.2.2 regardless.
