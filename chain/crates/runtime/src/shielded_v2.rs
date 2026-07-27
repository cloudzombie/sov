//! Pool-v2 (post-quantum shielded pool) **consensus verification** — the
//! validation half of `Action::ShieldedV2`, v0.2.0 slice S2c.
//!
//! This module is a pure function of `(bundle bytes, ledger, block context)`:
//! it decides whether a v2 bundle may execute and returns the exact state
//! effect it would have. It NEVER mutates anything — the executor
//! ([`crate::execution`]) applies the returned [`V2Effects`] atomically only
//! after every check has passed, so a rejected bundle cannot leave a partial
//! footprint.
//!
//! # Every failure is a HARD reject
//!
//! [`ShieldedV2Error`] has no "failed receipt" arm. A v2 action either
//! succeeds or its transaction is REJECTED, which invalidates any block
//! carrying it — uniformly on every node running the same deployment
//! schedule. See the module-level rationale in the executor and the
//! `hard_reject` law tests: the pool-v2 surface deliberately has **no**
//! mineable failure mode, because a mineable failure is exactly how a
//! dormant variant became mineable through a carrier's short-circuit
//! (PR #8 finding F1).
//!
//! # Determinism
//!
//! No wall clock, no floating point, no map-iteration order (the only
//! collections are [`NUM_SLOTS`]-bounded arrays/vectors), and every
//! allocation's capacity is a compile-time constant — never a length read
//! from the bundle. All arithmetic is checked.

use sov_mining::MiningPolicy;
use sov_primitives::{AccountId, Balance};
use sov_shielded_pq::air::NUM_SLOTS;
use sov_shielded_pq::carrier::{verify_carrier_auth, CarrierContext};
use sov_shielded_pq::{
    check_structure, decode_bundle, verify_spend, PqDigest, ShieldedV2State, MAX_V2_NOTES,
};
use sov_state::Ledger;

/// Every way a pool-v2 bundle can be refused. **All are hard, transaction-
/// rejecting (and therefore block-invalidating) errors** — the variant is a
/// diagnostic, never a consensus-visible value: no reject path writes state
/// or produces a receipt, so nodes cannot disagree about *which* rejection
/// applied, only that the transaction is inadmissible.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ShieldedV2Error {
    /// The leading `proof_version` byte selects no decoder in this build
    /// (D6). A FUTURE circuit ships as version N+1 behind its own signal
    /// bit; until then an unknown version is inadmissible rather than
    /// "failed", so a producer can never mine a transaction a future build
    /// would execute differently.
    #[error("unknown proof_version {0}")]
    UnknownProofVersion(u8),
    /// The bundle bytes are not a canonical v1 encoding (total, panic-free
    /// decode — including the proof-frame pre-validation of D15).
    #[error("malformed bundle: {0}")]
    MalformedBundle(String),
    /// The decoded bundle violates a structural rule: a public leg above the
    /// native bound, a dummy/real slot convention, or a nullifier repeated
    /// **inside the bundle**.
    #[error("malformed bundle structure: {0}")]
    MalformedStructure(String),
    /// The bundle has no real input and no real output — a no-op that would
    /// consume block space and touch the pool for nothing.
    #[error("bundle has no real inputs and no real outputs")]
    NoEffect,
    /// The in-circuit fee leg is nonzero. v0.2.0 pays transaction fees
    /// transparently from the carrier (exactly like pool v1); paying fees
    /// *out of the pool* is a future `proof_version` with its own
    /// accounting. Pinning the leg to zero keeps the pool's tracked value
    /// equal to the sum of its live notes — no value can be created, and
    /// none can be stranded (law F8.5).
    #[error("in-circuit fee leg must be zero in proof_version 1 (got {0} grains)")]
    FeeLegNotZero(u64),
    /// The ML-DSA-65 authorization does not verify **for this carrier**:
    /// either the signature is invalid, or it authorizes the bundle under a
    /// different `{signer, nonce}` (a lifted/replayed authorization).
    #[error("carrier authorization invalid or not bound to this transaction")]
    CarrierAuth,
    /// The STARK proof does not verify against the bundle's public inputs.
    #[error("invalid spend proof: {0}")]
    InvalidProof(String),
    /// A real input's anchor is not in the pool's 128-entry anchor ring
    /// (unknown, or evicted because it is too old — the spend must be
    /// re-proven against a recent root).
    #[error("input {0}: anchor is not in the pool-v2 anchor ring")]
    UnknownAnchor(usize),
    /// A revealed nullifier is already in the on-chain spent set — a double
    /// spend, whether from an earlier block, an earlier transaction in this
    /// same block, or a re-carried bundle.
    #[error("input {0}: nullifier already spent")]
    NullifierAlreadySpent(usize),
    /// The pool's note-commitment tree cannot fit this bundle's outputs.
    #[error("pool-v2 note-commitment tree is full")]
    TreeFull,
    /// The signer cannot fund the bundle's shield leg (`transparent_in`)
    /// after the transaction fee.
    #[error("signer cannot fund the shield leg of {0} grains")]
    InsufficientBalance(u128),
    /// The de-shield leg exceeds the pool's tracked value: the turnstile
    /// would go negative. Consensus-enforced exactly as pool v1's is — a
    /// proof-system break can never mint SOV out of the pool.
    #[error("turnstile: de-shield of {out} grains exceeds pool value {pool} grains")]
    Turnstile {
        /// The de-shield leg, in grains.
        out: u128,
        /// The pool value available (after crediting the shield leg), in grains.
        pool: u128,
    },
    /// A value computation overflowed. Unreachable under the supply cap and
    /// the 61-bit note bound, but checked rather than assumed.
    #[error("value balance arithmetic overflow")]
    ValueOverflow,
    /// The de-shield leg does not fit the pool's own rolling drain-limiter
    /// window (D11 — v2 has its own window with v1's parameters).
    #[error("pool-v2 de-shield rate limit exceeded for this window")]
    DrainLimit,
}

/// The exact, fully validated state effect of one accepted bundle. Applied
/// by the executor; nothing here is optional or recomputed at apply time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V2Effects {
    /// Nullifiers to publish (real input slots only, in slot order).
    pub nullifiers: Vec<PqDigest>,
    /// Note commitments to append (real output slots only, in slot order).
    pub commitments: Vec<PqDigest>,
    /// Value entering the pool from the signer's transparent balance.
    pub shield_in: Balance,
    /// Value leaving the pool to the signer's transparent balance.
    pub deshield_out: Balance,
    /// The drain-limiter window to persist when `deshield_out > 0` and the
    /// limiter is enabled: `(window_start, spent_in_window)`.
    pub window_update: Option<(u64, Balance)>,
}

/// Verify one pool-v2 bundle for the transaction carrying it, returning the
/// state effect it earns.
///
/// **Order of checks** (chosen for cost — cheapest and most local first, so
/// a hostile bundle is refused before any expensive work — and for
/// diagnostics; it is *not* consensus-visible, because every failure is a
/// hard reject with no state effect and no receipt):
///
/// 1. **decode** the bundle, enforcing the `proof_version` gate (total,
///    panic-free, size-capped — the S1c/D15 decoder, unweakened);
/// 2. **structure**: native public bounds, dummy/real slot conventions,
///    in-bundle nullifier uniqueness, non-emptiness, zero fee leg;
/// 3. **carrier authorization**: ML-DSA-65 over the carrier-bound sighash
///    (~0.1 ms; runs before the proof so a bundle lifted out of another
///    transaction never costs a STARK verification);
/// 4. **STARK proof** against the bundle's public inputs (~0.7 ms);
/// 5. **anchors**: every real input's anchor is in the 128-entry ring;
/// 6. **nullifiers**: none already spent on chain (which also covers
///    earlier transactions in the same block, since each transaction's
///    effect is applied before the next executes);
/// 7. **capacity**: the outputs fit the depth-20 tree;
/// 8. **value balance + turnstile**: the signer funds the shield leg and
///    the pool covers the de-shield leg without going negative;
/// 9. **drain limiter**: the de-shield fits pool v2's own rolling window.
#[allow(clippy::too_many_arguments)]
pub fn verify_bundle_for_carrier(
    bundle_bytes: &[u8],
    ledger: &Ledger,
    mining: &MiningPolicy,
    height: u64,
    signer: &AccountId,
    nonce: u64,
    signer_balance: Balance,
) -> Result<V2Effects, ShieldedV2Error> {
    // ── 1. Decode + proof_version gate (D6) ─────────────────────────────
    let bundle = decode_bundle(bundle_bytes).map_err(|e| match e {
        sov_shielded_pq::WireError::UnknownProofVersion(v) => {
            ShieldedV2Error::UnknownProofVersion(v)
        }
        other => ShieldedV2Error::MalformedBundle(other.to_string()),
    })?;
    let pi = &bundle.public_inputs;

    // ── 2. Structure (state-independent) ────────────────────────────────
    check_structure(&bundle).map_err(|e| ShieldedV2Error::MalformedStructure(e.to_string()))?;
    if pi.fee_grains != 0 {
        return Err(ShieldedV2Error::FeeLegNotZero(pi.fee_grains));
    }
    let real_inputs = (0..NUM_SLOTS).filter(|&i| !pi.input_dummy[i]);
    let real_outputs = (0..NUM_SLOTS).filter(|&j| !pi.output_dummy[j]);
    let nullifiers: Vec<PqDigest> = real_inputs.clone().map(|i| pi.nullifiers[i]).collect();
    let commitments: Vec<PqDigest> = real_outputs.map(|j| pi.output_commitments[j]).collect();
    if nullifiers.is_empty() && commitments.is_empty() {
        return Err(ShieldedV2Error::NoEffect);
    }

    // ── 3. Carrier authorization (binds the bundle to THIS transaction) ─
    let carrier = CarrierContext {
        signer: signer.as_str().as_bytes(),
        nonce,
    };
    if !verify_carrier_auth(&bundle, &carrier) {
        return Err(ShieldedV2Error::CarrierAuth);
    }

    // ── 4. The STARK proof over the full public-input set ───────────────
    verify_spend(&bundle.proof_bytes, pi)
        .map_err(|e| ShieldedV2Error::InvalidProof(e.to_string()))?;

    // ── 5. Anchors: each real input against the 128-entry ring (D5) ─────
    let pool: &ShieldedV2State = ledger.shielded_v2();
    for i in real_inputs.clone() {
        if !pool.anchor_is_known(&pi.anchors[i]) {
            return Err(ShieldedV2Error::UnknownAnchor(i));
        }
    }

    // ── 6. Double spend against the on-chain nullifier set ──────────────
    // In-bundle duplicates were refused in step 2; duplicates ACROSS
    // transactions in one block are caught here because each accepted
    // transaction's effect is applied to the ledger before the next runs.
    for (n, i) in real_inputs.enumerate() {
        if pool.nullifier_seen(&nullifiers[n]) {
            return Err(ShieldedV2Error::NullifierAlreadySpent(i));
        }
    }

    // ── 7. Tree capacity (state-local; a full pool is refused before any
    // value moves) ─────────────────────────────────────────────────────
    let outputs = commitments.len() as u64;
    match pool.note_count().checked_add(outputs) {
        Some(n) if n <= MAX_V2_NOTES => {}
        _ => return Err(ShieldedV2Error::TreeFull),
    }

    // ── 8. Value balance + turnstile ────────────────────────────────────
    // The legs are u64 grains, each bounded by MAX_NOTE_VALUE (< 2^61) in
    // step 2, so these conversions cannot lose precision.
    let shield_in = Balance::from_grains(u128::from(pi.transparent_in));
    let deshield_out = Balance::from_grains(u128::from(pi.transparent_out));
    if signer_balance.checked_sub(shield_in).is_none() {
        return Err(ShieldedV2Error::InsufficientBalance(shield_in.grains()));
    }
    let pool_value = ledger.shielded_v2_value();
    let after_shield = pool_value
        .checked_add(shield_in)
        .ok_or(ShieldedV2Error::ValueOverflow)?;
    if after_shield.checked_sub(deshield_out).is_none() {
        return Err(ShieldedV2Error::Turnstile {
            out: deshield_out.grains(),
            pool: after_shield.grains(),
        });
    }

    // ── 9. Pool v2's OWN de-shield drain limiter (D11) ──────────────────
    // Identical shape and parameters to v1's, over v2's own window counter.
    // The GROSS de-shield leg is metered (never the net of a shield in the
    // same bundle) — the conservative reading.
    let mut window_update = None;
    if deshield_out != Balance::ZERO && mining.deshield_window_blocks != 0 {
        let (start, spent) = ledger.deshield_v2_window();
        let elapsed = height.saturating_sub(start) >= mining.deshield_window_blocks;
        let (base_start, base_spent) = if elapsed {
            (height, Balance::ZERO)
        } else {
            (start, spent)
        };
        match base_spent.checked_add(deshield_out) {
            Some(new_spent) if new_spent.grains() <= mining.deshield_limit_grains => {
                window_update = Some((base_start, new_spent));
            }
            _ => return Err(ShieldedV2Error::DrainLimit),
        }
    }

    Ok(V2Effects {
        nullifiers,
        commitments,
        shield_in,
        deshield_out,
        window_update,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use sov_shielded_pq::bundle::SpendBundle;
    use sov_shielded_pq::hd::PqShieldedKey;
    use sov_shielded_pq::wallet::{authorize_for_carrier, build_shield, build_spend};
    use sov_shielded_pq::wire::encode_bundle;

    const SIGNER: &str = "usa.reserve.sov";
    const XUS: u128 = 100_000_000;

    fn key(byte: u8) -> PqShieldedKey {
        PqShieldedKey::from_leaf_seed(&[byte; 32])
    }

    fn policy() -> MiningPolicy {
        MiningPolicy::mainnet_like()
    }

    fn signer() -> AccountId {
        AccountId::new(SIGNER).expect("valid account id")
    }

    /// A carrier-bound, encoded shield of `xus` XUS into pool v2.
    fn shield_bundle(k: &PqShieldedKey, xus: u128, nonce: u64) -> (SpendBundle, Vec<u8>) {
        let grains = u64::try_from(xus * XUS).expect("fits");
        let mut bundle = build_shield(k, &k.address(), grains, 0).expect("build shield");
        authorize_for_carrier(&mut bundle, k, SIGNER, nonce).expect("carrier-bind");
        let bytes = encode_bundle(&bundle);
        (bundle, bytes)
    }

    /// An honest shield must verify and report the exact turnstile effect.
    #[test]
    fn an_honest_shield_verifies_and_reports_exact_effects() {
        let k = key(1);
        let (_, bytes) = shield_bundle(&k, 5, 0);
        let ledger = Ledger::default();
        let effects = verify_bundle_for_carrier(
            &bytes,
            &ledger,
            &policy(),
            1,
            &signer(),
            0,
            Balance::from_grains(10 * XUS),
        )
        .expect("an honest shield must verify");
        assert_eq!(effects.shield_in.grains(), 5 * XUS, "value entering the pool");
        assert_eq!(effects.deshield_out.grains(), 0, "a shield takes nothing out");
        assert!(
            effects.nullifiers.is_empty(),
            "a shield spends no notes, so it must publish NO nullifiers"
        );
        assert!(
            !effects.commitments.is_empty(),
            "a shield must append at least one note commitment"
        );
    }

    /// The carrier binding is the whole authorization story: a bundle proved
    /// and signed for one {signer, nonce} must NOT be liftable onto another
    /// transaction. This is the replay vector.
    #[test]
    fn a_bundle_cannot_be_lifted_onto_another_carrier() {
        let k = key(2);
        let (_, bytes) = shield_bundle(&k, 5, 7);
        let ledger = Ledger::default();
        let ok = |nonce: u64, who: &str| {
            verify_bundle_for_carrier(
                &bytes,
                &ledger,
                &policy(),
                1,
                &AccountId::new(who).expect("id"),
                nonce,
                Balance::from_grains(10 * XUS),
            )
        };
        assert!(ok(7, SIGNER).is_ok(), "its own carrier must verify");
        assert!(
            matches!(ok(8, SIGNER), Err(ShieldedV2Error::CarrierAuth)),
            "a DIFFERENT nonce must be refused — otherwise the bundle replays"
        );
        assert!(
            matches!(ok(7, "miner.sov"), Err(ShieldedV2Error::CarrierAuth)),
            "a DIFFERENT signer must be refused — otherwise the bundle is stealable"
        );
    }

    /// A shield for more than the signer holds must be refused BEFORE any
    /// state is touched — the pool must never be credited value the
    /// transparent ledger cannot pay.
    #[test]
    fn a_shield_beyond_the_signer_balance_is_refused() {
        let k = key(3);
        let (_, bytes) = shield_bundle(&k, 5, 0);
        let ledger = Ledger::default();
        let out = verify_bundle_for_carrier(
            &bytes,
            &ledger,
            &policy(),
            1,
            &signer(),
            0,
            Balance::from_grains(XUS), // only 1 XUS, shielding 5
        );
        assert!(
            matches!(out, Err(ShieldedV2Error::InsufficientBalance(_))),
            "expected InsufficientBalance, got {out:?}"
        );
    }

    /// Any mutation of the encoded bundle must fail closed — decode error,
    /// structure error, bad authorization or bad proof, never silent
    /// acceptance and never a panic.
    #[test]
    fn every_single_byte_mutation_fails_closed() {
        let k = key(4);
        let (_, bytes) = shield_bundle(&k, 5, 0);
        let ledger = Ledger::default();
        // Sample across the encoding rather than all ~100 KB (each rejection
        // is cheap, but the proof-verifying paths are not).
        let probes: Vec<usize> = (0..bytes.len()).step_by(bytes.len() / 64 + 1).collect();
        for i in probes {
            let mut bad = bytes.clone();
            bad[i] ^= 0x01;
            if bad == bytes {
                continue;
            }
            let out = verify_bundle_for_carrier(
                &bad,
                &ledger,
                &policy(),
                1,
                &signer(),
                0,
                Balance::from_grains(10 * XUS),
            );
            assert!(
                out.is_err(),
                "flipping a bit at offset {i} produced an ACCEPTED bundle"
            );
        }
    }

    /// THE double-spend test. A note whose nullifier is already on-chain must
    /// be refused — this is the property that makes the pool sound, and it had
    /// no test at any layer before now.
    #[test]
    fn a_note_cannot_be_spent_twice() {
        let k = key(6);
        let (shield, _) = shield_bundle(&k, 5, 0);

        // Put the shield's notes into a REAL ledger, so its anchor is known.
        let mut ledger = Ledger::default();
        let commitments: Vec<PqDigest> = shield
            .public_inputs
            .output_commitments
            .iter()
            .zip(shield.public_inputs.output_dummy)
            .filter_map(|(c, dummy)| (!dummy).then_some(*c))
            .collect();
        ledger
            .apply_shielded_v2(&[], &commitments)
            .expect("seed the pool");
        ledger
            .add_shielded_v2_value(Balance::from_grains(5 * XUS))
            .expect("seed pool value");

        // Build a spend against that pool.
        let mut store = sov_shielded_pq::scan::PqNoteStore::new(0);
        store.ingest_block(&k, 1, [9u8; 32], &[&shield]);
        let built = build_spend(&k, &store, None, XUS as u64, 0).expect("build spend");
        let mut spend = built.bundle;
        authorize_for_carrier(&mut spend, &k, SIGNER, 0).expect("carrier-bind");
        let bytes = encode_bundle(&spend);

        // First spend verifies.
        let effects = verify_bundle_for_carrier(
            &bytes,
            &ledger,
            &policy(),
            1,
            &signer(),
            0,
            Balance::from_grains(10 * XUS),
        )
        .expect("the first spend must verify");
        assert!(
            !effects.nullifiers.is_empty(),
            "a spend must publish a nullifier"
        );

        // Publish its nullifiers, exactly as block execution would.
        ledger
            .apply_shielded_v2(&effects.nullifiers, &effects.commitments)
            .expect("apply the spend");

        // The SAME bundle must now be refused as a double spend.
        let again = verify_bundle_for_carrier(
            &bytes,
            &ledger,
            &policy(),
            1,
            &signer(),
            0,
            Balance::from_grains(10 * XUS),
        );
        assert!(
            matches!(again, Err(ShieldedV2Error::NullifierAlreadySpent(_))),
            "re-spending a note must be refused, got {again:?}"
        );
    }

    /// Spending a note requires its anchor to be in the ring. A spend proved
    /// against a tree this chain has never seen must be refused.
    #[test]
    fn a_spend_against_an_unknown_anchor_is_refused() {
        let k = key(5);
        // Fund a store on a private tree the ledger knows nothing about.
        let (bundle, _) = shield_bundle(&k, 5, 0);
        let mut store = sov_shielded_pq::scan::PqNoteStore::new(0);
        store.ingest_block(&k, 1, [9u8; 32], &[&bundle]);
        assert!(store.balance() > 0, "the test store must hold a note");

        let built = build_spend(&k, &store, None, XUS as u64, 0).expect("build spend");
        let mut spend = built.bundle;
        authorize_for_carrier(&mut spend, &k, SIGNER, 0).expect("carrier-bind");
        let bytes = encode_bundle(&spend);

        // The consensus ledger never saw that tree, so its anchor is unknown.
        let ledger = Ledger::default();
        let out = verify_bundle_for_carrier(
            &bytes,
            &ledger,
            &policy(),
            1,
            &signer(),
            0,
            Balance::from_grains(10 * XUS),
        );
        assert!(
            matches!(out, Err(ShieldedV2Error::UnknownAnchor(_))),
            "expected UnknownAnchor, got {out:?}"
        );
    }
}
