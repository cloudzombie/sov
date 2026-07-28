//! Spend bundles: the carrier structure a pool-v2 transaction would embed.
//!
//! One bundle = ONE 4-in/4-out STARK proof + the public inputs it binds +
//! per-real-output ciphertexts + one ML-DSA-65 carrier signature.
//! **Scope, stated precisely:**
//!
//! - PROVEN by the STARK, in zero knowledge ([`crate::air`]): per real
//!   input — commitment opening, depth-20 membership under its public
//!   anchor, nullifier derivation bound to the owner's `nsk`; per real
//!   output — commitment integrity; per dummy slot — zero value +
//!   domain-separated dummy nullifier; 61-bit range checks on every value;
//!   and value conservation with ONLY `t_in`/`t_out`/`fee` public.
//!   **All note values are private witnesses.**
//! - CHECKED NATIVELY here: the public bounds the no-wrap argument needs
//!   (`t_in`/`t_out`/`fee` ≤ [`MAX_NOTE_VALUE`], re-checked in
//!   [`verify_spend`]), dummy-slot conventions (zero anchors/nullifiers/
//!   commitments, no ciphertext), anchor acceptance against the caller's
//!   valid-anchor set (D5's anchor ring is chain state, so the caller
//!   supplies it), in-bundle nullifier uniqueness, and the ML-DSA-65
//!   carrier signature over [`bundle_digest`].
//! - LEFT TO THE CALLER (the future consensus layer, W2): global nullifier
//!   double-spend tracking, appending real output commitments to the tree,
//!   and the transparent-leg accounting for `t_in`/`t_out`/`fee`.

use crate::air::{BundlePublicInputs, NUM_SLOTS};
use crate::auth::{verify_auth, AUTH_PK_LEN, AUTH_SIG_LEN};
use crate::domains::B3_BUNDLE_DIGEST;
use crate::encrypt::NoteCiphertext;
use crate::hash::PqDigest;
use crate::note::MAX_NOTE_VALUE;
use crate::prover::{verify_spend, SpendProofError};

/// A full spend bundle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpendBundle {
    /// The public inputs the STARK proof is verified against. Everything
    /// value-related in here is either a hiding commitment output or one of
    /// the three transparent legs.
    pub public_inputs: BundlePublicInputs,
    /// The serialized winterfell proof for the whole 4-in/4-out bundle.
    pub proof_bytes: Vec<u8>,
    /// Per-slot output ciphertext: `Some` exactly for real output slots.
    pub output_ciphertexts: [Option<NoteCiphertext>; NUM_SLOTS],
    /// ML-DSA-65 authorizing public key.
    pub auth_pk: [u8; AUTH_PK_LEN],
    /// ML-DSA-65 signature over [`bundle_digest`].
    pub auth_sig: [u8; AUTH_SIG_LEN],
}

/// Bundle verification errors.
#[derive(Debug, thiserror::Error)]
pub enum BundleError {
    /// The STARK bundle proof failed.
    #[error("bundle proof: {0}")]
    Proof(SpendProofError),
    /// A public transparent leg exceeds the native bound.
    #[error("public value out of range")]
    PublicValue,
    /// A real input's anchor is not in the caller's valid-anchor set.
    #[error("input {0}: unknown anchor")]
    Anchor(usize),
    /// A dummy slot violates the zero-digest / no-ciphertext convention.
    #[error("slot {0}: malformed dummy slot")]
    DummySlot(usize),
    /// A real slot carries a zero digest or is missing its ciphertext.
    #[error("slot {0}: malformed real slot")]
    RealSlot(usize),
    /// Duplicate nullifier inside the bundle.
    #[error("duplicate nullifier in bundle")]
    DuplicateNullifier,
    /// The authorization signature failed.
    #[error("authorization signature invalid")]
    Auth,
}

/// The digest the authorization signature covers (D4): the FULL public
/// input set of the STARK proof, every output ciphertext, AND the
/// authorizing public key itself, so neither the value balance, the
/// anchors/nullifiers/commitments, the dummy pattern, the encrypted
/// payloads, nor the key the signature speaks for can be reshaped around
/// a signature — the signature attests "THIS key authorized THIS bundle",
/// not mere well-formedness.
///
/// **CARRIER SEAM (D4) — CLOSED in S2c, extended for PQV2-06:** the
/// authorization consensus verifies is NOT a signature over this digest
/// alone. [`crate::carrier`] wraps it in a second, domain-separated digest
/// over `(bundle_digest, carrier_context)` with the carrier context pinned
/// to this chain's `{chain_id, genesis}` AND the transaction's
/// `{signer, nonce}` (scheme byte 2), so a bundle cannot be lifted out of one
/// transaction, nor replayed onto another network. This function, its bytes,
/// and its KATs stayed frozen: the binding is additive.
/// The carrier transaction id was rejected as the context because it is
/// circular — the id hashes the full Borsh transaction, whose action embeds
/// these very bundle bytes *including `auth_sig`*.
pub fn bundle_digest(
    public_inputs: &BundlePublicInputs,
    output_ciphertexts: &[Option<NoteCiphertext>; NUM_SLOTS],
    auth_pk: &[u8; AUTH_PK_LEN],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(B3_BUNDLE_DIGEST);
    for i in 0..NUM_SLOTS {
        hasher.update(&public_inputs.anchors[i].to_bytes());
        hasher.update(&public_inputs.nullifiers[i].to_bytes());
        hasher.update(&[public_inputs.input_dummy[i] as u8]);
    }
    for (j, ct) in output_ciphertexts.iter().enumerate() {
        hasher.update(&public_inputs.output_commitments[j].to_bytes());
        hasher.update(&[public_inputs.output_dummy[j] as u8]);
        match ct {
            Some(ct) => {
                hasher.update(&[1u8]);
                hasher.update(&ct.kem_ct);
                hasher.update(&ct.detection_tag);
                hasher.update(&(ct.aead_ct.len() as u64).to_le_bytes());
                hasher.update(&ct.aead_ct);
            }
            None => {
                hasher.update(&[0u8]);
            }
        }
    }
    hasher.update(&public_inputs.transparent_in.to_le_bytes());
    hasher.update(&public_inputs.transparent_out.to_le_bytes());
    hasher.update(&public_inputs.fee_grains.to_le_bytes());
    // Audit S1 follow-up: fold the authorizing key into the signed
    // statement (length-prefixed), so the signature binds a KEY to the
    // bundle. The carrier-context binding (D4) is an OPEN seam owned by
    // S2c — see the doc comment above; it must wrap this digest, not
    // change it.
    hasher.update(&(AUTH_PK_LEN as u64).to_le_bytes());
    hasher.update(auth_pk);
    *hasher.finalize().as_bytes()
}

/// The bundle's STATE-INDEPENDENT structural rules: the native public
/// bounds the in-circuit no-wrap argument depends on, the dummy/real slot
/// conventions, and in-bundle nullifier uniqueness.
///
/// Split out of [`verify_bundle`] so a caller that must interleave these
/// with *chain-state* rules in its own order — the consensus executor
/// (`sov-runtime`'s pool-v2 pipeline) does — can run them as one step
/// without re-implementing them. Pure: no chain state, no allocation from
/// untrusted lengths (every collection is [`NUM_SLOTS`]-bounded).
pub fn check_structure(bundle: &SpendBundle) -> Result<(), BundleError> {
    let pi = &bundle.public_inputs;
    // Native public bounds (the in-circuit no-wrap argument depends on
    // these; verify_spend re-checks them, but fail fast with a typed error).
    if pi.transparent_in > MAX_NOTE_VALUE
        || pi.transparent_out > MAX_NOTE_VALUE
        || pi.fee_grains > MAX_NOTE_VALUE
    {
        return Err(BundleError::PublicValue);
    }
    // Slot conventions: dummies are all-zero and ciphertext-free; real
    // slots are nonzero and (for outputs) carry a ciphertext.
    for i in 0..NUM_SLOTS {
        if pi.input_dummy[i] {
            if pi.anchors[i] != PqDigest::ZERO || pi.nullifiers[i] != PqDigest::ZERO {
                return Err(BundleError::DummySlot(i));
            }
        } else if pi.nullifiers[i] == PqDigest::ZERO {
            return Err(BundleError::RealSlot(i));
        }
    }
    for (j, ct) in bundle.output_ciphertexts.iter().enumerate() {
        if pi.output_dummy[j] {
            if pi.output_commitments[j] != PqDigest::ZERO || ct.is_some() {
                return Err(BundleError::DummySlot(j));
            }
        } else if pi.output_commitments[j] == PqDigest::ZERO || ct.is_none() {
            return Err(BundleError::RealSlot(j));
        }
    }
    // In-bundle nullifier uniqueness (real slots only). At most NUM_SLOTS
    // entries — the capacity is a compile-time constant, never attacker data.
    let mut nfs: Vec<PqDigest> = Vec::with_capacity(NUM_SLOTS);
    for i in 0..NUM_SLOTS {
        if !pi.input_dummy[i] {
            nfs.push(pi.nullifiers[i]);
        }
    }
    nfs.sort();
    if nfs.windows(2).any(|w| w[0] == w[1]) {
        return Err(BundleError::DuplicateNullifier);
    }
    Ok(())
}

/// Verify a bundle with an **unbound** authorization signature (the S1
/// prototype form: the signature covers [`bundle_digest`] alone).
///
/// **NOT the consensus entry point.** Consensus verifies the authorization
/// against its carrier via [`crate::carrier::verify_carrier_auth`], which
/// binds the signature to the carrying transaction's `{signer, nonce}`; a
/// signature accepted here would be liftable into another transaction. This
/// function remains for the circuit-level KATs and for callers with no
/// carrier (offline bundle inspection).
///
/// `valid_anchors` is the caller's acceptable-anchor set (the anchor ring
/// per D5); each REAL input's anchor must be in it — different inputs may
/// use different anchors. Checks, in order: structure ([`check_structure`]),
/// anchors, the STARK proof, and the ML-DSA-65 authorization. Global
/// double-spend tracking is the caller's (state layer's) job.
pub fn verify_bundle(bundle: &SpendBundle, valid_anchors: &[PqDigest]) -> Result<(), BundleError> {
    let pi = &bundle.public_inputs;
    check_structure(bundle)?;
    for i in 0..NUM_SLOTS {
        if !pi.input_dummy[i] && !valid_anchors.contains(&pi.anchors[i]) {
            return Err(BundleError::Anchor(i));
        }
    }
    // The STARK proof over the full public-input set.
    verify_spend(&bundle.proof_bytes, pi).map_err(BundleError::Proof)?;
    // Carrier authorization over the same set + ciphertexts + the key.
    let digest = bundle_digest(pi, &bundle.output_ciphertexts, &bundle.auth_pk);
    if !verify_auth(&bundle.auth_pk, &digest, &bundle.auth_sig) {
        return Err(BundleError::Auth);
    }
    Ok(())
}
