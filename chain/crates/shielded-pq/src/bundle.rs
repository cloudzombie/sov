//! Spend bundles: the carrier structure a pool-v2 transaction would embed.
//!
//! A bundle spends one or more notes (each with a STARK spend proof) and
//! creates output notes. **Prototype scope, stated precisely:**
//!
//! - PROVEN by the STARK, per spend: commitment opening, tree membership
//!   under the anchor, and nullifier derivation bound to the owner's `nsk`
//!   (see [`crate::air`]).
//! - CHECKED NATIVELY (transparent, NOT zero-knowledge): value conservation
//!   `sum(inputs) = sum(outputs) + fee`, via public spend values and output
//!   commitment OPENINGS carried in the bundle; and output-commitment
//!   integrity by recomputation.
//! - CHECKED NATIVELY (carrier auth): one ML-DSA-65 signature over the
//!   bundle digest.
//! - LEFT TO THE CALLER (as in the Orchard pool): nullifier double-spend
//!   tracking against a global set, and anchor validity against chain state.

use crate::air::SpendPublicInputs;
use crate::auth::{verify_auth, AUTH_PK_LEN, AUTH_SIG_LEN};
use crate::encrypt::NoteCiphertext;
use crate::hash::PqDigest;
use crate::note::{Note, MAX_NOTE_VALUE};
use crate::prover::{verify_spend, SpendProofError};

/// One spent note: anchor, revealed nullifier, public value, STARK proof.
#[derive(Clone, Debug)]
pub struct SpendDescription {
    /// Tree anchor the membership proof is against.
    pub anchor: PqDigest,
    /// Revealed nullifier.
    pub nullifier: PqDigest,
    /// Spent value in grains (public in this prototype).
    pub value_grains: u64,
    /// Serialized winterfell proof.
    pub proof_bytes: Vec<u8>,
}

/// One created note: its commitment, its opening (prototype: values are
/// transparent), and the ciphertext for the recipient.
#[derive(Clone, Debug)]
pub struct OutputDescription {
    /// The output note's opening. PROTOTYPE: carried in the clear so the
    /// verifier can check conservation and commitment integrity natively.
    pub note: Note,
    /// The note commitment entering the tree.
    pub commitment: PqDigest,
    /// The note encrypted to the recipient (ML-KEM-768 + AEAD).
    pub ciphertext: NoteCiphertext,
}

/// A full spend bundle.
pub struct SpendBundle {
    /// Notes consumed.
    pub spends: Vec<SpendDescription>,
    /// Notes created.
    pub outputs: Vec<OutputDescription>,
    /// Transparent fee in grains.
    pub fee_grains: u64,
    /// ML-DSA-65 authorizing public key.
    pub auth_pk: [u8; AUTH_PK_LEN],
    /// ML-DSA-65 signature over [`bundle_digest`].
    pub auth_sig: [u8; AUTH_SIG_LEN],
}

/// Bundle verification errors.
#[derive(Debug, thiserror::Error)]
pub enum BundleError {
    /// A spend's STARK proof failed.
    #[error("spend {0}: {1}")]
    Spend(usize, SpendProofError),
    /// An output's commitment does not match its opening.
    #[error("output {0}: commitment does not open")]
    OutputCommitment(usize),
    /// An output value is out of range.
    #[error("output {0}: value out of range")]
    OutputValue(usize),
    /// A spend value is out of range.
    #[error("spend {0}: value out of range")]
    SpendValue(usize),
    /// Inputs != outputs + fee.
    #[error("value conservation violated")]
    Conservation,
    /// Duplicate nullifier inside the bundle.
    #[error("duplicate nullifier in bundle")]
    DuplicateNullifier,
    /// The authorization signature failed.
    #[error("authorization signature invalid")]
    Auth,
    /// A spend's anchor is not the expected one.
    #[error("spend {0}: unknown anchor")]
    Anchor(usize),
}

/// The digest the authorization signature covers:
/// blake3(domain ‖ anchors ‖ nullifiers ‖ values ‖ output commitments ‖
/// output values ‖ fee).
pub fn bundle_digest(
    spends: &[SpendDescription],
    outputs: &[OutputDescription],
    fee_grains: u64,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("sov-shielded-pq:bundle:v1");
    hasher.update(&(spends.len() as u64).to_le_bytes());
    for s in spends {
        hasher.update(&s.anchor.to_bytes());
        hasher.update(&s.nullifier.to_bytes());
        hasher.update(&s.value_grains.to_le_bytes());
    }
    hasher.update(&(outputs.len() as u64).to_le_bytes());
    for o in outputs {
        hasher.update(&o.commitment.to_bytes());
        hasher.update(&o.note.value_grains.to_le_bytes());
    }
    hasher.update(&fee_grains.to_le_bytes());
    *hasher.finalize().as_bytes()
}

/// Verify a bundle against the expected tree anchor. Checks, in order:
/// anchors, per-spend STARK proofs, in-bundle nullifier uniqueness, output
/// commitment openings, value conservation, and the ML-DSA-65 authorization.
/// Global double-spend tracking is the caller's (state layer's) job.
pub fn verify_bundle(bundle: &SpendBundle, expected_anchor: PqDigest) -> Result<(), BundleError> {
    // Per-spend STARK proofs.
    for (i, spend) in bundle.spends.iter().enumerate() {
        if spend.anchor != expected_anchor {
            return Err(BundleError::Anchor(i));
        }
        if spend.value_grains > MAX_NOTE_VALUE {
            return Err(BundleError::SpendValue(i));
        }
        let pub_inputs = SpendPublicInputs {
            root: spend.anchor,
            nullifier: spend.nullifier,
            value_grains: spend.value_grains,
        };
        verify_spend(&spend.proof_bytes, &pub_inputs).map_err(|e| BundleError::Spend(i, e))?;
    }
    // In-bundle nullifier uniqueness.
    let mut nfs: Vec<PqDigest> = bundle.spends.iter().map(|s| s.nullifier).collect();
    nfs.sort();
    if nfs.windows(2).any(|w| w[0] == w[1]) {
        return Err(BundleError::DuplicateNullifier);
    }
    // Output openings (native, transparent in the prototype).
    for (i, out) in bundle.outputs.iter().enumerate() {
        if out.note.value_grains > MAX_NOTE_VALUE {
            return Err(BundleError::OutputValue(i));
        }
        if out.note.commitment() != out.commitment {
            return Err(BundleError::OutputCommitment(i));
        }
    }
    // Value conservation (u128 arithmetic; MAX_NOTE_VALUE bounds preclude
    // overflow for any realistic bundle size).
    let inputs: u128 = bundle.spends.iter().map(|s| s.value_grains as u128).sum();
    let outputs: u128 = bundle
        .outputs
        .iter()
        .map(|o| o.note.value_grains as u128)
        .sum();
    if inputs != outputs + bundle.fee_grains as u128 {
        return Err(BundleError::Conservation);
    }
    // Carrier authorization.
    let digest = bundle_digest(&bundle.spends, &bundle.outputs, bundle.fee_grains);
    if !verify_auth(&bundle.auth_pk, &digest, &bundle.auth_sig) {
        return Err(BundleError::Auth);
    }
    Ok(())
}
