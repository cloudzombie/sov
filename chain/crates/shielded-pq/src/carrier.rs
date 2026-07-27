//! **Carrier-auth binding** (v0.2.0 slice S2c): the isolated seam that ties a
//! bundle's ML-DSA-65 authorization to the *transaction that carries it*.
//!
//! # The problem
//!
//! [`crate::bundle::bundle_digest`] commits to everything a bundle *is*: its
//! public inputs (anchors, nullifiers, output commitments, dummy pattern,
//! the transparent legs and fee), its note ciphertexts, and the authorizing
//! key. It deliberately says nothing about *where* the bundle appears. A
//! signature over that digest alone therefore authorizes the bundle in ANY
//! transaction: an observer who sees a bundle in the mempool could re-carry
//! the identical bytes under their own transaction and — if the pool's
//! transparent leg pays out — redirect the de-shielded value to themselves.
//! The bundle's own STARK proof cannot prevent this: it proves note math,
//! not carriage.
//!
//! # The scheme (D4's pinned form)
//!
//! The signature covers a SECOND, domain-separated digest that wraps the
//! frozen bundle digest together with the carrier's context:
//!
//! ```text
//! sighash = blake3_derive_key(B3_CARRIER_BINDING,
//!               scheme_byte ‖ len(signer) ‖ signer ‖ nonce ‖ bundle_digest)
//! ```
//!
//! with `scheme_byte = ` [`SCHEME_SIGNER_NONCE`] and the carrier context the
//! transaction's `{signer, nonce}` — the pair that is unique per accepted
//! transaction in SOV's account model (the nonce is consumed on execution,
//! so no second transaction from that signer can ever reuse it).
//!
//! **What it excludes, and why it must.** The sighash cannot commit to the
//! carrier transaction id: `Transaction::id()` hashes the whole Borsh
//! transaction, whose action embeds these bundle bytes *including the
//! `auth_sig` field* — the signature would have to sign a hash of itself.
//! For the same reason the sighash cannot commit to the serialized proof:
//! the winterfell prover is not required to be deterministic, so a re-proof
//! of the identical statement would invalidate an otherwise valid signature.
//! Neither exclusion weakens the binding:
//!
//! - the proof is bound to the *public inputs* by STARK verification, and
//!   every public input is inside `bundle_digest`;
//! - the transaction as a whole is bound to the chain by the signer's own
//!   transaction signature (chain-bound since the `tx-domain` fork), so a
//!   bundle cannot be replayed onto another network either.
//!
//! # Why this is a seam and not a hardcoded rule
//!
//! The binding is one byte-tagged scheme in one function. A future carriage
//! model (a nonce-free/UTXO transaction path, say) adds a variant and a new
//! `scheme_byte` here — `bundle_digest` and its KATs stay frozen, and no
//! verification logic in the executor changes: the executor asks this module
//! for the message to verify and nothing else. See the trade-off write-up in
//! `notes/v0.2.0-carrier-binding.md`.

use crate::auth::{verify_auth, AuthError, AuthKeypair, AUTH_PK_LEN, AUTH_SIG_LEN};
use crate::bundle::{bundle_digest, SpendBundle};
use crate::domains::B3_CARRIER_BINDING;

/// Binding scheme 1 — the carrier's `{signer, nonce}` (the account-model
/// form pinned by D4, and the only scheme v0.2.0 accepts).
pub const SCHEME_SIGNER_NONCE: u8 = 1;

/// The carrier context an authorization is bound to.
///
/// Constructed by the executor from the transaction being applied; there is
/// no `Default` and no "unbound" variant, so a consensus caller cannot
/// accidentally verify an unbound signature — the binding is unrepresentable
/// as absent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CarrierContext<'a> {
    /// The carrier transaction's signer account, as its canonical bytes.
    pub signer: &'a [u8],
    /// The carrier transaction's nonce (the value the transaction spends,
    /// i.e. the signer's nonce *before* execution increments it).
    pub nonce: u64,
}

/// The message an authorization signature must cover: the carrier-bound
/// sighash over `(scheme, signer, nonce, bundle_digest)`.
///
/// Injective in its inputs: the scheme byte is fixed-width and leads, the
/// signer is length-prefixed, and the nonce and digest are fixed-width — so
/// no two distinct `(scheme, signer, nonce, digest)` tuples share a
/// preimage.
pub fn carrier_sighash(bundle_digest: &[u8; 32], ctx: &CarrierContext<'_>) -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key(B3_CARRIER_BINDING);
    h.update(&[SCHEME_SIGNER_NONCE]);
    h.update(&(ctx.signer.len() as u64).to_le_bytes());
    h.update(ctx.signer);
    h.update(&ctx.nonce.to_le_bytes());
    h.update(bundle_digest);
    *h.finalize().as_bytes()
}

/// The carrier-bound authorization message for a complete bundle.
pub fn authorization_message(bundle: &SpendBundle, ctx: &CarrierContext<'_>) -> [u8; 32] {
    let inner = bundle_digest(
        &bundle.public_inputs,
        &bundle.output_ciphertexts,
        &bundle.auth_pk,
    );
    carrier_sighash(&inner, ctx)
}

/// Verify a bundle's ML-DSA-65 authorization **as carried by this
/// transaction**. The ONLY authorization check consensus performs.
pub fn verify_carrier_auth(bundle: &SpendBundle, ctx: &CarrierContext<'_>) -> bool {
    let msg = authorization_message(bundle, ctx);
    verify_auth(&bundle.auth_pk, &msg, &bundle.auth_sig)
}

/// Sign a bundle for a specific carrier (the wallet/prover side of the same
/// seam): `auth_pk`/`auth_sig` produced here verify under
/// [`verify_carrier_auth`] for exactly this `{signer, nonce}` and no other.
pub fn sign_in_carrier(
    keypair: &AuthKeypair,
    public_inputs: &crate::air::BundlePublicInputs,
    output_ciphertexts: &[Option<crate::encrypt::NoteCiphertext>; crate::air::NUM_SLOTS],
    ctx: &CarrierContext<'_>,
) -> Result<([u8; AUTH_PK_LEN], [u8; AUTH_SIG_LEN]), AuthError> {
    let pk = keypair.public_bytes();
    let inner = bundle_digest(public_inputs, output_ciphertexts, &pk);
    let sig = keypair.sign(&carrier_sighash(&inner, ctx))?;
    Ok((pk, sig))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::air::{BundlePublicInputs, NUM_SLOTS};
    use crate::hash::PqDigest;

    fn publics() -> BundlePublicInputs {
        BundlePublicInputs {
            anchors: [PqDigest::ZERO; NUM_SLOTS],
            nullifiers: [PqDigest::ZERO; NUM_SLOTS],
            input_dummy: [true; NUM_SLOTS],
            output_commitments: [PqDigest::ZERO; NUM_SLOTS],
            output_dummy: [true; NUM_SLOTS],
            transparent_in: 7,
            transparent_out: 0,
            fee_grains: 0,
        }
    }

    fn bundle_with(sig: [u8; AUTH_SIG_LEN], pk: [u8; AUTH_PK_LEN]) -> SpendBundle {
        SpendBundle {
            public_inputs: publics(),
            proof_bytes: vec![0u8; 8],
            output_ciphertexts: [None, None, None, None],
            auth_pk: pk,
            auth_sig: sig,
        }
    }

    #[test]
    fn a_signature_verifies_only_under_its_own_carrier() {
        let kp = AuthKeypair::from_seed(&[3u8; 32]);
        let cts = [None, None, None, None];
        let ctx = CarrierContext {
            signer: b"usa.reserve.sov",
            nonce: 4,
        };
        let (pk, sig) = sign_in_carrier(&kp, &publics(), &cts, &ctx).expect("sign");
        let bundle = bundle_with(sig, pk);
        assert!(verify_carrier_auth(&bundle, &ctx));
        // A different nonce — the same signer replaying their own bundle at
        // another sequence position — does NOT verify.
        assert!(!verify_carrier_auth(
            &bundle,
            &CarrierContext {
                signer: b"usa.reserve.sov",
                nonce: 5
            }
        ));
        // A different signer — the mempool-lifting attack — does NOT verify.
        assert!(!verify_carrier_auth(
            &bundle,
            &CarrierContext {
                signer: b"thief.sov",
                nonce: 4
            }
        ));
    }

    #[test]
    fn an_unbound_signature_over_the_bare_bundle_digest_is_refused() {
        // The S1 (pre-binding) authorization form must NOT satisfy the
        // consensus check — this is the regression guard for the seam.
        let kp = AuthKeypair::from_seed(&[4u8; 32]);
        let pk = kp.public_bytes();
        let cts = [None, None, None, None];
        let bare = bundle_digest(&publics(), &cts, &pk);
        let sig = kp.sign(&bare).expect("sign");
        let bundle = bundle_with(sig, pk);
        assert!(!verify_carrier_auth(
            &bundle,
            &CarrierContext {
                signer: b"usa.reserve.sov",
                nonce: 0
            }
        ));
    }

    #[test]
    fn the_sighash_is_deterministic_injective_and_domain_separated() {
        let d = [9u8; 32];
        let a = CarrierContext {
            signer: b"ab",
            nonce: 1,
        };
        assert_eq!(carrier_sighash(&d, &a), carrier_sighash(&d, &a));
        // Length prefixing: ("ab", 1) and ("a", …) can never share a preimage.
        let b = CarrierContext {
            signer: b"a",
            nonce: 1,
        };
        assert_ne!(carrier_sighash(&d, &a), carrier_sighash(&d, &b));
        // The wrapped digest is not the signed message (the seam WRAPS, it
        // does not replace — bundle_digest and its KATs stay frozen).
        assert_ne!(carrier_sighash(&d, &a), d);
        // Distinct bundles under one carrier stay distinct.
        let mut d2 = d;
        d2[0] ^= 1;
        assert_ne!(carrier_sighash(&d, &a), carrier_sighash(&d2, &a));
    }
}
