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
//! # The scheme (D4's pinned form, with the PQV2-06 network binding)
//!
//! The signature covers a SECOND, domain-separated digest that wraps the
//! frozen bundle digest together with the carrier's context — the network it
//! belongs to AND the transaction that carries it:
//!
//! ```text
//! sighash = blake3_derive_key(B3_CARRIER_BINDING,
//!               scheme_byte ‖ len(chain_id) ‖ chain_id ‖ genesis(32)
//!                           ‖ len(signer) ‖ signer ‖ nonce ‖ bundle_digest)
//! ```
//!
//! with `scheme_byte = ` [`SCHEME_DOMAIN_SIGNER_NONCE`], the network context
//! this chain's `{chain_id, genesis}`, and the carrier context the
//! transaction's `{signer, nonce}` — the pair that is unique per accepted
//! transaction in SOV's account model (the nonce is consumed on execution,
//! so no second transaction from that signer can ever reuse it).
//!
//! **Why the network is in the preimage (audit PQV2-06).** An earlier form of
//! this seam bound only `{signer, nonce}` and leaned on the *carrier
//! transaction's own signature* being chain-bound (the `tx-domain` fork) to
//! stop cross-network replay. That is an activation-ORDERING assumption
//! consensus does not enforce: nothing requires `tx-domain` to be in force
//! before/with `shielded-v2`. If `shielded-v2` were active while `tx-domain`
//! was still `Legacy` (or in its `Grace` window, where a legacy carrier
//! signature is accepted), the whole `Action::ShieldedV2` transaction — a
//! legacy-signed carrier plus a `{signer,nonce}`-only bundle — is
//! network-agnostic and replays byte-for-byte onto any sibling SOV network
//! where that signer holds the same implicit id and nonce. Folding
//! `{chain_id, genesis}` into the authorized message makes the binding
//! INTRINSIC: a bundle authorized for network A cannot verify under network
//! B's domain, whatever `tx-domain` has or has not done. The executor sources
//! the domain from the chain's own identity (always known), not from the
//! `tx-domain` deployment state, so the protection does not depend on any
//! activation order.
//!
//! **What it excludes, and why it must.** The sighash cannot commit to the
//! carrier transaction id: `Transaction::id()` hashes the whole Borsh
//! transaction, whose action embeds these bundle bytes *including the
//! `auth_sig` field* — the signature would have to sign a hash of itself.
//! For the same reason the sighash cannot commit to the serialized proof:
//! the winterfell prover is not required to be deterministic, so a re-proof
//! of the identical statement would invalidate an otherwise valid signature.
//! Neither exclusion weakens the binding: the proof is bound to the *public
//! inputs* by STARK verification, and every public input is inside
//! `bundle_digest`.
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

/// Binding scheme 2 — the chain's `{chain_id, genesis}` PLUS the carrier's
/// `{signer, nonce}` (the account-model form pinned by D4, extended with the
/// intrinsic network binding of audit PQV2-06, and the only scheme v0.2.0
/// accepts). Scheme byte 1 (the network-agnostic `{signer, nonce}`-only form)
/// is retired: it never authorized a bundle on any chain (bit 2 is DORMANT
/// everywhere), so retiring it strands nothing.
pub const SCHEME_DOMAIN_SIGNER_NONCE: u8 = 2;

/// The carrier context an authorization is bound to: the NETWORK it belongs to
/// and the transaction that carries it.
///
/// Constructed by the executor from the chain's own identity and the
/// transaction being applied; there is no `Default` and no "unbound" variant,
/// so a consensus caller cannot accidentally verify an unbound signature — the
/// binding is unrepresentable as absent. The `{chain_id, genesis}` pair is the
/// chain's branch-independent identity (the same one the `tx-domain` fork
/// binds transaction signatures to), sourced independently of whether that
/// fork has activated, so the network binding does not depend on activation
/// order (PQV2-06).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CarrierContext<'a> {
    /// This chain's network id, as its canonical ASCII bytes.
    pub chain_id: &'a [u8],
    /// This chain's frozen genesis block hash.
    pub genesis: &'a [u8; 32],
    /// The carrier transaction's signer account, as its canonical bytes.
    pub signer: &'a [u8],
    /// The carrier transaction's nonce (the value the transaction spends,
    /// i.e. the signer's nonce *before* execution increments it).
    pub nonce: u64,
}

/// The message an authorization signature must cover: the carrier-bound
/// sighash over `(scheme, chain_id, genesis, signer, nonce, bundle_digest)`.
///
/// Injective in its inputs: the scheme byte is fixed-width and leads, the two
/// variable-length fields (`chain_id`, `signer`) are each length-prefixed, and
/// the genesis, nonce and digest are fixed-width — so no two distinct
/// `(scheme, chain_id, genesis, signer, nonce, digest)` tuples share a
/// preimage. Changing any of the six changes the message, so a signature made
/// for one network cannot be reused on another.
pub fn carrier_sighash(bundle_digest: &[u8; 32], ctx: &CarrierContext<'_>) -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key(B3_CARRIER_BINDING);
    h.update(&[SCHEME_DOMAIN_SIGNER_NONCE]);
    h.update(&(ctx.chain_id.len() as u64).to_le_bytes());
    h.update(ctx.chain_id);
    h.update(ctx.genesis);
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

    const GEN_A: &[u8; 32] = &[0xAA; 32];
    const GEN_B: &[u8; 32] = &[0xBB; 32];

    fn ctx_a(signer: &'static [u8], nonce: u64) -> CarrierContext<'static> {
        CarrierContext {
            chain_id: b"sov-mainnet",
            genesis: GEN_A,
            signer,
            nonce,
        }
    }

    #[test]
    fn a_signature_verifies_only_under_its_own_carrier() {
        let kp = AuthKeypair::from_seed(&[3u8; 32]);
        let cts = [None, None, None, None];
        let ctx = ctx_a(b"usa.reserve.sov", 4);
        let (pk, sig) = sign_in_carrier(&kp, &publics(), &cts, &ctx).expect("sign");
        let bundle = bundle_with(sig, pk);
        assert!(verify_carrier_auth(&bundle, &ctx));
        // A different nonce — the same signer replaying their own bundle at
        // another sequence position — does NOT verify.
        assert!(!verify_carrier_auth(&bundle, &ctx_a(b"usa.reserve.sov", 5)));
        // A different signer — the mempool-lifting attack — does NOT verify.
        assert!(!verify_carrier_auth(&bundle, &ctx_a(b"thief.sov", 4)));
    }

    /// PQV2-06: a bundle authorized for one network must NOT verify under
    /// another network's domain — even with the identical `{signer, nonce}`.
    /// This is the intrinsic cross-network replay guard; it holds regardless of
    /// the `tx-domain` fork's activation state, because the network is inside
    /// the authorized message itself.
    #[test]
    fn a_signature_does_not_verify_under_another_network() {
        let kp = AuthKeypair::from_seed(&[7u8; 32]);
        let cts = [None, None, None, None];
        // Authorize on network A.
        let ctx = ctx_a(b"usa.reserve.sov", 4);
        let (pk, sig) = sign_in_carrier(&kp, &publics(), &cts, &ctx).expect("sign");
        let bundle = bundle_with(sig, pk);
        assert!(
            verify_carrier_auth(&bundle, &ctx),
            "its own network verifies"
        );
        // A DIFFERENT chain id, same signer/nonce/genesis: refused.
        assert!(!verify_carrier_auth(
            &bundle,
            &CarrierContext {
                chain_id: b"sov-testnet-1",
                genesis: GEN_A,
                signer: b"usa.reserve.sov",
                nonce: 4,
            }
        ));
        // A DIFFERENT genesis (a fork with the same id), same signer/nonce:
        // refused.
        assert!(!verify_carrier_auth(
            &bundle,
            &CarrierContext {
                chain_id: b"sov-mainnet",
                genesis: GEN_B,
                signer: b"usa.reserve.sov",
                nonce: 4,
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
        assert!(!verify_carrier_auth(&bundle, &ctx_a(b"usa.reserve.sov", 0)));
    }

    #[test]
    fn the_sighash_is_deterministic_injective_and_domain_separated() {
        let d = [9u8; 32];
        let a = ctx_a(b"ab", 1);
        assert_eq!(carrier_sighash(&d, &a), carrier_sighash(&d, &a));
        // Length prefixing: ("ab", 1) and ("a", …) can never share a preimage.
        let b = ctx_a(b"a", 1);
        assert_ne!(carrier_sighash(&d, &a), carrier_sighash(&d, &b));
        // The network is in the preimage: a different chain id or genesis
        // yields a different sighash for the identical bundle + carrier.
        assert_ne!(
            carrier_sighash(&d, &a),
            carrier_sighash(
                &d,
                &CarrierContext {
                    chain_id: b"other",
                    genesis: GEN_A,
                    signer: b"ab",
                    nonce: 1,
                }
            )
        );
        assert_ne!(
            carrier_sighash(&d, &a),
            carrier_sighash(
                &d,
                &CarrierContext {
                    chain_id: b"sov-mainnet",
                    genesis: GEN_B,
                    signer: b"ab",
                    nonce: 1,
                }
            )
        );
        // The wrapped digest is not the signed message (the seam WRAPS, it
        // does not replace — bundle_digest and its KATs stay frozen).
        assert_ne!(carrier_sighash(&d, &a), d);
        // Distinct bundles under one carrier stay distinct.
        let mut d2 = d;
        d2[0] ^= 1;
        assert_ne!(carrier_sighash(&d, &a), carrier_sighash(&d2, &a));
    }

    #[test]
    fn carrier_sighash_byte_kat_pinned() {
        // BYTE-EXACT KAT (audit PQV2-08). Every other carrier test re-derives
        // the sighash through this same code, so they are self-consistent: a
        // silent change to the preimage layout, the scheme byte, or the
        // `B3_CARRIER_BINDING` domain separator would keep them ALL green while
        // changing the actual authorized message. This pins the known answer
        // for a fully-fixed input, so any such change screams here.
        //
        // The scheme byte is part of the preimage, so its value is pinned too:
        assert_eq!(SCHEME_DOMAIN_SIGNER_NONCE, 2, "carrier scheme byte moved");
        let digest = [0x11u8; 32];
        let ctx = CarrierContext {
            chain_id: b"sov-mainnet",
            genesis: &[0xAA; 32],
            signer: b"usa.reserve.sov",
            nonce: 4,
        };
        assert_eq!(
            hex::encode(carrier_sighash(&digest, &ctx)),
            "22eba1d2409986def8fdc3f32fb4a2b848626948638447cd72043f749d2ef042",
            "carrier sighash KAT drifted — the network/carrier binding preimage changed"
        );
    }
}
