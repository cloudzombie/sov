//! Canonical byte serialization for shielded bundles.
//!
//! Orchard's bundle/action types implement neither Borsh nor serde, so a
//! shielded bundle needs an explicit, canonical byte encoding to travel on the
//! wire and be committed to inside a transaction. This module implements that
//! codec — the Zcash-v5-style Orchard layout:
//!
//! ```text
//! flags:1 | value_balance:i64le:8 | anchor:32 | num_actions:u32le:4
//! per action: nf:32 | rk:32 | cmx:32 | epk:32 | enc:580 | out:80 | cv_net:32 | spend_auth_sig:64
//! proof_len:u32le:4 | proof:proof_len | binding_sig:64
//! ```
//!
//! Decoding rebuilds the exact bundle; the round-trip test re-verifies its
//! proof and authorization signatures afterward. Decoding only checks the
//! encoding: callers must run [`ShieldedBundle::verify`] for cryptographic
//! validity. Truncated input, invalid components, and trailing bytes all error.

use nonempty::NonEmpty;
use orchard::bundle::{Authorized, Flags, ProofSizeEnforcement};
use orchard::note::{ExtractedNoteCommitment, Nullifier, TransmittedNoteCiphertext};
use orchard::primitives::redpallas::{Binding, Signature, SpendAuth, VerificationKey};
use orchard::tree::Anchor;
use orchard::value::ValueCommitment;
use orchard::{Action, Bundle, Proof};

use crate::pool::ShieldedBundle;
use crate::ShieldedError;

// Orchard fixed component sizes, in bytes.
const ENC_CIPHERTEXT: usize = 580;
const OUT_CIPHERTEXT: usize = 80;
const ACTION_BYTES: usize = 32 * 5 + ENC_CIPHERTEXT + OUT_CIPHERTEXT + 64;

impl ShieldedBundle {
    /// Serialize to the canonical byte encoding (see module docs).
    pub fn to_bytes(&self) -> Vec<u8> {
        let b = self.inner();
        let mut out = Vec::new();
        out.push(b.flags().to_byte());
        out.extend_from_slice(&(*b.value_balance()).to_le_bytes());
        out.extend_from_slice(&b.anchor().to_bytes());
        out.extend_from_slice(&(b.actions().len() as u32).to_le_bytes());
        for a in b.actions().iter() {
            out.extend_from_slice(&a.nullifier().to_bytes());
            out.extend_from_slice(&<[u8; 32]>::from(a.rk()));
            out.extend_from_slice(&a.cmx().to_bytes());
            let ct = a.encrypted_note();
            out.extend_from_slice(&ct.epk_bytes);
            out.extend_from_slice(&ct.enc_ciphertext);
            out.extend_from_slice(&ct.out_ciphertext);
            out.extend_from_slice(&a.cv_net().to_bytes());
            out.extend_from_slice(&<[u8; 64]>::from(a.authorization()));
        }
        let proof = b.authorization().proof().as_ref();
        out.extend_from_slice(&(proof.len() as u32).to_le_bytes());
        out.extend_from_slice(proof);
        out.extend_from_slice(&<[u8; 64]>::from(b.authorization().binding_signature()));
        out
    }

    /// Decode a bundle from [`to_bytes`](Self::to_bytes). Rejects truncated,
    /// malformed, or trailing-garbage input.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ShieldedError> {
        let mut r = Reader::new(bytes);

        let flags = Flags::from_byte(r.u8()?).ok_or_else(|| decode("invalid flags"))?;
        let value_balance = i64::from_le_bytes(r.arr::<8>()?);
        let anchor =
            Option::from(Anchor::from_bytes(r.arr::<32>()?)).ok_or_else(|| decode("anchor"))?;

        let count = u32::from_le_bytes(r.arr::<4>()?) as usize;
        // The action count is untrusted. Bound it by the actual input before
        // allocating, leaving room for the proof length and binding signature.
        // Otherwise even a tiny malformed bundle can request a huge allocation.
        if count == 0 || count > r.remaining().saturating_sub(4 + 64) / ACTION_BYTES {
            return Err(decode("invalid action count"));
        }
        let mut actions = Vec::with_capacity(count);
        for _ in 0..count {
            let nf = Option::from(Nullifier::from_bytes(&r.arr::<32>()?))
                .ok_or_else(|| decode("nullifier"))?;
            let rk = VerificationKey::try_from(r.arr::<32>()?).map_err(|_| decode("rk"))?;
            let cmx = Option::from(ExtractedNoteCommitment::from_bytes(&r.arr::<32>()?))
                .ok_or_else(|| decode("cmx"))?;
            let epk_bytes = r.arr::<32>()?;
            let enc_ciphertext = r.arr::<ENC_CIPHERTEXT>()?;
            let out_ciphertext = r.arr::<OUT_CIPHERTEXT>()?;
            let cv_net = Option::from(ValueCommitment::from_bytes(&r.arr::<32>()?))
                .ok_or_else(|| decode("cv_net"))?;
            let auth: Signature<SpendAuth> = Signature::from(r.arr::<64>()?);
            let ct = TransmittedNoteCiphertext {
                epk_bytes,
                enc_ciphertext,
                out_ciphertext,
            };
            // orchard 0.14 validates rk and epk are non-identity points here.
            let action =
                Action::from_parts(nf, rk, cmx, ct, cv_net, auth).map_err(|_| decode("action"))?;
            actions.push(action);
        }
        let actions = NonEmpty::from_vec(actions).ok_or_else(|| decode("no actions"))?;

        let proof_len = u32::from_le_bytes(r.arr::<4>()?) as usize;
        let proof = Proof::new(r.take(proof_len)?.to_vec());
        let binding: Signature<Binding> = Signature::from(r.arr::<64>()?);

        if !r.finished() {
            return Err(decode("trailing bytes"));
        }

        let authorized = Authorized::from_parts(proof, binding);
        // Strict proof-size enforcement rejects a proof padded with arbitrary
        // trailing data — the only authorized-bundle constructor in orchard 0.14
        // (GHSA-2x4w-pxqw-58v9). Combined with the trailing-bytes check above, a
        // decoded bundle is canonical.
        let bundle = Bundle::try_from_parts(
            actions,
            flags,
            value_balance,
            anchor,
            authorized,
            ProofSizeEnforcement::Strict,
        )
        .map_err(|_| decode("non-canonical bundle"))?;
        Ok(ShieldedBundle::from_authorized(bundle))
    }
}

fn decode(what: &str) -> ShieldedError {
    ShieldedError::Decode(what.to_string())
}

/// A minimal forward-only byte reader with bounds checks.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], ShieldedError> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or_else(|| decode("length overflow"))?;
        let slice = self
            .buf
            .get(self.pos..end)
            .ok_or_else(|| decode("unexpected end of input"))?;
        self.pos = end;
        Ok(slice)
    }

    fn arr<const N: usize>(&mut self) -> Result<[u8; N], ShieldedError> {
        let mut a = [0u8; N];
        a.copy_from_slice(self.take(N)?);
        Ok(a)
    }

    fn u8(&mut self) -> Result<u8, ShieldedError> {
        Ok(self.take(1)?[0])
    }

    fn finished(&self) -> bool {
        self.pos == self.buf.len()
    }

    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }
}

/// Regression checks shared by real mint and spend tests. Alter only the
/// authorization/value-balance bytes in a legitimately generated bundle; no
/// custom proof construction or unauthorized spending is involved.
#[cfg(test)]
pub(crate) fn assert_authorization_mutations_rejected(
    bundle: &ShieldedBundle,
    params: &crate::ShieldedParams,
) {
    const HEADER_BYTES: usize = 1 + 8 + 32 + 4;
    const ACTION_SIGNATURE_OFFSET: usize = ACTION_BYTES - 64;

    let bytes = bundle.to_bytes();
    for action_index in 0..bundle.inner().actions().len() {
        let mut changed = bytes.clone();
        let start = HEADER_BYTES + action_index * ACTION_BYTES + ACTION_SIGNATURE_OFFSET;
        changed[start..start + 64].fill(0);
        let invalid = ShieldedBundle::from_bytes(&changed).expect("signature has valid encoding");
        assert!(
            invalid.verify_proof_only_legacy(params),
            "changing spend authorization must leave the proof intact"
        );
        assert!(
            !invalid.verify(params),
            "each spend signature must be verified"
        );
    }

    let mut changed = bytes.clone();
    let binding_start = changed.len() - 64;
    changed[binding_start..].fill(0);
    let invalid = ShieldedBundle::from_bytes(&changed).expect("binding has valid encoding");
    assert!(invalid.verify_proof_only_legacy(params));
    assert!(
        !invalid.verify(params),
        "the binding signature must be verified"
    );

    let mut changed = bytes;
    changed[1] ^= 1;
    let invalid = ShieldedBundle::from_bytes(&changed).expect("modified value balance encodes");
    assert!(
        invalid.verify_proof_only_legacy(params),
        "the proof alone does not bind the public value balance"
    );
    assert!(
        !invalid.verify(params),
        "value-balance mutations must be rejected"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pool::{mint_to_shielded, ShieldedParams};
    use crate::ShieldedKey;

    #[test]
    fn bundle_round_trips_through_bytes_and_proof_still_verifies() {
        let params = ShieldedParams::build();
        let addr = ShieldedKey::from_seed([9u8; 32]).unwrap().address();
        let bundle = mint_to_shielded(&params, &addr, 77).unwrap();

        let bytes = bundle.to_bytes();
        let decoded = ShieldedBundle::from_bytes(&bytes).expect("decodes");

        // Re-encoding is identical (canonical), complete authorization verifies,
        // and the public value balance survived the round trip.
        assert_eq!(decoded.to_bytes(), bytes, "encoding is canonical");
        assert!(
            decoded.verify(&params),
            "authorization verifies after round-trip"
        );
        assert_eq!(decoded.value_balance(), bundle.value_balance());
        assert_eq!(decoded.value_balance(), -77);

        assert_authorization_mutations_rejected(&decoded, &params);
    }

    #[test]
    fn malformed_input_is_rejected() {
        assert!(ShieldedBundle::from_bytes(&[]).is_err());
        assert!(ShieldedBundle::from_bytes(&[0u8; 10]).is_err());

        let mut oversized_count = vec![0; 1 + 8];
        oversized_count.extend_from_slice(&Anchor::empty_tree().to_bytes());
        oversized_count.extend_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(
            ShieldedBundle::from_bytes(&oversized_count).err(),
            Some(decode("invalid action count")),
            "untrusted action counts must be bounded before allocation"
        );
    }
}
