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
//! Decoding rebuilds the exact bundle; the round-trip test re-verifies the
//! Halo2 proof afterward, so a mis-encoding cannot pass silently. Decoding is
//! strict: truncated input, an invalid component, or trailing bytes all error.

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

        // Re-encoding is identical (canonical), the proof still verifies, and the
        // public value balance survived the round trip.
        assert_eq!(decoded.to_bytes(), bytes, "encoding is canonical");
        assert!(decoded.verify(&params), "proof verifies after round-trip");
        assert_eq!(decoded.value_balance(), bundle.value_balance());
        assert_eq!(decoded.value_balance(), -77);
    }

    #[test]
    fn malformed_input_is_rejected() {
        assert!(ShieldedBundle::from_bytes(&[]).is_err());
        assert!(ShieldedBundle::from_bytes(&[0u8; 10]).is_err());
    }
}
