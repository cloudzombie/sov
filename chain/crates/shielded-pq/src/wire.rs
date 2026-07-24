//! The v1 wire format for [`SpendBundle`] — a TOTAL, canonical,
//! version-gated codec (S1c, decisions D6 + D15).
//!
//! # Versioning (D6)
//!
//! Every encoded bundle starts with a `proof_version` byte that selects
//! the decoder. This build understands exactly [`PROOF_VERSION_V1`];
//! any other version is a clean typed reject
//! ([`WireError::UnknownProofVersion`]) — never a panic, never a silent
//! skip. Future circuits ship as version N+1 with their own decoder arm.
//!
//! # v1 layout (all integers little-endian)
//!
//! ```text
//! u8            proof_version                   == 1
//! [u8; 32] × 4  anchors                         (canonical PqDigest bytes)
//! [u8; 32] × 4  nullifiers
//! u8       × 4  input_dummy                     (strictly 0 or 1)
//! [u8; 32] × 4  output_commitments
//! u8       × 4  output_dummy                    (strictly 0 or 1)
//! u64           transparent_in
//! u64           transparent_out
//! u64           fee_grains
//! u32           proof_len                       (1..=MAX_PROOF_LEN)
//! [u8; proof_len] proof bytes                   (frame pre-validated, see below)
//! per output slot (4×):
//!   u8          present                         (strictly 0 or 1)
//!   if present: [u8; 1088] kem_ct ‖ [u8; 4] detection_tag
//!               ‖ u16 aead_len == 88 ‖ [u8; 88] aead_ct
//! [u8; 1952]    auth_pk                         (ML-DSA-65)
//! [u8; 3309]    auth_sig
//! (end — trailing bytes rejected)
//! ```
//!
//! # Totality and canonicity
//!
//! [`decode_bundle`] is a total function: for ANY byte string it returns
//! `Ok` or a typed [`WireError`] — it never panics (fuzzed; see
//! `fuzz/`). The embedded proof bytes are additionally run through the
//! [`crate::proof_frame`] pre-validator against the bundle's OWN decoded
//! public inputs, so a decoded bundle's proof can never make winterfell
//! panic downstream even if a caller bypasses
//! [`crate::prover::verify_spend`]'s own pre-validation.
//!
//! The accepted format is canonical: digests must be canonical field
//! encodings, flags strictly 0/1, the ciphertext length exactly
//! [`AEAD_CT_LEN`], the proof frame exactly consumed, and no trailing
//! bytes — so `encode_bundle(&decode_bundle(b)?) == b` for every accepted
//! `b` (asserted by the fuzz targets). The proof blob itself is carried
//! verbatim.
//!
//! Semantic rules (dummy-slot conventions, anchor ring, value bounds,
//! signature, the proof itself) stay in [`crate::bundle::verify_bundle`]
//! — decoding is structural only.

use crate::air::{BundlePublicInputs, NUM_SLOTS};
use crate::auth::{AUTH_PK_LEN, AUTH_SIG_LEN};
use crate::bundle::SpendBundle;
use crate::encrypt::{NoteCiphertext, KEM_CT_LEN};
use crate::hash::PqDigest;
use crate::proof_frame::{validate_proof_frame, ProofFrameError, MAX_PROOF_LEN};

/// The one proof/wire version this build understands (D6; v0.2.0 = 1).
pub const PROOF_VERSION_V1: u8 = 1;

/// Exact AEAD ciphertext length: the 72-byte note plaintext plus the
/// 16-byte Poly1305 tag.
pub const AEAD_CT_LEN: usize = 88;

/// Typed rejection reasons for a malformed bundle encoding. Every variant
/// is a clean `Err`; no decode path panics.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WireError {
    /// The input ended before the named field was complete.
    #[error("unexpected end of input (in {0})")]
    UnexpectedEnd(&'static str),
    /// The leading version byte selects no decoder in this build (D6).
    #[error("unknown proof_version {0} (this build understands only version {PROOF_VERSION_V1})")]
    UnknownProofVersion(u8),
    /// A flag byte was neither 0 nor 1.
    #[error("invalid flag byte {value:#04x} in {field} (must be 0 or 1)")]
    InvalidFlag {
        /// The field carrying the flag.
        field: &'static str,
        /// The offending byte.
        value: u8,
    },
    /// A 32-byte digest was not a canonical field-element encoding.
    #[error("non-canonical digest encoding in {0}")]
    NonCanonicalDigest(&'static str),
    /// The declared proof length is zero or above [`MAX_PROOF_LEN`].
    #[error("declared proof length {0} outside 1..={MAX_PROOF_LEN}")]
    ProofLength(u32),
    /// The declared AEAD ciphertext length is not exactly [`AEAD_CT_LEN`].
    #[error("declared ciphertext length {0} != {AEAD_CT_LEN}")]
    CiphertextLength(u16),
    /// The embedded proof failed structural frame validation.
    #[error("malformed proof frame: {0}")]
    ProofFrame(#[from] ProofFrameError),
    /// Bytes remain after a structurally complete bundle.
    #[error("{0} trailing bytes after the bundle")]
    TrailingBytes(usize),
}

/// A total, bounds-checked forward reader (no indexing, no panics).
struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Reader { data, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    fn bytes(&mut self, len: usize, field: &'static str) -> Result<&'a [u8], WireError> {
        if len > self.remaining() {
            return Err(WireError::UnexpectedEnd(field));
        }
        let out = &self.data[self.pos..self.pos + len];
        self.pos += len;
        Ok(out)
    }

    fn array<const N: usize>(&mut self, field: &'static str) -> Result<[u8; N], WireError> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.bytes(N, field)?);
        Ok(out)
    }

    fn u8(&mut self, field: &'static str) -> Result<u8, WireError> {
        Ok(self.bytes(1, field)?[0])
    }

    fn u16_le(&mut self, field: &'static str) -> Result<u16, WireError> {
        Ok(u16::from_le_bytes(self.array::<2>(field)?))
    }

    fn u32_le(&mut self, field: &'static str) -> Result<u32, WireError> {
        Ok(u32::from_le_bytes(self.array::<4>(field)?))
    }

    fn u64_le(&mut self, field: &'static str) -> Result<u64, WireError> {
        Ok(u64::from_le_bytes(self.array::<8>(field)?))
    }

    fn flag(&mut self, field: &'static str) -> Result<bool, WireError> {
        match self.u8(field)? {
            0 => Ok(false),
            1 => Ok(true),
            value => Err(WireError::InvalidFlag { field, value }),
        }
    }

    fn digest(&mut self, field: &'static str) -> Result<PqDigest, WireError> {
        let raw = self.array::<32>(field)?;
        PqDigest::from_bytes(&raw).ok_or(WireError::NonCanonicalDigest(field))
    }
}

/// Encode a bundle in the v1 wire format (see the module docs).
pub fn encode_bundle(bundle: &SpendBundle) -> Vec<u8> {
    let pi = &bundle.public_inputs;
    let mut out = Vec::with_capacity(
        1 + 12 * 32 + 8 + 24 + 4 + bundle.proof_bytes.len() + AUTH_PK_LEN + AUTH_SIG_LEN + 64,
    );
    out.push(PROOF_VERSION_V1);
    for d in &pi.anchors {
        out.extend_from_slice(&d.to_bytes());
    }
    for d in &pi.nullifiers {
        out.extend_from_slice(&d.to_bytes());
    }
    for &f in &pi.input_dummy {
        out.push(f as u8);
    }
    for d in &pi.output_commitments {
        out.extend_from_slice(&d.to_bytes());
    }
    for &f in &pi.output_dummy {
        out.push(f as u8);
    }
    out.extend_from_slice(&pi.transparent_in.to_le_bytes());
    out.extend_from_slice(&pi.transparent_out.to_le_bytes());
    out.extend_from_slice(&pi.fee_grains.to_le_bytes());
    // An honest proof always fits u32 (verify-side cap is MAX_PROOF_LEN);
    // saturate rather than truncate if a caller hands us something absurd
    // (such an encoding is then rejected on decode, never mis-framed).
    let proof_len = u32::try_from(bundle.proof_bytes.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&proof_len.to_le_bytes());
    out.extend_from_slice(&bundle.proof_bytes);
    for ct in &bundle.output_ciphertexts {
        match ct {
            Some(ct) => {
                out.push(1);
                out.extend_from_slice(&ct.kem_ct);
                out.extend_from_slice(&ct.detection_tag);
                let aead_len = u16::try_from(ct.aead_ct.len()).unwrap_or(u16::MAX);
                out.extend_from_slice(&aead_len.to_le_bytes());
                out.extend_from_slice(&ct.aead_ct);
            }
            None => out.push(0),
        }
    }
    out.extend_from_slice(&bundle.auth_pk);
    out.extend_from_slice(&bundle.auth_sig);
    out
}

/// Decode a v1 bundle. TOTAL: for any byte string this returns `Ok` or a
/// typed [`WireError`] — it never panics. Structural + canonical checks
/// only (see the module docs); run [`crate::bundle::verify_bundle`] on
/// the result for the semantic/cryptographic rules.
pub fn decode_bundle(data: &[u8]) -> Result<SpendBundle, WireError> {
    let mut r = Reader::new(data);
    // D6 version gate: the FIRST byte selects the decoder.
    let version = r.u8("proof_version")?;
    if version != PROOF_VERSION_V1 {
        return Err(WireError::UnknownProofVersion(version));
    }

    let mut anchors = [PqDigest::ZERO; NUM_SLOTS];
    for a in &mut anchors {
        *a = r.digest("anchor")?;
    }
    let mut nullifiers = [PqDigest::ZERO; NUM_SLOTS];
    for n in &mut nullifiers {
        *n = r.digest("nullifier")?;
    }
    let mut input_dummy = [false; NUM_SLOTS];
    for f in &mut input_dummy {
        *f = r.flag("input_dummy")?;
    }
    let mut output_commitments = [PqDigest::ZERO; NUM_SLOTS];
    for c in &mut output_commitments {
        *c = r.digest("output_commitment")?;
    }
    let mut output_dummy = [false; NUM_SLOTS];
    for f in &mut output_dummy {
        *f = r.flag("output_dummy")?;
    }
    let transparent_in = r.u64_le("transparent_in")?;
    let transparent_out = r.u64_le("transparent_out")?;
    let fee_grains = r.u64_le("fee_grains")?;
    let public_inputs = BundlePublicInputs {
        anchors,
        nullifiers,
        input_dummy,
        output_commitments,
        output_dummy,
        transparent_in,
        transparent_out,
        fee_grains,
    };

    // Proof: length-bounded BEFORE any read, then frame-validated against
    // this bundle's own public inputs so the blob can never panic
    // winterfell downstream (D15).
    let proof_len = r.u32_le("proof_len")?;
    if proof_len == 0 || proof_len as usize > MAX_PROOF_LEN {
        return Err(WireError::ProofLength(proof_len));
    }
    let proof_bytes = r.bytes(proof_len as usize, "proof")?.to_vec();
    validate_proof_frame(&proof_bytes, &public_inputs)?;

    let mut output_ciphertexts: [Option<NoteCiphertext>; NUM_SLOTS] = [None, None, None, None];
    for slot in &mut output_ciphertexts {
        if r.flag("ciphertext present")? {
            *slot = Some(decode_ciphertext_fields(&mut r)?);
        }
    }

    let auth_pk = r.array::<AUTH_PK_LEN>("auth_pk")?;
    let auth_sig = r.array::<AUTH_SIG_LEN>("auth_sig")?;
    if r.remaining() != 0 {
        return Err(WireError::TrailingBytes(r.remaining()));
    }
    Ok(SpendBundle {
        public_inputs,
        proof_bytes,
        output_ciphertexts,
        auth_pk,
        auth_sig,
    })
}

/// The ciphertext body (everything after the presence flag).
fn decode_ciphertext_fields(r: &mut Reader<'_>) -> Result<NoteCiphertext, WireError> {
    let kem_ct = r.array::<KEM_CT_LEN>("kem_ct")?;
    let detection_tag = r.array::<4>("detection_tag")?;
    let aead_len = r.u16_le("aead_len")?;
    if aead_len as usize != AEAD_CT_LEN {
        return Err(WireError::CiphertextLength(aead_len));
    }
    let aead_ct = r.bytes(AEAD_CT_LEN, "aead_ct")?.to_vec();
    Ok(NoteCiphertext {
        kem_ct,
        detection_tag,
        aead_ct,
    })
}

/// Decode ONE standalone note-ciphertext encoding (the per-slot body used
/// inside the bundle format, exact-consume). TOTAL; used directly by the
/// `fuzz_note_ciphertext_decode` target.
pub fn decode_note_ciphertext(data: &[u8]) -> Result<NoteCiphertext, WireError> {
    let mut r = Reader::new(data);
    let ct = decode_ciphertext_fields(&mut r)?;
    if r.remaining() != 0 {
        return Err(WireError::TrailingBytes(r.remaining()));
    }
    Ok(ct)
}

/// Encode ONE standalone note ciphertext (inverse of
/// [`decode_note_ciphertext`]).
pub fn encode_note_ciphertext(ct: &NoteCiphertext) -> Vec<u8> {
    let mut out = Vec::with_capacity(KEM_CT_LEN + 4 + 2 + ct.aead_ct.len());
    out.extend_from_slice(&ct.kem_ct);
    out.extend_from_slice(&ct.detection_tag);
    let aead_len = u16::try_from(ct.aead_ct.len()).unwrap_or(u16::MAX);
    out.extend_from_slice(&aead_len.to_le_bytes());
    out.extend_from_slice(&ct.aead_ct);
    out
}
