//! Total (panic-free) structural pre-validation of serialized winterfell
//! bundle proofs — the S1c / D15 hardening layer.
//!
//! # Why this exists
//!
//! `winterfell::Proof::from_bytes` is NOT total on adversarial input. The
//! audited panic/abort paths in winterfell 0.13.1 are:
//!
//! - `ProofOptions::read_from` calls `ProofOptions::new`, which `assert!`s
//!   on out-of-range parameters (zero queries, non-power-of-two blowup,
//!   grinding > 32, …) — a one-byte corruption of the option header is a
//!   remote panic. `PartitionOptions::new` (via `with_partitions`) asserts
//!   the same way.
//! - `TraceInfo::read_from` computes `2usize.pow(trace_length_byte)` (a
//!   byte of 255 overflows) and funnels into `new_multi_segment`, which
//!   asserts on its inputs.
//! - `Vec<T>::read_from` (winter-utils) reads an attacker-controlled vint
//!   length up to `u64::MAX` and calls `Vec::with_capacity(len)` BEFORE
//!   reading any element: a huge declared length is at best a catchable
//!   "capacity overflow" panic and at worst an uncatchable allocation
//!   abort. These lengths appear in the trace/constraint query sections.
//!
//! In consensus (W2) a spend bundle arrives from an untrusted peer, so any
//! of these is a remote-crash DoS (D15: BLOCKER). This module makes the
//! decode path total: [`validate_proof_frame`] walks the COMPLETE
//! winterfell 0.13 proof layout with a bounds-checked cursor and rejects,
//! with a typed error and no allocation proportional to declared (rather
//! than actual) sizes, every input on which `Proof::from_bytes` could
//! panic, abort, or over-allocate:
//!
//! 1. The total length is capped at [`MAX_PROOF_LEN`].
//! 2. The proof context (trace info + field modulus + proof options +
//!    constraint count) must be BYTE-IDENTICAL to the canonical context an
//!    honest prover emits for this circuit and the given public inputs
//!    (the dummy pattern fixes the assertion count). This removes every
//!    assert path in the header parsers: no attacker-chosen option or
//!    trace-shape byte ever reaches `ProofOptions::new`/`TraceInfo`.
//!    Strictness is sound: `verify_spend` only accepts the standard
//!    [`crate::prover::proof_options`] and the AIR fixes the trace shape,
//!    so any proof that could verify has exactly these context bytes.
//! 3. Every declared length in the body (commitments, query sections, OOD
//!    frame, FRI layers, remainder) is checked against the bytes ACTUALLY
//!    remaining before winterfell is allowed to allocate for it.
//! 4. Trailing bytes after the proof are rejected (canonical framing).
//!
//! The single decode entry point, [`crate::prover::decode_proof`], runs
//! this validator FIRST and only then hands the bytes to winterfell —
//! additionally wrapped in `catch_unwind` as a last line of defense.

use crate::air::{BundleAir, BundlePublicInputs, TRACE_LENGTH, TRACE_WIDTH};
use crate::hash::Felt;
use crate::prover::proof_options;
use winter_math::StarkField;
use winter_utils::{ByteWriter, Serializable};
use winterfell::{Air, TraceInfo};

/// Hard cap on accepted serialized proof size. An honest proof for this
/// circuit is ~35.5 KB; the cap leaves headroom without letting a peer
/// make us buffer megabytes. (Re-check if [`proof_options`] change.)
pub const MAX_PROOF_LEN: usize = 128 * 1024;

/// Typed rejection reasons for a malformed proof frame. Every variant is a
/// clean `Err` — none of these paths panic.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProofFrameError {
    /// The proof exceeds [`MAX_PROOF_LEN`].
    #[error("proof is {0} bytes, above the {MAX_PROOF_LEN}-byte cap")]
    TooLong(usize),
    /// The input ended before the named section was complete.
    #[error("truncated proof (in {0})")]
    Truncated(&'static str),
    /// The context bytes differ from the canonical context for this
    /// circuit + public-input shape (wrong options, trace shape, field,
    /// or constraint count — including every corrupt-header panic path).
    #[error("proof context does not match this circuit's canonical context")]
    ContextMismatch,
    /// `num_unique_queries` outside `1..=num_queries`.
    #[error("unique query count {0} outside 1..={1}")]
    QueryCount(u8, u8),
    /// A declared section length exceeds the bytes actually present.
    #[error("declared {section} length {declared} exceeds {remaining} remaining bytes")]
    LengthOverrun {
        /// Which section declared the length.
        section: &'static str,
        /// The declared length.
        declared: u64,
        /// Bytes actually remaining in the input.
        remaining: usize,
    },
    /// A FRI layer declared zero query-value bytes (winterfell rejects
    /// this too, but we refuse it before winterfell sees it).
    #[error("FRI layer {0} declares zero query-value bytes")]
    EmptyFriLayer(usize),
    /// Bytes remain after a structurally complete proof.
    #[error("{0} trailing bytes after the proof")]
    TrailingBytes(usize),
}

/// A total, bounds-checked forward cursor. Every read returns `Err` on
/// exhaustion; nothing here indexes, allocates, or panics.
struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Cursor { data, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    fn take(&mut self, len: u64, section: &'static str) -> Result<(), ProofFrameError> {
        if len > self.remaining() as u64 {
            return Err(ProofFrameError::LengthOverrun {
                section,
                declared: len,
                remaining: self.remaining(),
            });
        }
        self.pos += len as usize;
        Ok(())
    }

    fn bytes(&mut self, len: usize, section: &'static str) -> Result<&'a [u8], ProofFrameError> {
        if len > self.remaining() {
            return Err(ProofFrameError::Truncated(section));
        }
        let out = &self.data[self.pos..self.pos + len];
        self.pos += len;
        Ok(out)
    }

    fn u8(&mut self, section: &'static str) -> Result<u8, ProofFrameError> {
        Ok(self.bytes(1, section)?[0])
    }

    fn u16_le(&mut self, section: &'static str) -> Result<u16, ProofFrameError> {
        let b = self.bytes(2, section)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    fn u32_le(&mut self, section: &'static str) -> Result<u32, ProofFrameError> {
        let b = self.bytes(4, section)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// winter-utils vint64 (`ByteReader::read_usize`), replicated totally:
    /// the first byte's trailing zeros select a 1–9 byte encoding. Accepts
    /// exactly the encodings winter-utils accepts (including non-minimal
    /// ones) and returns the value WITHOUT allocating for it.
    fn vint(&mut self, section: &'static str) -> Result<u64, ProofFrameError> {
        let first = self.data[self.pos..]
            .first()
            .copied()
            .ok_or(ProofFrameError::Truncated(section))?;
        let length = first.trailing_zeros() as usize + 1;
        if length == 9 {
            let b = self.bytes(9, section)?;
            let mut le = [0u8; 8];
            le.copy_from_slice(&b[1..9]);
            Ok(u64::from_le_bytes(le))
        } else {
            let b = self.bytes(length, section)?;
            let mut le = [0u8; 8];
            le[..length].copy_from_slice(b);
            Ok(u64::from_le_bytes(le) >> length)
        }
    }
}

/// The exact context bytes an honest prover emits for this circuit with
/// the given public-input shape: `TraceInfo` (31×1024, no aux segment),
/// the f64 field modulus, the standard [`proof_options`], and the
/// constraint count (which depends only on the public dummy pattern).
/// Built with winterfell's OWN `Serializable` impls, mirroring the
/// prover-channel `Context::new` + `Context::write_into` path, so it is
/// byte-identical by construction (and pinned against a real proof by the
/// `honest_kat_proof_passes_frame_validation` test).
pub fn expected_context_bytes(pub_inputs: &BundlePublicInputs) -> Vec<u8> {
    let trace_info = TraceInfo::new(TRACE_WIDTH, TRACE_LENGTH);
    let air = BundleAir::new(trace_info.clone(), pub_inputs.clone(), proof_options());
    let num_constraints =
        air.context().num_assertions() + air.context().num_transition_constraints();
    let mut out: Vec<u8> = Vec::with_capacity(32);
    trace_info.write_into(&mut out);
    let modulus = Felt::get_modulus_le_bytes();
    out.write_u8(modulus.len() as u8);
    out.write_bytes(&modulus);
    proof_options().write_into(&mut out);
    out.write_usize(num_constraints);
    out
}

/// Validate the complete structural frame of a serialized winterfell proof
/// for this circuit, TOTALLY: for any byte string this returns `Ok` or a
/// typed [`ProofFrameError`] — it never panics, never aborts, and never
/// allocates in proportion to a declared (rather than actual) size. After
/// `Ok`, `winterfell::Proof::from_bytes` on the same bytes performs only
/// allocations bounded by the (capped) input length and reaches none of
/// its assert/overflow paths (see the module docs for the audit).
///
/// `pub_inputs` fixes the expected context (the assertion count depends on
/// the public dummy pattern).
pub fn validate_proof_frame(
    proof_bytes: &[u8],
    pub_inputs: &BundlePublicInputs,
) -> Result<(), ProofFrameError> {
    if proof_bytes.len() > MAX_PROOF_LEN {
        return Err(ProofFrameError::TooLong(proof_bytes.len()));
    }
    // 1. Context: exact byte match with the canonical context. Kills every
    //    corrupt-header panic path (options / trace info / partitions).
    let expected = expected_context_bytes(pub_inputs);
    if proof_bytes.len() < expected.len() {
        return Err(ProofFrameError::Truncated("context"));
    }
    if proof_bytes[..expected.len()] != expected[..] {
        return Err(ProofFrameError::ContextMismatch);
    }
    let mut c = Cursor::new(&proof_bytes[expected.len()..]);

    // 2. num_unique_queries: u8, 1..=num_queries for the standard options.
    let num_queries = proof_options().num_queries() as u8;
    let unique = c.u8("num_unique_queries")?;
    if unique == 0 || unique > num_queries {
        return Err(ProofFrameError::QueryCount(unique, num_queries));
    }

    // 3. Commitments: u16 length + bytes.
    let commitments_len = c.u16_le("commitments length")?;
    c.take(commitments_len as u64, "commitments")?;

    // 4. Query sections. This circuit has exactly ONE trace segment (no
    //    aux columns), so winterfell reads one trace-query section plus
    //    one constraint-query section; each is two vint-length byte
    //    vectors (values, then opening proof). The vint lengths are the
    //    `Vec::with_capacity` abort path — checked against remaining bytes
    //    HERE, before winterfell allocates.
    for section in [
        "trace query values",
        "trace query proof",
        "constraint query values",
        "constraint query proof",
    ] {
        let len = c.vint(section)?;
        c.take(len, section)?;
    }

    // 5. OOD frame: two u16-length byte vectors.
    let trace_states_len = c.u16_le("ood trace-states length")?;
    c.take(trace_states_len as u64, "ood trace states")?;
    let quotient_len = c.u16_le("ood quotient-states length")?;
    c.take(quotient_len as u64, "ood quotient states")?;

    // 6. FRI proof: u8 layer count; per layer a u32-length value vector
    //    (must be nonzero) and a u32-length path vector; then a u16-length
    //    remainder and a u8 partition count.
    let num_layers = c.u8("fri layer count")?;
    for layer in 0..num_layers as usize {
        let values_len = c.u32_le("fri layer values length")?;
        if values_len == 0 {
            return Err(ProofFrameError::EmptyFriLayer(layer));
        }
        c.take(values_len as u64, "fri layer values")?;
        let paths_len = c.u32_le("fri layer paths length")?;
        c.take(paths_len as u64, "fri layer paths")?;
    }
    let remainder_len = c.u16_le("fri remainder length")?;
    c.take(remainder_len as u64, "fri remainder")?;
    let _num_partitions = c.u8("fri partition count")?;

    // 7. PoW nonce: 8 bytes, then the input must END (canonical framing).
    c.bytes(8, "pow nonce")?;
    if c.remaining() != 0 {
        return Err(ProofFrameError::TrailingBytes(c.remaining()));
    }
    Ok(())
}
