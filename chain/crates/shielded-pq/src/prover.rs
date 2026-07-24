//! Execution-trace builder, prover, and verifier for the 4-in/4-out bundle
//! circuit ([`crate::air::BundleAir`]).

use crate::air::{
    input_base, merkle_inject_row, rc_base, BundleAir, BundlePublicInputs, ACTIVE_ROWS, BIT_COL,
    CAPACITY_SEED, CYCLE_LENGTH, NSK_COL, NUM_SLOTS, OUTPUTS_START_ROW, RC_ACC_COL, RC_BIT_COL,
    RHO_COL, TRACE_LENGTH, TRACE_WIDTH, VAL_COL,
};
use crate::domains::{
    RESCUE_DOMAIN_COMMIT_STAGE1, RESCUE_DOMAIN_COMMIT_STAGE2, RESCUE_DOMAIN_DUMMY_NULLIFIER,
    RESCUE_DOMAIN_MERKLE_NODE, RESCUE_DOMAIN_NULLIFIER, RESCUE_DOMAIN_OWNER_TAG,
};
use crate::hash::{Felt, PqDigest, NUM_ROUNDS, STATE_WIDTH};
use crate::note::{Note, SpendingKey, MAX_NOTE_VALUE, VALUE_BITS};
use crate::tree::{MerklePath, TREE_DEPTH};
use winter_crypto::hashers::Rp64_256;
use winter_math::FieldElement;
use winterfell::{
    crypto::{DefaultRandomCoin, MerkleTree},
    matrix::ColMatrix,
    AcceptableOptions, AuxRandElements, BatchingMethod, CompositionPoly, CompositionPolyTrace,
    DefaultConstraintCommitment, DefaultConstraintEvaluator, DefaultTraceLde, FieldExtension,
    PartitionOptions, Proof, ProofOptions, Prover, StarkDomain, TraceInfo, TracePolyTable,
    TraceTable,
};

/// The hash used for the STARK's own commitments (FRI/trace Merkle trees).
/// Blake3 — hash-based, so the proof carrier is itself PQ.
type CarrierHash = winterfell::crypto::hashers::Blake3_256<Felt>;
type CarrierVc = MerkleTree<CarrierHash>;
type CarrierCoin = DefaultRandomCoin<CarrierHash>;

/// Errors from proving or verifying a bundle proof.
#[derive(Debug, thiserror::Error)]
pub enum SpendProofError {
    /// The witness is inconsistent (wrong key, path, note, or balance).
    #[error("invalid bundle witness: {0}")]
    InvalidWitness(&'static str),
    /// A public input violates its native bound.
    #[error("public input out of range: {0}")]
    PublicInput(&'static str),
    /// The winterfell prover failed.
    #[error("prover error: {0}")]
    Prover(String),
    /// Proof deserialization or verification failed.
    #[error("verification failed: {0}")]
    Verification(String),
}

/// Standard proof options: 42 FRI queries, blowup 8, 16 bits of grinding,
/// quadratic extension field — ≥ 100 bits conjectured security against a
/// classical adversary, and no number-theoretic assumptions a quantum
/// adversary could break (hashes only).
pub fn proof_options() -> ProofOptions {
    ProofOptions::new(
        42,
        8,
        16,
        FieldExtension::Quadratic,
        4,
        31,
        BatchingMethod::Linear,
        BatchingMethod::Linear,
    )
}

/// One real spend's witness: the owning key, the note, and its Merkle path.
pub struct BundleSpend {
    /// The key owning the note (its `owner_tag` must match).
    pub key: SpendingKey,
    /// The note being spent.
    pub note: Note,
    /// Membership witness; its implied root becomes the slot's public
    /// anchor (each slot may use a different anchor, D5).
    pub path: MerklePath,
}

/// Build the 31×1024 execution trace COLUMNS for one bundle, plus the
/// public inputs they commit to. Up to [`NUM_SLOTS`] real spends and
/// outputs; remaining slots are filled with in-circuit dummies (zero value,
/// domain-separated dummy nullifier, unconstrained junk chain).
///
/// Exposed (rather than private to [`prove_bundle`]) so negative tests can
/// tamper with individual trace cells and watch the constraint system
/// reject.
pub fn build_bundle_columns(
    spends: &[BundleSpend],
    outputs: &[Note],
    transparent_in: u64,
    transparent_out: u64,
    fee_grains: u64,
) -> Result<(Vec<Vec<Felt>>, BundlePublicInputs), SpendProofError> {
    if spends.len() > NUM_SLOTS {
        return Err(SpendProofError::InvalidWitness("more than 4 spends"));
    }
    if outputs.len() > NUM_SLOTS {
        return Err(SpendProofError::InvalidWitness("more than 4 outputs"));
    }
    if spends.is_empty() && outputs.is_empty() {
        return Err(SpendProofError::InvalidWitness("empty bundle"));
    }
    if transparent_in > MAX_NOTE_VALUE || transparent_out > MAX_NOTE_VALUE {
        return Err(SpendProofError::PublicInput("transparent leg too large"));
    }
    if fee_grains > MAX_NOTE_VALUE {
        return Err(SpendProofError::PublicInput("fee too large"));
    }
    for s in spends {
        if s.key.owner_tag() != s.note.owner_tag {
            return Err(SpendProofError::InvalidWitness(
                "spending key does not own this note",
            ));
        }
    }
    // Native conservation pre-check (u128: cannot overflow). The circuit
    // proves the same identity; an unbalanced witness would only waste
    // proving time on an unverifiable proof.
    let in_sum: u128 = spends.iter().map(|s| s.note.value_grains as u128).sum();
    let out_sum: u128 = outputs.iter().map(|o| o.value_grains as u128).sum();
    if in_sum + transparent_in as u128 != out_sum + transparent_out as u128 + fee_grains as u128 {
        return Err(SpendProofError::InvalidWitness("value conservation"));
    }

    let mut cols = vec![vec![Felt::ZERO; TRACE_LENGTH]; TRACE_WIDTH];

    // Runs one 8-row hash cycle starting at `cycle`: writes the initial
    // state and the state after each round; returns the output digest.
    let run_cycle = |cols: &mut Vec<Vec<Felt>>, cycle: usize, init: [Felt; STATE_WIDTH]| {
        let base = cycle * CYCLE_LENGTH;
        let mut state = init;
        for j in 0..STATE_WIDTH {
            cols[j][base] = state[j];
        }
        for round in 0..NUM_ROUNDS {
            Rp64_256::apply_round(&mut state, round);
            for j in 0..STATE_WIDTH {
                cols[j][base + round + 1] = state[j];
            }
        }
        let digest: [Felt; 4] = state[4..8].try_into().expect("4 elements");
        digest
    };
    let merge_init = |domain: u64, left: [Felt; 4], right: [Felt; 4]| {
        let mut state = [Felt::ZERO; STATE_WIDTH];
        state[0] = Felt::new(CAPACITY_SEED);
        state[1] = Felt::new(domain);
        state[4..8].copy_from_slice(&left);
        state[8..12].copy_from_slice(&right);
        state
    };
    // Non-constant, non-binary filler (see the AIR docs: released register
    // and bit cells carry filler so masked constraint polynomials attain
    // their declared degrees).
    let filler = |row: usize, k: usize| {
        Felt::new((row as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ (k as u64 + 1))
    };

    // Merkle bit column: non-binary filler everywhere first; real bits
    // overwrite the Merkle injection rows below.
    for (row, cell) in cols[BIT_COL].iter_mut().enumerate() {
        *cell = Felt::new((row as u64).wrapping_mul(6_364_136_223_846_793_005) | 2);
    }

    let zero4 = [Felt::ZERO; 4];
    let mut anchors = [PqDigest::ZERO; NUM_SLOTS];
    let mut nullifiers = [PqDigest::ZERO; NUM_SLOTS];
    let mut input_dummy = [true; NUM_SLOTS];
    let mut in_values = [0u64; NUM_SLOTS];

    for i in 0..NUM_SLOTS {
        let (nsk, rho, value, position, siblings, nf_domain) = match spends.get(i) {
            Some(s) => {
                input_dummy[i] = false;
                (
                    s.key.nsk().to_elements(),
                    s.note.rho.to_elements(),
                    s.note.value_grains,
                    s.path.position,
                    s.path.siblings,
                    RESCUE_DOMAIN_NULLIFIER,
                )
            }
            // Dummy slot: zero-valued, zero witness, dummy nullifier
            // domain. Its chain is computed consistently but never bound
            // to any public input.
            None => (
                zero4,
                zero4,
                0u64,
                0u64,
                [PqDigest::ZERO; TREE_DEPTH],
                RESCUE_DOMAIN_DUMMY_NULLIFIER,
            ),
        };
        in_values[i] = value;
        let seg_cycle = i * 24;
        // Cycle 0: owner_tag = merge_d(TAG, nsk, 0).
        let tag = run_cycle(
            &mut cols,
            seg_cycle,
            merge_init(RESCUE_DOMAIN_OWNER_TAG, nsk, zero4),
        );
        // Cycle 1: d1 = merge_d(C1, [value,0,0,0], tag).
        let value_pad = [Felt::new(value), Felt::ZERO, Felt::ZERO, Felt::ZERO];
        let d1 = run_cycle(
            &mut cols,
            seg_cycle + 1,
            merge_init(RESCUE_DOMAIN_COMMIT_STAGE1, value_pad, tag),
        );
        // Cycle 2: cm = merge_d(C2, d1, rho).
        let mut acc = run_cycle(
            &mut cols,
            seg_cycle + 2,
            merge_init(RESCUE_DOMAIN_COMMIT_STAGE2, d1, rho),
        );
        if let Some(s) = spends.get(i) {
            debug_assert_eq!(PqDigest::from_elements(acc), s.note.commitment());
        }
        // Cycles 3..23: the Merkle path, leaf level first.
        for level in 0..TREE_DEPTH {
            let bit = (position >> level) & 1;
            let sib = siblings[level].to_elements();
            cols[BIT_COL][merkle_inject_row(i, level)] = Felt::new(bit);
            let init = if bit == 0 {
                merge_init(RESCUE_DOMAIN_MERKLE_NODE, acc, sib)
            } else {
                merge_init(RESCUE_DOMAIN_MERKLE_NODE, sib, acc)
            };
            acc = run_cycle(&mut cols, seg_cycle + 3 + level, init);
        }
        anchors[i] = PqDigest::from_elements(acc);
        if let Some(s) = spends.get(i) {
            debug_assert_eq!(anchors[i], s.path.compute_root(s.note.commitment()));
        }
        // Cycle 23: nf = merge_d(NF or DUMMY_NF, nsk, rho).
        let nf = run_cycle(&mut cols, seg_cycle + 23, merge_init(nf_domain, nsk, rho));
        if let Some(s) = spends.get(i) {
            nullifiers[i] = PqDigest::from_elements(nf);
            debug_assert_eq!(nullifiers[i], s.key.nullifier(s.note.rho));
        } else {
            // Dummy: the public nullifier stays ZERO; the in-trace dummy
            // digest is never surfaced.
            anchors[i] = PqDigest::ZERO;
        }
        // rho/nsk registers: constant over this input's segment.
        let seg = input_base(i)..input_base(i) + INPUT_ROWS;
        for k in 0..4 {
            cols[RHO_COL + k][seg.clone()].fill(rho[k]);
            cols[NSK_COL + k][seg.clone()].fill(nsk[k]);
        }
    }

    let mut output_commitments = [PqDigest::ZERO; NUM_SLOTS];
    let mut output_dummy = [true; NUM_SLOTS];
    let mut out_values = [0u64; NUM_SLOTS];
    for j in 0..NUM_SLOTS {
        let (value, tag, rho) = match outputs.get(j) {
            Some(n) => {
                output_dummy[j] = false;
                (
                    n.value_grains,
                    n.owner_tag.to_elements(),
                    n.rho.to_elements(),
                )
            }
            None => (0u64, zero4, zero4),
        };
        out_values[j] = value;
        let seg_cycle = NUM_SLOTS * 24 + j * 2;
        let value_pad = [Felt::new(value), Felt::ZERO, Felt::ZERO, Felt::ZERO];
        let d1 = run_cycle(
            &mut cols,
            seg_cycle,
            merge_init(RESCUE_DOMAIN_COMMIT_STAGE1, value_pad, tag),
        );
        let cm = run_cycle(
            &mut cols,
            seg_cycle + 1,
            merge_init(RESCUE_DOMAIN_COMMIT_STAGE2, d1, rho),
        );
        if let Some(n) = outputs.get(j) {
            output_commitments[j] = PqDigest::from_elements(cm);
            debug_assert_eq!(output_commitments[j], n.commitment());
        }
    }

    // Padding cycles: keep hashing the zero state so the periodic round
    // constraints stay satisfied.
    for cycle in ACTIVE_ROWS / CYCLE_LENGTH..TRACE_LENGTH / CYCLE_LENGTH {
        run_cycle(&mut cols, cycle, [Felt::ZERO; STATE_WIDTH]);
    }

    // rho/nsk filler in the output + padding region (constancy released).
    for k in 0..4 {
        for (row, cell) in cols[RHO_COL + k]
            .iter_mut()
            .enumerate()
            .skip(OUTPUTS_START_ROW)
        {
            *cell = filler(row, k);
        }
        for (row, cell) in cols[NSK_COL + k]
            .iter_mut()
            .enumerate()
            .skip(OUTPUTS_START_ROW)
        {
            *cell = filler(row, k) + Felt::ONE;
        }
    }
    // Value registers: constant over the active region, filler after.
    for (m, &v) in in_values.iter().chain(out_values.iter()).enumerate() {
        for (row, cell) in cols[VAL_COL + m].iter_mut().enumerate() {
            *cell = if row < ACTIVE_ROWS {
                Felt::new(v)
            } else {
                filler(row, m)
            };
        }
    }
    // Range-check columns: MSB-first double-and-add per value segment;
    // filler in slack and beyond.
    for (row, cell) in cols[RC_BIT_COL].iter_mut().enumerate() {
        *cell = filler(row, 30) + Felt::new(2);
    }
    for (row, cell) in cols[RC_ACC_COL].iter_mut().enumerate() {
        *cell = filler(row, 31);
    }
    for (m, &v) in in_values.iter().chain(out_values.iter()).enumerate() {
        let base = rc_base(m);
        debug_assert!(v < (1u64 << VALUE_BITS));
        let mut acc = 0u64;
        cols[RC_ACC_COL][base] = Felt::ZERO;
        for t in 1..=VALUE_BITS {
            let bit = (v >> (VALUE_BITS - t)) & 1;
            acc = 2 * acc + bit;
            cols[RC_BIT_COL][base + t] = Felt::new(bit);
            cols[RC_ACC_COL][base + t] = Felt::new(acc);
        }
        debug_assert_eq!(acc, v);
    }

    let pub_inputs = BundlePublicInputs {
        anchors,
        nullifiers,
        input_dummy,
        output_commitments,
        output_dummy,
        transparent_in,
        transparent_out,
        fee_grains,
    };
    Ok((cols, pub_inputs))
}

const INPUT_ROWS: usize = crate::air::INPUT_SEGMENT_ROWS;

/// The winterfell prover for [`BundleAir`]. Carries the public inputs
/// (dummy flags and the transparent legs are not derivable from the trace
/// alone).
pub struct BundleProver {
    options: ProofOptions,
    pub_inputs: BundlePublicInputs,
}

impl BundleProver {
    /// A prover with the standard [`proof_options`] for the given publics.
    pub fn new(pub_inputs: BundlePublicInputs) -> Self {
        BundleProver {
            options: proof_options(),
            pub_inputs,
        }
    }
}

impl Prover for BundleProver {
    type BaseField = Felt;
    type Air = BundleAir;
    type Trace = TraceTable<Felt>;
    type HashFn = CarrierHash;
    type VC = CarrierVc;
    type RandomCoin = CarrierCoin;
    type TraceLde<E: FieldElement<BaseField = Felt>> = DefaultTraceLde<E, CarrierHash, CarrierVc>;
    type ConstraintCommitment<E: FieldElement<BaseField = Felt>> =
        DefaultConstraintCommitment<E, CarrierHash, CarrierVc>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = Felt>> =
        DefaultConstraintEvaluator<'a, BundleAir, E>;

    fn get_pub_inputs(&self, trace: &Self::Trace) -> BundlePublicInputs {
        // Sanity: the trace must agree with the carried publics on every
        // non-dummy binding row.
        #[cfg(debug_assertions)]
        {
            use crate::air::{nf_row, out_cm_row, root_row};
            let read4 = |row: usize| {
                let mut out = [0u64; 4];
                for (k, o) in out.iter_mut().enumerate() {
                    *o = trace.get(4 + k, row).as_int();
                }
                PqDigest(out)
            };
            for i in 0..NUM_SLOTS {
                if !self.pub_inputs.input_dummy[i] {
                    debug_assert_eq!(read4(root_row(i)), self.pub_inputs.anchors[i]);
                    debug_assert_eq!(read4(nf_row(i)), self.pub_inputs.nullifiers[i]);
                }
                if !self.pub_inputs.output_dummy[i] {
                    debug_assert_eq!(read4(out_cm_row(i)), self.pub_inputs.output_commitments[i]);
                }
            }
        }
        let _ = trace;
        self.pub_inputs.clone()
    }

    fn options(&self) -> &ProofOptions {
        &self.options
    }

    fn new_trace_lde<E: FieldElement<BaseField = Felt>>(
        &self,
        trace_info: &TraceInfo,
        main_trace: &ColMatrix<Felt>,
        domain: &StarkDomain<Felt>,
        partition_option: PartitionOptions,
    ) -> (Self::TraceLde<E>, TracePolyTable<E>) {
        DefaultTraceLde::new(trace_info, main_trace, domain, partition_option)
    }

    fn build_constraint_commitment<E: FieldElement<BaseField = Felt>>(
        &self,
        composition_poly_trace: CompositionPolyTrace<E>,
        num_constraint_composition_columns: usize,
        domain: &StarkDomain<Felt>,
        partition_options: PartitionOptions,
    ) -> (Self::ConstraintCommitment<E>, CompositionPoly<E>) {
        DefaultConstraintCommitment::new(
            composition_poly_trace,
            num_constraint_composition_columns,
            domain,
            partition_options,
        )
    }

    fn new_evaluator<'a, E: FieldElement<BaseField = Felt>>(
        &self,
        air: &'a BundleAir,
        aux_rand_elements: Option<AuxRandElements<E>>,
        composition_coefficients: winterfell::ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E> {
        DefaultConstraintEvaluator::new(air, aux_rand_elements, composition_coefficients)
    }
}

/// Prove one 4-in/4-out bundle. Returns the serialized proof and its public
/// inputs. Unused slots are filled with in-circuit dummies.
pub fn prove_bundle(
    spends: &[BundleSpend],
    outputs: &[Note],
    transparent_in: u64,
    transparent_out: u64,
    fee_grains: u64,
) -> Result<(Vec<u8>, BundlePublicInputs), SpendProofError> {
    let (cols, pub_inputs) =
        build_bundle_columns(spends, outputs, transparent_in, transparent_out, fee_grains)?;
    let trace = TraceTable::init(cols);
    let prover = BundleProver::new(pub_inputs.clone());
    let proof = prover
        .prove(trace)
        .map_err(|e| SpendProofError::Prover(e.to_string()))?;
    Ok((proof.to_bytes(), pub_inputs))
}

/// Verify one bundle proof against its public inputs. Accepts only proofs
/// generated with the standard [`proof_options`].
///
/// Enforces the NATIVE public bounds the in-circuit no-wrap argument
/// depends on: `transparent_in`, `transparent_out`, and `fee_grains` must
/// each be `<= MAX_NOTE_VALUE` (< 2^61). See [`crate::note`].
///
/// Also enforces the dummy-slot zero convention (defense-in-depth, audit
/// S1 follow-up): a dummy slot's anchor/nullifier/commitment publics must
/// be the zero digest even for a caller that bypasses
/// [`crate::bundle::verify_bundle`] — which remains the authoritative
/// convention layer (ciphertext rules, anchor ring, in-bundle nullifier
/// uniqueness live there).
pub fn verify_spend(
    proof_bytes: &[u8],
    pub_inputs: &BundlePublicInputs,
) -> Result<(), SpendProofError> {
    if pub_inputs.transparent_in > MAX_NOTE_VALUE || pub_inputs.transparent_out > MAX_NOTE_VALUE {
        return Err(SpendProofError::PublicInput("transparent leg too large"));
    }
    if pub_inputs.fee_grains > MAX_NOTE_VALUE {
        return Err(SpendProofError::PublicInput("fee too large"));
    }
    for i in 0..NUM_SLOTS {
        if pub_inputs.input_dummy[i]
            && (pub_inputs.anchors[i] != PqDigest::ZERO
                || pub_inputs.nullifiers[i] != PqDigest::ZERO)
        {
            return Err(SpendProofError::PublicInput("nonzero dummy input publics"));
        }
        if pub_inputs.output_dummy[i] && pub_inputs.output_commitments[i] != PqDigest::ZERO {
            return Err(SpendProofError::PublicInput("nonzero dummy output publics"));
        }
    }
    let proof = Proof::from_bytes(proof_bytes)
        .map_err(|e| SpendProofError::Verification(format!("malformed proof: {e}")))?;
    let acceptable = AcceptableOptions::OptionSet(vec![proof_options()]);
    winterfell::verify::<BundleAir, CarrierHash, CarrierCoin, CarrierVc>(
        proof,
        pub_inputs.clone(),
        &acceptable,
    )
    .map_err(|e| SpendProofError::Verification(e.to_string()))
}
