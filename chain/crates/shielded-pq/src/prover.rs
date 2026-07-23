//! Execution-trace builder, prover, and verifier for the spend circuit.

use crate::air::{
    SpendAir, SpendPublicInputs, BIT_COL, CAPACITY_SEED, CYCLE_LENGTH, NF_ROW, NSK_COL, RHO_COL,
    ROOT_ROW, TRACE_LENGTH, TRACE_WIDTH,
};
use crate::hash::{Felt, PqDigest, NUM_ROUNDS, STATE_WIDTH};
use crate::note::{Note, SpendingKey};
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

/// Errors from proving or verifying a spend.
#[derive(Debug, thiserror::Error)]
pub enum SpendProofError {
    /// The witness is inconsistent (wrong key, path, or note).
    #[error("invalid spend witness: {0}")]
    InvalidWitness(&'static str),
    /// The winterfell prover failed.
    #[error("prover error: {0}")]
    Prover(String),
    /// Proof deserialization or verification failed.
    #[error("verification failed: {0}")]
    Verification(String),
}

/// Standard proof options for the prototype: 42 FRI queries, blowup 8,
/// 16 bits of grinding, quadratic extension field — ≥ 100 bits conjectured
/// security against a classical adversary, and no number-theoretic
/// assumptions a quantum adversary could break (hashes only).
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

/// Build the 21×256 execution trace for one spend. Returns the trace and the
/// public inputs it commits to. Errors if the witness is internally
/// inconsistent (the caller's key does not own the note, or the path does
/// not open to a root containing the note's commitment).
pub fn build_spend_trace(
    key: &SpendingKey,
    note: &Note,
    path: &MerklePath,
) -> Result<(TraceTable<Felt>, SpendPublicInputs), SpendProofError> {
    if key.owner_tag() != note.owner_tag {
        return Err(SpendProofError::InvalidWitness(
            "spending key does not own this note",
        ));
    }
    let cm = note.commitment();
    let root = path.compute_root(cm);
    let nullifier = key.nullifier(note.rho);
    let nsk = key.nsk().to_elements();
    let rho = note.rho.to_elements();

    let mut cols = vec![vec![Felt::ZERO; TRACE_LENGTH]; TRACE_WIDTH];

    // Runs one 8-row hash cycle starting at `row`: writes the initial state
    // and the state after each round; returns the output digest.
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

    let merge_init = |left: [Felt; 4], right: [Felt; 4]| {
        let mut state = [Felt::ZERO; STATE_WIDTH];
        state[0] = Felt::new(CAPACITY_SEED);
        state[4..8].copy_from_slice(&left);
        state[8..12].copy_from_slice(&right);
        state
    };

    // Cycle 0: owner_tag = merge(nsk, 0).
    let tag = run_cycle(&mut cols, 0, merge_init(nsk, [Felt::ZERO; 4]));
    // Cycle 1: d1 = merge([value,0,0,0], owner_tag).
    let value_pad = [
        Felt::new(note.value_grains),
        Felt::ZERO,
        Felt::ZERO,
        Felt::ZERO,
    ];
    let d1 = run_cycle(&mut cols, 1, merge_init(value_pad, tag));
    // Cycle 2: cm = merge(d1, rho).
    let mut acc = run_cycle(&mut cols, 2, merge_init(d1, rho));
    debug_assert_eq!(PqDigest::from_elements(acc), cm);
    // Cycles 3..23: the Merkle path, leaf level first.
    for level in 0..TREE_DEPTH {
        let bit = (path.position >> level) & 1;
        let sib = path.siblings[level].to_elements();
        // The bit lives on the injection row that closes the previous cycle.
        cols[BIT_COL][(3 + level) * CYCLE_LENGTH - 1] = Felt::new(bit);
        let init = if bit == 0 {
            merge_init(acc, sib)
        } else {
            merge_init(sib, acc)
        };
        acc = run_cycle(&mut cols, 3 + level, init);
    }
    debug_assert_eq!(PqDigest::from_elements(acc), root);
    // Cycle 23: nf = merge(nsk, rho).
    let nf = run_cycle(&mut cols, 23, merge_init(nsk, rho));
    debug_assert_eq!(PqDigest::from_elements(nf), nullifier);
    // Padding cycles 24..32: keep hashing the zero state so the periodic
    // round constraints stay satisfied.
    for cycle in 24..TRACE_LENGTH / CYCLE_LENGTH {
        run_cycle(&mut cols, cycle, [Felt::ZERO; STATE_WIDTH]);
    }

    // rho / nsk witness registers: constant over the active region, then
    // non-constant filler in padding so the constancy-constraint polynomial
    // attains its declared degree (the constraint is masked off there).
    let filler = |row: usize, k: usize| {
        Felt::new((row as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ (k as u64 + 1))
    };
    for k in 0..4 {
        for (row, cell) in cols[RHO_COL + k].iter_mut().enumerate() {
            *cell = if row <= NF_ROW {
                rho[k]
            } else {
                filler(row, k)
            };
        }
        for (row, cell) in cols[NSK_COL + k].iter_mut().enumerate() {
            *cell = if row <= NF_ROW {
                nsk[k]
            } else {
                filler(row, k) + Felt::ONE
            };
        }
    }
    // Path-bit column: real bits sit on Merkle injection rows (set above);
    // all other rows carry non-binary filler for the same degree reason.
    for (row, cell) in cols[BIT_COL].iter_mut().enumerate() {
        let is_merkle_inject = row % CYCLE_LENGTH == CYCLE_LENGTH - 1
            && (3 * CYCLE_LENGTH - 1..(3 + TREE_DEPTH) * CYCLE_LENGTH).contains(&row);
        if !is_merkle_inject {
            *cell = Felt::new((row as u64).wrapping_mul(6_364_136_223_846_793_005) | 2);
        }
    }

    let pub_inputs = SpendPublicInputs {
        root,
        nullifier,
        value_grains: note.value_grains,
    };
    Ok((TraceTable::init(cols), pub_inputs))
}

/// The winterfell prover for [`SpendAir`].
pub struct SpendProver {
    options: ProofOptions,
}

impl SpendProver {
    /// A prover with the standard [`proof_options`].
    pub fn new() -> Self {
        SpendProver {
            options: proof_options(),
        }
    }
}

impl Default for SpendProver {
    fn default() -> Self {
        Self::new()
    }
}

impl Prover for SpendProver {
    type BaseField = Felt;
    type Air = SpendAir;
    type Trace = TraceTable<Felt>;
    type HashFn = CarrierHash;
    type VC = CarrierVc;
    type RandomCoin = CarrierCoin;
    type TraceLde<E: FieldElement<BaseField = Felt>> = DefaultTraceLde<E, CarrierHash, CarrierVc>;
    type ConstraintCommitment<E: FieldElement<BaseField = Felt>> =
        DefaultConstraintCommitment<E, CarrierHash, CarrierVc>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = Felt>> =
        DefaultConstraintEvaluator<'a, SpendAir, E>;

    fn get_pub_inputs(&self, trace: &Self::Trace) -> SpendPublicInputs {
        let read4 = |row: usize| {
            let mut out = [0u64; 4];
            for (k, o) in out.iter_mut().enumerate() {
                *o = trace.get(4 + k, row).as_int();
            }
            PqDigest(out)
        };
        SpendPublicInputs {
            root: read4(ROOT_ROW),
            nullifier: read4(NF_ROW),
            value_grains: trace.get(4, CYCLE_LENGTH).as_int(),
        }
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
        air: &'a SpendAir,
        aux_rand_elements: Option<AuxRandElements<E>>,
        composition_coefficients: winterfell::ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E> {
        DefaultConstraintEvaluator::new(air, aux_rand_elements, composition_coefficients)
    }
}

/// Prove one spend. Returns the serialized proof and its public inputs.
pub fn prove_spend(
    key: &SpendingKey,
    note: &Note,
    path: &MerklePath,
) -> Result<(Vec<u8>, SpendPublicInputs), SpendProofError> {
    let (trace, pub_inputs) = build_spend_trace(key, note, path)?;
    let prover = SpendProver::new();
    let proof = prover
        .prove(trace)
        .map_err(|e| SpendProofError::Prover(e.to_string()))?;
    Ok((proof.to_bytes(), pub_inputs))
}

/// Verify one spend proof against its public inputs. Accepts only proofs
/// generated with the standard [`proof_options`].
pub fn verify_spend(
    proof_bytes: &[u8],
    pub_inputs: &SpendPublicInputs,
) -> Result<(), SpendProofError> {
    let proof = Proof::from_bytes(proof_bytes)
        .map_err(|e| SpendProofError::Verification(format!("malformed proof: {e}")))?;
    let acceptable = AcceptableOptions::OptionSet(vec![proof_options()]);
    winterfell::verify::<SpendAir, CarrierHash, CarrierCoin, CarrierVc>(
        proof,
        pub_inputs.clone(),
        &acceptable,
    )
    .map_err(|e| SpendProofError::Verification(e.to_string()))
}
