//! Opt-in versioned, hiding STARK candidate for existing pool-v2 notes.
//!
//! This changes proof bytes, never note commitments, addresses, tree roots or
//! position-bound nullifiers. The deployed Winterfell verifier remains separate.
//! Uses the complete Plonky3 0.8.0 uni-STARK ZK path: fresh private trace masks,
//! hiding Merkle commitments, randomization polynomial, randomized quotient
//! chunks and enforced opening budgets. This module is a candidate pending
//! circuit/backend review and consensus activation, not a claim of completed
//! production quantum security or repair of already disclosed legacy secrets.

use crate::air::*;
use crate::auth::AUTH_PK_LEN;
use crate::domains::*;
use crate::hash::{Felt, STATE_WIDTH};
use crate::note::Note;
use crate::prover::{build_bundle_columns, proof_options, Bounded, BundleSpend, SpendProofError};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_challenger::{HashChallenger, SerializingChallenger64};
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::{extension::BinomialExtensionField, PrimeCharacteristicRing};
use p3_fri::{FriParameters, HidingFriPcs};
use p3_goldilocks::Goldilocks;
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTreeHidingMmcs;
use p3_symmetric::{CompressionFunctionFromHasher, CryptographicHasher, SerializingHasher};
use p3_uni_stark::{StarkConfig, StarkGenericConfig};
use rand::{rngs::StdRng, SeedableRng};
use std::borrow::Cow;
use tiny_keccak::{Hasher, Keccak};
use winter_crypto::hashers::Rp64_256;
use winter_math::ToElements;
use winterfell::{Air as WinterAir, Assertion, TraceInfo};
use zeroize::Zeroizing;

/// Explicit candidate proof suite identifier. Existing deployed proof version is 1.
pub const PROOF_SUITE: u8 = 2;
/// Frozen parameter profile, independent of deployment activation.
pub const PARAMETER_ID: u32 = 2;
/// FRI query count. This is not a quantified QROM security claim.
pub const NUM_QUERIES: usize = 96;
/// Low-degree extension blowup: 16.
pub const LOG_BLOWUP: usize = 4;
/// Goldilocks extension degree: 5 (approximately 320 bits).
pub const EXTENSION_DEGREE: usize = 5;
/// Salt length: six Goldilocks elements, approximately 384 bits of entropy.
pub const SALT_ELEMENTS: usize = 6;
/// Candidate-only bounded decoding limit. This does NOT widen deployed action limits.
pub const MAX_CANDIDATE_PROOF_BYTES: usize = 2 * 1024 * 1024;
const CANDIDATE_WIDTH: usize = TRACE_WIDTH + crate::zk_seed::WIDTH;
const MAGIC: &[u8; 8] = b"SOVPQZK2";
const COIN_DOMAIN: &[u8] =
    b"sov-shielded-pq:suite2:p3-0.8.0:keccak384:goldilocks5:seed-preimage:profile2";

type Val = Goldilocks;
type Challenge = BinomialExtensionField<Val, EXTENSION_DEGREE>;
type FieldHash = SerializingHasher<Keccak384Words>;
type Compress = CompressionFunctionFromHasher<Keccak384Words, 2, 6>;
type HidingMmcs = MerkleTreeHidingMmcs<Val, u64, FieldHash, Compress, StdRng, 2, 6, SALT_ELEMENTS>;
type ChallengeMmcs = ExtensionMmcs<Val, Challenge, HidingMmcs>;
type Challenger = SerializingChallenger64<Val, HashChallenger<u8, Keccak384Bytes, 48>>;
type Pcs = HidingFriPcs<Val, Radix2DitParallel<Val>, HidingMmcs, ChallengeMmcs, StdRng>;
type Config = StarkConfig<Pcs, Challenge, Challenger>;
type CandidateProof = p3_uni_stark::Proof<Config>;

/// A note witness plus knowledge of the original spending-seed preimage.
/// Possession of an NSK exposed by an old trace is insufficient.
pub struct Suite2Spend {
    spend: BundleSpend,
    seed: Zeroizing<[u8; 32]>,
}
impl Suite2Spend {
    /// Check that the private seed generates this witness's exact NSK. The
    /// circuit independently checks the same relation.
    pub fn new(spend: BundleSpend, seed: &[u8; 32]) -> Result<Self, SpendProofError> {
        if crate::SpendingKey::from_seed(seed).nsk() != spend.key.nsk() {
            return Err(SpendProofError::PublicInput(
                "spending seed does not generate note ownership key",
            ));
        }
        Ok(Self {
            spend,
            seed: Zeroizing::new(*seed),
        })
    }
}

/// The actual carrier identity chosen BEFORE proving. Verifiers must construct
/// this from the enclosing transaction, never accept context supplied by a proof.
/// Binding this in the STARK transcript stops copying an unchanged withdrawal
/// proof and signing it under another key or payout account.
#[derive(Clone, Copy)]
pub struct Suite2Context<'a> {
    /// Network chain identifier.
    pub chain_id: &'a [u8],
    /// Genesis hash of this network.
    pub genesis: &'a [u8; 32],
    /// Exact transparent transaction signer/payout account bytes.
    pub signer: &'a [u8],
    /// Exact transaction nonce.
    pub nonce: u64,
    /// ML-DSA carrier authorization public key of this transaction.
    pub auth_pk: &'a [u8; AUTH_PK_LEN],
}

#[derive(Copy, Clone, Debug)]
struct Keccak384Bytes;
impl CryptographicHasher<u8, [u8; 48]> for Keccak384Bytes {
    fn hash_iter<I: IntoIterator<Item = u8>>(&self, input: I) -> [u8; 48] {
        let mut state = Keccak::v384();
        for byte in input {
            state.update(&[byte]);
        }
        let mut result = [0u8; 48];
        state.finalize(&mut result);
        result
    }
}
#[derive(Copy, Clone, Debug)]
struct Keccak384Words(&'static [u8]);
impl CryptographicHasher<u64, [u64; 6]> for Keccak384Words {
    fn hash_iter<I: IntoIterator<Item = u64>>(&self, input: I) -> [u64; 6] {
        let mut state = Keccak::v384();
        state.update(self.0);
        for word in input {
            state.update(&word.to_le_bytes());
        }
        let mut bytes = [0u8; 48];
        state.finalize(&mut bytes);
        std::array::from_fn(|i| {
            u64::from_le_bytes(bytes[i * 8..i * 8 + 8].try_into().expect("fixed word"))
        })
    }
}
fn rng() -> Result<StdRng, SpendProofError> {
    let mut seed = Zeroizing::new([0u8; 32]);
    getrandom::getrandom(seed.as_mut())
        .map_err(|_| SpendProofError::Prover("secure OS entropy unavailable".into()))?;
    Ok(StdRng::from_seed(*seed))
}
fn config(proving: bool) -> Result<Config, SpendProofError> {
    let hash = FieldHash::new(Keccak384Words(b"sov-shielded-pq:suite2:mmcs-leaf:v1"));
    let compress = Compress::new(Keccak384Words(b"sov-shielded-pq:suite2:mmcs-node:v1"));
    // Verification never uses private randomness and must not depend on the
    // availability of OS entropy. Only the proving path obtains fresh seeds.
    let new_rng = || {
        if proving {
            rng()
        } else {
            Ok(StdRng::from_seed([0; 32]))
        }
    };
    let mmcs = HidingMmcs::new(hash, compress, 0, new_rng()?);
    let fri = FriParameters {
        log_blowup: LOG_BLOWUP,
        log_final_poly_len: 5,
        max_log_arity: 2,
        num_queries: NUM_QUERIES,
        batch_proof_of_work_bits: 0,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: 0,
        mmcs: ChallengeMmcs::new(mmcs.clone()),
    };
    let pcs = Pcs::new(
        Radix2DitParallel::default(),
        mmcs,
        fri,
        EXTENSION_DEGREE,
        new_rng()?,
    );
    let challenger = Challenger::new(HashChallenger::new(COIN_DOMAIN.to_vec(), Keccak384Bytes));
    let config = Config::new(pcs, challenger);
    debug_assert_eq!(config.is_zk(), 1);
    Ok(config)
}
fn context_digest(context: &Suite2Context<'_>) -> Result<[u8; 48], SpendProofError> {
    if context.chain_id.is_empty()
        || context.chain_id.len() > 256
        || context.signer.is_empty()
        || context.signer.len() > 256
    {
        return Err(SpendProofError::PublicInput(
            "suite2 carrier identity length",
        ));
    }
    let mut state = Keccak::v384();
    state.update(b"sov-shielded-pq:suite2:carrier-context:v1");
    for bytes in [
        context.chain_id,
        context.genesis.as_slice(),
        context.signer,
        context.nonce.to_le_bytes().as_slice(),
        context.auth_pk.as_slice(),
    ] {
        state.update(&(bytes.len() as u64).to_le_bytes());
        state.update(bytes);
    }
    let mut result = [0u8; 48];
    state.finalize(&mut result);
    Ok(result)
}
fn publics(
    input: &BundlePublicInputs,
    context: &Suite2Context<'_>,
) -> Result<Vec<Val>, SpendProofError> {
    let mut values: Vec<Val> = input
        .to_elements()
        .iter()
        .map(|x| Val::from_u64(x.as_int()))
        .collect();
    values.extend(
        context_digest(context)?
            .into_iter()
            .map(|x| Val::from_u64(x as u64)),
    );
    Ok(values)
}
fn c<AB: AirBuilder<F = Val>>(value: Felt) -> AB::Expr {
    Val::from_u64(value.as_int()).into()
}
fn pow7<E: PrimeCharacteristicRing>(x: E) -> E {
    let x2 = x.clone() * x.clone();
    let x4 = x2.clone() * x2.clone();
    x4 * x2 * x
}

struct Suite2Air {
    pub_inputs: BundlePublicInputs,
    assertions: Vec<Assertion<Felt>>,
    periodic: Vec<Vec<Val>>,
    num_public_values: usize,
}
impl Suite2Air {
    fn new(pub_inputs: &BundlePublicInputs, num_public_values: usize) -> Self {
        let legacy = BundleAir::new(
            TraceInfo::new(TRACE_WIDTH, TRACE_LENGTH),
            pub_inputs.clone(),
            proof_options(),
        );
        let assertions = legacy.get_assertions();
        let mut periodic: Vec<Vec<Val>> = legacy
            .get_periodic_column_values()
            .into_iter()
            .map(|c| c.into_iter().map(|x| Val::from_u64(x.as_int())).collect())
            .collect();
        for assertion in &assertions {
            assert_eq!(
                assertion.values().len(),
                1,
                "suite2 supports only single boundary assertions"
            );
            let mut selector = vec![Val::ZERO; TRACE_LENGTH];
            selector[assertion.first_step()] = Val::ONE;
            periodic.push(selector);
        }
        periodic.extend(crate::zk_seed::periodic());
        Self {
            pub_inputs: pub_inputs.clone(),
            assertions,
            periodic,
            num_public_values,
        }
    }
}
impl BaseAir<Val> for Suite2Air {
    fn width(&self) -> usize {
        CANDIDATE_WIDTH
    }
    fn num_public_values(&self) -> usize {
        self.num_public_values
    }
    fn num_periodic_columns(&self) -> usize {
        self.periodic.len()
    }
    fn periodic_columns(&self) -> Cow<'_, [Vec<Val>]> {
        Cow::Borrowed(&self.periodic)
    }
}
impl<AB: AirBuilder<F = Val>> Air<AB> for Suite2Air {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let cur: Vec<AB::Expr> = main.current_slice()[..TRACE_WIDTH]
            .iter()
            .map(|x| (*x).into())
            .collect();
        let nxt: Vec<AB::Expr> = main.next_slice()[..TRACE_WIDTH]
            .iter()
            .map(|x| (*x).into())
            .collect();
        let periodic_values: Vec<AB::Expr> = builder
            .periodic_values()
            .iter()
            .map(|x| (*x).into())
            .collect();
        let mut result = vec![AB::Expr::ZERO; NUM_CONSTRAINTS];

        let hmask = periodic_values[0].clone();
        let ark1 = &periodic_values[1..1 + STATE_WIDTH];
        let ark2 = &periodic_values[1 + STATE_WIDTH..1 + 2 * STATE_WIDTH];
        let m_row0 = periodic_values[P_ROW0].clone();
        let m_seed_in = periodic_values[P_SEED_IN].clone();
        let m_tag = periodic_values[P_TAG].clone();
        let m_tag_i = &periodic_values[P_TAG_I..P_TAG_I + NUM_SLOTS];
        let m_cm = periodic_values[P_CM].clone();
        let m_merkle = periodic_values[P_MERKLE].clone();
        let m_nf_any = periodic_values[P_NF_ANY].clone();
        let m_nf_i = &periodic_values[P_NF_I..P_NF_I + NUM_SLOTS];
        let m_outseed = periodic_values[P_OUTSEED].clone();
        let m_outseed_j = &periodic_values[P_OUTSEED_J..P_OUTSEED_J + NUM_SLOTS];
        let m_outcm = periodic_values[P_OUTCM].clone();
        let m_acc = periodic_values[P_ACC].clone();
        let m_isbit = periodic_values[P_ISBIT].clone();
        let m_rcend = &periodic_values[P_RCEND_M..P_RCEND_M + 2 * NUM_SLOTS];
        let m_bal = periodic_values[P_BAL].clone();
        let m_const_keys = periodic_values[P_CONST_KEYS].clone();
        let m_const_vals = periodic_values[P_CONST_VALS].clone();
        let m_pos_step = periodic_values[P_POS_STEP].clone();
        let pos_w = periodic_values[P_POS_W].clone();

        let cap_seed = c::<AB>(Felt::new(CAPACITY_SEED));
        let dom_tag = c::<AB>(Felt::new(RESCUE_DOMAIN_OWNER_TAG));
        let dom_c1 = c::<AB>(Felt::new(RESCUE_DOMAIN_COMMIT_STAGE1));
        let dom_c2 = c::<AB>(Felt::new(RESCUE_DOMAIN_COMMIT_STAGE2));
        let dom_merkle = c::<AB>(Felt::new(RESCUE_DOMAIN_MERKLE_NODE));

        // --- 0..12: Rescue-Prime round. Round r maps s -> s' via
        //   t = MDS * s^7 + ARK1[r];  s' = MDS * t^(1/7) + ARK2[r]
        // which is equivalent (degree 7 both sides) to
        //   MDS * s^7 + ARK1[r] == ( INV_MDS * (s' - ARK2[r]) )^7.
        let mut fwd = vec![AB::Expr::ZERO; STATE_WIDTH];
        let mut bwd = vec![AB::Expr::ZERO; STATE_WIDTH];
        for j in 0..STATE_WIDTH {
            let s7 = pow7(cur[j].clone());
            for (i, f) in fwd.iter_mut().enumerate() {
                *f += c::<AB>(Rp64_256::MDS[i][j]) * s7.clone();
            }
            let d = nxt[j].clone() - ark2[j].clone();
            for (i, b) in bwd.iter_mut().enumerate() {
                *b += c::<AB>(Rp64_256::INV_MDS[i][j]) * d.clone();
            }
        }
        for j in 0..STATE_WIDTH {
            result[j] = hmask.clone() * (fwd[j].clone() + ark1[j].clone() - pow7(bwd[j].clone()));
        }

        // --- 12..20: rho / nsk registers constant within each input
        // segment (mask released at segment boundaries so each input loads
        // its own witness).
        for k in 0..4 {
            result[12 + k] =
                m_const_keys.clone() * (nxt[RHO_COL + k].clone() - cur[RHO_COL + k].clone());
            result[16 + k] =
                m_const_keys.clone() * (nxt[NSK_COL + k].clone() - cur[NSK_COL + k].clone());
        }
        // --- 20..28: the eight value registers constant over the whole
        // active region (they are read at range-check rows, absorption rows,
        // and the balance row).
        for m in 0..2 * NUM_SLOTS {
            result[20 + m] =
                m_const_vals.clone() * (nxt[VAL_COL + m].clone() - cur[VAL_COL + m].clone());
        }

        // --- 28..32: input 0's owner-tag hash absorbs nsk in the left rate
        // half on row 0 (capacity + right half are boundary assertions).
        for k in 0..4 {
            result[28 + k] = m_row0.clone() * (cur[4 + k].clone() - cur[NSK_COL + k].clone());
        }

        // --- 32..44: inputs 1..3 segment seed — the row after input i-1's
        // nullifier digest starts input i's owner-tag hash:
        // capacity [8, TAG, 0, 0], left rate = the NEW nsk registers,
        // right rate = 0.
        result[32] = m_seed_in.clone() * (nxt[0].clone() - cap_seed.clone());
        result[33] = m_seed_in.clone() * (nxt[1].clone() - dom_tag.clone());
        result[34] = m_seed_in.clone() * nxt[2].clone();
        result[35] = m_seed_in.clone() * nxt[3].clone();
        for k in 0..4 {
            result[36 + k] = m_seed_in.clone() * (nxt[4 + k].clone() - nxt[NSK_COL + k].clone());
            result[40 + k] = m_seed_in.clone() * nxt[8 + k].clone();
        }

        // --- 44..59: tag injection — owner-tag digest into commitment
        // stage 1: capacity [8, C1, 0, 0], left rate [value_i, 0, 0, 0]
        // (value from the input's PRIVATE register, per-input mask),
        // right rate = tag digest.
        result[44] = m_tag.clone() * (nxt[0].clone() - cap_seed.clone());
        result[45] = m_tag.clone() * (nxt[1].clone() - dom_c1.clone());
        result[46] = m_tag.clone() * nxt[2].clone();
        result[47] = m_tag.clone() * nxt[3].clone();
        result[48] = m_tag.clone() * nxt[5].clone();
        result[49] = m_tag.clone() * nxt[6].clone();
        result[50] = m_tag.clone() * nxt[7].clone();
        for k in 0..4 {
            result[51 + k] = m_tag.clone() * (nxt[8 + k].clone() - cur[4 + k].clone());
        }
        for (i, mask_expr) in m_tag_i.iter().enumerate() {
            result[55 + i] = mask_expr.clone() * (nxt[4].clone() - cur[VAL_COL + i].clone());
        }

        // --- 59..71: cm stage-2 injection — stage-1 digest chained left,
        // rho absorbed right, capacity [8, C2, 0, 0].
        result[59] = m_cm.clone() * (nxt[0].clone() - cap_seed.clone());
        result[60] = m_cm.clone() * (nxt[1].clone() - dom_c2.clone());
        result[61] = m_cm.clone() * nxt[2].clone();
        result[62] = m_cm.clone() * nxt[3].clone();
        for k in 0..4 {
            result[63 + k] = m_cm.clone() * (nxt[4 + k].clone() - cur[4 + k].clone());
            result[67 + k] = m_cm.clone() * (nxt[8 + k].clone() - cur[RHO_COL + k].clone());
        }

        // --- 71..84: Merkle level injection. Bit b.clone() picks which child the
        // running digest is; the sibling half is a free witness. Capacity
        // [8, MERKLE, 0, 0].
        let b = cur[BIT_COL].clone();
        let one = AB::Expr::ONE;
        result[71] = m_merkle.clone() * (nxt[0].clone() - cap_seed.clone());
        result[72] = m_merkle.clone() * (nxt[1].clone() - dom_merkle.clone());
        result[73] = m_merkle.clone() * nxt[2].clone();
        result[74] = m_merkle.clone() * nxt[3].clone();
        for k in 0..4 {
            // b.clone() = 0: digest is the LEFT child (rate 4..8).
            result[75 + k] = m_merkle.clone()
                * (one.clone() - b.clone())
                * (nxt[4 + k].clone() - cur[4 + k].clone());
            // b.clone() = 1: digest is the RIGHT child (rate 8..12).
            result[79 + k] =
                m_merkle.clone() * b.clone() * (nxt[8 + k].clone() - cur[4 + k].clone());
        }
        result[83] = m_merkle.clone() * b.clone() * (one.clone() - b.clone());

        // --- 84..99: nullifier injection — seeded with (nsk, rho);
        // capacity element 1 carries the REAL vs DUMMY nullifier domain
        // per the public dummy flag (per-input mask).
        result[84] = m_nf_any.clone() * (nxt[0].clone() - cap_seed.clone());
        // Capacity element 2 carries the note's Merkle leaf position — the
        // occurrence binding of audit PQV2-01. `cur[POS_ACC_COL].clone()` at this row
        // is the accumulator's landed value: every path bit has been folded
        // in (the last Merkle injection row precedes this one.clone()) and the step
        // constraint has held it constant since. This is the SAME register
        // that routed each Merkle level, so position and membership cannot
        // disagree.
        result[85] = m_nf_any.clone() * (nxt[2].clone() - cur[POS_ACC_COL].clone());
        result[86] = m_nf_any.clone() * nxt[3].clone();
        for k in 0..4 {
            result[87 + k] = m_nf_any.clone() * (nxt[4 + k].clone() - cur[NSK_COL + k].clone());
            result[91 + k] = m_nf_any.clone() * (nxt[8 + k].clone() - cur[RHO_COL + k].clone());
        }
        for (i, mask_expr) in m_nf_i.iter().enumerate() {
            let dom = if self.pub_inputs.input_dummy[i] {
                RESCUE_DOMAIN_DUMMY_NULLIFIER
            } else {
                RESCUE_DOMAIN_NULLIFIER
            };
            result[95 + i] = mask_expr.clone() * (nxt[1].clone() - c::<AB>(Felt::new(dom)));
        }

        // --- 99..110: output seed — the row before output j's stage-1
        // cycle: capacity [8, C1, 0, 0], left rate [value'_j, 0, 0, 0]
        // (private register, per-output mask), right rate = the output's
        // owner tag, a FREE witness (used exactly once, so it needs no
        // register).
        result[99] = m_outseed.clone() * (nxt[0].clone() - cap_seed.clone());
        result[100] = m_outseed.clone() * (nxt[1].clone() - dom_c1.clone());
        result[101] = m_outseed.clone() * nxt[2].clone();
        result[102] = m_outseed.clone() * nxt[3].clone();
        result[103] = m_outseed.clone() * nxt[5].clone();
        result[104] = m_outseed.clone() * nxt[6].clone();
        result[105] = m_outseed.clone() * nxt[7].clone();
        for (j, mask_expr) in m_outseed_j.iter().enumerate() {
            result[106 + j] =
                mask_expr.clone() * (nxt[4].clone() - nxt[VAL_COL + NUM_SLOTS + j].clone());
        }

        // --- 110..118: output cm stage-2 injection — stage-1 digest
        // chained left, rho' absorbed right as a FREE witness.
        result[110] = m_outcm.clone() * (nxt[0].clone() - cap_seed.clone());
        result[111] = m_outcm.clone() * (nxt[1].clone() - dom_c2.clone());
        result[112] = m_outcm.clone() * nxt[2].clone();
        result[113] = m_outcm.clone() * nxt[3].clone();
        for k in 0..4 {
            result[114 + k] = m_outcm.clone() * (nxt[4 + k].clone() - cur[4 + k].clone());
        }

        // --- 118..120: 61-bit range check (D3). MSB-first double-and-add:
        // acc' = 2·acc + bit', with every bit boolean-constrained. The
        // accumulator starts at 0 (boundary assertion per segment) and must
        // land on the value register (m_rcend below), so EVERY claimed bit
        // is constrained and the register is exactly the 61-bit sum.
        result[118] = m_acc.clone()
            * (nxt[RC_ACC_COL].clone()
                - (cur[RC_ACC_COL].clone() + cur[RC_ACC_COL].clone())
                - nxt[RC_BIT_COL].clone());
        result[119] =
            m_isbit.clone() * cur[RC_BIT_COL].clone() * (cur[RC_BIT_COL].clone() - one.clone());

        // --- 120..128: range-check landing per value register.
        for (m, mask_expr) in m_rcend.iter().enumerate() {
            result[120 + m] =
                mask_expr.clone() * (cur[RC_ACC_COL].clone() - cur[VAL_COL + m].clone());
        }

        // --- 129: leaf-position accumulator (PQV2-01). One constraint does
        // both jobs: the weight column is 2^level on a Merkle injection row
        // and ZERO everywhere else, so this reads as
        //   pos' = pos + bit·2^level   on a Merkle row,
        //   pos' = pos                 on every other row of the segment.
        // Combined with the per-segment boundary assertion pos = 0, the
        // accumulator at the nullifier seed row is exactly Σ bit_l·2^l — the
        // leaf index of the authenticated path. The path bits are already
        // boolean-constrained (result[83]) on precisely the rows where the
        // weight is non-zero, so no non-binary filler can inflate the sum.
        result[129] = m_pos_step.clone()
            * (nxt[POS_ACC_COL].clone()
                - cur[POS_ACC_COL].clone()
                - cur[BIT_COL].clone() * pos_w.clone());

        // --- 128: value conservation (D1). Only t_in/t_out/fee are public;
        // all eight values are private registers. Sound over the integers
        // by the 61-bit range checks + native public-leg bounds (see
        // crate::note).
        let mut bal = c::<AB>(Felt::new(self.pub_inputs.transparent_in))
            - c::<AB>(Felt::new(self.pub_inputs.transparent_out))
            - c::<AB>(Felt::new(self.pub_inputs.fee_grains));
        for i in 0..NUM_SLOTS {
            bal += cur[VAL_COL + i].clone();
            bal -= cur[VAL_COL + NUM_SLOTS + i].clone();
        }
        result[128] = m_bal.clone() * bal;
        for constraint in result {
            builder.assert_zero(constraint);
        }
        for (idx, assertion) in self.assertions.iter().enumerate() {
            let selector = periodic_values[NUM_PERIODIC + idx].clone();
            builder.assert_zero(
                selector * (cur[assertion.column()].clone() - c::<AB>(assertion.values()[0])),
            );
        }
        let seed_cur: Vec<AB::Expr> = main.current_slice()[TRACE_WIDTH..]
            .iter()
            .map(|x| (*x).into())
            .collect();
        let seed_next: Vec<AB::Expr> = main.next_slice()[TRACE_WIDTH..]
            .iter()
            .map(|x| (*x).into())
            .collect();
        crate::zk_seed::evaluate(
            builder,
            &seed_cur,
            &seed_next,
            &periodic_values[NUM_PERIODIC + self.assertions.len()..],
            &cur,
            periodic_values[P_CONST_KEYS].clone(),
            &self.pub_inputs.input_dummy,
        );
    }
}

/// Create a hiding proof against EXISTING note/anchor/nullifier encodings and
/// the exact enclosing carrier. No contextless proof API exists for suite 2.
pub fn prove_bundle(
    spends: &[Suite2Spend],
    outputs: &[Note],
    transparent_in: u64,
    transparent_out: u64,
    fee_grains: u64,
    context: &Suite2Context<'_>,
) -> Result<(Vec<u8>, BundlePublicInputs), SpendProofError> {
    let legacy_spends: Vec<_> = spends.iter().map(|w| w.spend.clone()).collect();
    let (mut columns, pub_inputs) = build_bundle_columns(
        &legacy_spends,
        outputs,
        transparent_in,
        transparent_out,
        fee_grains,
    )?;
    let mut seeds = Zeroizing::new([[0u8; 32]; NUM_SLOTS]);
    for (index, witness) in spends.iter().enumerate() {
        seeds[index] = *witness.seed;
    }
    columns.extend(crate::zk_seed::columns(&seeds));
    Bounded::check(&pub_inputs)?;
    let public_values = publics(&pub_inputs, context)?;
    let air = Suite2Air::new(&pub_inputs, public_values.len());
    let mut rows = Vec::with_capacity(CANDIDATE_WIDTH * TRACE_LENGTH);
    for row in 0..TRACE_LENGTH {
        for col in &columns {
            rows.push(Val::from_u64(col[row].as_int()));
        }
    }
    let cfg = config(true)?;
    let proof = p3_uni_stark::prove(
        &cfg,
        &air,
        RowMajorMatrix::new(rows, CANDIDATE_WIDTH),
        &public_values,
    )
    .map_err(|e| SpendProofError::Prover(format!("suite2: {e:?}")))?;
    encode(&proof).map(|bytes| (bytes, pub_inputs))
}
fn encode(proof: &CandidateProof) -> Result<Vec<u8>, SpendProofError> {
    let body = postcard::to_allocvec(proof)
        .map_err(|e| SpendProofError::Prover(format!("suite2 encode: {e}")))?;
    let mut bytes = Vec::with_capacity(12 + body.len());
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&PARAMETER_ID.to_le_bytes());
    bytes.extend_from_slice(&body);
    if bytes.len() > MAX_CANDIDATE_PROOF_BYTES {
        return Err(SpendProofError::Prover(format!(
            "suite2 candidate proof {} bytes exceeds {}",
            bytes.len(),
            MAX_CANDIDATE_PROOF_BYTES
        )));
    }
    Ok(bytes)
}
fn decode(bytes: &[u8]) -> Result<CandidateProof, SpendProofError> {
    if bytes.len() < 12
        || bytes.len() > MAX_CANDIDATE_PROOF_BYTES
        || &bytes[..8] != MAGIC
        || bytes[8..12] != PARAMETER_ID.to_le_bytes()
    {
        return Err(SpendProofError::Verification(
            "suite2 frame/profile mismatch".into(),
        ));
    }
    let proof: CandidateProof = crate::zk_suite2_decode::from_bytes(&bytes[12..])
        .map_err(|e| SpendProofError::Verification(format!("suite2 decode: {e}")))?;
    if proof.degree_bits != TRACE_LENGTH.ilog2() as usize + 1 {
        return Err(SpendProofError::Verification(
            "suite2 trace length mismatch".into(),
        ));
    }
    if proof.opened_values.trace_local.len() != CANDIDATE_WIDTH
        || proof
            .opened_values
            .trace_next
            .as_ref()
            .is_none_or(|row| row.len() != CANDIDATE_WIDTH)
        || proof.opened_values.preprocessed.is_some()
        || proof
            .opened_values
            .random
            .as_ref()
            .is_none_or(|row| row.len() != EXTENSION_DEGREE)
        || proof.commitments.random.is_none()
        || proof.opened_values.quotient_chunks.len() > 64
        || proof
            .opened_values
            .quotient_chunks
            .iter()
            .any(|row| row.len() != EXTENSION_DEGREE)
    {
        return Err(SpendProofError::Verification(
            "suite2 opening shape mismatch".into(),
        ));
    }
    if encode(&proof)? != bytes {
        return Err(SpendProofError::Verification(
            "suite2 noncanonical bytes".into(),
        ));
    }
    Ok(proof)
}
/// Validate only the bounded, canonical candidate proof frame. Callers must
/// still verify the actual statement and carrier context before acceptance.
pub fn validate_proof_frame(bytes: &[u8]) -> Result<(), SpendProofError> {
    decode(bytes).map(|_| ())
}
/// Verify suite 2 only, with the actual transaction's public context. Legacy
/// Winterfell proofs and profile changes are rejected without any fallback.
pub fn verify_spend(
    bytes: &[u8],
    pub_inputs: &BundlePublicInputs,
    context: &Suite2Context<'_>,
) -> Result<(), SpendProofError> {
    Bounded::check(pub_inputs)?;
    let public_values = publics(pub_inputs, context)?;
    let air = Suite2Air::new(pub_inputs, public_values.len());
    let proof = decode(bytes)?;
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        p3_uni_stark::verify(&config(false)?, &air, &proof, &public_values)
            .map_err(|e| SpendProofError::Verification(format!("suite2: {e:?}")))
    }))
    .unwrap_or_else(|_| {
        Err(SpendProofError::Verification(
            "suite2 verifier rejected malformed proof".into(),
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hd::PqShieldedKey;
    use crate::note::{derive_rho, SpendingKey};
    use crate::tree::CommitmentTree;

    fn inputs() -> (Vec<BundleSpend>, Vec<Note>) {
        let key = SpendingKey::from_seed(&[0x42; 32]);
        let first = Note::new(5000, key.owner_tag(), derive_rho(&[0x41; 32], 0)).expect("first");
        let second = Note::new(4000, key.owner_tag(), derive_rho(&[0x41; 32], 1)).expect("second");
        let mut tree = CommitmentTree::new();
        tree.append(first.commitment()).expect("append");
        tree.append(second.commitment()).expect("append");
        tree.mark().expect("mark");
        let recipient = PqShieldedKey::from_leaf_seed_suite2(&[0x43; 32]);
        let output =
            Note::new(3500, recipient.owner_tag(), derive_rho(&[0x44; 32], 0)).expect("payment");
        let change =
            Note::new(4400, recipient.owner_tag(), derive_rho(&[0x44; 32], 1)).expect("change");
        (
            vec![
                BundleSpend {
                    key: key.clone(),
                    note: first,
                    path: tree.witness(0).expect("witness").0,
                },
                BundleSpend {
                    key,
                    note: second,
                    path: tree.witness(1).expect("witness").0,
                },
            ],
            vec![output, change],
        )
    }
    #[test]
    fn existing_notes_prove_verify_hiding_and_bind_exact_carrier() {
        let (spends, outputs) = inputs();
        let witnesses: Vec<_> = spends
            .iter()
            .cloned()
            .map(|spend| Suite2Spend::new(spend, &[0x42; 32]).expect("original seed"))
            .collect();
        assert!(
            Suite2Spend::new(spends[0].clone(), &[0x99; 32]).is_err(),
            "knowledge of the derived NSK is insufficient without its seed preimage"
        );
        let auth = PqShieldedKey::from_leaf_seed_suite2(&[0x45; 32]);
        let pk = auth.auth_key().public_bytes();
        let ctx = Suite2Context {
            chain_id: b"sov-pq-suite2-rehearsal",
            genesis: &[0xAA; 32],
            signer: b"owner.sov",
            nonce: 7,
            auth_pk: &pk,
        };
        let (first, pi) =
            prove_bundle(&witnesses, &outputs, 0, 1000, 100, &ctx).expect("suite2 proves");
        eprintln!("suite2 proof bytes: {}", first.len());
        verify_spend(&first, &pi, &ctx).expect("suite2 verifies old notes");
        assert_eq!(
            pi.nullifiers[0],
            spends[0].key.nullifier(spends[0].note.rho, 0)
        );
        assert_eq!(
            pi.nullifiers[1],
            spends[1].key.nullifier(spends[1].note.rho, 1)
        );
        assert_eq!(pi.output_commitments[0], outputs[0].commitment());
        let (second, second_pi) =
            prove_bundle(&witnesses, &outputs, 0, 1000, 100, &ctx).expect("new masks");
        assert_eq!(pi, second_pi);
        assert_ne!(first, second, "fresh masks and salts on every proof");
        verify_spend(&second, &pi, &ctx).expect("second verifies");
        let old =
            crate::prover::prove_bundle(&spends, &outputs, 0, 1000, 100).expect("legacy proof");
        crate::prover::verify_spend(&old.0, &old.1).expect("historical v1 intact");
        assert!(
            verify_spend(&old.0, &old.1, &ctx).is_err(),
            "no downgrade to old verifier"
        );
        let mut changed = pi.clone();
        changed.fee_grains += 1;
        assert!(verify_spend(&first, &changed, &ctx).is_err());
        let unrelated = PqShieldedKey::from_leaf_seed_suite2(&[0x46; 32])
            .auth_key()
            .public_bytes();
        for badctx in [
            Suite2Context {
                auth_pk: &unrelated,
                ..ctx
            },
            Suite2Context {
                chain_id: b"another-chain",
                ..ctx
            },
            Suite2Context {
                genesis: &[0xBB; 32],
                ..ctx
            },
            Suite2Context {
                signer: b"thief.sov",
                ..ctx
            },
            Suite2Context { nonce: 8, ..ctx },
        ] {
            assert!(
                verify_spend(&first, &pi, &badctx).is_err(),
                "copied proof cannot redirect payout, replay or replace authorization key"
            );
        }
        let mut tampered = first.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(verify_spend(&tampered, &pi, &ctx).is_err());
        let a = decode(&first).expect("first decode");
        let b = decode(&second).expect("second decode");
        assert_ne!(
            a.opened_values.trace_local, b.opened_values.trace_local,
            "OOD private column openings must be masked afresh"
        );
        assert!(
            a.commitments.random.is_some() && b.commitments.random.is_some(),
            "full uni-STARK randomization polynomial, not PCS-only hiding"
        );
        assert_eq!(encode(&a).expect("canonical encode"), first);
    }
    #[test]
    fn stolen_nsk_without_original_seed_cannot_make_a_valid_proof() {
        let (spends, outputs) = inputs();
        // Deliberately bypass the public constructor: an attacker can write
        // their own prover, so native witness validation is not an ownership
        // boundary. They know the exact note, path and exposed legacy NSK.
        let forged: Vec<_> = spends
            .into_iter()
            .map(|spend| Suite2Spend {
                spend,
                seed: Zeroizing::new([0x99; 32]),
            })
            .collect();
        let auth = PqShieldedKey::from_leaf_seed_suite2(&[0x99; 32]);
        let pk = auth.auth_key().public_bytes();
        let context = Suite2Context {
            chain_id: b"sov-pq-suite2-rehearsal",
            genesis: &[0xAA; 32],
            signer: b"thief.sov",
            nonce: 7,
            auth_pk: &pk,
        };
        // Debug backends reject the bad trace during proving. Optimized
        // backends can emit proof bytes; consensus must still reject them.
        let attempt = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prove_bundle(&forged, &outputs, 0, 1000, 100, &context)
        }));
        if let Ok(Ok((proof, pi))) = attempt {
            assert!(verify_spend(&proof, &pi, &context).is_err());
        }
    }
    #[test]
    fn seed_air_rejects_changed_message_initialization_carry_and_output() {
        let (spends, outputs) = inputs();
        let (mut columns, pi) =
            build_bundle_columns(&spends, &outputs, 0, 1000, 100).expect("legacy trace");
        let mut seeds = [[0; 32]; NUM_SLOTS];
        seeds[0] = [0x42; 32];
        seeds[1] = [0x42; 32];
        columns.extend(crate::zk_seed::columns(&seeds));
        let pk = [0; AUTH_PK_LEN];
        let context = Suite2Context {
            chain_id: b"sov-pq-suite2-rehearsal",
            genesis: &[0xAA; 32],
            signer: b"owner.sov",
            nonce: 7,
            auth_pk: &pk,
        };
        let public_values = publics(&pi, &context).unwrap();
        let air = Suite2Air::new(&pi, public_values.len());
        let mut values = Vec::with_capacity(CANDIDATE_WIDTH * TRACE_LENGTH);
        for row in 0..TRACE_LENGTH {
            for column in &columns {
                values.push(Val::from_u64(column[row].as_int()));
            }
        }
        let good = RowMajorMatrix::new(values, CANDIDATE_WIDTH);
        p3_air::check_constraints(&air, &good, &public_values);
        // Initial state, held secret message, arithmetic carry, and final
        // seed digest/NSK binding must all be constrained inside the AIR.
        for (row, column) in [(0, 0), (50, 512), (31, 768), (224, 0)] {
            let mut bad = good.clone();
            let offset = row * CANDIDATE_WIDTH + TRACE_WIDTH + column;
            bad.values[offset] = Val::ONE - bad.values[offset];
            assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                p3_air::check_constraints(&air, &bad, &public_values);
            }))
            .is_err());
        }
    }
    #[test]
    fn suite2_context_framing_is_injective_and_requires_identity() {
        let pk = [0u8; AUTH_PK_LEN];
        let a = Suite2Context {
            chain_id: b"ab",
            genesis: &[0xAA; 32],
            signer: b"c",
            nonce: 1,
            auth_pk: &pk,
        };
        let b = Suite2Context {
            chain_id: b"a",
            signer: b"bc",
            ..a
        };
        assert_ne!(
            context_digest(&a).expect("a"),
            context_digest(&b).expect("b")
        );
        assert!(context_digest(&Suite2Context { chain_id: b"", ..a }).is_err());
    }
    #[test]
    fn keccak384_standard_empty_vector_and_word_encoding() {
        let bytes = Keccak384Bytes.hash_iter([]);
        assert_eq!(hex::encode(bytes),"2c23146a63a29acf99e73b88f8c24eaa7dc60aa771780ccc006afbfa8fe2479b2dd2b21362337441ac12b515911957ff");
        let words = Keccak384Words(b"").hash_iter([0x0807060504030201]);
        let direct = Keccak384Bytes.hash_iter([1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(
            words,
            std::array::from_fn(|i| u64::from_le_bytes(
                direct[i * 8..i * 8 + 8].try_into().expect("word")
            ))
        );
        assert_ne!(
            Keccak384Words(b"leaf").hash_iter([1, 2]),
            Keccak384Words(b"node").hash_iter([1, 2]),
            "leaf/internal-node domain separation"
        );
    }

    #[test]
    fn hostile_frames_are_bounded_canonical_rejections() {
        for size in 0..64 {
            let mut bytes = vec![0; size];
            if size >= 12 {
                bytes[..8].copy_from_slice(MAGIC);
                bytes[8..12].copy_from_slice(&PARAMETER_ID.to_le_bytes());
            }
            assert!(validate_proof_frame(&bytes).is_err());
        }
        let mut oversized = vec![0; MAX_CANDIDATE_PROOF_BYTES + 1];
        oversized[..8].copy_from_slice(MAGIC);
        oversized[8..12].copy_from_slice(&PARAMETER_ID.to_le_bytes());
        assert!(validate_proof_frame(&oversized).is_err());
    }
}
