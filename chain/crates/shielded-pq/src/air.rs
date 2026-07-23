//! The consensus-grade 4-in/4-out bundle STARK circuit (winterfell AIR).
//!
//! # Statement (S1a)
//!
//! For public inputs `{anchors[4], nullifiers[4], input_dummy[4],
//! output_commitments[4], output_dummy[4], t_in, t_out, fee}` the prover
//! knows, for every input slot `i`, secrets `nsk_i`, `rho_i`, `v_i`, and a
//! Merkle path, and for every output slot `j` secrets `v'_j`, `tag'_j`,
//! `rho'_j`, such that (with `merge_d` = the domain-separated Rescue-Prime
//! 2-to-1 compression of [`crate::hash::merge_domain`]):
//!
//! **Per REAL input `i` (`input_dummy[i] = false`):**
//! 1. `tag_i = merge_d(TAG, nsk_i, 0)`                       (ownership)
//! 2. `cm_i = merge_d(C2, merge_d(C1, [v_i,0,0,0], tag_i), rho_i)`
//!    (commitment opening — `v_i` is a WITNESS, never public)
//! 3. `cm_i` is a depth-20 Merkle leaf under `anchors[i]` (membership; each
//!    input may use a DIFFERENT public anchor — D5's anchor-ring acceptance
//!    is the native verifier's job)
//! 4. `nullifiers[i] = merge_d(NF, nsk_i, rho_i)`            (nullifier)
//!
//! **Per DUMMY input `i`:** `v_i = 0` (asserted on the committed value
//! register), and the slot's nullifier hash runs under the distinct
//! `DUMMY_NF` domain, so no in-trace value of a dummy can ever equal a real
//! nullifier. The Merkle chain and root of a dummy are UNCONSTRAINED junk:
//! no root/nullifier assertion binds them, and the native verifier never
//! surfaces a dummy slot's anchor or nullifier (they are the zero digest by
//! convention, enforced in [`crate::bundle`]). Dummy-ness is PUBLIC (the
//! flags are part of the public inputs and the Fiat-Shamir transcript);
//! this leaks only the bundle's arity (≤ 4), never any value.
//!
//! **Per REAL output `j`:** `output_commitments[j] =
//! merge_d(C2, merge_d(C1, [v'_j,0,0,0], tag'_j), rho'_j)` with `v'_j`,
//! `tag'_j`, `rho'_j` all witnesses (commitment integrity; the value is
//! private). **Per DUMMY output:** `v'_j = 0`, commitment unconstrained and
//! never surfaced.
//!
//! **Range checks (D3):** every value register (4 input + 4 output) is
//! decomposed in-circuit into [`VALUE_BITS`] = 61 boolean-constrained bits
//! via a running double-and-add accumulator that starts at 0 (assertion)
//! and must land exactly on the value register. Every claimed bit is
//! constrained boolean; the accumulator recurrence covers all 61 bits.
//! See [`crate::note`] for why 61 bits (not 64) is the sound width in
//! Goldilocks.
//!
//! **Conservation (D1):** one linear constraint over the constant value
//! registers: `Σ v_i + t_in = Σ v'_j + t_out + fee` in the field, where
//! only `t_in`, `t_out`, `fee` are public. With all eight private values
//! range-checked `< 2^61` and the three public legs bounded `< 2^61` by the
//! native verifier ([`crate::prover::verify_spend`] rejects otherwise),
//! both sides are integers `< p`, so field equality is integer equality
//! (the full argument, with numbers, lives in [`crate::note`]).
//!
//! `t_in`/`t_out` are the two unsigned halves of the signed net transparent
//! value balance: `t_in` = transparent value entering the pool (shielding),
//! `t_out` = transparent value leaving it (unshielding). Representing the
//! sign as two verifier-bounded unsigned publics avoids any signed
//! encoding ambiguity in the field.
//!
//! # What is NOT in-circuit (honesty)
//!
//! - Spend authorization is a carrier-level ML-DSA-65 signature over the
//!   full public-input set (D4), not an in-circuit signature check.
//! - Anchor-ring membership (which anchors are acceptable) is native (D5).
//! - Global nullifier double-spend tracking is native state.
//!
//! # Trace layout
//!
//! 31 columns × 1024 rows, in 8-row hash cycles (7 Rescue rounds + 1
//! injection row):
//!
//! - Columns 0..12: the Rescue-Prime sponge state.
//! - Columns 12..16 / 16..20: `rho` / `nsk` witness registers, constant
//!   within each input's segment (re-loaded at segment boundaries).
//! - Column 20: Merkle path bit.
//! - Columns 21..29: the eight value registers (4 input then 4 output),
//!   constant over the whole active region.
//! - Column 29/30: range-check bit / running-sum accumulator.
//!
//! Row map: input `i` occupies rows `192·i .. 192·i+191` (cycle 0 = owner
//! tag, 1–2 = commitment, 3..22 = Merkle ×20 with the root on row
//! `192·i+183`, 23 = nullifier on row `192·i+191`). Output `j` occupies
//! rows `768+16·j .. 768+16·j+15` (2 commitment cycles, commitment on row
//! `768+16·j+15`). Rows 832..1024 are padding (hash rounds only). The
//! range check for value `m ∈ 0..8` runs in columns 29–30 over rows
//! `64·m .. 64·m+61`, in parallel with the hash columns.
//!
//! Injection rows wire each phase's output into the next phase's sponge
//! input and stamp the next phase's DOMAIN into capacity element 1 — the
//! circuit enforces the same domain separation the native hashes use.

use crate::domains::{
    RESCUE_DOMAIN_COMMIT_STAGE1, RESCUE_DOMAIN_COMMIT_STAGE2, RESCUE_DOMAIN_DUMMY_NULLIFIER,
    RESCUE_DOMAIN_MERKLE_NODE, RESCUE_DOMAIN_NULLIFIER, RESCUE_DOMAIN_OWNER_TAG,
};
use crate::hash::{Felt, PqDigest, STATE_WIDTH};
use crate::note::VALUE_BITS;
use crate::tree::TREE_DEPTH;
use winter_crypto::hashers::Rp64_256;
use winter_math::{FieldElement, ToElements};
use winterfell::{
    Air, AirContext, Assertion, EvaluationFrame, ProofOptions, TraceInfo,
    TransitionConstraintDegree,
};

/// Rows per hash invocation (7 rounds + 1 injection row).
pub const CYCLE_LENGTH: usize = 8;
/// Total trace length: 104 active cycles padded to a power of two.
pub const TRACE_LENGTH: usize = 1024;
/// Trace width: 12 sponge + 4 rho + 4 nsk + 1 path bit + 8 values + 2 rc.
pub const TRACE_WIDTH: usize = 31;
/// Input and output slots per bundle (D2: fixed 4-in/4-out shape).
pub const NUM_SLOTS: usize = 4;

/// First rho register column.
pub const RHO_COL: usize = 12;
/// First nsk register column.
pub const NSK_COL: usize = 16;
/// Merkle path bit column.
pub const BIT_COL: usize = 20;
/// First value register column (inputs 21..25, outputs 25..29).
pub const VAL_COL: usize = 21;
/// Range-check bit column.
pub const RC_BIT_COL: usize = 29;
/// Range-check running-sum accumulator column.
pub const RC_ACC_COL: usize = 30;

/// Rows per input segment (24 cycles).
pub const INPUT_SEGMENT_ROWS: usize = 24 * CYCLE_LENGTH;
/// Rows per output segment (2 cycles).
pub const OUTPUT_SEGMENT_ROWS: usize = 2 * CYCLE_LENGTH;
/// First row of the output region.
pub const OUTPUTS_START_ROW: usize = NUM_SLOTS * INPUT_SEGMENT_ROWS;
/// First padding row (all constraint activity ends before this).
pub const ACTIVE_ROWS: usize = OUTPUTS_START_ROW + NUM_SLOTS * OUTPUT_SEGMENT_ROWS;
/// Rows allocated per range-check segment (61 used + 3 slack).
pub const RC_SEGMENT_ROWS: usize = 64;

/// Sponge capacity seed for a 2-to-1 merge (`Rp64_256` sets capacity[0] to
/// the rate width, 8).
pub const CAPACITY_SEED: u64 = 8;

/// First row of input `i`'s segment.
pub const fn input_base(i: usize) -> usize {
    i * INPUT_SEGMENT_ROWS
}
/// Injection row closing input `i`'s owner-tag cycle.
pub const fn tag_inject_row(i: usize) -> usize {
    input_base(i) + CYCLE_LENGTH - 1
}
/// Injection row closing input `i`'s commitment stage-1 cycle.
pub const fn cm_inject_row(i: usize) -> usize {
    input_base(i) + 2 * CYCLE_LENGTH - 1
}
/// Injection row for input `i`'s Merkle level `level` (0 = leaf level).
pub const fn merkle_inject_row(i: usize, level: usize) -> usize {
    input_base(i) + (3 + level) * CYCLE_LENGTH - 1
}
/// Row where input `i`'s Merkle chain output (the root) sits; the same row
/// injects the nullifier hash.
pub const fn root_row(i: usize) -> usize {
    input_base(i) + 23 * CYCLE_LENGTH - 1
}
/// Row where input `i`'s nullifier digest sits.
pub const fn nf_row(i: usize) -> usize {
    input_base(i) + 24 * CYCLE_LENGTH - 1
}
/// First row of output `j`'s segment.
pub const fn output_base(j: usize) -> usize {
    OUTPUTS_START_ROW + j * OUTPUT_SEGMENT_ROWS
}
/// Injection row closing output `j`'s commitment stage-1 cycle.
pub const fn out_cm_inject_row(j: usize) -> usize {
    output_base(j) + CYCLE_LENGTH - 1
}
/// Row where output `j`'s commitment digest sits.
pub const fn out_cm_row(j: usize) -> usize {
    output_base(j) + 2 * CYCLE_LENGTH - 1
}
/// First row of value `m`'s range-check segment (`m` = 0..3 inputs,
/// 4..7 outputs).
pub const fn rc_base(m: usize) -> usize {
    m * RC_SEGMENT_ROWS
}

/// Public inputs of one 4-in/4-out bundle proof. NOTHING else about the
/// bundle is public: all values, owner tags, and note randomness are
/// witnesses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BundlePublicInputs {
    /// Per-input tree anchor (zero digest for dummy slots). Inputs may use
    /// DIFFERENT anchors (D5).
    pub anchors: [PqDigest; NUM_SLOTS],
    /// Per-input revealed nullifier (zero digest for dummy slots).
    pub nullifiers: [PqDigest; NUM_SLOTS],
    /// Which input slots are dummies (public by design; leaks arity only).
    pub input_dummy: [bool; NUM_SLOTS],
    /// Per-output note commitment (zero digest for dummy slots).
    pub output_commitments: [PqDigest; NUM_SLOTS],
    /// Which output slots are dummies.
    pub output_dummy: [bool; NUM_SLOTS],
    /// Transparent value entering the pool (shielding leg), grains.
    pub transparent_in: u64,
    /// Transparent value leaving the pool (unshielding leg), grains.
    pub transparent_out: u64,
    /// Transparent fee, grains.
    pub fee_grains: u64,
}

impl ToElements<Felt> for BundlePublicInputs {
    fn to_elements(&self) -> Vec<Felt> {
        let mut out = Vec::with_capacity(12 * 4 + 8 + 3);
        for d in self
            .anchors
            .iter()
            .chain(self.nullifiers.iter())
            .chain(self.output_commitments.iter())
        {
            out.extend_from_slice(&d.to_elements());
        }
        for &f in self.input_dummy.iter().chain(self.output_dummy.iter()) {
            out.push(Felt::new(f as u64));
        }
        out.push(Felt::new(self.transparent_in));
        out.push(Felt::new(self.transparent_out));
        out.push(Felt::new(self.fee_grains));
        out
    }
}

// Transition-constraint index map (must match `evaluate_transition`):
//   0..12    Rescue rounds (deg 7, period-8 mask)
//   12..16   rho constancy            16..20  nsk constancy
//   20..28   value-register constancy
//   28..32   row-0 nsk absorb (input 0 seed, left rate)
//   32..44   input 1..3 segment seed (cap+domain, nsk left, zero right)
//   44..55   tag injection, shared parts (cap+domain, zero, tag chain)
//   55..59   tag injection, per-input value absorb
//   59..71   cm stage-2 injection (cap+domain, chain left, rho right)
//   71..84   Merkle injection (cap+domain ×4, bit-select ×8, bit-binary)
//   84..95   nf injection, shared parts (cap, zeros, nsk left, rho right)
//   95..99   nf injection, per-input DOMAIN (real vs dummy)
//   99..106  output seed, shared parts (cap+domain, zero left tail)
//   106..110 output seed, per-output value absorb
//   110..118 output cm injection (cap+domain, chain left; rho right free)
//   118      range-check accumulator recurrence
//   119      range-check bit is boolean
//   120..128 range-check landing: accumulator == value register (×8)
//   128      value conservation (public t_in/t_out/fee folded in)
const NUM_CONSTRAINTS: usize = 129;

// Periodic column index map (must match `get_periodic_column_values`):
//   0        hash-round mask (period 8)
//   1..25    ARK1 / ARK2 (period 8)
//   25 m_row0        26 m_seed_in      27 m_tag       28..32 m_tag_i
//   32 m_cm          33 m_merkle       34 m_nf_any    35..39 m_nf_i
//   39 m_outseed     40..44 m_outseed_j  44 m_outcm
//   45 m_acc         46 m_isbit        47..55 m_rcend_m
//   55 m_bal         56 m_const_keys   57 m_const_vals
const P_ROW0: usize = 25;
const P_SEED_IN: usize = 26;
const P_TAG: usize = 27;
const P_TAG_I: usize = 28;
const P_CM: usize = 32;
const P_MERKLE: usize = 33;
const P_NF_ANY: usize = 34;
const P_NF_I: usize = 35;
const P_OUTSEED: usize = 39;
const P_OUTSEED_J: usize = 40;
const P_OUTCM: usize = 44;
const P_ACC: usize = 45;
const P_ISBIT: usize = 46;
const P_RCEND_M: usize = 47;
const P_BAL: usize = 55;
const P_CONST_KEYS: usize = 56;
const P_CONST_VALS: usize = 57;
const NUM_PERIODIC: usize = 58;

/// The bundle AIR. See the module docs for the statement and trace layout.
pub struct BundleAir {
    context: AirContext<Felt>,
    pub_inputs: BundlePublicInputs,
}

impl Air for BundleAir {
    type BaseField = Felt;
    type PublicInputs = BundlePublicInputs;

    fn new(trace_info: TraceInfo, pub_inputs: BundlePublicInputs, options: ProofOptions) -> Self {
        assert_eq!(TRACE_WIDTH, trace_info.width(), "unexpected trace width");
        let mut degrees = Vec::with_capacity(NUM_CONSTRAINTS);
        for _ in 0..STATE_WIDTH {
            degrees.push(TransitionConstraintDegree::with_cycles(
                7,
                vec![CYCLE_LENGTH],
            ));
        }
        for idx in STATE_WIDTH..NUM_CONSTRAINTS {
            // Degree-2 constraints: Merkle bit selection + bit-binary
            // (75..84) and the range-check bit-binary (119).
            let deg = if (75..84).contains(&idx) || idx == 119 {
                2
            } else {
                1
            };
            degrees.push(TransitionConstraintDegree::with_cycles(
                deg,
                vec![TRACE_LENGTH],
            ));
        }
        // Assertion count depends on the (public) dummy pattern.
        let mut num_assertions = 8 /* row-0 seed */ + NUM_SLOTS * 2 /* rc acc starts */;
        for i in 0..NUM_SLOTS {
            num_assertions += if pub_inputs.input_dummy[i] { 1 } else { 8 };
            num_assertions += if pub_inputs.output_dummy[i] { 1 } else { 4 };
        }
        let context = AirContext::new(trace_info, degrees, num_assertions, options);
        BundleAir {
            context,
            pub_inputs,
        }
    }

    fn context(&self) -> &AirContext<Felt> {
        &self.context
    }

    fn evaluate_transition<E: FieldElement<BaseField = Felt>>(
        &self,
        frame: &EvaluationFrame<E>,
        periodic_values: &[E],
        result: &mut [E],
    ) {
        let cur = frame.current();
        let nxt = frame.next();

        let hmask = periodic_values[0];
        let ark1 = &periodic_values[1..1 + STATE_WIDTH];
        let ark2 = &periodic_values[1 + STATE_WIDTH..1 + 2 * STATE_WIDTH];
        let m_row0 = periodic_values[P_ROW0];
        let m_seed_in = periodic_values[P_SEED_IN];
        let m_tag = periodic_values[P_TAG];
        let m_tag_i = &periodic_values[P_TAG_I..P_TAG_I + NUM_SLOTS];
        let m_cm = periodic_values[P_CM];
        let m_merkle = periodic_values[P_MERKLE];
        let m_nf_any = periodic_values[P_NF_ANY];
        let m_nf_i = &periodic_values[P_NF_I..P_NF_I + NUM_SLOTS];
        let m_outseed = periodic_values[P_OUTSEED];
        let m_outseed_j = &periodic_values[P_OUTSEED_J..P_OUTSEED_J + NUM_SLOTS];
        let m_outcm = periodic_values[P_OUTCM];
        let m_acc = periodic_values[P_ACC];
        let m_isbit = periodic_values[P_ISBIT];
        let m_rcend = &periodic_values[P_RCEND_M..P_RCEND_M + 2 * NUM_SLOTS];
        let m_bal = periodic_values[P_BAL];
        let m_const_keys = periodic_values[P_CONST_KEYS];
        let m_const_vals = periodic_values[P_CONST_VALS];

        let cap_seed = E::from(Felt::new(CAPACITY_SEED));
        let dom_tag = E::from(Felt::new(RESCUE_DOMAIN_OWNER_TAG));
        let dom_c1 = E::from(Felt::new(RESCUE_DOMAIN_COMMIT_STAGE1));
        let dom_c2 = E::from(Felt::new(RESCUE_DOMAIN_COMMIT_STAGE2));
        let dom_merkle = E::from(Felt::new(RESCUE_DOMAIN_MERKLE_NODE));

        // --- 0..12: Rescue-Prime round. Round r maps s -> s' via
        //   t = MDS * s^7 + ARK1[r];  s' = MDS * t^(1/7) + ARK2[r]
        // which is equivalent (degree 7 both sides) to
        //   MDS * s^7 + ARK1[r] == ( INV_MDS * (s' - ARK2[r]) )^7.
        let mut fwd = [E::ZERO; STATE_WIDTH];
        let mut bwd = [E::ZERO; STATE_WIDTH];
        for j in 0..STATE_WIDTH {
            let s7 = exp7(cur[j]);
            for (i, f) in fwd.iter_mut().enumerate() {
                *f += E::from(Rp64_256::MDS[i][j]) * s7;
            }
            let d = nxt[j] - ark2[j];
            for (i, b) in bwd.iter_mut().enumerate() {
                *b += E::from(Rp64_256::INV_MDS[i][j]) * d;
            }
        }
        for j in 0..STATE_WIDTH {
            result[j] = hmask * (fwd[j] + ark1[j] - exp7(bwd[j]));
        }

        // --- 12..20: rho / nsk registers constant within each input
        // segment (mask released at segment boundaries so each input loads
        // its own witness).
        for k in 0..4 {
            result[12 + k] = m_const_keys * (nxt[RHO_COL + k] - cur[RHO_COL + k]);
            result[16 + k] = m_const_keys * (nxt[NSK_COL + k] - cur[NSK_COL + k]);
        }
        // --- 20..28: the eight value registers constant over the whole
        // active region (they are read at range-check rows, absorption rows,
        // and the balance row).
        for m in 0..2 * NUM_SLOTS {
            result[20 + m] = m_const_vals * (nxt[VAL_COL + m] - cur[VAL_COL + m]);
        }

        // --- 28..32: input 0's owner-tag hash absorbs nsk in the left rate
        // half on row 0 (capacity + right half are boundary assertions).
        for k in 0..4 {
            result[28 + k] = m_row0 * (cur[4 + k] - cur[NSK_COL + k]);
        }

        // --- 32..44: inputs 1..3 segment seed — the row after input i-1's
        // nullifier digest starts input i's owner-tag hash:
        // capacity [8, TAG, 0, 0], left rate = the NEW nsk registers,
        // right rate = 0.
        result[32] = m_seed_in * (nxt[0] - cap_seed);
        result[33] = m_seed_in * (nxt[1] - dom_tag);
        result[34] = m_seed_in * nxt[2];
        result[35] = m_seed_in * nxt[3];
        for k in 0..4 {
            result[36 + k] = m_seed_in * (nxt[4 + k] - nxt[NSK_COL + k]);
            result[40 + k] = m_seed_in * nxt[8 + k];
        }

        // --- 44..59: tag injection — owner-tag digest into commitment
        // stage 1: capacity [8, C1, 0, 0], left rate [value_i, 0, 0, 0]
        // (value from the input's PRIVATE register, per-input mask),
        // right rate = tag digest.
        result[44] = m_tag * (nxt[0] - cap_seed);
        result[45] = m_tag * (nxt[1] - dom_c1);
        result[46] = m_tag * nxt[2];
        result[47] = m_tag * nxt[3];
        result[48] = m_tag * nxt[5];
        result[49] = m_tag * nxt[6];
        result[50] = m_tag * nxt[7];
        for k in 0..4 {
            result[51 + k] = m_tag * (nxt[8 + k] - cur[4 + k]);
        }
        for (i, &m) in m_tag_i.iter().enumerate() {
            result[55 + i] = m * (nxt[4] - cur[VAL_COL + i]);
        }

        // --- 59..71: cm stage-2 injection — stage-1 digest chained left,
        // rho absorbed right, capacity [8, C2, 0, 0].
        result[59] = m_cm * (nxt[0] - cap_seed);
        result[60] = m_cm * (nxt[1] - dom_c2);
        result[61] = m_cm * nxt[2];
        result[62] = m_cm * nxt[3];
        for k in 0..4 {
            result[63 + k] = m_cm * (nxt[4 + k] - cur[4 + k]);
            result[67 + k] = m_cm * (nxt[8 + k] - cur[RHO_COL + k]);
        }

        // --- 71..84: Merkle level injection. Bit b picks which child the
        // running digest is; the sibling half is a free witness. Capacity
        // [8, MERKLE, 0, 0].
        let b = cur[BIT_COL];
        let one = E::ONE;
        result[71] = m_merkle * (nxt[0] - cap_seed);
        result[72] = m_merkle * (nxt[1] - dom_merkle);
        result[73] = m_merkle * nxt[2];
        result[74] = m_merkle * nxt[3];
        for k in 0..4 {
            // b = 0: digest is the LEFT child (rate 4..8).
            result[75 + k] = m_merkle * (one - b) * (nxt[4 + k] - cur[4 + k]);
            // b = 1: digest is the RIGHT child (rate 8..12).
            result[79 + k] = m_merkle * b * (nxt[8 + k] - cur[4 + k]);
        }
        result[83] = m_merkle * b * (one - b);

        // --- 84..99: nullifier injection — seeded with (nsk, rho);
        // capacity element 1 carries the REAL vs DUMMY nullifier domain
        // per the public dummy flag (per-input mask).
        result[84] = m_nf_any * (nxt[0] - cap_seed);
        result[85] = m_nf_any * nxt[2];
        result[86] = m_nf_any * nxt[3];
        for k in 0..4 {
            result[87 + k] = m_nf_any * (nxt[4 + k] - cur[NSK_COL + k]);
            result[91 + k] = m_nf_any * (nxt[8 + k] - cur[RHO_COL + k]);
        }
        for (i, &m) in m_nf_i.iter().enumerate() {
            let dom = if self.pub_inputs.input_dummy[i] {
                RESCUE_DOMAIN_DUMMY_NULLIFIER
            } else {
                RESCUE_DOMAIN_NULLIFIER
            };
            result[95 + i] = m * (nxt[1] - E::from(Felt::new(dom)));
        }

        // --- 99..110: output seed — the row before output j's stage-1
        // cycle: capacity [8, C1, 0, 0], left rate [value'_j, 0, 0, 0]
        // (private register, per-output mask), right rate = the output's
        // owner tag, a FREE witness (used exactly once, so it needs no
        // register).
        result[99] = m_outseed * (nxt[0] - cap_seed);
        result[100] = m_outseed * (nxt[1] - dom_c1);
        result[101] = m_outseed * nxt[2];
        result[102] = m_outseed * nxt[3];
        result[103] = m_outseed * nxt[5];
        result[104] = m_outseed * nxt[6];
        result[105] = m_outseed * nxt[7];
        for (j, &m) in m_outseed_j.iter().enumerate() {
            result[106 + j] = m * (nxt[4] - nxt[VAL_COL + NUM_SLOTS + j]);
        }

        // --- 110..118: output cm stage-2 injection — stage-1 digest
        // chained left, rho' absorbed right as a FREE witness.
        result[110] = m_outcm * (nxt[0] - cap_seed);
        result[111] = m_outcm * (nxt[1] - dom_c2);
        result[112] = m_outcm * nxt[2];
        result[113] = m_outcm * nxt[3];
        for k in 0..4 {
            result[114 + k] = m_outcm * (nxt[4 + k] - cur[4 + k]);
        }

        // --- 118..120: 61-bit range check (D3). MSB-first double-and-add:
        // acc' = 2·acc + bit', with every bit boolean-constrained. The
        // accumulator starts at 0 (boundary assertion per segment) and must
        // land on the value register (m_rcend below), so EVERY claimed bit
        // is constrained and the register is exactly the 61-bit sum.
        result[118] =
            m_acc * (nxt[RC_ACC_COL] - (cur[RC_ACC_COL] + cur[RC_ACC_COL]) - nxt[RC_BIT_COL]);
        result[119] = m_isbit * cur[RC_BIT_COL] * (cur[RC_BIT_COL] - one);

        // --- 120..128: range-check landing per value register.
        for (m, &mask) in m_rcend.iter().enumerate() {
            result[120 + m] = mask * (cur[RC_ACC_COL] - cur[VAL_COL + m]);
        }

        // --- 128: value conservation (D1). Only t_in/t_out/fee are public;
        // all eight values are private registers. Sound over the integers
        // by the 61-bit range checks + native public-leg bounds (see
        // crate::note).
        let mut bal = E::from(Felt::new(self.pub_inputs.transparent_in))
            - E::from(Felt::new(self.pub_inputs.transparent_out))
            - E::from(Felt::new(self.pub_inputs.fee_grains));
        for i in 0..NUM_SLOTS {
            bal += cur[VAL_COL + i];
            bal -= cur[VAL_COL + NUM_SLOTS + i];
        }
        result[128] = m_bal * bal;
    }

    fn get_assertions(&self) -> Vec<Assertion<Felt>> {
        let mut assertions = Vec::with_capacity(8 + 2 * NUM_SLOTS + 8 * NUM_SLOTS);
        // Row 0: input 0's owner-tag sponge seed — capacity
        // [8, TAG, 0, 0] and zero right rate half (owner_tag =
        // merge_d(TAG, nsk, 0); nsk itself is wired by constraints 28..32).
        assertions.push(Assertion::single(0, 0, Felt::new(CAPACITY_SEED)));
        assertions.push(Assertion::single(1, 0, Felt::new(RESCUE_DOMAIN_OWNER_TAG)));
        assertions.push(Assertion::single(2, 0, Felt::ZERO));
        assertions.push(Assertion::single(3, 0, Felt::ZERO));
        for col in 8..12 {
            assertions.push(Assertion::single(col, 0, Felt::ZERO));
        }
        // Range-check accumulators start at 0 in every segment.
        for m in 0..2 * NUM_SLOTS {
            assertions.push(Assertion::single(RC_ACC_COL, rc_base(m), Felt::ZERO));
        }
        // Real inputs: root and nullifier bound to the public inputs.
        // Dummy inputs: value register pinned to ZERO (the root/nullifier
        // rows stay unconstrained junk that is never surfaced).
        for i in 0..NUM_SLOTS {
            if self.pub_inputs.input_dummy[i] {
                assertions.push(Assertion::single(VAL_COL + i, 0, Felt::ZERO));
            } else {
                let root = self.pub_inputs.anchors[i].to_elements();
                for (k, r) in root.iter().enumerate() {
                    assertions.push(Assertion::single(4 + k, root_row(i), *r));
                }
                let nf = self.pub_inputs.nullifiers[i].to_elements();
                for (k, n) in nf.iter().enumerate() {
                    assertions.push(Assertion::single(4 + k, nf_row(i), *n));
                }
            }
        }
        // Real outputs: commitment bound to the public inputs. Dummy
        // outputs: value register pinned to ZERO.
        for j in 0..NUM_SLOTS {
            if self.pub_inputs.output_dummy[j] {
                assertions.push(Assertion::single(VAL_COL + NUM_SLOTS + j, 0, Felt::ZERO));
            } else {
                let cm = self.pub_inputs.output_commitments[j].to_elements();
                for (k, c) in cm.iter().enumerate() {
                    assertions.push(Assertion::single(4 + k, out_cm_row(j), *c));
                }
            }
        }
        assertions
    }

    fn get_periodic_column_values(&self) -> Vec<Vec<Felt>> {
        let mut columns = Vec::with_capacity(NUM_PERIODIC);
        // 0: round mask (rounds on the first 7 rows of each cycle).
        let mut hmask = vec![Felt::ONE; CYCLE_LENGTH];
        hmask[CYCLE_LENGTH - 1] = Felt::ZERO;
        columns.push(hmask);
        // 1..25: ARK1 / ARK2 per state element, per in-cycle round.
        for ark in [&Rp64_256::ARK1, &Rp64_256::ARK2] {
            for j in 0..STATE_WIDTH {
                let mut col = vec![Felt::ZERO; CYCLE_LENGTH];
                for (cell, round_constants) in col.iter_mut().zip(ark.iter()) {
                    *cell = round_constants[j];
                }
                columns.push(col);
            }
        }
        // Full-trace-length masks (index map in the const block above).
        let mask = |rows: &[usize]| {
            let mut col = vec![Felt::ZERO; TRACE_LENGTH];
            for &r in rows {
                col[r] = Felt::ONE;
            }
            col
        };
        columns.push(mask(&[0])); // 25: m_row0
        columns.push(mask(&[nf_row(0), nf_row(1), nf_row(2)])); // 26: m_seed_in
        let tag_rows: Vec<usize> = (0..NUM_SLOTS).map(tag_inject_row).collect();
        columns.push(mask(&tag_rows)); // 27: m_tag
        for i in 0..NUM_SLOTS {
            columns.push(mask(&[tag_inject_row(i)])); // 28..32: m_tag_i
        }
        let cm_rows: Vec<usize> = (0..NUM_SLOTS).map(cm_inject_row).collect();
        columns.push(mask(&cm_rows)); // 32: m_cm
        let mut merkle_rows = Vec::with_capacity(NUM_SLOTS * TREE_DEPTH);
        for i in 0..NUM_SLOTS {
            for level in 0..TREE_DEPTH {
                merkle_rows.push(merkle_inject_row(i, level));
            }
        }
        columns.push(mask(&merkle_rows)); // 33: m_merkle
        let nf_seed_rows: Vec<usize> = (0..NUM_SLOTS).map(root_row).collect();
        columns.push(mask(&nf_seed_rows)); // 34: m_nf_any
        for i in 0..NUM_SLOTS {
            columns.push(mask(&[root_row(i)])); // 35..39: m_nf_i
        }
        let outseed_rows: Vec<usize> = (0..NUM_SLOTS).map(|j| output_base(j) - 1).collect();
        columns.push(mask(&outseed_rows)); // 39: m_outseed
        for j in 0..NUM_SLOTS {
            columns.push(mask(&[output_base(j) - 1])); // 40..44: m_outseed_j
        }
        let outcm_rows: Vec<usize> = (0..NUM_SLOTS).map(out_cm_inject_row).collect();
        columns.push(mask(&outcm_rows)); // 44: m_outcm
        let mut acc_rows = Vec::new();
        let mut bit_rows = Vec::new();
        let mut end_rows = Vec::new();
        for m in 0..2 * NUM_SLOTS {
            let base = rc_base(m);
            acc_rows.extend(base..base + VALUE_BITS);
            bit_rows.extend(base + 1..=base + VALUE_BITS);
            end_rows.push(base + VALUE_BITS);
        }
        columns.push(mask(&acc_rows)); // 45: m_acc
        columns.push(mask(&bit_rows)); // 46: m_isbit
        for &r in &end_rows {
            columns.push(mask(&[r])); // 47..55: m_rcend_m
        }
        columns.push(mask(&[0])); // 55: m_bal
                                  // 56: rho/nsk constancy — active within each input segment,
                                  // released on segment-boundary rows and through the whole
                                  // output/padding region (registers carry non-constant filler there
                                  // so the constraint polynomial attains its declared degree).
        let mut m_keys = vec![Felt::ZERO; TRACE_LENGTH];
        for (r, v) in m_keys.iter_mut().enumerate().take(OUTPUTS_START_ROW) {
            if r % INPUT_SEGMENT_ROWS != INPUT_SEGMENT_ROWS - 1 {
                *v = Felt::ONE;
            }
        }
        columns.push(m_keys);
        // 57: value-register constancy — active over the whole active
        // region, released in padding.
        let mut m_vals = vec![Felt::ZERO; TRACE_LENGTH];
        for v in m_vals.iter_mut().take(ACTIVE_ROWS - 1) {
            *v = Felt::ONE;
        }
        columns.push(m_vals);
        debug_assert_eq!(columns.len(), NUM_PERIODIC);
        columns
    }
}

/// `x^7` via square-and-multiply (keeps the constraint degree explicit).
#[inline]
fn exp7<E: FieldElement>(x: E) -> E {
    let x2 = x * x;
    let x4 = x2 * x2;
    x4 * x2 * x
}
