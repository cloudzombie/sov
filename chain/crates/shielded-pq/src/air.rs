//! The STARK spend circuit (winterfell AIR).
//!
//! # Statement
//!
//! For public inputs `(root, nf, value)` the prover knows secrets
//! `nsk`, `rho`, and a Merkle path `(bits, siblings)` such that, with
//! `merge` = the Rescue-Prime 2-to-1 compression of [`crate::hash`]:
//!
//! 1. `owner_tag = merge(nsk, 0)`                       (ownership binding)
//! 2. `cm = merge(merge([value,0,0,0], owner_tag), rho)` (commitment opening)
//! 3. `cm` is a depth-20 Merkle leaf under `root` via `(bits, siblings)`
//!    (membership)
//! 4. `nf = merge(nsk, rho)`                            (nullifier derivation)
//!
//! All four equations share the SAME `nsk`/`rho` witness registers, so the
//! nullifier is bound to the committed note and only the `nsk` holder (not a
//! sender who merely knows the note opening) can produce a valid spend.
//!
//! # What is NOT in-circuit (prototype honesty)
//!
//! - The spent value is a PUBLIC input (revealed), so value conservation is
//!   checked natively by the bundle verifier — not proven zero-knowledge.
//! - No in-circuit range check on `value` (it is public; the native verifier
//!   bounds it).
//! - Spend authorization is a carrier-level ML-DSA-65 signature, not an
//!   in-circuit signature check.
//!
//! # Trace layout
//!
//! 21 columns × 256 rows. Columns 0..12 are the Rescue-Prime sponge state,
//! 12..16 carry `rho`, 16..20 carry `nsk` (both constant over the active
//! region), column 20 carries the Merkle path bit for each level.
//!
//! Each hash invocation is one 8-row cycle: rows `8c..8c+7` hold the sponge
//! state before rounds `0..7`; row `8c+7` holds the permutation output. The
//! transition from row `8c+7` to `8(c+1)` is an "injection" row where masked
//! constraints wire the previous digest, `rho`/`nsk` registers, or Merkle
//! siblings into the next sponge input.
//!
//! Cycle map: cycle 0 = eq. 1; cycle 1–2 = eq. 2; cycles 3..23 = eq. 3
//! (20 levels, root asserted at row 183); cycle 23 = eq. 4 (`nf` asserted at
//! row 191); cycles 24..32 = padding (unconstrained except hash rounds).

use crate::hash::{Felt, PqDigest, STATE_WIDTH};
use crate::tree::TREE_DEPTH;
use winter_crypto::hashers::Rp64_256;
use winter_math::{FieldElement, ToElements};
use winterfell::{
    Air, AirContext, Assertion, EvaluationFrame, ProofOptions, TraceInfo,
    TransitionConstraintDegree,
};

/// Rows per hash invocation (7 rounds + 1 injection row).
pub const CYCLE_LENGTH: usize = 8;
/// Total trace length: 24 active cycles padded to a power of two.
pub const TRACE_LENGTH: usize = 256;
/// Trace width: 12 sponge + 4 rho + 4 nsk + 1 path bit.
pub const TRACE_WIDTH: usize = 21;

/// First rho register column.
pub const RHO_COL: usize = 12;
/// First nsk register column.
pub const NSK_COL: usize = 16;
/// Merkle path bit column.
pub const BIT_COL: usize = 20;

/// Row holding the owner-tag injection (end of cycle 0).
pub const TAG_INJECT_ROW: usize = 7;
/// Row holding the rho injection into the commitment hash (end of cycle 1).
pub const CM_INJECT_ROW: usize = 15;
/// First Merkle injection row (then every 8 rows, 20 total).
pub const FIRST_MERKLE_INJECT_ROW: usize = 23;
/// Row where the Merkle root is asserted / the nullifier hash is seeded.
pub const ROOT_ROW: usize = 183;
/// Row where the nullifier digest is asserted.
pub const NF_ROW: usize = 191;

/// Sponge capacity seed for a 2-to-1 merge (`Rp64_256` sets capacity[0] to
/// the rate width, 8).
pub const CAPACITY_SEED: u64 = 8;

/// Public inputs of one spend proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpendPublicInputs {
    /// The note-commitment tree anchor the spend is proven against.
    pub root: PqDigest,
    /// The revealed nullifier.
    pub nullifier: PqDigest,
    /// The spent note's value in grains (PUBLIC in this prototype).
    pub value_grains: u64,
}

impl ToElements<Felt> for SpendPublicInputs {
    fn to_elements(&self) -> Vec<Felt> {
        let mut out = Vec::with_capacity(9);
        out.extend_from_slice(&self.root.to_elements());
        out.extend_from_slice(&self.nullifier.to_elements());
        out.push(Felt::new(self.value_grains));
        out
    }
}

/// The spend AIR. See the module docs for the statement and trace layout.
pub struct SpendAir {
    context: AirContext<Felt>,
    pub_inputs: SpendPublicInputs,
}

impl Air for SpendAir {
    type BaseField = Felt;
    type PublicInputs = SpendPublicInputs;

    fn new(trace_info: TraceInfo, pub_inputs: SpendPublicInputs, options: ProofOptions) -> Self {
        assert_eq!(TRACE_WIDTH, trace_info.width(), "unexpected trace width");
        let mut degrees = Vec::with_capacity(69);
        // 0..12: Rescue rounds (degree 7, gated by the period-8 round mask).
        for _ in 0..STATE_WIDTH {
            degrees.push(TransitionConstraintDegree::with_cycles(
                7,
                vec![CYCLE_LENGTH],
            ));
        }
        // 12..16 rho constancy, 16..20 nsk constancy, 20..24 row-0 nsk absorb.
        for _ in 0..12 {
            degrees.push(TransitionConstraintDegree::with_cycles(
                1,
                vec![TRACE_LENGTH],
            ));
        }
        // 24..32 tag injection, 32..44 cm injection.
        for _ in 0..20 {
            degrees.push(TransitionConstraintDegree::with_cycles(
                1,
                vec![TRACE_LENGTH],
            ));
        }
        // 44..48 Merkle capacity injection (degree 1 × mask).
        for _ in 0..4 {
            degrees.push(TransitionConstraintDegree::with_cycles(
                1,
                vec![TRACE_LENGTH],
            ));
        }
        // 48..56 Merkle bit-selected digest wiring + 56 bit-is-binary
        // (degree 2 × mask).
        for _ in 0..9 {
            degrees.push(TransitionConstraintDegree::with_cycles(
                2,
                vec![TRACE_LENGTH],
            ));
        }
        // 57..69 nullifier injection.
        for _ in 0..12 {
            degrees.push(TransitionConstraintDegree::with_cycles(
                1,
                vec![TRACE_LENGTH],
            ));
        }
        let context = AirContext::new(trace_info, degrees, 20, options);
        SpendAir {
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

        // Periodic value layout — must match get_periodic_column_values().
        let hmask = periodic_values[0];
        let ark1 = &periodic_values[1..1 + STATE_WIDTH];
        let ark2 = &periodic_values[1 + STATE_WIDTH..1 + 2 * STATE_WIDTH];
        let m_row0 = periodic_values[25];
        let m_tag = periodic_values[26];
        let m_cm = periodic_values[27];
        let m_merkle = periodic_values[28];
        let m_nf = periodic_values[29];
        let m_const = periodic_values[30];

        let cap_seed = E::from(Felt::new(CAPACITY_SEED));

        // --- 0..12: Rescue-Prime round.
        // Round r maps s -> s' via:
        //   t  = MDS * s^7 + ARK1[r]
        //   s' = MDS * t^(1/7) + ARK2[r]
        // which is equivalent (and degree-7 on both sides) to:
        //   MDS * s^7 + ARK1[r] == ( INV_MDS * (s' - ARK2[r]) )^7
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

        // --- 12..16 / 16..20: rho and nsk registers constant over the
        // active region.
        for k in 0..4 {
            result[12 + k] = m_const * (nxt[RHO_COL + k] - cur[RHO_COL + k]);
            result[16 + k] = m_const * (nxt[NSK_COL + k] - cur[NSK_COL + k]);
        }

        // --- 20..24: row 0 seeds the owner-tag hash with nsk in the left
        // rate half (right half + capacity are boundary assertions).
        for k in 0..4 {
            result[20 + k] = m_row0 * (cur[4 + k] - cur[NSK_COL + k]);
        }

        // --- 24..32: owner-tag digest into the commitment hash's right rate
        // half; capacity reseeded. (Left half = [value,0,0,0] is asserted.)
        result[24] = m_tag * (nxt[0] - cap_seed);
        result[25] = m_tag * nxt[1];
        result[26] = m_tag * nxt[2];
        result[27] = m_tag * nxt[3];
        for k in 0..4 {
            result[28 + k] = m_tag * (nxt[8 + k] - cur[4 + k]);
        }

        // --- 32..44: first-stage digest chained left, rho absorbed right.
        result[32] = m_cm * (nxt[0] - cap_seed);
        result[33] = m_cm * nxt[1];
        result[34] = m_cm * nxt[2];
        result[35] = m_cm * nxt[3];
        for k in 0..4 {
            result[36 + k] = m_cm * (nxt[4 + k] - cur[4 + k]);
            result[40 + k] = m_cm * (nxt[8 + k] - cur[RHO_COL + k]);
        }

        // --- 44..57: Merkle level injection. Bit b picks which child the
        // running digest is; the sibling half is a free witness.
        let b = cur[BIT_COL];
        let one = E::ONE;
        result[44] = m_merkle * (nxt[0] - cap_seed);
        result[45] = m_merkle * nxt[1];
        result[46] = m_merkle * nxt[2];
        result[47] = m_merkle * nxt[3];
        for k in 0..4 {
            // b = 0: digest is the LEFT child (rate 4..8).
            result[48 + k] = m_merkle * (one - b) * (nxt[4 + k] - cur[4 + k]);
            // b = 1: digest is the RIGHT child (rate 8..12).
            result[52 + k] = m_merkle * b * (nxt[8 + k] - cur[4 + k]);
        }
        result[56] = m_merkle * b * (one - b);

        // --- 57..69: nullifier hash seeded with (nsk, rho).
        result[57] = m_nf * (nxt[0] - cap_seed);
        result[58] = m_nf * nxt[1];
        result[59] = m_nf * nxt[2];
        result[60] = m_nf * nxt[3];
        for k in 0..4 {
            result[61 + k] = m_nf * (nxt[4 + k] - cur[NSK_COL + k]);
            result[65 + k] = m_nf * (nxt[8 + k] - cur[RHO_COL + k]);
        }
    }

    fn get_assertions(&self) -> Vec<Assertion<Felt>> {
        let mut assertions = Vec::with_capacity(20);
        // Row 0: merge capacity seed + zero right rate half (owner_tag =
        // merge(nsk, 0); nsk itself is wired by transition constraint 20..24).
        assertions.push(Assertion::single(0, 0, Felt::new(CAPACITY_SEED)));
        for col in 1..4 {
            assertions.push(Assertion::single(col, 0, Felt::ZERO));
        }
        for col in 8..12 {
            assertions.push(Assertion::single(col, 0, Felt::ZERO));
        }
        // Row 8: the commitment hash absorbs [value, 0, 0, 0] on the left.
        assertions.push(Assertion::single(
            4,
            CYCLE_LENGTH,
            Felt::new(self.pub_inputs.value_grains),
        ));
        for col in 5..8 {
            assertions.push(Assertion::single(col, CYCLE_LENGTH, Felt::ZERO));
        }
        // Row 183: the Merkle chain ends at the public root.
        let root = self.pub_inputs.root.to_elements();
        for (k, r) in root.iter().enumerate() {
            assertions.push(Assertion::single(4 + k, ROOT_ROW, *r));
        }
        // Row 191: the nullifier digest is the public nullifier.
        let nf = self.pub_inputs.nullifier.to_elements();
        for (k, n) in nf.iter().enumerate() {
            assertions.push(Assertion::single(4 + k, NF_ROW, *n));
        }
        assertions
    }

    fn get_periodic_column_values(&self) -> Vec<Vec<Felt>> {
        let mut columns = Vec::with_capacity(31);
        // 0: round mask (rounds on the first 7 rows of each cycle).
        let mut hmask = vec![Felt::ONE; CYCLE_LENGTH];
        hmask[CYCLE_LENGTH - 1] = Felt::ZERO;
        columns.push(hmask);
        // 1..13, 13..25: ARK1 / ARK2 per state element, per in-cycle round.
        for ark in [&Rp64_256::ARK1, &Rp64_256::ARK2] {
            for j in 0..STATE_WIDTH {
                let mut col = vec![Felt::ZERO; CYCLE_LENGTH];
                for (cell, round_constants) in col.iter_mut().zip(ark.iter()) {
                    *cell = round_constants[j];
                }
                columns.push(col);
            }
        }
        // 25..30: injection masks (full-trace period).
        let single = |row: usize| {
            let mut col = vec![Felt::ZERO; TRACE_LENGTH];
            col[row] = Felt::ONE;
            col
        };
        columns.push(single(0)); // 25: m_row0
        columns.push(single(TAG_INJECT_ROW)); // 26: m_tag
        columns.push(single(CM_INJECT_ROW)); // 27: m_cm
        let mut merkle = vec![Felt::ZERO; TRACE_LENGTH];
        for level in 0..TREE_DEPTH {
            merkle[FIRST_MERKLE_INJECT_ROW + level * CYCLE_LENGTH] = Felt::ONE;
        }
        columns.push(merkle); // 28: m_merkle
        columns.push(single(ROOT_ROW)); // 29: m_nf
                                        // 30: register-constancy mask — active through the nullifier phase,
                                        // released in padding (padding registers carry non-constant filler so
                                        // the constraint polynomial has its declared degree).
        let mut m_const = vec![Felt::ZERO; TRACE_LENGTH];
        for v in m_const.iter_mut().take(NF_ROW) {
            *v = Felt::ONE;
        }
        columns.push(m_const);
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
