//! MEASURED security level of the pool-v2 proof, in bits.
//!
//! Our design doc long carried "127 bits conjectured", with a note that the
//! proven figure is lower — a number nobody had derived. Winterfell computes
//! BOTH from the real proof, so there is no reason to guess:
//!
//! * `conjectured_security` — the capacity/conjecture-based figure every
//!   deployed STARK quotes. The strongest up-to-capacity forms of that
//!   conjecture class were disproved over large fields in late 2025, so this
//!   number is an assumption, not a guarantee.
//! * `proven_security` — unconditional, from Theorems 2 and 3 of
//!   eprint 2024/1553. Winterfell's own docs note provable security typically
//!   needs 2-3x the queries of conjectured security at the same level.
//!
//! BOTH figures are *classical* soundness bounds. Neither is a post-quantum
//! (QROM) security level: quoting either as "128-bit post-quantum" overstates
//! it (PQV2-05; see `prover::proof_options` and `notes/audit-scope-pq-pool.md`
//! §9).
//!
//! Run with:
//! `cargo test -p sov-shielded-pq --release --test security_level -- --nocapture`

use sov_shielded_pq::hash::PqDigest;
use sov_shielded_pq::note::{derive_rho, Note, SpendingKey};
use sov_shielded_pq::prover::{decode_proof, prove_bundle, BundleSpend};
use sov_shielded_pq::tree::CommitmentTree;
use winterfell::crypto::hashers::Blake3_256;
use winterfell::math::fields::f64::BaseElement;

const SEED: [u8; 32] = [0x42; 32];

/// The same realistic 2-in/2-out shape the cost test uses.
/// The witness set for a realistic 2-in/2-out bundle, reusable by the sweep.
fn realistic_inputs() -> (Vec<BundleSpend>, Vec<Note>, u64, u64) {
    let key = SpendingKey::from_seed(&SEED);
    let note0 = Note::new(1_250_000_000, key.owner_tag(), derive_rho(&SEED, 1)).expect("note");
    let note1 = Note::new(300_000_000, key.owner_tag(), derive_rho(&SEED, 3)).expect("note");
    let decoy0 = Note::new(1, key.owner_tag(), derive_rho(&SEED, 0)).expect("note");
    let decoy2 = Note::new(2, key.owner_tag(), derive_rho(&SEED, 2)).expect("note");
    let mut tree = CommitmentTree::new();
    tree.append(decoy0.commitment()).expect("append");
    tree.append(note0.commitment()).expect("append");
    tree.mark().expect("mark");
    tree.append(decoy2.commitment()).expect("append");
    tree.append(note1.commitment()).expect("append");
    tree.mark().expect("mark");

    let recipient = SpendingKey::from_seed(&[0x77; 32]);
    let fee = 1_000u64;
    let t_out = 50_000_000u64;
    let out_value = 400_000_000u64;
    let change = 1_250_000_000 + 300_000_000 - out_value - fee - t_out;
    let out_note =
        Note::new(out_value, recipient.owner_tag(), derive_rho(&[0x55; 32], 0)).expect("note");
    let change_note = Note::new(change, key.owner_tag(), derive_rho(&SEED, 100)).expect("note");
    let spends = vec![
        BundleSpend {
            key: key.clone(),
            note: note0,
            path: tree.witness(1).expect("witness").0,
        },
        BundleSpend {
            key,
            note: note1,
            path: tree.witness(3).expect("witness").0,
        },
    ];
    (spends, vec![out_note, change_note], t_out, fee)
}

fn realistic_proof() -> (Vec<u8>, sov_shielded_pq::air::BundlePublicInputs) {
    let (spends, outputs, t_out, fee) = realistic_inputs();
    let _ = PqDigest::ZERO;
    prove_bundle(&spends, &outputs, 0, t_out, fee).expect("prove")
}

#[test]
fn report_conjectured_and_proven_security_bits() {
    let (bytes, pub_inputs) = realistic_proof();
    let proof = decode_proof(&bytes, &pub_inputs).expect("decode");

    let conjectured = proof.conjectured_security::<Blake3_256<BaseElement>>();
    let proven = proof.proven_security::<Blake3_256<BaseElement>>();

    // These are the SHIPPED options (`prover::proof_options`): 64 queries,
    // blowup 16, 16 grinding bits, cubic extension. The label previously read
    // "42 queries, blowup 8, quadratic" — the OLD set — while the code below
    // measured the new one (audit PQV2-08: the label had drifted off the
    // parameters actually shipped).
    println!("--- pool-v2 proof security (64 queries, blowup 16, 16 grinding, cubic ext)");
    println!("conjectured        : {} bits", conjectured.bits());
    println!("proven (Johnson/ldr): {} bits", proven.ldr_bits());
    println!("proven (unique dec) : {} bits", proven.udr_bits());

    // Regression FLOOR (audit PQV2-08). The whole reason the parameters moved
    // 42q/8/quadratic -> 64q/16/cubic was to raise PROVEN security 75 -> 128
    // bits. Previously this test asserted NOTHING, so a silent revert of the
    // options would drop proven security to 75 with no failing test. A floor
    // (>=, not ==) does not "move the goalposts": it can only catch a
    // downward regression, never bless a change. Measured today: conjectured
    // 128, proven (ldr) 128. The build-time `const _` guards in `prover.rs`
    // pin the parameters themselves; this pins the security level they buy.
    assert!(
        conjectured.bits() >= 128,
        "conjectured security regressed below 128 bits: {} — did proof_options() change?",
        conjectured.bits()
    );
    assert!(
        proven.ldr_bits() >= 128,
        "PROVEN (Johnson/ldr) security regressed below 128 bits: {} — the 64q/16/cubic \
         parameter set exists specifically to reach 128 proven; a drop means proof_options() \
         regressed toward the old 42q/8/quadratic set (75 proven)",
        proven.ldr_bits()
    );
}

/// What parameter set reaches a PROVEN target?
///
/// The security module is private in winterfell, so the only way to get a
/// proven figure is from a real proof — this actually proves the same bundle
/// at each parameter set and reads the number off.
#[test]
fn parameter_sets_reaching_a_proven_target() {
    use sov_shielded_pq::prover::BundleProver;
    use winterfell::{BatchingMethod, FieldExtension, ProofOptions, Prover, TraceTable};

    let (spends, outputs, t_out, fee) = realistic_inputs();
    println!("--- proven-security sweep (target: 100 bits, Johnson/ldr bound)");
    for &(extname, ext) in &[
        ("quadratic", FieldExtension::Quadratic),
        ("cubic", FieldExtension::Cubic),
    ] {
        for &blowup in &[8usize, 16, 32] {
            for &queries in &[42usize, 64, 96, 128, 160, 200] {
                let options = ProofOptions::new(
                    queries,
                    blowup,
                    16,
                    ext,
                    4,
                    31,
                    BatchingMethod::Linear,
                    BatchingMethod::Linear,
                );
                let (cols, pub_inputs) =
                    sov_shielded_pq::prover::build_bundle_columns(&spends, &outputs, 0, t_out, fee)
                        .expect("columns");
                let prover = BundleProver::with_options(pub_inputs, options);
                let proof = prover.prove(TraceTable::init(cols)).expect("prove");
                let proven = proof.proven_security::<Blake3_256<BaseElement>>();
                let conj = proof.conjectured_security::<Blake3_256<BaseElement>>();
                let size_kb = proof.to_bytes().len() as f64 / 1024.0;
                println!(
                "{extname:<9} blowup {blowup:>2}  queries {queries:>3}  ->  proven {:>3}  conjectured {:>3}  proof {size_kb:.1} KB",
                proven.ldr_bits(),
                conj.bits()
            );
                if proven.ldr_bits() >= 128 {
                    break;
                }
            }
        }
    }
}
