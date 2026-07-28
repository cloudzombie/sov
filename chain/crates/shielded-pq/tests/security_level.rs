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

    println!("--- pool-v2 proof security (42 queries, blowup 8, 16 grinding, quadratic ext)");
    println!("conjectured        : {} bits", conjectured.bits());
    println!("proven (Johnson/ldr): {} bits", proven.ldr_bits());
    println!("proven (unique dec) : {} bits", proven.udr_bits());

    // No assertion on the numbers themselves: this test exists to REPORT them
    // honestly, and the derived figures are written down in
    // `chain/docs/pq-shielded-soundness.md`. Asserting a target here would let
    // a parameter change silently move the goalposts instead of failing the
    // documented claim.
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
