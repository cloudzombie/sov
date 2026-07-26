//! Measure the REAL per-note wallet scan cost of pool v2 (decision D7).
//!
//! ```text
//! cargo run --release --example scan_cost -p sov-shielded-pq
//! ```
//!
//! ML-KEM has no ECDH detection trick, so a v2 wallet trial-decapsulates
//! every note ciphertext on the chain. This program measures exactly what
//! that costs, with no estimates and no adjectives:
//!
//! 1. **miss** — a note addressed to someone else: one ML-KEM-768
//!    decapsulation + one blake3 detection tag, rejected before any AEAD.
//!    This is the cost that dominates a scan, because almost every note on
//!    the chain belongs to someone else.
//! 2. **hit** — a note addressed to us: the same, plus ChaCha20-Poly1305
//!    and note parsing.
//! 3. **block ingest** — the full [`PqNoteStore::ingest_block`] path over
//!    realistic 4-output bundles, i.e. what a wallet actually experiences.
//!
//! Numbers are printed as microseconds per note and extrapolated to the
//! sync time for a chain of a given size, so the UX claim is checkable
//! rather than asserted.

use std::time::Instant;

use sov_shielded_pq::air::{BundlePublicInputs, NUM_SLOTS};
use sov_shielded_pq::auth::{AUTH_PK_LEN, AUTH_SIG_LEN};
use sov_shielded_pq::bundle::SpendBundle;
use sov_shielded_pq::encrypt::{encrypt_note, NoteCiphertext};
use sov_shielded_pq::hash::PqDigest;
use sov_shielded_pq::{Note, PqNoteStore, PqShieldedKey};

/// How many ciphertexts each micro-benchmark runs.
const SAMPLES: usize = 2_000;
/// Blocks (each one 4-output bundle) for the end-to-end ingest measurement.
const BLOCKS: u64 = 500;

fn main() {
    let me = PqShieldedKey::from_leaf_seed(&[1u8; 32]);
    let other = PqShieldedKey::from_leaf_seed(&[2u8; 32]);

    // ---- 1. miss: someone else's note --------------------------------
    let theirs: Vec<NoteCiphertext> = (0..SAMPLES as u64)
        .map(|i| {
            let address = other.address();
            let note = Note::new(1_000 + i, address.owner_tag(), other.rho(i)).expect("note");
            encrypt_note(address.kem_ek(), &note).expect("encrypt")
        })
        .collect();
    let start = Instant::now();
    let mut misses = 0usize;
    for ct in &theirs {
        if me.encryption_key().decrypt(ct).is_err() {
            misses += 1;
        }
    }
    let miss = start.elapsed();
    assert_eq!(misses, SAMPLES, "every foreign note must miss");

    // ---- 2. hit: our own note ----------------------------------------
    let mine: Vec<NoteCiphertext> = (0..SAMPLES as u64)
        .map(|i| {
            let address = me.address();
            let note = Note::new(1_000 + i, address.owner_tag(), me.rho(i)).expect("note");
            encrypt_note(address.kem_ek(), &note).expect("encrypt")
        })
        .collect();
    let start = Instant::now();
    let mut hits = 0usize;
    for ct in &mine {
        if me.encryption_key().decrypt(ct).is_ok() {
            hits += 1;
        }
    }
    let hit = start.elapsed();
    assert_eq!(hits, SAMPLES, "every own note must decrypt");

    // ---- 3. end-to-end block ingest ----------------------------------
    // 500 blocks × one 4-output bundle = 2000 notes, none of them ours:
    // the realistic worst case for a wallet with no activity.
    let bundles: Vec<SpendBundle> = (0..BLOCKS)
        .map(|h| foreign_bundle(&other, h * NUM_SLOTS as u64))
        .collect();
    let mut store = PqNoteStore::new(0);
    let start = Instant::now();
    for (i, bundle) in bundles.iter().enumerate() {
        store.ingest_block(&me, i as u64 + 1, [i as u8; 32], &[bundle]);
    }
    let ingest = start.elapsed();
    let ingested = store.stats().ciphertexts_examined;
    assert_eq!(ingested, BLOCKS * NUM_SLOTS as u64);
    assert_eq!(store.balance(), 0);

    let miss_us = miss.as_secs_f64() * 1e6 / SAMPLES as f64;
    let hit_us = hit.as_secs_f64() * 1e6 / SAMPLES as f64;
    let ingest_us = ingest.as_secs_f64() * 1e6 / ingested as f64;

    println!("pool-v2 wallet scan cost (D7), {SAMPLES} samples per case");
    println!("  miss  (foreign note, rejected at the 4-byte detection tag): {miss_us:8.2} us/note");
    println!("  hit   (own note, decap + AEAD + parse)                    : {hit_us:8.2} us/note");
    println!(
        "  ingest(full store path incl. tree append + bookkeeping)   : {ingest_us:8.2} us/note"
    );
    for notes in [100_000u64, 1_000_000] {
        println!(
            "  => {notes:>9} v2 notes on chain: {:6.1} s of scanning (one key, one core)",
            notes as f64 * ingest_us / 1e6
        );
    }
}

/// A 4-output bundle none of whose notes belong to the scanning wallet.
fn foreign_bundle(recipient: &PqShieldedKey, rho_base: u64) -> SpendBundle {
    let address = recipient.address();
    let mut pi = BundlePublicInputs {
        anchors: [PqDigest::ZERO; NUM_SLOTS],
        nullifiers: [PqDigest::ZERO; NUM_SLOTS],
        input_dummy: [true; NUM_SLOTS],
        output_commitments: [PqDigest::ZERO; NUM_SLOTS],
        output_dummy: [false; NUM_SLOTS],
        transparent_in: 0,
        transparent_out: 0,
        fee_grains: 0,
    };
    let mut cts: [Option<NoteCiphertext>; NUM_SLOTS] = [None, None, None, None];
    for (slot, ct) in cts.iter_mut().enumerate() {
        let note = Note::new(
            7_000 + slot as u64,
            address.owner_tag(),
            recipient.rho(rho_base + slot as u64),
        )
        .expect("note");
        pi.output_commitments[slot] = note.commitment();
        *ct = Some(encrypt_note(address.kem_ek(), &note).expect("encrypt"));
    }
    SpendBundle {
        public_inputs: pi,
        proof_bytes: Vec::new(),
        output_ciphertexts: cts,
        auth_pk: [0u8; AUTH_PK_LEN],
        auth_sig: [0u8; AUTH_SIG_LEN],
    }
}
