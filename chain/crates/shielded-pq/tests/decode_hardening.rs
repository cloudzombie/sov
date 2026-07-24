//! S1c regression tests: TOTAL (panic-free) bundle/proof deserialization.
//!
//! Every adversarial input here must produce the SPECIFIC typed error
//! asserted — and, throughout, must NOT panic. The one place a panic is
//! expected is the `raw_winterfell_decode_panics_on_corrupt_option_header`
//! evidence test, which demonstrates (under `catch_unwind`) that the
//! upstream hazard of D15 is real and that the pre-validator is
//! load-bearing, not decorative.

use std::sync::OnceLock;

use sov_shielded_pq::air::{BundlePublicInputs, NUM_SLOTS};
use sov_shielded_pq::auth::AuthKeypair;
use sov_shielded_pq::bundle::{bundle_digest, verify_bundle, SpendBundle};
use sov_shielded_pq::encrypt::{encrypt_note, EncryptionKeypair, NoteCiphertext, KEM_CT_LEN};
use sov_shielded_pq::hash::PqDigest;
use sov_shielded_pq::note::{derive_rho, Note, SpendingKey};
use sov_shielded_pq::proof_frame::{
    expected_context_bytes, validate_proof_frame, ProofFrameError, MAX_PROOF_LEN,
};
use sov_shielded_pq::prover::{
    decode_proof, prove_bundle, verify_spend, BundleSpend, SpendProofError,
};
use sov_shielded_pq::tree::CommitmentTree;
use sov_shielded_pq::wire::{
    decode_bundle, decode_note_ciphertext, encode_bundle, encode_note_ciphertext, WireError,
    AEAD_CT_LEN, PROOF_VERSION_V1,
};

const SEED: [u8; 32] = [0x42; 32];

/// One shared proven fixture (proving is the expensive part): the encoded
/// KAT-shaped bundle (2 real inputs / 2 real outputs), its raw proof, its
/// public inputs, and the valid anchor.
struct Fixture {
    encoded: Vec<u8>,
    proof: Vec<u8>,
    pub_inputs: BundlePublicInputs,
    anchor: PqDigest,
}

fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let key = SpendingKey::from_seed(&SEED);
        let n0 = Note::new(1_250_000_000, key.owner_tag(), derive_rho(&SEED, 1)).expect("note");
        let n1 = Note::new(300_000_000, key.owner_tag(), derive_rho(&SEED, 3)).expect("note");
        let mut tree = CommitmentTree::new();
        tree.append(
            Note::new(1, key.owner_tag(), derive_rho(&SEED, 0))
                .expect("note")
                .commitment(),
        )
        .expect("append");
        tree.append(n0.commitment()).expect("append");
        tree.append(
            Note::new(2, key.owner_tag(), derive_rho(&SEED, 2))
                .expect("note")
                .commitment(),
        )
        .expect("append");
        tree.append(n1.commitment()).expect("append");
        let spends = vec![
            BundleSpend {
                key: key.clone(),
                note: n0,
                path: tree.witness(1).expect("witness").0,
            },
            BundleSpend {
                key: key.clone(),
                note: n1,
                path: tree.witness(3).expect("witness").0,
            },
        ];
        let fee = 1_000;
        let t_out = 50_000_000;
        let out_value = 400_000_000;
        let change = 1_250_000_000 + 300_000_000 - out_value - fee - t_out;
        let recipient = SpendingKey::from_seed(&[0x77; 32]);
        let outputs = vec![
            Note::new(out_value, recipient.owner_tag(), derive_rho(&[0x55; 32], 0)).expect("note"),
            Note::new(change, key.owner_tag(), derive_rho(&SEED, 100)).expect("note"),
        ];
        let (proof, pub_inputs) = prove_bundle(&spends, &outputs, 0, t_out, fee).expect("prove");
        let kem = EncryptionKeypair::generate().expect("keygen");
        let cts: [Option<NoteCiphertext>; NUM_SLOTS] = [
            Some(encrypt_note(&kem.public_bytes(), &outputs[0]).expect("encrypt")),
            Some(encrypt_note(&kem.public_bytes(), &outputs[1]).expect("encrypt")),
            None,
            None,
        ];
        let auth = AuthKeypair::from_seed(&SEED);
        let digest = bundle_digest(&pub_inputs, &cts, &auth.public_bytes());
        let bundle = SpendBundle {
            public_inputs: pub_inputs.clone(),
            proof_bytes: proof.clone(),
            output_ciphertexts: cts,
            auth_pk: auth.public_bytes(),
            auth_sig: auth.sign(&digest).expect("sign"),
        };
        Fixture {
            encoded: encode_bundle(&bundle),
            proof,
            pub_inputs,
            anchor: tree.root(),
        }
    })
}

/// Byte offset of the fixed public-input section after the version byte.
const PUBLICS_LEN: usize = 12 * 32 + 2 * NUM_SLOTS + 3 * 8;
/// Offset of the u32 proof length field in an encoded bundle.
const PROOF_LEN_OFFSET: usize = 1 + PUBLICS_LEN;

// --- The honest path must NOT be over-rejected. -------------------------

#[test]
fn honest_kat_proof_passes_frame_validation_and_verifies() {
    let f = fixture();
    validate_proof_frame(&f.proof, &f.pub_inputs).expect("honest frame validates");
    decode_proof(&f.proof, &f.pub_inputs).expect("honest proof decodes");
    verify_spend(&f.proof, &f.pub_inputs).expect("honest proof verifies");
}

#[test]
fn bundle_wire_roundtrip_end_to_end() {
    let f = fixture();
    let bundle = decode_bundle(&f.encoded).expect("decode");
    // Canonical: re-encoding reproduces the exact bytes.
    assert_eq!(
        encode_bundle(&bundle),
        f.encoded,
        "wire format is not canonical"
    );
    // The decoded bundle passes full semantic verification.
    verify_bundle(&bundle, &[f.anchor]).expect("decoded bundle verifies");
}

// --- D6: the proof_version gate. ----------------------------------------

#[test]
fn unknown_proof_version_typed_reject() {
    let f = fixture();
    let mut enc = f.encoded.clone();
    enc[0] = 2;
    assert_eq!(decode_bundle(&enc), Err(WireError::UnknownProofVersion(2)));
    enc[0] = 0;
    assert_eq!(decode_bundle(&enc), Err(WireError::UnknownProofVersion(0)));
    enc[0] = 0xFF;
    assert_eq!(
        decode_bundle(&enc),
        Err(WireError::UnknownProofVersion(0xFF))
    );
    assert_eq!(f.encoded[0], PROOF_VERSION_V1);
}

#[test]
fn zero_length_input_typed_reject() {
    assert_eq!(
        decode_bundle(&[]),
        Err(WireError::UnexpectedEnd("proof_version"))
    );
    assert!(matches!(
        decode_proof(&[], &fixture().pub_inputs),
        Err(SpendProofError::Frame(ProofFrameError::Truncated(
            "context"
        )))
    ));
    assert_eq!(
        decode_note_ciphertext(&[]),
        Err(WireError::UnexpectedEnd("kem_ct"))
    );
}

// --- The exact D15 hazard: corrupt winterfell option header. ------------

/// The serialized offset of the ProofOptions blowup-factor byte inside the
/// proof context: TraceInfo (6 bytes for this circuit: width, aux width,
/// aux rands, log2 length, u16 meta length) + modulus (1 length byte + 8
/// bytes) + 1 (num_queries byte precedes blowup).
fn blowup_byte_offset(pub_inputs: &BundlePublicInputs) -> usize {
    // Locate it robustly: the context bytes are canonical, so scan for the
    // options run [42, 8, 16] (num_queries, blowup, grinding) which occurs
    // exactly once in the short context prefix.
    let ctx = expected_context_bytes(pub_inputs);
    let pos = ctx
        .windows(3)
        .position(|w| w == [42, 8, 16])
        .expect("standard options bytes present in context");
    pos + 1
}

#[test]
fn raw_winterfell_decode_panics_on_corrupt_option_header() {
    // EVIDENCE test: the upstream hazard is real. A one-byte corruption of
    // the option header (blowup factor 8 -> 3, not a power of two) makes
    // raw `Proof::from_bytes` PANIC (`ProofOptions::new` assert). This is
    // the exact case S1 flagged, and why the pre-validator exists.
    let f = fixture();
    let mut corrupt = f.proof.clone();
    let off = blowup_byte_offset(&f.pub_inputs);
    assert_eq!(corrupt[off], 8, "blowup byte located");
    corrupt[off] = 3;
    let raw = std::panic::catch_unwind(|| winterfell::Proof::from_bytes(&corrupt));
    assert!(
        raw.is_err(),
        "expected raw winterfell decode to panic on corrupt option header; \
         if this stops panicking upstream, update the module docs in proof_frame.rs"
    );
}

#[test]
fn corrupt_option_header_is_a_typed_error_through_the_decoder() {
    // The same corrupt input through OUR decoder: clean typed reject, no
    // panic (this test fails by crashing if the pre-validator misses it).
    let f = fixture();
    let mut corrupt = f.proof.clone();
    let off = blowup_byte_offset(&f.pub_inputs);
    corrupt[off] = 3;
    assert!(matches!(
        decode_proof(&corrupt, &f.pub_inputs),
        Err(SpendProofError::Frame(ProofFrameError::ContextMismatch))
    ));
    // And through the bundle path: the embedded proof is frame-validated.
    let mut enc = fixture().encoded.clone();
    enc[PROOF_LEN_OFFSET + 4 + off] = 3;
    assert_eq!(
        decode_bundle(&enc),
        Err(WireError::ProofFrame(ProofFrameError::ContextMismatch))
    );
}

#[test]
fn every_corrupt_context_byte_is_a_typed_reject() {
    // Flip EVERY byte of the context prefix (framing bytes) one at a time:
    // always ContextMismatch, never a panic. Covers the TraceInfo
    // 2^255-overflow and partition-assert paths as well.
    let f = fixture();
    let ctx_len = expected_context_bytes(&f.pub_inputs).len();
    for i in 0..ctx_len {
        let mut corrupt = f.proof.clone();
        corrupt[i] ^= 0xFF;
        assert!(
            matches!(
                decode_proof(&corrupt, &f.pub_inputs),
                Err(SpendProofError::Frame(ProofFrameError::ContextMismatch))
            ),
            "context byte {i}: expected ContextMismatch"
        );
    }
}

// --- Truncation / oversize / huge-length-prefix. ------------------------

#[test]
fn truncated_proof_typed_reject() {
    let f = fixture();
    // Every truncation length must give a typed frame error (and the
    // specific section errors at a few pinned points).
    for cut in [0, 1, 10, f.proof.len() / 2, f.proof.len() - 1] {
        assert!(
            matches!(
                decode_proof(&f.proof[..cut], &f.pub_inputs),
                Err(SpendProofError::Frame(_))
            ),
            "truncation at {cut}: expected a typed frame error"
        );
    }
    let ctx_len = expected_context_bytes(&f.pub_inputs).len();
    assert!(matches!(
        decode_proof(&f.proof[..ctx_len], &f.pub_inputs),
        Err(SpendProofError::Frame(ProofFrameError::Truncated(
            "num_unique_queries"
        )))
    ));
}

#[test]
fn oversized_proof_typed_reject() {
    let f = fixture();
    let mut huge = f.proof.clone();
    huge.resize(MAX_PROOF_LEN + 1, 0);
    assert!(matches!(
        decode_proof(&huge, &f.pub_inputs),
        Err(SpendProofError::Frame(ProofFrameError::TooLong(len))) if len == MAX_PROOF_LEN + 1
    ));
}

#[test]
fn huge_declared_length_prefixes_typed_reject() {
    let f = fixture();
    let ctx = expected_context_bytes(&f.pub_inputs);

    // u16::MAX commitments length with nothing behind it.
    let mut input = ctx.clone();
    input.push(1); // num_unique_queries
    input.extend_from_slice(&u16::MAX.to_le_bytes());
    assert!(matches!(
        decode_proof(&input, &f.pub_inputs),
        Err(SpendProofError::Frame(ProofFrameError::LengthOverrun {
            section: "commitments",
            declared: 65535,
            ..
        }))
    ));

    // A 9-byte vint declaring u64::MAX bytes of trace query values: the
    // exact `Vec::with_capacity` abort path in winterfell, now typed.
    let mut input = ctx.clone();
    input.push(1); // num_unique_queries
    input.extend_from_slice(&0u16.to_le_bytes()); // empty commitments
    input.push(0x00); // vint marker: 9-byte encoding
    input.extend_from_slice(&u64::MAX.to_le_bytes());
    assert!(matches!(
        decode_proof(&input, &f.pub_inputs),
        Err(SpendProofError::Frame(ProofFrameError::LengthOverrun {
            section: "trace query values",
            declared: u64::MAX,
            ..
        }))
    ));

    // Bundle path: a u32 proof length above the cap.
    let mut enc = f.encoded.clone();
    enc[PROOF_LEN_OFFSET..PROOF_LEN_OFFSET + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(decode_bundle(&enc), Err(WireError::ProofLength(u32::MAX)));
    // And a zero proof length.
    enc[PROOF_LEN_OFFSET..PROOF_LEN_OFFSET + 4].copy_from_slice(&0u32.to_le_bytes());
    assert_eq!(decode_bundle(&enc), Err(WireError::ProofLength(0)));
}

#[test]
fn zero_unique_queries_typed_reject() {
    let f = fixture();
    let ctx_len = expected_context_bytes(&f.pub_inputs).len();
    let mut corrupt = f.proof.clone();
    corrupt[ctx_len] = 0;
    assert!(matches!(
        decode_proof(&corrupt, &f.pub_inputs),
        Err(SpendProofError::Frame(ProofFrameError::QueryCount(0, 42)))
    ));
    corrupt[ctx_len] = 43;
    assert!(matches!(
        decode_proof(&corrupt, &f.pub_inputs),
        Err(SpendProofError::Frame(ProofFrameError::QueryCount(43, 42)))
    ));
}

#[test]
fn trailing_bytes_typed_reject() {
    let f = fixture();
    let mut padded = f.proof.clone();
    padded.push(0);
    assert!(matches!(
        decode_proof(&padded, &f.pub_inputs),
        Err(SpendProofError::Frame(ProofFrameError::TrailingBytes(1)))
    ));
    let mut enc = f.encoded.clone();
    enc.push(0);
    assert_eq!(decode_bundle(&enc), Err(WireError::TrailingBytes(1)));
}

// --- Bundle framing corruption. -----------------------------------------

#[test]
fn flag_and_digest_corruption_typed_reject() {
    let f = fixture();
    // input_dummy flag byte -> 2 (flags sit after version + 8 digests).
    let flag_off = 1 + 8 * 32;
    let mut enc = f.encoded.clone();
    assert!(enc[flag_off] <= 1, "flag byte located");
    enc[flag_off] = 2;
    assert_eq!(
        decode_bundle(&enc),
        Err(WireError::InvalidFlag {
            field: "input_dummy",
            value: 2
        })
    );
    // Non-canonical digest: an anchor of all 0xFF exceeds the f64 modulus.
    let mut enc = f.encoded.clone();
    enc[1..33].fill(0xFF);
    assert_eq!(
        decode_bundle(&enc),
        Err(WireError::NonCanonicalDigest("anchor"))
    );
}

#[test]
fn ciphertext_length_field_typed_reject() {
    let f = fixture();
    // First ciphertext slot: presence flag right after the proof bytes.
    let ct_flag_off = PROOF_LEN_OFFSET + 4 + f.proof.len();
    assert_eq!(f.encoded[ct_flag_off], 1, "slot 0 carries a ciphertext");
    let aead_len_off = ct_flag_off + 1 + KEM_CT_LEN + 4;
    let mut enc = f.encoded.clone();
    enc[aead_len_off..aead_len_off + 2].copy_from_slice(&(AEAD_CT_LEN as u16 + 1).to_le_bytes());
    assert_eq!(
        decode_bundle(&enc),
        Err(WireError::CiphertextLength(AEAD_CT_LEN as u16 + 1))
    );
}

// --- Deterministic wire KATs (new in S1c — no prior digest to re-pin:
// --- the bundle had NO wire format before this slice). -------------------

#[test]
fn wire_kat_publics_header_pinned() {
    // The version byte + public-input section of the KAT bundle is fully
    // deterministic: pin it. Any wire-layout or KAT drift screams here.
    let f = fixture();
    let header = &f.encoded[..1 + PUBLICS_LEN];
    assert_eq!(
        hex::encode(blake3::hash(header).as_bytes()),
        "cb6562850769c8df761d2d73781c5179a442e8b723981ac1659da4546c697b1d",
        "v1 wire publics-header KAT drifted"
    );
}

#[test]
fn context_bytes_kat_pinned() {
    // The canonical proof context for the KAT dummy pattern (2 real / 2
    // dummy on both sides), pinned byte-for-byte. This is the exact-match
    // prefix the pre-validator enforces.
    let f = fixture();
    let ctx = expected_context_bytes(&f.pub_inputs);
    assert_eq!(
        hex::encode(&ctx),
        "1f00000a00000801000000ffffffff2a081002041f00000101b602",
        "canonical context KAT drifted"
    );
    // And it must literally prefix the honest proof.
    assert_eq!(&f.proof[..ctx.len()], &ctx[..], "context prefix mismatch");
}

#[test]
fn note_ciphertext_wire_kat_roundtrip() {
    // Synthetic, fully deterministic ciphertext: pin the encoding.
    let ct = NoteCiphertext {
        kem_ct: [0xA5; KEM_CT_LEN],
        detection_tag: [1, 2, 3, 4],
        aead_ct: vec![0x5A; AEAD_CT_LEN],
    };
    let enc = encode_note_ciphertext(&ct);
    assert_eq!(enc.len(), KEM_CT_LEN + 4 + 2 + AEAD_CT_LEN);
    assert_eq!(
        hex::encode(blake3::hash(&enc).as_bytes()),
        "a004000c7eb20dffc9dd082fbbb49f9841e8ab88008e9a3a00d1cc58d9a4b28a",
        "v1 note-ciphertext wire KAT drifted"
    );
    assert_eq!(decode_note_ciphertext(&enc), Ok(ct));
    // Truncated: typed reject.
    assert_eq!(
        decode_note_ciphertext(&enc[..enc.len() - 1]),
        Err(WireError::UnexpectedEnd("aead_ct"))
    );
}

// --- Structured-random hammer (CI-resident fallback fuzzer). ------------
//
// The committed `fuzz/` sub-crate runs the same decoders under libFuzzer
// with coverage guidance; THIS test keeps a smaller deterministic version
// permanently in `cargo test` so a decode panic can never land unnoticed
// even where nightly/cargo-fuzz is unavailable.

/// Regenerate the committed seed corpus for the `fuzz/` sub-crate. Run
/// manually (`cargo test -p sov-shielded-pq --release generate_fuzz_corpus
/// -- --ignored`) after any wire-format change, and commit the output.
#[test]
#[ignore = "writes the fuzz seed corpus; run explicitly after wire changes"]
fn generate_fuzz_corpus() {
    use std::fs;
    use std::path::Path;
    let f = fixture();
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/corpus");

    let write = |target: &str, name: &str, data: &[u8]| {
        let dir = root.join(target);
        fs::create_dir_all(&dir).expect("mkdir");
        fs::write(dir.join(name), data).expect("write seed");
    };

    // fuzz_bundle_decode: the valid encoding + hand-crafted malformations.
    write("fuzz_bundle_decode", "valid_kat_bundle.bin", &f.encoded);
    write(
        "fuzz_bundle_decode",
        "truncated_mid_proof.bin",
        &f.encoded[..PROOF_LEN_OFFSET + 4 + f.proof.len() / 2],
    );
    let mut v2 = f.encoded.clone();
    v2[0] = 2;
    write("fuzz_bundle_decode", "unknown_version.bin", &v2);
    let mut huge = f.encoded.clone();
    huge[PROOF_LEN_OFFSET..PROOF_LEN_OFFSET + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    write("fuzz_bundle_decode", "huge_proof_len.bin", &huge);
    write("fuzz_bundle_decode", "empty.bin", &[]);

    // fuzz_proof_decode: [dummy-flag selector byte] ++ proof candidate.
    // The KAT dummy pattern (inputs+outputs 2 real / 2 dummy) = 0xCC.
    let sel = 0xCCu8;
    let with_sel = |proof: &[u8]| {
        let mut out = vec![sel];
        out.extend_from_slice(proof);
        out
    };
    write(
        "fuzz_proof_decode",
        "valid_kat_proof.bin",
        &with_sel(&f.proof),
    );
    write(
        "fuzz_proof_decode",
        "truncated.bin",
        &with_sel(&f.proof[..f.proof.len() / 3]),
    );
    let mut corrupt = f.proof.clone();
    corrupt[blowup_byte_offset(&f.pub_inputs)] = 3;
    write(
        "fuzz_proof_decode",
        "corrupt_option_header.bin",
        &with_sel(&corrupt),
    );
    let mut huge_vint = expected_context_bytes(&f.pub_inputs);
    huge_vint.push(1);
    huge_vint.extend_from_slice(&0u16.to_le_bytes());
    huge_vint.push(0x00);
    huge_vint.extend_from_slice(&u64::MAX.to_le_bytes());
    write(
        "fuzz_proof_decode",
        "huge_vint_length.bin",
        &with_sel(&huge_vint),
    );

    // fuzz_note_ciphertext_decode.
    let ct = NoteCiphertext {
        kem_ct: [0xA5; KEM_CT_LEN],
        detection_tag: [1, 2, 3, 4],
        aead_ct: vec![0x5A; AEAD_CT_LEN],
    };
    let enc = encode_note_ciphertext(&ct);
    write("fuzz_note_ciphertext_decode", "valid_ciphertext.bin", &enc);
    write(
        "fuzz_note_ciphertext_decode",
        "truncated.bin",
        &enc[..enc.len() - 40],
    );
}

struct XorShift(u64);
impl XorShift {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
}

fn assert_no_panic(what: &str, input: &[u8], pub_inputs: &BundlePublicInputs) {
    let bundle_res = std::panic::catch_unwind(|| {
        let _ = decode_bundle(input);
    });
    assert!(bundle_res.is_ok(), "{what}: decode_bundle panicked");
    let proof_res = std::panic::catch_unwind(|| {
        matches!(
            decode_proof(input, pub_inputs),
            Err(SpendProofError::DecodePanic)
        )
    });
    match proof_res {
        Ok(hit_last_line_of_defense) => assert!(
            !hit_last_line_of_defense,
            "{what}: pre-validated input panicked inside winterfell (caught by catch_unwind) — \
             the pre-validator has a gap"
        ),
        Err(_) => panic!("{what}: decode_proof panicked"),
    }
    let ct_res = std::panic::catch_unwind(|| {
        let _ = decode_note_ciphertext(input);
    });
    assert!(ct_res.is_ok(), "{what}: decode_note_ciphertext panicked");
}

#[test]
fn random_and_mutated_inputs_never_panic() {
    let f = fixture();
    let mut rng = XorShift(0x5EED_CAFE_F00D_D15C);

    // Pure-random inputs across a spread of lengths.
    for i in 0..4_000 {
        let len = (rng.next() % 2_048) as usize;
        let mut input = vec![0u8; len];
        for b in &mut input {
            *b = rng.next() as u8;
        }
        // Bias some toward the valid version byte so decoding goes deep.
        if !input.is_empty() && i % 2 == 0 {
            input[0] = PROOF_VERSION_V1;
        }
        assert_no_panic("random", &input, &f.pub_inputs);
    }

    // Mutations of the two valid encodings (bundle + raw proof): flips,
    // truncations, extensions, and length-field splices.
    for base in [&f.encoded, &f.proof] {
        for _ in 0..2_000 {
            let mut input = base.clone();
            match rng.next() % 4 {
                0 => {
                    let i = (rng.next() as usize) % input.len();
                    input[i] ^= (rng.next() as u8) | 1;
                }
                1 => {
                    let cut = (rng.next() as usize) % input.len();
                    input.truncate(cut);
                }
                2 => {
                    let extra = (rng.next() % 64) as usize + 1;
                    for _ in 0..extra {
                        input.push(rng.next() as u8);
                    }
                }
                _ => {
                    // Splice random bytes over a random 4-byte window
                    // (hits the length fields often).
                    let i = (rng.next() as usize) % input.len().saturating_sub(4).max(1);
                    for k in 0..4.min(input.len() - i) {
                        input[i + k] = rng.next() as u8;
                    }
                }
            }
            assert_no_panic("mutated", &input, &f.pub_inputs);
        }
    }
}
