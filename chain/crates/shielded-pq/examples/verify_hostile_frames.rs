//! Release-profile corpus for the real suite-2 verifier with `panic = abort`.
//!
//! Run from the repository root:
//! `cargo run --release --locked --offline --manifest-path chain/Cargo.toml
//! -p sov-shielded-pq --features zk-suite2 --example verify_hostile_frames`
//! All notes and keys below are disposable fixtures, never production data.

#[cfg(not(feature = "zk-suite2"))]
fn main() {
    eprintln!("enable --features zk-suite2 to run the release verifier corpus");
    std::process::exit(2);
}

#[cfg(feature = "zk-suite2")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    harness::run()
}

#[cfg(feature = "zk-suite2")]
mod harness {
    use p3_field::{extension::BinomialExtensionField, PrimeCharacteristicRing};
    use p3_goldilocks::Goldilocks;
    use serde::{Deserialize, Serialize};
    use sov_shielded_pq::note::{derive_rho, Note, SpendingKey};
    use sov_shielded_pq::prover::BundleSpend;
    use sov_shielded_pq::tree::CommitmentTree;
    use sov_shielded_pq::zk_suite2::{self, Suite2Context, Suite2Spend};
    use sov_shielded_pq::{BundlePublicInputs, PqShieldedKey};
    use std::error::Error;
    use std::time::{Duration, Instant};

    type Val = Goldilocks;
    type Challenge = BinomialExtensionField<Val, 5>;
    type Digest = [u64; 6];
    type MmcsProof = (Vec<Vec<Vec<Val>>>, RawPrunedPaths);
    type RandomOpenings = Vec<Vec<Vec<Vec<Challenge>>>>;
    type Mutation = (&'static str, fn(&mut RawProof));

    // These are codec-only mirrors of Plonky3 0.8.0's serialized structures.
    // Deserialization is applied only to OUR valid prover-generated fixture.
    // Re-encoding must match it byte for byte before any hostile cases run.
    // Raw caps permit malformed sizes that upstream checked constructors deny.
    #[derive(Clone, Serialize, Deserialize)]
    struct RawCap {
        cap: Vec<Digest>,
    }

    #[derive(Clone, Serialize, Deserialize)]
    struct RawPrunedPaths {
        sibling_hashes: Vec<Digest>,
    }

    #[derive(Clone, Serialize, Deserialize)]
    struct RawCommitments {
        trace: RawCap,
        quotient_chunks: RawCap,
        random: Option<RawCap>,
    }

    #[derive(Clone, Serialize, Deserialize)]
    struct RawOpenings {
        trace_local: Vec<Challenge>,
        trace_next: Option<Vec<Challenge>>,
        preprocessed_local: Option<Vec<Challenge>>,
        preprocessed_next: Option<Vec<Challenge>>,
        quotient_chunks: Vec<Vec<Challenge>>,
        random: Option<Vec<Challenge>>,
    }

    #[derive(Clone, Serialize, Deserialize)]
    struct RawBatchOpening {
        opened_values: Vec<Vec<Vec<Val>>>,
        opening_proof: MmcsProof,
    }

    #[derive(Clone, Serialize, Deserialize)]
    struct RawCommitPhaseOpening {
        sibling_values: Vec<Vec<Challenge>>,
        opening_proof: MmcsProof,
    }

    #[derive(Clone, Serialize, Deserialize)]
    struct RawFriProof {
        batch_pow_witness: Val,
        commit_phase_commits: Vec<RawCap>,
        commit_pow_witnesses: Vec<Val>,
        input_openings: Vec<RawBatchOpening>,
        commit_phase_openings: Vec<RawCommitPhaseOpening>,
        final_poly: Vec<Challenge>,
        query_pow_witness: Val,
    }

    #[derive(Clone, Serialize, Deserialize)]
    struct RawProof {
        commitments: RawCommitments,
        opened_values: RawOpenings,
        opening_proof: (RandomOpenings, RawFriProof),
        degree_bits: usize,
        ood_pow_witness: Val,
    }

    struct Corpus<'a> {
        public_inputs: &'a BundlePublicInputs,
        context: Suite2Context<'a>,
        rejected: usize,
        decoded_rejections: usize,
    }

    impl Corpus<'_> {
        fn reject(&mut self, name: &str, bytes: &[u8]) -> Result<(), Box<dyn Error>> {
            // No catch_unwind: an upstream panic under the release abort profile
            // terminates this process and makes the shell command fail.
            let decoded = zk_suite2::validate_proof_frame(bytes).is_ok();
            if zk_suite2::verify_spend(bytes, self.public_inputs, &self.context).is_ok() {
                return Err(format!("hostile frame unexpectedly verified: {name}").into());
            }
            self.rejected += 1;
            self.decoded_rejections += usize::from(decoded);
            println!("reject {:03}: {name}", self.rejected);
            Ok(())
        }
    }

    fn frame(body: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(12 + body.len());
        bytes.extend_from_slice(b"SOVPQZK2");
        bytes.extend_from_slice(&zk_suite2::PARAMETER_ID.to_le_bytes());
        bytes.extend_from_slice(body);
        bytes
    }

    fn fixture() -> Result<Vec<Suite2Spend>, Box<dyn Error>> {
        let seed = [0x42; 32];
        let key = SpendingKey::from_seed(&seed);
        let first = Note::new(5_000, key.owner_tag(), derive_rho(&[0x41; 32], 0))
            .ok_or("first fixture note")?;
        let second = Note::new(4_000, key.owner_tag(), derive_rho(&[0x41; 32], 1))
            .ok_or("second fixture note")?;
        let mut tree = CommitmentTree::new();
        tree.append(first.commitment())
            .ok_or("first fixture append")?;
        tree.append(second.commitment())
            .ok_or("second fixture append")?;
        tree.mark().ok_or("fixture anchor")?;
        let mut spends = Vec::new();
        for (position, note) in [(0, first), (1, second)] {
            spends.push(Suite2Spend::new(
                BundleSpend {
                    key: key.clone(),
                    note,
                    path: tree.witness(position).ok_or("fixture witness")?.0,
                },
                &seed,
            )?);
        }
        Ok(spends)
    }

    fn mutations() -> Vec<Mutation> {
        vec![
            ("empty trace cap", |p| p.commitments.trace.cap.clear()),
            ("three-root trace cap", |p| {
                p.commitments.trace.cap.resize(3, [0; 6])
            }),
            ("changed trace commitment", |p| {
                p.commitments.trace.cap[0][0] ^= 1
            }),
            ("changed quotient commitment", |p| {
                p.commitments.quotient_chunks.cap[0][0] ^= 1
            }),
            ("absent random commitment", |p| p.commitments.random = None),
            ("empty OOD local row", |p| {
                p.opened_values.trace_local.clear()
            }),
            ("short OOD local row", |p| {
                p.opened_values.trace_local.pop();
            }),
            ("long OOD local row", |p| {
                p.opened_values.trace_local.push(Challenge::ZERO)
            }),
            ("changed OOD local evaluation", |p| {
                p.opened_values.trace_local[0] += Challenge::ONE
            }),
            ("absent OOD next row", |p| p.opened_values.trace_next = None),
            ("short OOD next row", |p| {
                p.opened_values.trace_next.as_mut().unwrap().pop();
            }),
            ("unproved preprocessing", |p| {
                p.opened_values.preprocessed_local = Some(vec![Challenge::ZERO])
            }),
            ("preprocessing next without local", |p| {
                p.opened_values.preprocessed_next = Some(vec![Challenge::ZERO])
            }),
            ("empty quotient chunks", |p| {
                p.opened_values.quotient_chunks.clear()
            }),
            ("65 quotient chunks", |p| {
                p.opened_values
                    .quotient_chunks
                    .resize(65, vec![Challenge::ZERO; 5])
            }),
            ("short quotient chunk", |p| {
                p.opened_values.quotient_chunks[0].pop();
            }),
            ("absent OOD random opening", |p| {
                p.opened_values.random = None
            }),
            ("wrong OOD random width", |p| {
                p.opened_values.random = Some(vec![Challenge::ZERO; 4])
            }),
            ("absent hiding random openings", |p| {
                p.opening_proof.0.clear()
            }),
            ("wrong hiding round count", |p| {
                p.opening_proof.0.push(Vec::new())
            }),
            ("wrong hiding matrix count", |p| {
                p.opening_proof.0[0].clear()
            }),
            ("wrong hiding opening count", |p| {
                p.opening_proof.0[0][0].clear()
            }),
            ("wrong hiding codeword width", |p| {
                p.opening_proof.0[0][0][0].clear()
            }),
            ("absent FRI commits", |p| {
                p.opening_proof.1.commit_phase_commits.clear()
            }),
            ("extra FRI commit", |p| {
                let x = p.opening_proof.1.commit_phase_commits[0].clone();
                p.opening_proof.1.commit_phase_commits.push(x);
            }),
            ("absent FRI commit grinding witnesses", |p| {
                p.opening_proof.1.commit_pow_witnesses.clear()
            }),
            ("extra FRI commit grinding witness", |p| {
                p.opening_proof.1.commit_pow_witnesses.push(Val::ZERO)
            }),
            ("absent input batches", |p| {
                p.opening_proof.1.input_openings.clear()
            }),
            ("extra input batch", |p| {
                let x = p.opening_proof.1.input_openings[0].clone();
                p.opening_proof.1.input_openings.push(x);
            }),
            ("absent input query rows", |p| {
                p.opening_proof.1.input_openings[0].opened_values.clear()
            }),
            ("empty queried matrix row", |p| {
                p.opening_proof.1.input_openings[0].opened_values[0][0].clear()
            }),
            ("missing input salts", |p| {
                p.opening_proof.1.input_openings[0].opening_proof.0.clear()
            }),
            ("missing input query matrix salts", |p| {
                p.opening_proof.1.input_openings[0].opening_proof.0[0].clear()
            }),
            ("wrong input salt width", |p| {
                p.opening_proof.1.input_openings[0].opening_proof.0[0][0].clear()
            }),
            ("missing input authentication frontier", |p| {
                p.opening_proof.1.input_openings[0]
                    .opening_proof
                    .1
                    .sibling_hashes
                    .clear()
            }),
            ("absent FRI phase openings", |p| {
                p.opening_proof.1.commit_phase_openings.clear()
            }),
            ("empty FRI sibling evaluations", |p| {
                p.opening_proof.1.commit_phase_openings[0]
                    .sibling_values
                    .clear()
            }),
            ("wrong FRI sibling arity", |p| {
                p.opening_proof.1.commit_phase_openings[0].sibling_values[0].clear()
            }),
            ("missing FRI phase salts", |p| {
                p.opening_proof.1.commit_phase_openings[0]
                    .opening_proof
                    .0
                    .clear()
            }),
            ("missing FRI authentication frontier", |p| {
                p.opening_proof.1.commit_phase_openings[0]
                    .opening_proof
                    .1
                    .sibling_hashes
                    .clear()
            }),
            ("empty FRI final polynomial", |p| {
                p.opening_proof.1.final_poly.clear()
            }),
            ("oversized FRI final polynomial", |p| {
                p.opening_proof.1.final_poly.resize(129, Challenge::ZERO)
            }),
            ("zero degree bits", |p| p.degree_bits = 0),
            ("degree usize max", |p| p.degree_bits = usize::MAX),
        ]
    }

    pub fn run() -> Result<(), Box<dyn Error>> {
        if !cfg!(panic = "abort") {
            return Err("this corpus must run with the release panic=abort profile".into());
        }
        println!(
            "panic strategy: abort; suite: {}; profile: {}",
            zk_suite2::PROOF_SUITE,
            zk_suite2::PARAMETER_ID
        );
        let auth = PqShieldedKey::from_leaf_seed_suite2(&[0x45; 32]);
        let auth_pk = auth.auth_key().public_bytes();
        let context = Suite2Context {
            chain_id: b"sov-pq-suite2-hostile-corpus",
            genesis: &[0xAA; 32],
            signer: b"fixture.owner.sov",
            nonce: 7,
            auth_pk: &auth_pk,
        };
        let spends = fixture()?;
        println!("creating original-seed proof for two existing-format notes");
        let prove_start = Instant::now();
        let (good, public_inputs) = zk_suite2::prove_bundle(&spends, &[], 0, 8_900, 100, &context)?;
        println!(
            "valid proof: {} bytes; proving: {:.3}s",
            good.len(),
            prove_start.elapsed().as_secs_f64()
        );
        let mut verify_times: Vec<Duration> = Vec::with_capacity(11);
        for _ in 0..11 {
            let start = Instant::now();
            zk_suite2::verify_spend(&good, &public_inputs, &context)?;
            verify_times.push(start.elapsed());
        }
        verify_times.sort_unstable();
        println!(
            "valid verification: 11/11; median {:.3}ms; max {:.3}ms",
            verify_times[5].as_secs_f64() * 1_000.0,
            verify_times[10].as_secs_f64() * 1_000.0
        );
        let original: RawProof = postcard::from_bytes(&good[12..])?;
        if postcard::to_allocvec(&original)? != good[12..] {
            return Err("codec mirror did not round-trip the valid fixture exactly".into());
        }
        let mut corpus = Corpus {
            public_inputs: &public_inputs,
            context,
            rejected: 0,
            decoded_rejections: 0,
        };

        for size in 0..64 {
            corpus.reject(&format!("short frame {size}"), &vec![0; size])?;
        }
        for length in [
            0,
            1,
            11,
            12,
            13,
            20,
            64,
            127,
            512,
            4_096,
            good.len() / 4,
            good.len() / 2,
            good.len() * 3 / 4,
            good.len() - 64,
            good.len() - 1,
        ] {
            corpus.reject(
                &format!("valid-prefix truncation {length}"),
                &good[..length],
            )?;
        }
        for profile in [0u32, 1, 3, u32::MAX] {
            let mut bytes = good.clone();
            bytes[8..12].copy_from_slice(&profile.to_le_bytes());
            corpus.reject(&format!("wrong parameter profile {profile}"), &bytes)?;
        }
        let mut wrong_magic = good.clone();
        wrong_magic[0] ^= 1;
        corpus.reject("wrong magic", &wrong_magic)?;
        let mut trailing = good.clone();
        trailing.push(0);
        corpus.reject("valid proof plus trailing byte", &trailing)?;
        corpus.reject(
            "byte cap exceeded",
            &vec![0; zk_suite2::MAX_CANDIDATE_PROOF_BYTES + 1],
        )?;

        let huge = postcard::to_allocvec(&usize::MAX)?;
        corpus.reject("top cap huge length varint", &frame(&huge))?;
        let mut huge_cap = huge.clone();
        huge_cap.resize(huge_cap.len() + 16_385 * 6, 0);
        corpus.reject(
            "top cap huge length with actual zero roots",
            &frame(&huge_cap),
        )?;
        // Reach the four-level random-opening vector after valid commitments
        // and OOD openings. Empty children use one byte, so a length hint can
        // disappear while actual elements still exceed the per-sequence cap.
        let prefix = postcard::to_allocvec(&(&original.commitments, &original.opened_values))?;
        for declared in [16_385usize, 16_386, usize::MAX] {
            let mut body = prefix.clone();
            body.push(1); // one random-opening round
            body.extend(postcard::to_allocvec(&declared)?); // matrix count
            body.resize(body.len() + 16_385, 0); // empty opening vectors
            corpus.reject(
                &format!("nested empty-vector count {declared}"),
                &frame(&body),
            )?;
        }
        for count in [1usize, 8, 16, 32] {
            let mut body = prefix.clone();
            for _ in 0..count {
                body.extend_from_slice(&huge);
            }
            corpus.reject(
                &format!("nested repeated huge varint {count}"),
                &frame(&body),
            )?;
        }

        for (name, mutate) in mutations() {
            let mut bad = original.clone();
            mutate(&mut bad);
            corpus.reject(name, &frame(&postcard::to_allocvec(&bad)?))?;
        }
        for bit in 0..8 {
            let mut bad = original.clone();
            bad.commitments.trace.cap[0][0] ^= 1u64 << bit;
            corpus.reject(
                &format!("commitment bit tamper {bit}"),
                &frame(&postcard::to_allocvec(&bad)?),
            )?;
        }
        let mut random = 0x5729_6341_B1ED_942Au64;
        for size in [16usize, 32, 64, 128, 256, 512, 1_024, 2_048, 4_096] {
            let mut body = Vec::with_capacity(size);
            for _ in 0..size {
                random ^= random << 13;
                random ^= random >> 7;
                random ^= random << 17;
                body.push(random as u8);
            }
            corpus.reject(&format!("deterministic random body {size}"), &frame(&body))?;
        }
        if corpus.decoded_rejections == 0 {
            return Err(
                "corpus never reached the cryptographic verifier with a canonical frame".into(),
            );
        }
        println!("PASS: 11 valid verifications; {} hostile frames rejected; {} canonical malformed/tampered frames reached verifier; no abort", corpus.rejected, corpus.decoded_rejections);
        Ok(())
    }
}
