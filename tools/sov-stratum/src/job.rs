//! The job layer: parsing a `sov_getBlockTemplate` result into a [`Template`],
//! the blob ⇄ nonce mapping, and seal recomputation via the REAL `pow_seal`.
//!
//! The template's `blob` is the exact Borsh `BlockHeader` preimage the importer
//! hashes; the nonce is its **trailing little-endian u64** at `nonceOffset`
//! (`= blob.len() − 8`). A miner mutates only those 8 bytes, so splicing a
//! candidate nonce in place is byte-identical to re-encoding the header with
//! that nonce — proven by `splice_equals_borsh_reencode` below (the bridge-side
//! twin of the node-side Phase-1 round-trip test).

use serde_json::Value;
use sov_pow::{pow_seal, pow_seal_mining, PowAlgo};

/// One block template fetched from the node — everything the bridge needs to
/// issue Stratum jobs against it and to verify + forward submissions.
#[derive(Clone, Debug)]
pub struct Template {
    /// The node-side cache key for `sov_submitBlock` (hash of the unsealed header).
    pub template_id: String,
    /// Height this template mines (tip + 1).
    pub height: u64,
    /// Parent hash — the tip-change detector between polls.
    pub prev_hash: String,
    /// The Borsh header preimage at nonce 0: the exact bytes `pow_seal` hashes.
    pub blob: Vec<u8>,
    /// Byte offset of the trailing little-endian u64 nonce (`blob.len() − 8`).
    pub nonce_offset: usize,
    /// The full 256-bit network target (big-endian threshold; `seal <= target` wins).
    pub network_target: [u8; 32],
    /// The seal algorithm (RandomX on mainnet, Sha256d on dev/test chains).
    pub algo: PowAlgo,
    /// The RandomX key/seed bytes (the genesis hash — constant for SOV, so
    /// miners build their dataset once). Ignored by Sha256d.
    pub pow_key: Vec<u8>,
    /// `pow_key` as hex — the Stratum job's `seed_hash` field, verbatim.
    pub seed_hash: String,
    /// The timestamp baked into `blob`. Frozen per job and passed through to
    /// `sov_submitBlock` so the node reconstructs the identical preimage.
    pub timestamp_ms: u64,
}

impl Template {
    /// Parse the documented `sov_getBlockTemplate` result. Every field the
    /// bridge relies on is validated here so a malformed or drifted node
    /// response fails loudly at the poll, never silently at a submit.
    pub fn from_rpc(v: &Value) -> Result<Template, String> {
        let str_field = |k: &str| -> Result<String, String> {
            v.get(k)
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| format!("template missing string field `{k}`"))
        };
        let u64_field = |k: &str| -> Result<u64, String> {
            v.get(k)
                .and_then(Value::as_u64)
                .ok_or_else(|| format!("template missing numeric field `{k}`"))
        };
        let template_id = str_field("templateId")?;
        let height = u64_field("height")?;
        let prev_hash = str_field("prevHash")?;
        let blob = hex::decode(str_field("blob")?)
            .map_err(|e| format!("template `blob` is not hex: {e}"))?;
        let nonce_offset = u64_field("nonceOffset")? as usize;
        // The nonce is the header's trailing u64 — anything else means the node
        // and bridge disagree on the header layout; refuse to hand out the job.
        if blob.len() < 8 || nonce_offset != blob.len() - 8 {
            return Err(format!(
                "template nonceOffset {} inconsistent with blob length {} (expected len − 8)",
                nonce_offset,
                blob.len()
            ));
        }
        let target_hex = str_field("target")?;
        let target_bytes =
            hex::decode(&target_hex).map_err(|e| format!("template `target` is not hex: {e}"))?;
        let network_target: [u8; 32] = target_bytes
            .as_slice()
            .try_into()
            .map_err(|_| format!("template `target` is {} bytes, want 32", target_bytes.len()))?;
        let algo = match str_field("powAlgo")?.as_str() {
            "RandomX" => PowAlgo::RandomX,
            "Sha256d" => PowAlgo::Sha256d,
            other => return Err(format!("template has unknown powAlgo `{other}`")),
        };
        let seed_hash = str_field("powKey")?;
        let pow_key =
            hex::decode(&seed_hash).map_err(|e| format!("template `powKey` is not hex: {e}"))?;
        Ok(Template {
            template_id,
            height,
            prev_hash,
            blob,
            nonce_offset,
            network_target,
            algo,
            pow_key,
            seed_hash,
            timestamp_ms: u64_field("timestampMs")?,
        })
    }

    /// The blob with `nonce` spliced in — the exact preimage the node will hash
    /// when this nonce is submitted.
    pub fn blob_with_nonce(&self, nonce: u64) -> Vec<u8> {
        let mut blob = self.blob.clone();
        splice_nonce(&mut blob, self.nonce_offset, nonce);
        blob
    }

    /// Recompute the seal for `nonce` on the VERIFY path (light RandomX VM) —
    /// the same `pow_seal` the importer runs. Used for share validation.
    pub fn seal_for_nonce(&self, nonce: u64) -> [u8; 32] {
        pow_seal(self.algo, &self.pow_key, &self.blob_with_nonce(nonce))
    }

    /// The same seal on the MINING path (fast full-dataset VM, ~10× the hash
    /// rate, transparent fallback to light on RAM-constrained hosts). Used only
    /// by the built-in worker's hot loop.
    pub fn seal_for_nonce_mining(&self, nonce: u64) -> [u8; 32] {
        pow_seal_mining(self.algo, &self.pow_key, &self.blob_with_nonce(nonce))
    }

    /// The Stratum job `algo` string for this template's seal.
    pub fn stratum_algo(&self) -> &'static str {
        match self.algo {
            PowAlgo::RandomX => "rx/0",
            PowAlgo::Sha256d => "sha256d",
        }
    }
}

/// Write `nonce` as a little-endian u64 at `offset` — the single mutation a
/// miner performs on the blob.
pub fn splice_nonce(blob: &mut [u8], offset: usize, nonce: u64) {
    blob[offset..offset + 8].copy_from_slice(&nonce.to_le_bytes());
}

/// Parse a Stratum `submit.nonce` hex string as the **little-endian bytes** the
/// miner wrote into the blob: 8 hex chars for a u32 nonce (what xmrig-class
/// miners send, zero-extended into the u64 field) or 16 hex chars for the full
/// u64. An optional `0x` prefix is tolerated.
pub fn parse_nonce_hex(s: &str) -> Result<u64, String> {
    let stripped = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(stripped).map_err(|e| format!("nonce is not hex: {e}"))?;
    if bytes.len() != 4 && bytes.len() != 8 {
        return Err(format!(
            "nonce must be 8 or 16 hex chars (little-endian u32/u64), got {} chars",
            stripped.len()
        ));
    }
    let mut le = [0u8; 8];
    le[..bytes.len()].copy_from_slice(&bytes);
    Ok(u64::from_le_bytes(le))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use sov_primitives::{AccountId, BlockHeight, Hash};
    use sov_types::BlockHeader;

    #[test]
    fn splice_writes_little_endian_at_offset() {
        let mut blob = vec![0xaa; 20];
        splice_nonce(&mut blob, 12, 0x0123_4567_89ab_cdef);
        assert_eq!(&blob[..12], &[0xaa; 12][..]);
        assert_eq!(
            &blob[12..],
            &[0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01]
        );
    }

    #[test]
    fn parse_nonce_hex_reads_miner_wire_forms() {
        // xmrig's u32 form, little-endian.
        assert_eq!(parse_nonce_hex("02000000").unwrap(), 2);
        assert_eq!(parse_nonce_hex("000000ff").unwrap(), 0xff00_0000);
        // Full u64 form, with and without the 0x prefix.
        assert_eq!(parse_nonce_hex("0100000000000000").unwrap(), 1);
        assert_eq!(
            parse_nonce_hex("0xefcdab8967452301").unwrap(),
            0x0123_4567_89ab_cdef
        );
        // Malformed forms fail loudly.
        assert!(parse_nonce_hex("123").is_err()); // odd length
        assert!(parse_nonce_hex("0102").is_err()); // wrong width
        assert!(parse_nonce_hex("zz000000").is_err()); // not hex
        assert!(parse_nonce_hex("010203040506070809").is_err()); // too long
    }

    /// A representative header for the splice-equivalence proof.
    fn sample_header(nonce: u64) -> BlockHeader {
        BlockHeader {
            height: BlockHeight::new(4242),
            prev_hash: Hash::digest(b"parent"),
            tx_root: Hash::digest(b"txs"),
            receipts_root: Hash::digest(b"receipts"),
            state_root: Hash::digest(b"state"),
            timestamp_ms: 1_752_800_000_000,
            proposer: AccountId::new("81f4ccaa000000000000000000000000").unwrap(),
            version_bits: 0,
            bits: 0x1d00_ffff,
            nonce,
        }
    }

    #[test]
    fn splice_equals_borsh_reencode() {
        // The bridge-side twin of the node-side Phase-1 invariant: splicing the
        // LE nonce at blob.len() − 8 IS re-encoding the header with that nonce.
        let base = sample_header(0).pow_preimage();
        let nonce = 0xdead_beef_cafe_babe;
        let reencoded = sample_header(nonce).pow_preimage();
        let mut spliced = base.clone();
        splice_nonce(&mut spliced, base.len() - 8, nonce);
        assert_eq!(spliced, reencoded);
    }

    fn sample_template(target: [u8; 32]) -> Template {
        let blob = sample_header(0).pow_preimage();
        let nonce_offset = blob.len() - 8;
        Template {
            template_id: "00".repeat(32),
            height: 4242,
            prev_hash: Hash::digest(b"parent").to_hex(),
            blob,
            nonce_offset,
            network_target: target,
            algo: PowAlgo::Sha256d,
            pow_key: vec![],
            seed_hash: String::new(),
            timestamp_ms: 1_752_800_000_000,
        }
    }

    #[test]
    fn seal_for_nonce_is_the_real_seal_over_the_spliced_blob() {
        // Sha256d keeps this test instant while exercising the identical splice +
        // pow_seal path RandomX uses (the algo is a genesis-fixed parameter).
        let t = sample_template([0xff; 32]);
        let nonce = 7_777_777;
        let expected = sov_pow::sha256d(&t.blob_with_nonce(nonce));
        assert_eq!(t.seal_for_nonce(nonce), expected);
        // And a different nonce yields a different seal (the splice really lands).
        assert_ne!(t.seal_for_nonce(nonce), t.seal_for_nonce(nonce + 1));
    }

    #[test]
    fn share_vs_block_classification_over_real_seals() {
        use crate::share::{classify_seal, difficulty_to_target256, ShareOutcome};
        // An easy share target (diff 2) over an unreachable network target: grind
        // a few nonces and check every outcome is Share/TooWeak, never Block.
        let t = sample_template([0x00; 32]);
        let share_target = difficulty_to_target256(2);
        let mut saw_share = false;
        for nonce in 0..64 {
            match classify_seal(&t.seal_for_nonce(nonce), &share_target, &t.network_target) {
                ShareOutcome::Share => saw_share = true,
                ShareOutcome::TooWeak => {}
                ShareOutcome::Block => panic!("nothing beats an all-zero network target"),
            }
        }
        // 64 fair coin flips: P(no share) = 2^-64 — this cannot flake.
        assert!(
            saw_share,
            "diff-2 share target must accept within 64 nonces"
        );
    }

    #[test]
    fn template_parses_the_documented_rpc_shape() {
        let blob = sample_header(0).pow_preimage();
        let v = json!({
            "templateId": "11".repeat(32),
            "height": 9000u64,
            "prevHash": "22".repeat(32),
            "txRoot": "33".repeat(32),
            "stateRoot": "44".repeat(32),
            "receiptsRoot": "55".repeat(32),
            "timestampMs": 1_752_800_000_123u64,
            "minTimestampMs": 1_752_799_999_000u64,
            "bits": 0x1d00_ffffu32,
            "target": "00000000ffff0000000000000000000000000000000000000000000000000000",
            "powAlgo": "RandomX",
            "powKey": "cb0272ff88e64c18cde0257f7fae1c8236b02651f10cc7a02456fd682ee2e72d",
            "proposer": "81f4ccaa000000000000000000000000",
            "versionBits": 0u32,
            "blob": hex::encode(&blob),
            "nonceOffset": blob.len() - 8,
        });
        let t = Template::from_rpc(&v).expect("documented shape parses");
        assert_eq!(t.height, 9000);
        assert_eq!(t.algo, PowAlgo::RandomX);
        assert_eq!(t.stratum_algo(), "rx/0");
        assert_eq!(t.nonce_offset, blob.len() - 8);
        assert_eq!(t.timestamp_ms, 1_752_800_000_123);
        assert_eq!(t.network_target[..4], [0, 0, 0, 0]);
        assert_eq!(t.pow_key.len(), 32);

        // A nonceOffset that disagrees with the blob layout is refused outright.
        let mut bad = v.clone();
        bad["nonceOffset"] = json!(39);
        assert!(Template::from_rpc(&bad)
            .unwrap_err()
            .contains("nonceOffset"));
        // And an unknown algorithm is refused rather than guessed at.
        let mut bad = v;
        bad["powAlgo"] = json!("Scrypt");
        assert!(Template::from_rpc(&bad).unwrap_err().contains("powAlgo"));
    }

    /// A header whose proposer is `id` — for exercising the VARIABLE nonce
    /// offset (AccountId is Borsh length-prefixed, so the proposer's length
    /// moves every downstream field, including the trailing nonce).
    fn header_with_proposer(id: &str, nonce: u64) -> BlockHeader {
        BlockHeader {
            height: BlockHeight::new(77),
            prev_hash: Hash::digest(b"parent"),
            tx_root: Hash::digest(b"txs"),
            receipts_root: Hash::digest(b"receipts"),
            state_root: Hash::digest(b"state"),
            timestamp_ms: 1_752_900_000_000,
            proposer: AccountId::new(id).unwrap(),
            version_bits: 0,
            bits: 0x1d00_ffff,
            nonce,
        }
    }

    #[test]
    fn splice_equals_borsh_reencode_across_proposer_lengths() {
        // The splice invariant must hold for EVERY proposer length the chain
        // admits — from AccountId::MIN_LEN to MAX_LEN — because the length
        // shifts the nonce offset. Each id here is a distinct valid shape:
        // minimum, human-named, hierarchical, implicit (64-hex), and maximum.
        let max_len_id = format!("{}.sov", "a".repeat(60)); // MAX_LEN = 64
        let proposers = [
            "ab",                                                               // MIN_LEN = 2
            "sov-pool",                                                         // named
            "ustreasury.tax.sov",                                               // hierarchical
            "81f4ccaa81f4ccaa81f4ccaa81f4ccaa81f4ccaa81f4ccaa81f4ccaa81f4ccaa", // implicit, 64
            max_len_id.as_str(),
        ];
        let nonces = [1u64, 0xff, 0xdead_beef, 0x0123_4567_89ab_cdef, u64::MAX];
        let mut seen_offsets = std::collections::HashSet::new();
        for id in proposers {
            let base = header_with_proposer(id, 0).pow_preimage();
            let offset = base.len() - 8;
            seen_offsets.insert(offset);
            // The template-variable offset really is the trailing u64: the base
            // preimage ends in nonce 0's eight zero bytes.
            assert_eq!(&base[offset..], &[0u8; 8], "proposer `{id}`");
            for nonce in nonces {
                let reencoded = header_with_proposer(id, nonce).pow_preimage();
                let mut spliced = base.clone();
                splice_nonce(&mut spliced, offset, nonce);
                assert_eq!(
                    spliced, reencoded,
                    "splice != Borsh re-encode for proposer `{id}` nonce {nonce:#x}"
                );
            }
        }
        // The offsets must actually have varied — otherwise this test proved
        // nothing about the variable part of the layout.
        assert!(
            seen_offsets.len() >= 4,
            "proposer lengths did not move the nonce offset: {seen_offsets:?}"
        );
    }

    #[test]
    fn blob_with_nonce_never_mutates_the_template() {
        let t = sample_template([0xff; 32]);
        let before = t.blob.clone();
        let out = t.blob_with_nonce(u64::MAX);
        assert_eq!(t.blob, before, "template blob must be untouched");
        // Only the trailing 8 bytes differ.
        assert_eq!(out[..t.nonce_offset], before[..t.nonce_offset]);
        assert_eq!(out[t.nonce_offset..], [0xffu8; 8]);
    }

    #[test]
    fn mining_seal_path_matches_verify_seal_path() {
        // seal_for_nonce (light/verify VM) and seal_for_nonce_mining (fast VM)
        // must be the SAME function of (algo, key, blob) — a share verified on
        // one path and ground on the other would otherwise disagree.
        let t = sample_template([0xff; 32]);
        for nonce in [0u64, 1, 42, u64::MAX] {
            assert_eq!(t.seal_for_nonce(nonce), t.seal_for_nonce_mining(nonce));
        }
    }

    #[test]
    fn parse_nonce_hex_roundtrips_and_rejects_adversarial_forms() {
        // Round-trip: the exact little-endian bytes a miner writes come back.
        for nonce in [0u64, 1, 0xffff_ffff, 0x1_0000_0000, u64::MAX] {
            let wire = hex::encode(nonce.to_le_bytes());
            assert_eq!(parse_nonce_hex(&wire).unwrap(), nonce, "u64 wire {wire}");
        }
        for nonce in [0u32, 1, 0xdead_beef, u32::MAX] {
            let wire = hex::encode(nonce.to_le_bytes());
            assert_eq!(
                parse_nonce_hex(&wire).unwrap(),
                nonce as u64,
                "u32 wire {wire}"
            );
        }
        // Uppercase hex digits are valid hex.
        assert_eq!(parse_nonce_hex("ABCDEF12").unwrap(), 0x12EF_CDAB);
        // Adversarial forms: every one is a clean error, never a panic, never a
        // silent zero.
        let huge = "00".repeat(1 << 16);
        for bad in [
            "",                   // empty
            "0x",                 // prefix only
            " 02000000",          // leading whitespace
            "02000000 ",          // trailing whitespace
            "02\t000000",         // interior whitespace
            "02000000\n",         // newline (a line-splitting bug upstream)
            "0X02000000",         // capital-X prefix is not the 0x form
            "0xzz000000",         // prefix + non-hex
            "Ω2000000",           // non-ASCII
            "0102030405",         // 5 bytes: neither u32 nor u64
            "01020304050607",     // 7 bytes
            "0102030405060708ff", // 9 bytes
            huge.as_str(),        // 64 KiB of hex — absurd length, no panic
        ] {
            assert!(parse_nonce_hex(bad).is_err(), "`{bad}` must be rejected");
        }
    }

    /// The documented-good RPC template value used as the mutation base below.
    fn good_rpc_value() -> serde_json::Value {
        let blob = sample_header(0).pow_preimage();
        json!({
            "templateId": "11".repeat(32),
            "height": 9000u64,
            "prevHash": "22".repeat(32),
            "timestampMs": 1_752_800_000_123u64,
            "target": "00000000ffff0000000000000000000000000000000000000000000000000000",
            "powAlgo": "Sha256d",
            "powKey": "",
            "blob": hex::encode(&blob),
            "nonceOffset": blob.len() - 8,
        })
    }

    #[test]
    fn from_rpc_accepts_sha256d_and_an_empty_pow_key() {
        let t = Template::from_rpc(&good_rpc_value()).expect("sha256d template parses");
        assert_eq!(t.algo, PowAlgo::Sha256d);
        assert_eq!(t.stratum_algo(), "sha256d");
        assert!(t.pow_key.is_empty());
        assert!(t.seed_hash.is_empty());
    }

    #[test]
    fn from_rpc_rejects_every_missing_field_by_name() {
        // Dropping ANY required field is a loud error that names the field.
        for field in [
            "templateId",
            "height",
            "prevHash",
            "timestampMs",
            "target",
            "powAlgo",
            "powKey",
            "blob",
            "nonceOffset",
        ] {
            let mut v = good_rpc_value();
            v.as_object_mut().unwrap().remove(field);
            let err =
                Template::from_rpc(&v).expect_err(&format!("missing `{field}` must be rejected"));
            assert!(err.contains(field), "error `{err}` must name `{field}`");
        }
    }

    #[test]
    fn from_rpc_rejects_type_confusion_and_malformed_values() {
        let cases: Vec<(&str, serde_json::Value, &str)> = vec![
            ("height", json!("9000"), "height"), // stringly number
            ("height", json!(-1), "height"),     // negative
            ("height", json!(1.5), "height"),    // fractional
            ("nonceOffset", json!("168"), "nonceOffset"),
            ("blob", json!("not hex!!"), "blob"),
            ("blob", json!(12345), "blob"),
            ("target", json!("zz".repeat(32)), "target"),
            ("target", json!("00".repeat(31)), "31 bytes"), // short target
            ("target", json!("00".repeat(33)), "33 bytes"), // long target
            ("powAlgo", json!("Equihash"), "powAlgo"),      // long-removed algo
            ("powAlgo", json!("randomx"), "powAlgo"),       // case-sensitive
            ("powKey", json!("xyz"), "powKey"),
            ("templateId", json!(7), "templateId"),
        ];
        for (field, value, expect_in_err) in cases {
            let mut v = good_rpc_value();
            v[field] = value.clone();
            let err =
                Template::from_rpc(&v).expect_err(&format!("{field}={value} must be rejected"));
            assert!(
                err.contains(expect_in_err),
                "error `{err}` for {field}={value} must mention `{expect_in_err}`"
            );
        }
    }

    #[test]
    fn from_rpc_rejects_inconsistent_nonce_offsets_and_short_blobs() {
        // Off-by-eight and pathological offsets are all refused.
        for offset in [0u64, 1, 100, 176, u32::MAX as u64, u64::MAX] {
            let mut v = good_rpc_value();
            let blob_len = hex::decode(v["blob"].as_str().unwrap()).unwrap().len() as u64;
            if offset == blob_len - 8 {
                continue; // the one valid value
            }
            v["nonceOffset"] = json!(offset);
            assert!(
                Template::from_rpc(&v).unwrap_err().contains("nonceOffset"),
                "offset {offset} must be rejected"
            );
        }
        // A blob shorter than one nonce cannot carry a job at all.
        let seven = "00".repeat(7);
        for short in ["", "00", seven.as_str()] {
            let mut v = good_rpc_value();
            v["blob"] = json!(short);
            v["nonceOffset"] = json!(0);
            assert!(
                Template::from_rpc(&v).is_err(),
                "{}-byte blob must be rejected",
                short.len() / 2
            );
        }
        // Exactly 8 bytes (nonce only) is degenerate but layout-consistent:
        // offset 0 == len − 8. The layout check admits it; it simply hashes an
        // 8-byte preimage. Document that this is where the boundary sits.
        let mut v = good_rpc_value();
        v["blob"] = json!("00".repeat(8));
        v["nonceOffset"] = json!(0);
        assert!(Template::from_rpc(&v).is_ok());
    }

    #[test]
    fn from_rpc_never_panics_on_arbitrary_json_shapes() {
        // Whatever a broken or hostile node returns, the parser must produce
        // Err — never panic. (Top-level non-objects, nulls, arrays, nested junk.)
        for v in [
            json!(null),
            json!(42),
            json!("a string"),
            json!([]),
            json!([{"templateId": "x"}]),
            json!({}),
            json!({"templateId": null}),
            json!({"height": {"nested": true}}),
        ] {
            assert!(Template::from_rpc(&v).is_err(), "shape {v} must be an Err");
        }
    }
}
