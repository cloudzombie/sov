//! Single source of truth for EVERY hash domain in this crate (S1b).
//!
//! Two hash families are in use, each with its own domain mechanism:
//!
//! 1. **In-circuit Rescue-Prime merges** ([`crate::hash::merge_domain`]):
//!    the 2-to-1 sponge compression carries a small domain constant in
//!    capacity element 1 (capacity element 0 stays the upstream rate-width
//!    seed, 8). Distinct capacity initialization is the standard sponge
//!    domain-separation technique: two merges with different domains are
//!    evaluations of the permutation on disjoint input sets, so a collision
//!    across domains is a permutation collision. Domain 0 is RESERVED as the
//!    upstream-compatibility point (`merge_domain(0, ..) == Rp64_256::merge`,
//!    pinned by a test) and is never used by the protocol.
//!
//! 2. **Native blake3 `derive_key` domains**: used only OUTSIDE the circuit
//!    (key/`rho` derivation, note AEAD keys, detection tags, the carrier
//!    bundle digest). blake3's `derive_key` mode gives full cryptographic
//!    context separation per string.
//!
//! Every constant below is used in exactly the place its name says; a test
//! in this module proves cross-domain outputs differ for identical inputs.

/// In-circuit domain: owner tag `merge_d(nsk, 0)`.
pub const RESCUE_DOMAIN_OWNER_TAG: u64 = 1;
/// In-circuit domain: note-commitment stage 1 `merge_d([value,0,0,0], tag)`.
pub const RESCUE_DOMAIN_COMMIT_STAGE1: u64 = 2;
/// In-circuit domain: note-commitment stage 2 `merge_d(stage1, rho)`.
pub const RESCUE_DOMAIN_COMMIT_STAGE2: u64 = 3;
/// In-circuit domain: Merkle-tree internal node `merge_d(left, right)`.
pub const RESCUE_DOMAIN_MERKLE_NODE: u64 = 4;
/// In-circuit domain: nullifier `merge_d(nsk, rho)` for a REAL spend.
pub const RESCUE_DOMAIN_NULLIFIER: u64 = 5;
/// In-circuit domain: the nullifier hash of a DUMMY input slot. Dummy slots
/// never surface a nullifier (the verifier excludes them), but the circuit
/// still domain-separates the dummy hash so a dummy's in-trace nullifier can
/// never equal any real nullifier — defense in depth against any future
/// handling bug that leaks a dummy slot into the nullifier set.
pub const RESCUE_DOMAIN_DUMMY_NULLIFIER: u64 = 6;

/// blake3 domain: spending-key (`nsk`) derivation from a seed.
pub const B3_NSK: &str = "sov-shielded-pq:nsk:v2";
/// blake3 domain: deterministic per-note randomness (`rho`) derivation.
pub const B3_RHO: &str = "sov-shielded-pq:rho:v2";
/// blake3 domain: ML-DSA-65 keygen seed expansion.
pub const B3_AUTH_KEYGEN: &str = "sov-shielded-pq:auth-keygen:v2";
/// blake3 domain: ML-DSA-65 deterministic signing seed expansion.
pub const B3_AUTH_SIGN: &str = "sov-shielded-pq:auth-sign:v2";
/// ML-DSA-65 signing context string (FIPS 204 `ctx` parameter).
pub const AUTH_SIGN_CTX: &[u8] = b"sov-shielded-pq:auth:v2";
/// blake3 domain: one-time note-AEAD key from the ML-KEM shared secret.
pub const B3_NOTE_AEAD: &str = "sov-shielded-pq:note-aead:v2";
/// blake3 domain: the 4-byte note detection tag (D7) from the ML-KEM shared
/// secret — lets a scanning wallet reject a failed trial-decapsulation in
/// ~µs without running the AEAD.
pub const B3_DETECTION_TAG: &str = "sov-shielded-pq:detect:v2";
/// blake3 domain: the carrier bundle digest the ML-DSA-65 signature covers.
pub const B3_BUNDLE_DIGEST: &str = "sov-shielded-pq:bundle:v2";
/// blake3 domain: test fixtures only. Never used by protocol code.
pub const B3_TEST: &str = "sov-shielded-pq:test:v2";

/// All in-circuit Rescue domains (protocol ones; 0 is reserved upstream).
pub const ALL_RESCUE_DOMAINS: [u64; 6] = [
    RESCUE_DOMAIN_OWNER_TAG,
    RESCUE_DOMAIN_COMMIT_STAGE1,
    RESCUE_DOMAIN_COMMIT_STAGE2,
    RESCUE_DOMAIN_MERKLE_NODE,
    RESCUE_DOMAIN_NULLIFIER,
    RESCUE_DOMAIN_DUMMY_NULLIFIER,
];

/// All blake3 derive-key domains.
pub const ALL_B3_DOMAINS: [&str; 8] = [
    B3_NSK,
    B3_RHO,
    B3_AUTH_KEYGEN,
    B3_AUTH_SIGN,
    B3_NOTE_AEAD,
    B3_DETECTION_TAG,
    B3_BUNDLE_DIGEST,
    B3_TEST,
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::{digest_from_bytes, merge_domain, PqDigest};

    #[test]
    fn rescue_domains_are_distinct_constants() {
        let mut sorted = ALL_RESCUE_DOMAINS.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), ALL_RESCUE_DOMAINS.len());
        assert!(!sorted.contains(&0), "domain 0 is reserved for upstream");
    }

    #[test]
    fn cross_domain_rescue_outputs_differ_for_identical_inputs() {
        let a = PqDigest([1, 2, 3, 4]);
        let b = PqDigest([5, 6, 7, 8]);
        let mut outs: Vec<PqDigest> = ALL_RESCUE_DOMAINS
            .iter()
            .map(|&d| merge_domain(d, a, b))
            .collect();
        // Include the reserved upstream point too: protocol domains must
        // also differ from it.
        outs.push(merge_domain(0, a, b));
        for i in 0..outs.len() {
            for j in i + 1..outs.len() {
                assert_ne!(
                    outs[i], outs[j],
                    "rescue domains {i} and {j} collided on identical inputs"
                );
            }
        }
    }

    #[test]
    fn cross_domain_blake3_outputs_differ_for_identical_inputs() {
        let input = b"identical input bytes";
        let outs: Vec<PqDigest> = ALL_B3_DOMAINS
            .iter()
            .map(|d| digest_from_bytes(d, input))
            .collect();
        for i in 0..outs.len() {
            for j in i + 1..outs.len() {
                assert_ne!(
                    outs[i], outs[j],
                    "blake3 domains {:?} and {:?} collided on identical inputs",
                    ALL_B3_DOMAINS[i], ALL_B3_DOMAINS[j]
                );
            }
        }
    }
}
