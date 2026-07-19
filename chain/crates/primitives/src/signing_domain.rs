//! Network-scoped signing domain — the anti-replay binding for the
//! miner-signaled `tx-domain` hard fork.
//!
//! Every SOV-family chain derives the same implicit account id from the same key
//! (`hex(blake3(pubkey))`), so a bare signature over a transaction's Borsh bytes
//! is valid on *every* such chain: a signature captured on one network can be
//! replayed onto another — "ghost chain" cross-network replay. A [`SigningDomain`]
//! closes this by binding a signature to one specific network, prefixing the
//! signing preimage with a scheme tag, the chain id, and the frozen genesis hash.
//!
//! This is **dormant** until the miner-signaled `tx-domain` deployment activates:
//! verification passes `None` (the legacy, un-prefixed preimage) before
//! activation, so the pre-fork signing bytes — and therefore the genesis hash and
//! every KAT vector — are reproduced exactly, byte for byte. Only after a
//! coordinated activation height does verification switch to the bound preimage.

use crate::Hash;

/// The network identity a signature is bound to: this chain's id and its genesis
/// block hash.
///
/// Framing (post-activation): `tag ‖ 0x00 ‖ chain_id ‖ 0x00 ‖ genesis(32) ‖ body`,
/// where `body` is the legacy signing bytes (the canonical Borsh encoding). The
/// `tag` is a fixed scheme label (`b"sov:tx:v1"`, `b"sov:intent:v1"`) containing
/// no interior `0x00`, `chain_id` is an ASCII network name, and the genesis hash
/// is a fixed 32 bytes — so the encoding is injective and cannot collide across
/// schemes or across networks. A verifier always frames with *its own* chain id
/// and genesis, so a signature made for a different network never matches.
///
/// Mirrors the existing intra-chain domain separators
/// (`sov:multisig:v1`, `sov:rotate:v1`), extended with network binding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SigningDomain {
    chain_id: String,
    genesis: Hash,
}

impl SigningDomain {
    /// Bind to `chain_id` and its `genesis` block hash.
    pub fn new(chain_id: impl Into<String>, genesis: Hash) -> Self {
        Self {
            chain_id: chain_id.into(),
            genesis,
        }
    }

    /// The bound chain id.
    pub fn chain_id(&self) -> &str {
        &self.chain_id
    }

    /// The bound genesis hash.
    pub fn genesis(&self) -> Hash {
        self.genesis
    }

    /// Frame `body` under `tag`: `tag ‖ 0x00 ‖ chain_id ‖ 0x00 ‖ genesis(32) ‖ body`.
    ///
    /// The two `0x00` separators plus the fixed-length genesis make the layout
    /// unambiguous; distinct `tag`s keep transaction and intent preimages disjoint.
    pub fn frame(&self, tag: &[u8], body: &[u8]) -> Vec<u8> {
        let cid = self.chain_id.as_bytes();
        let genesis = self.genesis.as_bytes();
        let mut buf =
            Vec::with_capacity(tag.len() + 1 + cid.len() + 1 + genesis.len() + body.len());
        buf.extend_from_slice(tag);
        buf.push(0x00);
        buf.extend_from_slice(cid);
        buf.push(0x00);
        buf.extend_from_slice(genesis);
        buf.extend_from_slice(body);
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn domain(chain: &str) -> SigningDomain {
        SigningDomain::new(chain, Hash::digest(chain.as_bytes()))
    }

    #[test]
    fn frame_layout_is_exact() {
        let d = SigningDomain::new("sov-mainnet", Hash::digest(b"g"));
        let framed = d.frame(b"sov:tx:v1", b"BODY");
        let mut expected = Vec::new();
        expected.extend_from_slice(b"sov:tx:v1");
        expected.push(0x00);
        expected.extend_from_slice(b"sov-mainnet");
        expected.push(0x00);
        expected.extend_from_slice(Hash::digest(b"g").as_bytes());
        expected.extend_from_slice(b"BODY");
        assert_eq!(framed, expected);
    }

    #[test]
    fn different_chain_id_yields_different_bytes() {
        assert_ne!(
            domain("sov-mainnet").frame(b"sov:tx:v1", b"x"),
            domain("sov-testnet").frame(b"sov:tx:v1", b"x"),
        );
    }

    #[test]
    fn different_genesis_yields_different_bytes() {
        let a = SigningDomain::new("sov", Hash::digest(b"genesis-a"));
        let b = SigningDomain::new("sov", Hash::digest(b"genesis-b"));
        assert_ne!(a.frame(b"sov:tx:v1", b"x"), b.frame(b"sov:tx:v1", b"x"));
    }

    #[test]
    fn different_tag_yields_different_bytes() {
        let d = domain("sov");
        assert_ne!(d.frame(b"sov:tx:v1", b"x"), d.frame(b"sov:intent:v1", b"x"),);
    }
}
