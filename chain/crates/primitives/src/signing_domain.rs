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

/// The signature-verification regime in force for a block at a given height —
/// the three-state resolution of the miner-signaled `tx-domain` hard fork,
/// including its post-activation **grace window**.
///
/// Activation is not a cliff. At the activation height `H_a` enforcement enters
/// a grace window of `G` blocks during which a transaction (or intent) is valid
/// if its signature verifies under EITHER preimage — legacy (un-bound) or
/// chain-bound — so anything legacy-signed and in flight when the fork
/// activates still confirms. Only after the window does verification become
/// bound-only, at which point cross-network replay is fully closed.
///
/// Exact boundaries (`G` = the configured grace length in blocks):
///
/// - [`Legacy`](Self::Legacy) — `height < H_a` (or the fork is dormant /
///   unscheduled): verify the legacy preimage ONLY. Byte-identical to the
///   pre-fork path (`signing_bytes_in(None)`).
/// - [`Grace`](Self::Grace) — `H_a <= height < H_a + G`: legacy OR bound
///   accepted. (Replay protection is not yet fully in force inside the window —
///   the accepted, bounded cost of a smooth cutover.)
/// - [`Bound`](Self::Bound) — `height >= H_a + G`: bound ONLY; a legacy
///   signature is rejected.
///
/// The mode is a pure function of (deployment schedule, grace length, height,
/// committed miner signals), so the producer and every importer resolve the
/// same mode for the same block. `G = 0` degenerates to the original cliff
/// (`Bound` immediately at `H_a`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum TxDomainMode {
    /// Pre-activation (or dormant): verify the legacy, un-bound preimage only.
    #[default]
    Legacy,
    /// The post-activation grace window: a signature verifying under EITHER the
    /// legacy preimage or the bound preimage (this domain) is accepted.
    Grace(SigningDomain),
    /// Post-grace steady state: only a signature bound to this domain verifies.
    Bound(SigningDomain),
}

impl TxDomainMode {
    /// Run `verify` under this mode's accepted preimage(s): `verify(None)`
    /// checks the legacy preimage, `verify(Some(domain))` the chain-bound one.
    ///
    /// - `Legacy` → `verify(None)` — exactly the pre-fork call, nothing else.
    /// - `Grace(d)` → `verify(Some(d)) || verify(None)` — either accepted.
    /// - `Bound(d)` → `verify(Some(d))` — legacy rejected.
    ///
    /// Centralizing the OR here keeps every verification site (execution,
    /// mempool admission, block import) in exact agreement.
    pub fn verifies(&self, verify: impl Fn(Option<&SigningDomain>) -> bool) -> bool {
        match self {
            TxDomainMode::Legacy => verify(None),
            TxDomainMode::Grace(domain) => verify(Some(domain)) || verify(None),
            TxDomainMode::Bound(domain) => verify(Some(domain)),
        }
    }

    /// The domain new signatures should bind to under this mode: `Some` from
    /// activation onward (grace included — wallets should switch to bound
    /// signing immediately), `None` while legacy-only.
    pub fn bound_domain(&self) -> Option<&SigningDomain> {
        match self {
            TxDomainMode::Legacy => None,
            TxDomainMode::Grace(domain) | TxDomainMode::Bound(domain) => Some(domain),
        }
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

    #[test]
    fn mode_legacy_calls_verify_exactly_once_with_none() {
        // The dormant guard: Legacy must be indistinguishable from the pre-fork
        // path — a single `verify(None)`, never a domain probe.
        use std::cell::RefCell;
        let calls = RefCell::new(Vec::new());
        let ok = TxDomainMode::Legacy.verifies(|d| {
            calls.borrow_mut().push(d.cloned());
            true
        });
        assert!(ok);
        assert_eq!(*calls.borrow(), vec![None]);
    }

    #[test]
    fn mode_grace_accepts_either_preimage() {
        let d = domain("sov-mainnet");
        let grace = TxDomainMode::Grace(d.clone());
        // legacy-only signature: bound check fails, legacy passes -> accepted
        assert!(grace.verifies(|dom| dom.is_none()));
        // bound-only signature: bound passes -> accepted
        assert!(grace.verifies(|dom| dom == Some(&d)));
        // neither verifies -> rejected
        assert!(!grace.verifies(|_| false));
    }

    #[test]
    fn mode_bound_rejects_legacy() {
        let d = domain("sov-mainnet");
        let bound = TxDomainMode::Bound(d.clone());
        assert!(!bound.verifies(|dom| dom.is_none()), "legacy must fail");
        assert!(bound.verifies(|dom| dom == Some(&d)));
    }

    #[test]
    fn mode_bound_domain_surface() {
        let d = domain("sov-mainnet");
        assert_eq!(TxDomainMode::Legacy.bound_domain(), None);
        assert_eq!(TxDomainMode::Grace(d.clone()).bound_domain(), Some(&d));
        assert_eq!(TxDomainMode::Bound(d.clone()).bound_domain(), Some(&d));
    }
}
