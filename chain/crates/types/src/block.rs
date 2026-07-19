//! Blocks: ordered batches of transactions that advance the chain.
//!
//! A [`BlockHeader`] is the small, hashable commitment to everything in a block:
//! its position ([`height`](BlockHeader::height)), its parent (`prev_hash`), and
//! three Merkle/state roots — `tx_root` (the transactions it contains),
//! `receipts_root` (what executing them produced), and `state_root` (the
//! resulting world state). A block's id is the hash of its header alone, because
//! the header already commits to the body through those roots.
//!
//! `state_root` and `receipts_root` are supplied by the execution layer (a later
//! phase); `tx_root` is always computed here from the actual transactions, so a
//! block can never claim a transaction set it doesn't carry.

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use sov_crypto::merkle_root;
use sov_primitives::{AccountId, BlockHeight, Hash, SigningDomain};

use crate::transaction::SignedTransaction;

/// The authenticated header of a block — the part that is hashed and sealed by
/// proof of work.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct BlockHeader {
    /// Position in the chain; genesis is `0`.
    pub height: BlockHeight,
    /// Hash of the parent block's header. [`Hash::ZERO`] for genesis.
    pub prev_hash: Hash,
    /// Merkle root over the contained transactions' ids.
    pub tx_root: Hash,
    /// Merkle root over the receipts produced by executing the transactions.
    pub receipts_root: Hash,
    /// Root of the world state after applying this block.
    pub state_root: Hash,
    /// Producer's wall-clock time, in Unix milliseconds.
    pub timestamp_ms: u64,
    /// Account credited the coinbase reward — **the miner that found this
    /// block's proof-of-work** (Nakamoto consensus).
    pub proposer: AccountId,
    /// BIP-9/8 miner-signaling version bits (bit `b` set = this block signals
    /// readiness for the deployment assigned bit `b`). `0` = signals nothing.
    /// Committed in the header hash, so signal history is consensus state.
    pub version_bits: u32,
    /// The proof-of-work difficulty target this block was mined against, in
    /// **Bitcoin's compact "nBits" encoding** (see [`Target::to_compact`]).
    /// Committed in the header hash, so a header self-describes the work it
    /// claims; consensus independently rejects any block whose `bits` differs
    /// from the value the retarget rule requires, and whose
    /// [`pow_hash`](BlockHeader::pow_hash) does not meet the decoded target.
    /// Carrying it makes a header verifiable — and chain work summable — without
    /// the full block index (headers-first / SPV sync).
    ///
    /// [`Target::to_compact`]: sov_pow::Target::to_compact
    pub bits: u32,
    /// The proof-of-work nonce. A miner grinds this until the header's
    /// [`pow_hash`](BlockHeader::pow_hash) meets the difficulty target — the
    /// work that secures the block under Nakamoto consensus.
    pub nonce: u64,
}

impl BlockHeader {
    /// The block id: the Blake3 hash of the Borsh-encoded header. Used for
    /// linking (`prev_hash`) and addressing — distinct from the PoW seal.
    pub fn hash(&self) -> Hash {
        Hash::digest(
            &borsh::to_vec(self).expect("Borsh serialization of a BlockHeader is infallible"),
        )
    }

    /// The proof-of-work **preimage**: the Borsh-encoded header — the bytes the
    /// chain's seal algorithm hashes. Since the `nonce` (and every other field)
    /// is part of it, a miner changes the seal by grinding the nonce.
    pub fn pow_preimage(&self) -> Vec<u8> {
        borsh::to_vec(self).expect("Borsh serialization of a BlockHeader is infallible")
    }

    /// The **SHA-256d** proof-of-work seal over the header preimage (Bitcoin's
    /// primitive). This is the seal for `PowAlgo::Sha256d` chains; the chain
    /// computes the active seal via its configured algorithm (RandomX on
    /// mainnet), so consensus code should seal through the chain, not here.
    pub fn pow_hash(&self) -> Hash {
        Hash::from_bytes(sov_pow::sha256d(&self.pow_preimage()))
    }
}

/// A block: its header plus the transactions it commits to.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct Block {
    /// Authenticated header.
    pub header: BlockHeader,
    /// The transactions, in execution order.
    pub transactions: Vec<SignedTransaction>,
}

impl Block {
    /// Assemble a block, computing `tx_root` from `transactions`. The
    /// `state_root` and `receipts_root` come from the execution layer that ran
    /// the transactions.
    #[allow(clippy::too_many_arguments)]
    pub fn assemble(
        height: BlockHeight,
        prev_hash: Hash,
        state_root: Hash,
        receipts_root: Hash,
        timestamp_ms: u64,
        proposer: AccountId,
        transactions: Vec<SignedTransaction>,
    ) -> Self {
        let tx_root = compute_tx_root(&transactions);
        Block {
            header: BlockHeader {
                height,
                prev_hash,
                tx_root,
                receipts_root,
                state_root,
                timestamp_ms,
                proposer,
                // Signals nothing by default; the producer sets its mask
                // (committed in the header hash) before sealing the block.
                version_bits: 0,
                // Set by the producer to the branch-required difficulty
                // (committed in the header hash) before sealing the block.
                bits: 0,
                // Unmined; the producer grinds the nonce to seal the block.
                nonce: 0,
            },
            transactions,
        }
    }

    /// The block id (its header hash).
    pub fn hash(&self) -> Hash {
        self.header.hash()
    }

    /// The block's canonical serialized size in bytes — the exact Borsh encoding that
    /// is written to the block log and gossiped on the wire. This is the "weight" the
    /// elastic block-size cap bounds (consensus): deterministic across nodes and
    /// platforms because Borsh is a canonical, length-prefixed encoding.
    pub fn serialized_size(&self) -> usize {
        borsh::to_vec(self)
            .expect("Borsh serialization of a Block is infallible")
            .len()
    }

    /// Whether this is the genesis block (height 0).
    pub fn is_genesis(&self) -> bool {
        self.header.height.is_genesis()
    }

    /// Validity check: the header's `tx_root` matches the carried transactions.
    /// A block whose body was altered after assembly fails this.
    #[must_use]
    pub fn tx_root_matches(&self) -> bool {
        self.header.tx_root == compute_tx_root(&self.transactions)
    }

    /// Validity check: every transaction's signature verifies (legacy, un-bound).
    #[must_use]
    pub fn all_signatures_valid(&self) -> bool {
        self.all_signatures_valid_in(None)
    }

    /// Validity check under an optional network [`SigningDomain`]: every
    /// transaction's signature verifies against `domain`. `None` is byte-identical
    /// to [`all_signatures_valid`](Self::all_signatures_valid); `Some(domain)` is
    /// what a post-`tx-domain`-activation importer uses so a block carrying a
    /// cross-network-replayed (or legacy un-bound) signature fails validation.
    #[must_use]
    pub fn all_signatures_valid_in(&self, domain: Option<&SigningDomain>) -> bool {
        self.transactions
            .iter()
            .all(|s| s.verify_signature_in(domain))
    }
}

/// The Merkle root over a transaction list's ids, in order.
pub fn compute_tx_root(transactions: &[SignedTransaction]) -> Hash {
    let leaves: Vec<Hash> = transactions.iter().map(SignedTransaction::id).collect();
    merkle_root(&leaves)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::{Action, Transaction};
    use sov_crypto::Keypair;
    use sov_primitives::Balance;

    fn signed(seed: [u8; 32], nonce: u64) -> SignedTransaction {
        let kp = Keypair::from_seed(seed);
        let tx = Transaction {
            signer: AccountId::new("usa.reserve.sov").unwrap(),
            public_key: kp.public_key(),
            nonce,
            action: Action::Transfer {
                to: AccountId::new("ecb.reserve.sov").unwrap(),
                amount: Balance::from_sov(1).unwrap(),
            },
        };
        SignedTransaction::sign(tx, &kp).unwrap()
    }

    fn block_with(txs: Vec<SignedTransaction>) -> Block {
        Block::assemble(
            BlockHeight::new(1),
            Hash::digest(b"parent"),
            Hash::digest(b"state"),
            Hash::digest(b"receipts"),
            1_700_000_000_000,
            AccountId::new("val01.node.sov").unwrap(),
            txs,
        )
    }

    #[test]
    fn assembled_tx_root_matches() {
        let block = block_with(vec![signed([1; 32], 0), signed([1; 32], 1)]);
        assert!(block.tx_root_matches());
    }

    #[test]
    fn empty_block_has_empty_merkle_root() {
        let block = block_with(vec![]);
        assert_eq!(block.header.tx_root, merkle_root(&[]));
        assert!(block.tx_root_matches());
    }

    #[test]
    fn tampered_body_breaks_tx_root() {
        let mut block = block_with(vec![signed([1; 32], 0)]);
        // Swap in a different transaction without updating the header root.
        block.transactions[0] = signed([1; 32], 42);
        assert!(!block.tx_root_matches());
    }

    #[test]
    fn detects_invalid_signature() {
        let mut block = block_with(vec![signed([1; 32], 0)]);
        assert!(block.all_signatures_valid());
        block.transactions[0].transaction.nonce = 999; // invalidates signature
        assert!(!block.all_signatures_valid());
    }

    #[test]
    fn header_hash_is_content_sensitive() {
        let a = block_with(vec![signed([1; 32], 0)]);
        let mut b = a.clone();
        b.header.state_root = Hash::digest(b"different state");
        assert_eq!(a.hash(), a.header.hash());
        assert_ne!(a.hash(), b.hash());
    }

    #[test]
    fn genesis_detection() {
        let mut block = block_with(vec![]);
        block.header.height = BlockHeight::GENESIS;
        assert!(block.is_genesis());
    }
}
