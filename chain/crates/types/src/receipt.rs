//! Receipts: the recorded outcome of executing a transaction.
//!
//! A transaction expresses *intent*; a [`Receipt`] records what actually
//! happened when the execution layer applied it — success or a specific
//! failure, plus the gas it consumed. Receipts are committed to in a block via
//! [`receipts_root`], so the outcome of execution is itself part of the chain's
//! authenticated state, not just the inputs.

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use sov_crypto::merkle_root;
use sov_primitives::Hash;

/// The outcome of applying a transaction.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ExecutionStatus {
    /// The transaction applied cleanly.
    Success,
    /// The transaction was rejected during execution; `reason` explains why
    /// (e.g. insufficient balance, bad nonce). Failed transactions are still
    /// recorded — they consumed gas and advanced the signer's nonce.
    Failed {
        /// Human-readable rejection reason.
        reason: String,
    },
}

/// An event emitted by a contract during execution (ABI v2). Events are part
/// of the receipt, hence committed under [`receipts_root`] — an authenticated,
/// re-executable record, not a node-local log.
#[derive(
    Clone, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize,
)]
pub struct Event {
    /// The event's topic (bounded by the VM at emission).
    pub topic: Vec<u8>,
    /// The event's payload (bounded by the VM at emission).
    pub data: Vec<u8>,
}

/// The recorded result of one transaction.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct Receipt {
    /// Id of the transaction this receipt is for.
    pub tx_id: Hash,
    /// Whether execution succeeded, and if not, why.
    pub status: ExecutionStatus,
    /// Gas consumed by execution.
    pub gas_used: u64,
    /// Return data set by a contract call (empty for every other action and
    /// for failed calls).
    pub return_data: Vec<u8>,
    /// Events emitted by a contract call, in emission order (empty for every
    /// other action and for failed calls).
    pub events: Vec<Event>,
}

impl Receipt {
    /// The receipt's content hash, used as a Merkle leaf in [`receipts_root`].
    pub fn hash(&self) -> Hash {
        Hash::digest(&borsh::to_vec(self).expect("Borsh serialization of a Receipt is infallible"))
    }

    /// Whether execution succeeded.
    pub fn succeeded(&self) -> bool {
        matches!(self.status, ExecutionStatus::Success)
    }
}

/// The Merkle root committing to an ordered list of receipts. Mirrors the
/// transaction root, so a block authenticates both what it was asked to do and
/// what resulted.
pub fn receipts_root(receipts: &[Receipt]) -> Hash {
    let leaves: Vec<Hash> = receipts.iter().map(Receipt::hash).collect();
    merkle_root(&leaves)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn receipt(tx: &[u8], ok: bool, gas: u64) -> Receipt {
        Receipt {
            tx_id: Hash::digest(tx),
            status: if ok {
                ExecutionStatus::Success
            } else {
                ExecutionStatus::Failed {
                    reason: "insufficient balance".into(),
                }
            },
            gas_used: gas,
            return_data: Vec::new(),
            events: Vec::new(),
        }
    }

    #[test]
    fn success_flag() {
        assert!(receipt(b"a", true, 21_000).succeeded());
        assert!(!receipt(b"a", false, 21_000).succeeded());
    }

    #[test]
    fn hash_is_content_sensitive() {
        assert_ne!(
            receipt(b"a", true, 21_000).hash(),
            receipt(b"a", false, 21_000).hash()
        );
        assert_ne!(
            receipt(b"a", true, 21_000).hash(),
            receipt(b"a", true, 22_000).hash()
        );
    }

    #[test]
    fn receipts_root_is_order_sensitive() {
        let r0 = receipt(b"a", true, 1);
        let r1 = receipt(b"b", true, 1);
        assert_ne!(
            receipts_root(&[r0.clone(), r1.clone()]),
            receipts_root(&[r1, r0])
        );
    }

    #[test]
    fn empty_receipts_root_is_stable() {
        assert_eq!(receipts_root(&[]), receipts_root(&[]));
    }

    #[test]
    fn json_status_is_tagged() {
        let json = serde_json::to_string(&receipt(b"a", false, 21_000)).unwrap();
        assert!(json.contains("\"status\":\"failed\""));
        assert!(json.contains("\"reason\":\"insufficient balance\""));
    }
}
