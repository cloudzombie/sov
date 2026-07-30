//! Receipts: the recorded outcome of executing a transaction.
//!
//! A transaction expresses *intent*; a [`Receipt`] records what actually
//! happened when the execution layer applied it — success or a specific
//! failure, plus the gas it consumed. Receipts are committed to in a block via
//! [`receipts_root`], so the outcome of execution is itself part of the chain's
//! authenticated state, not just the inputs.

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use sov_crypto::{merkle_proof, merkle_root, verify_merkle_proof, MerkleStep};
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

/// The **committed** timing of a transaction — present only on receipts for a
/// transaction that used the [`Action::Timestamped`](crate::Action::Timestamped)
/// envelope (`tx-timestamp`, signal bit 3), and therefore never before that
/// deployment activates.
///
/// # What is committed, and why only this
///
/// Consensus may commit ONLY values that every node derives identically from
/// block data — otherwise two honest nodes compute different `receipts_root`es
/// and the chain splits. That rule decides the whole shape of this struct:
///
/// - `created_at_ms` **is** committed. It lives inside the SIGNED transaction,
///   so it is the same bytes on every node, and consensus has already bounded it
///   against the including block's `timestamp_ms` (see
///   [`TX_TIMESTAMP_FUTURE_TOLERANCE_MS`](crate::TX_TIMESTAMP_FUTURE_TOLERANCE_MS)
///   / [`TX_TIMESTAMP_MAX_AGE_MS`](crate::TX_TIMESTAMP_MAX_AGE_MS)).
/// - **`first_seen` is NOT committed, ever.** When a node first heard a
///   transaction is node-subjective — it differs per node and per network
///   vantage point — so it is not a consensus value at all. It belongs in a
///   node-local index, and it lives there.
/// - **`waited_ms` is not committed because it does not need to be.** Any
///   verifier holding this receipt and the block header derives it exactly:
///   `header.timestamp_ms - created_at_ms`. Committing a value that is a pure
///   function of two already-committed values would only add bytes and a second
///   way to be inconsistent.
/// - **`waited_blocks` is NOT committed, because it is not derivable.** It would
///   need the HEIGHT at which the transaction was created, and nothing attests
///   to that: the sender declares a wall-clock time, not a height, and no rule
///   binds the two. Estimating it by dividing the wait by the block target would
///   be a fabrication — the difficulty retarget makes real block intervals vary
///   widely — so consensus does not state it. A node's local first-seen index
///   can report an observed `waited_blocks`; it is an observation, not a proof.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize,
)]
pub struct ReceiptTiming {
    /// The sender's declared creation time (Unix milliseconds), taken verbatim
    /// from the signed [`Action::Timestamped`](crate::Action::Timestamped)
    /// envelope after consensus bounded it against the including block's
    /// `timestamp_ms`. Identical on every node, hence committable.
    pub created_at_ms: u64,
}

/// The recorded result of one transaction.
///
/// **Encoding.** The derived Borsh impl is the STORAGE/wire encoding: it is
/// unambiguous inside a `Vec<Receipt>` because every field, including the
/// trailing `Option`, is self-delimiting. The CONSENSUS encoding — the preimage
/// of [`Receipt::hash`], the Merkle leaf under [`receipts_root`] — is
/// [`Receipt::consensus_bytes`] instead, which omits the `None` marker entirely
/// so that a receipt without timing hashes exactly as it did before this field
/// existed. See that method for the argument that this is still a sound
/// commitment.
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
    /// The transaction's committed creation time, present ONLY when it used the
    /// [`Action::Timestamped`](crate::Action::Timestamped) envelope — which is a
    /// hard reject until the `tx-timestamp` deployment (signal bit 3) is Active.
    /// `None` on every receipt the chain has ever produced to date, and `None`
    /// keeps [`Receipt::hash`] byte-identical to the pre-`tx-timestamp` hash.
    ///
    /// Appended LAST, and skipped in JSON when absent, so neither the consensus
    /// preimage nor the RPC shape of an ordinary receipt changes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timing: Option<ReceiptTiming>,
}

impl Receipt {
    /// The receipt's **canonical consensus encoding** — the exact preimage of
    /// [`Receipt::hash`], and therefore of the leaves under [`receipts_root`].
    ///
    /// # Why this is not just `borsh::to_vec(self)`
    ///
    /// A derived `Option` field encodes `None` as a trailing `0u8`. That single
    /// byte would change the hash of EVERY receipt the chain has ever produced,
    /// hence every historical `receipts_root`, hence every block hash — a silent
    /// hard fork, and an instantly red KAT. So the consensus encoding emits the
    /// legacy fields and then appends the timing bytes **only when timing is
    /// present**:
    ///
    /// ```text
    /// tx_id ‖ status ‖ gas_used ‖ return_data ‖ events            (timing None)
    /// tx_id ‖ status ‖ gas_used ‖ return_data ‖ events ‖ 1 ‖ ms   (timing Some)
    /// ```
    ///
    /// With `None` those are byte-for-byte the bytes the derived impl produced
    /// before the field existed.
    ///
    /// # Why it is still a sound commitment
    ///
    /// A commitment must be injective: two different receipts must never share a
    /// preimage. Each legacy field is Borsh-encoded and therefore
    /// self-delimiting, so the legacy prefix consumes an exactly determined
    /// number of bytes; the encoding is prefix-free at that boundary. What
    /// follows is either nothing (`None`) or the byte `1` plus a fixed-width
    /// `u64` (`Some`) — distinguishable by length alone, and never confusable
    /// with a continuation of the legacy portion. The map from `Receipt` to
    /// bytes is therefore injective, which is all `hash()` needs.
    ///
    /// The exhaustive destructuring below is deliberate: adding a field to
    /// `Receipt` fails to compile here, forcing whoever adds it to decide
    /// explicitly where it sits in the consensus preimage.
    pub fn consensus_bytes(&self) -> Vec<u8> {
        let Receipt {
            tx_id,
            status,
            gas_used,
            return_data,
            events,
            timing,
        } = self;
        let mut buf = Vec::new();
        // `Vec<u8>` writes are infallible, so every `expect` below is
        // unreachable; they mirror the pre-existing `Receipt::hash` contract.
        let msg = "Borsh serialization of a Receipt field into a Vec is infallible";
        BorshSerialize::serialize(tx_id, &mut buf).expect(msg);
        BorshSerialize::serialize(status, &mut buf).expect(msg);
        BorshSerialize::serialize(gas_used, &mut buf).expect(msg);
        BorshSerialize::serialize(return_data, &mut buf).expect(msg);
        BorshSerialize::serialize(events, &mut buf).expect(msg);
        if let Some(timing) = timing {
            // The `1u8` is the same present-marker the derived `Option` impl
            // uses, so a `Some` receipt's consensus bytes and its storage bytes
            // coincide. Only the `None` case diverges (by exactly the omitted
            // `0u8`), which is precisely the byte-identity we need.
            BorshSerialize::serialize(&1u8, &mut buf).expect(msg);
            BorshSerialize::serialize(timing, &mut buf).expect(msg);
        }
        buf
    }

    /// The receipt's content hash, used as a Merkle leaf in [`receipts_root`].
    /// Hashes [`Receipt::consensus_bytes`], NOT the derived Borsh encoding — see
    /// there for why the two differ and why the difference is sound.
    pub fn hash(&self) -> Hash {
        Hash::digest(&self.consensus_bytes())
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

/// An inclusion proof for one receipt under a block's `receipts_root`.
///
/// This is what turns a committed receipt into something a **light client can
/// check without trusting any node**: given the block header (which carries
/// `receipts_root`, `timestamp_ms` and `height`) and this proof, the client
/// verifies for itself that the node did not invent, alter, or omit the receipt.
/// Combined with [`ReceiptTiming::created_at_ms`] it yields a self-contained,
/// Merkle-verifiable statement of the form "this transaction declared creation
/// at `T` and was confirmed in a block timestamped `T + X`".
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct ReceiptProof {
    /// The receipt's position in the block's receipt list (transaction order).
    /// Carried for the caller's benefit — cross-checking against
    /// `sov_getBlockReceipts`, or locating the transaction — never as an input
    /// to verification, which needs only the sibling path.
    pub index: u32,
    /// The sibling path from the receipt's leaf up to the root.
    pub siblings: Vec<MerkleStep>,
}

/// The inclusion proof for `receipts[index]` under `receipts_root(receipts)`, or
/// `None` if `index` is out of range.
pub fn receipt_proof(receipts: &[Receipt], index: usize) -> Option<ReceiptProof> {
    let leaves: Vec<Hash> = receipts.iter().map(Receipt::hash).collect();
    let siblings = merkle_proof(&leaves, index)?;
    Some(ReceiptProof {
        index: index as u32,
        siblings,
    })
}

/// Whether `receipt` is committed under `root` by `proof`.
///
/// Everything a verifier needs is in the arguments — the receipt, the path, and
/// the root it read from a block header it trusts. No node, no chain state, no
/// network access. Fail-closed: a tampered receipt (including a forged
/// `timing`), a wrong sibling, or a path from a different block all return
/// `false`, because the receipt's timing is inside the hashed preimage.
pub fn verify_receipt_proof(receipt: &Receipt, proof: &ReceiptProof, root: &Hash) -> bool {
    verify_merkle_proof(&receipt.hash(), &proof.siblings, root)
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
            timing: None,
        }
    }

    /// The EXACT struct the derived Borsh impl encoded before `timing` existed.
    /// Kept as a standalone type (not a comment, not a hex blob) so the
    /// byte-identity test below compares against a real, independently derived
    /// encoding rather than against `Receipt`'s own new code.
    #[derive(BorshSerialize)]
    struct LegacyReceipt {
        tx_id: Hash,
        status: ExecutionStatus,
        gas_used: u64,
        return_data: Vec<u8>,
        events: Vec<Event>,
    }

    fn legacy_of(r: &Receipt) -> LegacyReceipt {
        LegacyReceipt {
            tx_id: r.tx_id,
            status: r.status.clone(),
            gas_used: r.gas_used,
            return_data: r.return_data.clone(),
            events: r.events.clone(),
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

    // ── `tx-timestamp`: committed timing, without disturbing anything ────────

    /// THE byte-identity guarantee, at the level it actually matters: a receipt
    /// with no timing hashes exactly the bytes the pre-`timing` derived impl
    /// produced. If this fails, every historical `receipts_root` moved and the
    /// chain silently hard-forked.
    #[test]
    fn untimed_receipt_consensus_bytes_are_byte_identical_to_the_legacy_encoding() {
        let mut r = receipt(b"a", false, 21_000);
        r.return_data = vec![7, 8, 9];
        r.events = vec![Event {
            topic: b"Transfer".to_vec(),
            data: vec![1, 2, 3],
        }];
        assert!(r.timing.is_none());

        let legacy = borsh::to_vec(&legacy_of(&r)).unwrap();
        assert_eq!(
            r.consensus_bytes(),
            legacy,
            "an untimed receipt's consensus preimage must be the legacy bytes exactly"
        );
        assert_eq!(r.hash(), Hash::digest(&legacy));

        // And the STORAGE encoding is the legacy bytes plus exactly the derived
        // `Option::None` marker — which is precisely the byte the consensus
        // encoding drops.
        let stored = borsh::to_vec(&r).unwrap();
        assert_eq!(stored.len(), legacy.len() + 1);
        assert_eq!(&stored[..legacy.len()], &legacy[..]);
        assert_eq!(stored[legacy.len()], 0u8, "Borsh encodes None as 0u8");
    }

    /// A timed receipt commits its timing: the bytes are the legacy prefix plus
    /// the present-marker and the `u64`, and the hash necessarily differs.
    #[test]
    fn timed_receipt_appends_timing_to_the_consensus_preimage() {
        let untimed = receipt(b"a", true, 21_000);
        let mut timed = untimed.clone();
        timed.timing = Some(ReceiptTiming {
            created_at_ms: 1_700_000_000_000,
        });

        let legacy = borsh::to_vec(&legacy_of(&untimed)).unwrap();
        let bytes = timed.consensus_bytes();
        assert_eq!(&bytes[..legacy.len()], &legacy[..]);
        assert_eq!(bytes.len(), legacy.len() + 1 + 8);
        assert_eq!(bytes[legacy.len()], 1u8, "the Some marker");
        assert_eq!(
            &bytes[legacy.len() + 1..],
            &1_700_000_000_000u64.to_le_bytes()[..]
        );
        assert_ne!(timed.hash(), untimed.hash(), "timing is committed");

        // For a `Some` receipt the consensus and storage encodings coincide,
        // so only the `None` case is special.
        assert_eq!(bytes, borsh::to_vec(&timed).unwrap());
    }

    /// Two receipts that differ only in their declared creation time must have
    /// different leaves — i.e. the commitment is injective over the new field,
    /// not merely appended to.
    #[test]
    fn timing_value_is_bound_not_merely_flagged() {
        let base = receipt(b"a", true, 21_000);
        let mut a = base.clone();
        let mut b = base.clone();
        a.timing = Some(ReceiptTiming {
            created_at_ms: 1_000,
        });
        b.timing = Some(ReceiptTiming {
            created_at_ms: 1_001,
        });
        assert_ne!(a.hash(), b.hash());
        assert_ne!(a.hash(), base.hash());
    }

    /// Receipts round-trip through the STORAGE encoding inside a sequence —
    /// the property a "read to end" scheme would have destroyed. The snapshot
    /// cache decodes `Vec<(u64, Vec<Receipt>)>`, so this is load-bearing.
    #[test]
    fn receipt_sequences_round_trip_through_borsh() {
        let mut timed = receipt(b"b", true, 1);
        timed.timing = Some(ReceiptTiming { created_at_ms: 42 });
        let batch = vec![
            (7u64, vec![receipt(b"a", true, 1), timed.clone()]),
            (9u64, vec![timed, receipt(b"c", false, 2)]),
        ];
        let bytes = borsh::to_vec(&batch).unwrap();
        let back: Vec<(u64, Vec<Receipt>)> = borsh::from_slice(&bytes).unwrap();
        assert_eq!(back, batch);
    }

    /// An ordinary receipt's JSON is unchanged — no `"timing": null` appears —
    /// so existing wallets/GUIs/tools parse post-change receipts identically.
    #[test]
    fn json_omits_absent_timing_and_carries_it_when_present() {
        let untimed = receipt(b"a", true, 21_000);
        let json = serde_json::to_string(&untimed).unwrap();
        assert!(!json.contains("timing"), "absent timing is skipped: {json}");
        // ...and an old receipt (no `timing` key at all) still deserializes.
        let back: Receipt = serde_json::from_str(&json).unwrap();
        assert_eq!(back, untimed);

        let mut timed = untimed;
        timed.timing = Some(ReceiptTiming {
            created_at_ms: 1_700_000_000_000,
        });
        let json = serde_json::to_string(&timed).unwrap();
        assert!(json.contains("\"created_at_ms\":1700000000000"), "{json}");
        assert_eq!(serde_json::from_str::<Receipt>(&json).unwrap(), timed);
    }

    /// The payoff, at the type level: a receipt verifies against a block's
    /// `receipts_root` with no node and no tree — and any tampering fails.
    #[test]
    fn receipt_proof_verifies_against_the_root_and_fails_closed() {
        let mut timed = receipt(b"target", true, 21_000);
        timed.timing = Some(ReceiptTiming {
            created_at_ms: 1_700_000_000_000,
        });
        let receipts = vec![
            receipt(b"a", true, 1),
            receipt(b"b", false, 2),
            timed.clone(),
            receipt(b"d", true, 4),
            receipt(b"e", true, 5),
        ];
        let root = receipts_root(&receipts);

        let proof = receipt_proof(&receipts, 2).expect("index 2 exists");
        assert_eq!(proof.index, 2);
        assert!(verify_receipt_proof(&timed, &proof, &root));

        // Every receipt in the block proves, at its own index.
        for (i, r) in receipts.iter().enumerate() {
            let p = receipt_proof(&receipts, i).unwrap();
            assert!(verify_receipt_proof(r, &p, &root), "index {i}");
        }
        assert!(receipt_proof(&receipts, receipts.len()).is_none());

        // NEGATIVE: a forged creation time is caught, because timing is inside
        // the hashed preimage.
        let mut forged = timed.clone();
        forged.timing = Some(ReceiptTiming { created_at_ms: 0 });
        assert!(!verify_receipt_proof(&forged, &proof, &root));
        // NEGATIVE: a forged status is caught.
        let mut restated = timed.clone();
        restated.status = ExecutionStatus::Failed {
            reason: "nope".into(),
        };
        assert!(!verify_receipt_proof(&restated, &proof, &root));
        // NEGATIVE: a tampered sibling is caught.
        let mut bad = proof.clone();
        bad.siblings[0].sibling = Hash::digest(b"forged sibling");
        assert!(!verify_receipt_proof(&timed, &bad, &root));
        // NEGATIVE: a proof from a different block is caught.
        let other = receipts_root(&receipts[..4]);
        assert!(!verify_receipt_proof(&timed, &proof, &other));
    }
}
