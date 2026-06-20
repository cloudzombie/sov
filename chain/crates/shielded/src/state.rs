//! Shielded-pool **consensus state**: the note-commitment tree, the nullifier
//! set, and the set of anchors the chain has held.
//!
//! This is the authoritative state a validator maintains for the shielded pool,
//! and that a block commits to (its [`ShieldedState::commitment`] folds into the
//! block's state root). It holds exactly what consensus needs to validate a
//! shielded action:
//!
//! - the **note-commitment tree** (an append-only Sinsemilla Merkle tree over
//!   note commitments, via Orchard's [`MerkleHashOrchard`]); its current root is
//!   the [`Anchor`];
//! - the set of **anchors** the chain has ever held, so a spend may reference a
//!   recent root (its zero-knowledge proof is checked against that anchor);
//! - the set of spent **nullifiers**, so a note can never be spent twice.
//!
//! Witnessing individual notes (building the Merkle path a *spender* needs) is a
//! wallet concern and lives outside consensus — the chain only ever appends and
//! reads the root, which is all [`Frontier`] provides.

use std::collections::BTreeSet;

use incrementalmerkletree::frontier::Frontier;
use orchard::note::{ExtractedNoteCommitment, Nullifier};
use orchard::tree::{Anchor, MerkleHashOrchard};
use orchard::NOTE_COMMITMENT_TREE_DEPTH;

use crate::pool::ShieldedBundle;
use crate::ShieldedError;

/// Depth of the Orchard note-commitment tree (32), as the `u8` const the
/// [`Frontier`] type parameterizes on.
const DEPTH: u8 = NOTE_COMMITMENT_TREE_DEPTH as u8;

/// The shielded pool's consensus state.
#[derive(Clone)]
pub struct ShieldedState {
    /// Append-only note-commitment tree; its root is the current anchor.
    tree: Frontier<MerkleHashOrchard, DEPTH>,
    /// Every anchor (tree root) the chain has held, including the empty-tree
    /// root, so a spend may reference any past root.
    anchors: BTreeSet<[u8; 32]>,
    /// Spent-note nullifiers; an entry here means that note is spent.
    nullifiers: BTreeSet<[u8; 32]>,
    /// Note commitments in append order. Kept so the state can be snapshotted and
    /// faithfully reconstructed (the `Frontier` exposes only the root, not its
    /// leaves), which `Ledger` persistence relies on.
    commitments: Vec<[u8; 32]>,
}

impl Default for ShieldedState {
    fn default() -> Self {
        Self::new()
    }
}

impl ShieldedState {
    /// A fresh, empty shielded pool. The empty-tree root is recorded as a known
    /// anchor, so the genesis state already has a valid (empty) anchor.
    pub fn new() -> Self {
        let tree = Frontier::<MerkleHashOrchard, DEPTH>::empty();
        let mut anchors = BTreeSet::new();
        anchors.insert(Anchor::from(tree.root()).to_bytes());
        ShieldedState {
            tree,
            anchors,
            nullifiers: BTreeSet::new(),
            commitments: Vec::new(),
        }
    }

    /// The current note-commitment tree root.
    pub fn anchor(&self) -> Anchor {
        Anchor::from(self.tree.root())
    }

    /// Whether `anchor` is a root the chain has held — the precondition for
    /// accepting a spend that references it.
    pub fn anchor_is_known(&self, anchor: &Anchor) -> bool {
        self.anchors.contains(&anchor.to_bytes())
    }

    /// Whether `nf` has already been spent (a double-spend if seen again).
    pub fn nullifier_seen(&self, nf: &Nullifier) -> bool {
        self.nullifiers.contains(&nf.to_bytes())
    }

    /// The number of note commitments appended to the tree.
    pub fn note_count(&self) -> u64 {
        self.commitments.len() as u64
    }

    /// Whether the pool has never been touched — no notes and no nullifiers. An
    /// empty pool contributes nothing to the ledger commitment, so a chain with
    /// no shielded activity has exactly the state root it would without the pool.
    pub fn is_empty(&self) -> bool {
        self.commitments.is_empty() && self.nullifiers.is_empty()
    }

    /// Append a note commitment, advancing the tree and recording the resulting
    /// anchor. Errors only if the tree is full (2^32 notes — practically never).
    pub fn add_commitment(&mut self, cmx: &ExtractedNoteCommitment) -> Result<(), ShieldedError> {
        if !self.tree.append(MerkleHashOrchard::from_cmx(cmx)) {
            return Err(ShieldedError::TreeFull);
        }
        self.commitments.push(cmx.to_bytes());
        self.anchors.insert(self.anchor().to_bytes());
        Ok(())
    }

    /// A compact, deterministic snapshot for persistence: the note commitments in
    /// append order and the spent nullifiers (sorted). [`restore`](Self::restore)
    /// rebuilds an identical state — same tree root, anchor history, and nullifier
    /// set — so a reloaded ledger reproduces the exact shielded commitment.
    pub fn snapshot(&self) -> (Vec<[u8; 32]>, Vec<[u8; 32]>) {
        (
            self.commitments.clone(),
            self.nullifiers.iter().copied().collect(),
        )
    }

    /// Reconstruct a state from a [`snapshot`](Self::snapshot): replay the
    /// commitments (rebuilding the tree + anchor history) then the nullifiers.
    pub fn restore(
        commitments: &[[u8; 32]],
        nullifiers: &[[u8; 32]],
    ) -> Result<Self, ShieldedError> {
        let mut state = ShieldedState::new();
        for c in commitments {
            let cmx = Option::from(ExtractedNoteCommitment::from_bytes(c))
                .ok_or(ShieldedError::Decode("commitment".to_string()))?;
            state.add_commitment(&cmx)?;
        }
        for n in nullifiers {
            state.nullifiers.insert(*n);
        }
        Ok(state)
    }

    /// Record a spent nullifier; errors with [`ShieldedError::DoubleSpend`] if it
    /// was already present.
    pub fn add_nullifier(&mut self, nf: &Nullifier) -> Result<(), ShieldedError> {
        if !self.nullifiers.insert(nf.to_bytes()) {
            return Err(ShieldedError::DoubleSpend);
        }
        Ok(())
    }

    /// Apply an authorized shielded `bundle` to the state: spend its inputs (by
    /// inserting their nullifiers) and add its output note commitments.
    ///
    /// This validates and applies atomically: it first checks that no nullifier
    /// is already spent and that the bundle does not repeat a nullifier, and
    /// only then mutates — so a rejected bundle leaves the state untouched. The
    /// **caller must already have verified the bundle's proof and that its
    /// anchor is known** ([`anchor_is_known`](Self::anchor_is_known)); this
    /// method enforces the double-spend rule and grows the tree.
    pub fn apply_bundle(&mut self, bundle: &ShieldedBundle) -> Result<(), ShieldedError> {
        let nullifiers = bundle.nullifiers();

        // Validate before mutating: none already spent, none repeated in-bundle.
        let mut within = BTreeSet::new();
        for nf in &nullifiers {
            let bytes = nf.to_bytes();
            if self.nullifiers.contains(&bytes) || !within.insert(bytes) {
                return Err(ShieldedError::DoubleSpend);
            }
        }

        for nf in &nullifiers {
            self.nullifiers.insert(nf.to_bytes());
        }
        for cmx in bundle.note_commitments() {
            self.add_commitment(&cmx)?;
        }
        Ok(())
    }

    /// A deterministic digest of the authoritative shielded state — the current
    /// anchor, the spent-nullifier set, and the held-anchor set — for folding
    /// into the block state root. Deterministic because the sets are ordered.
    pub fn commitment(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(b"sov-shielded-state-v1");
        h.update(&self.anchor().to_bytes());
        h.update(&(self.nullifiers.len() as u64).to_le_bytes());
        for nf in &self.nullifiers {
            h.update(nf);
        }
        h.update(&(self.anchors.len() as u64).to_le_bytes());
        for a in &self.anchors {
            h.update(a);
        }
        *h.finalize().as_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pool::{mint_to_shielded, ShieldedParams};
    use crate::ShieldedKey;

    /// A distinct, valid note commitment for tree tests, synthesized from a
    /// field element so we do not pay proof-generation cost per commitment. The
    /// value is `1 + 256·n`, which is always a canonical Pallas base element and
    /// never equals Orchard's uncommitted-leaf sentinel (the field element 2),
    /// so each is a genuinely new leaf that advances the root.
    fn cmx(n: u8) -> ExtractedNoteCommitment {
        let mut bytes = [0u8; 32];
        bytes[0] = 1;
        bytes[1] = n;
        Option::from(ExtractedNoteCommitment::from_bytes(&bytes)).expect("valid field element")
    }

    fn nf(n: u8) -> Nullifier {
        let mut bytes = [0u8; 32];
        bytes[0] = n;
        Option::from(Nullifier::from_bytes(&bytes)).expect("valid field element")
    }

    #[test]
    fn empty_state_anchor_is_the_empty_tree_anchor() {
        let state = ShieldedState::new();
        assert_eq!(state.anchor().to_bytes(), Anchor::empty_tree().to_bytes());
        assert!(state.anchor_is_known(&Anchor::empty_tree()));
        assert_eq!(state.note_count(), 0);
    }

    #[test]
    fn appending_commitments_advances_anchor_and_keeps_history() {
        let mut state = ShieldedState::new();
        let genesis = state.anchor();

        state.add_commitment(&cmx(1)).unwrap();
        let a1 = state.anchor();
        assert_ne!(
            a1.to_bytes(),
            genesis.to_bytes(),
            "anchor advances on append"
        );
        assert_eq!(state.note_count(), 1);

        state.add_commitment(&cmx(2)).unwrap();
        let a2 = state.anchor();
        assert_ne!(a2.to_bytes(), a1.to_bytes());
        assert_eq!(state.note_count(), 2);

        // Every past root remains a known anchor.
        assert!(state.anchor_is_known(&genesis));
        assert!(state.anchor_is_known(&a1));
        assert!(state.anchor_is_known(&a2));
    }

    #[test]
    fn nullifier_double_spend_is_rejected() {
        let mut state = ShieldedState::new();
        assert!(!state.nullifier_seen(&nf(7)));
        state.add_nullifier(&nf(7)).unwrap();
        assert!(state.nullifier_seen(&nf(7)));
        assert_eq!(state.add_nullifier(&nf(7)), Err(ShieldedError::DoubleSpend));
    }

    #[test]
    fn state_commitment_is_deterministic_and_changes_with_state() {
        let mut a = ShieldedState::new();
        let b = ShieldedState::new();
        assert_eq!(a.commitment(), b.commitment(), "same state -> same digest");
        let before = a.commitment();
        a.add_commitment(&cmx(3)).unwrap();
        assert_ne!(before, a.commitment(), "appending changes the digest");
        assert_eq!(a.commitment(), a.commitment(), "digest is deterministic");
    }

    #[test]
    fn applying_a_real_minted_bundle_absorbs_its_note_commitment() {
        // The one test that pays real proving cost: a genuine mint bundle's
        // output commitment must be absorbed by the tree.
        let params = ShieldedParams::build();
        let addr = ShieldedKey::from_seed([5u8; 32]).unwrap().address();
        let bundle = mint_to_shielded(&params, &addr, 50).unwrap();

        let mut state = ShieldedState::new();
        let before = state.note_count();
        state.apply_bundle(&bundle).unwrap();
        assert_eq!(
            state.note_count(),
            before + bundle.note_commitments().len() as u64,
            "every output commitment is appended",
        );
        assert!(state.anchor_is_known(&state.anchor()));
    }
}
