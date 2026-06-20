//! Wallet-side shielded operations: recovering received notes by trial
//! decryption (the "scan"), and witnessing a note so it can be spent.
//!
//! These run on the holder's side, not in consensus. The chain never decrypts
//! notes or builds witnesses — it only verifies proofs and tracks the tree root
//! and nullifiers (see [`ShieldedState`](crate::ShieldedState)).

use bridgetree::BridgeTree;
use incrementalmerkletree::frontier::Frontier;
use incrementalmerkletree::{Hashable, Position};
use orchard::note::{ExtractedNoteCommitment, Note, RandomSeed, Rho};
use orchard::note_encryption::OrchardDomain;
use orchard::tree::{Anchor, MerkleHashOrchard, MerklePath};
use orchard::value::NoteValue;
use orchard::Address;
use orchard::NOTE_COMMITMENT_TREE_DEPTH;
use zcash_note_encryption::try_note_decryption;

use crate::keys::ShieldedKey;
use crate::pool::ShieldedBundle;

const DEPTH: u8 = NOTE_COMMITMENT_TREE_DEPTH as u8;

/// Checkpoints the witnessing tree retains, for rewinding across short reorgs.
const MAX_CHECKPOINTS: usize = 100;

/// A wallet-side witnessing tree over note commitments.
///
/// Unlike the consensus [`Frontier`] (which yields only the current root), this
/// can produce a Merkle witness for **any** note the wallet has marked — not
/// just the most recent — which is what spending an arbitrary received note
/// requires. Backed by the audited `bridgetree`. The wallet appends every note
/// commitment in chain order and [`mark`](Self::mark)s the ones it owns.
pub struct NoteWitnessTree {
    tree: BridgeTree<MerkleHashOrchard, u32, DEPTH>,
}

impl Default for NoteWitnessTree {
    fn default() -> Self {
        Self::new()
    }
}

impl NoteWitnessTree {
    /// A fresh, empty witnessing tree.
    pub fn new() -> Self {
        NoteWitnessTree {
            tree: BridgeTree::new(MAX_CHECKPOINTS),
        }
    }

    /// Append a note commitment in chain order, returning its leaf position.
    /// `None` if the bytes are not a valid commitment or the tree is full.
    pub fn append(&mut self, cmx_bytes: &[u8; 32]) -> Option<u64> {
        let cmx = Option::<ExtractedNoteCommitment>::from(ExtractedNoteCommitment::from_bytes(
            cmx_bytes,
        ))?;
        if !self.tree.append(MerkleHashOrchard::from_cmx(&cmx)) {
            return None;
        }
        self.tree.current_position().map(u64::from)
    }

    /// Mark the most-recently-appended note as one to witness later (a note this
    /// wallet owns and may spend). Returns its position.
    pub fn mark(&mut self) -> Option<u64> {
        self.tree.mark().map(u64::from)
    }

    /// Build the Merkle witness (path + anchor) for a previously marked note at
    /// `position`, against the current tree root. `None` if the position was
    /// never marked or has been pruned. This is the witness a spender feeds to
    /// [`shielded_transfer`](crate::shielded_transfer).
    pub fn witness(&self, position: u64) -> Option<(MerklePath, Anchor)> {
        let auth = self.tree.witness(Position::from(position), 0).ok()?;
        let auth: [MerkleHashOrchard; NOTE_COMMITMENT_TREE_DEPTH] = auth.try_into().ok()?;
        let root = self.tree.root(0)?;
        let pos = u32::try_from(position).ok()?;
        Some((MerklePath::from_parts(pos, auth), Anchor::from(root)))
    }
}

/// A note received and decrypted by its owner — spendable once witnessed in the
/// note-commitment tree. Holds the recovered Orchard note; never serialized.
#[derive(Clone)]
pub struct ReceivedNote {
    note: Note,
}

impl ReceivedNote {
    /// The note's value, in the pool's smallest units.
    pub fn value(&self) -> u64 {
        self.note.value().inner()
    }

    /// This note's extracted commitment (32 bytes) — the leaf it occupies in the
    /// note-commitment tree. A wallet matches this against the bundle's
    /// commitments to learn the note's tree position (needed to witness it).
    pub fn commitment(&self) -> [u8; 32] {
        ExtractedNoteCommitment::from(self.note.commitment()).to_bytes()
    }

    /// This note's nullifier (32 bytes) under `key`. The chain records a
    /// nullifier when its note is spent, so a wallet compares this against the
    /// seen nullifiers to tell spent from unspent — i.e. to compute its balance.
    pub fn nullifier(&self, key: &ShieldedKey) -> [u8; 32] {
        self.note.nullifier(&key.fvk()).to_bytes()
    }

    pub(crate) fn note(&self) -> Note {
        self.note
    }

    pub(crate) fn note_value(&self) -> NoteValue {
        self.note.value()
    }

    /// Serialize the note to its raw Orchard components — `(recipient, value,
    /// rho, rseed)` — the exact parts a Zcash wallet persists for a received
    /// note. Reconstruct with [`ReceivedNote::from_parts`]. Lets a wallet store
    /// spendable notes without re-decrypting the chain.
    pub fn to_parts(&self) -> ([u8; 43], u64, [u8; 32], [u8; 32]) {
        (
            self.note.recipient().to_raw_address_bytes(),
            self.note.value().inner(),
            self.note.rho().to_bytes(),
            *self.note.rseed().as_bytes(),
        )
    }

    /// Reconstruct a note from its stored parts (see [`to_parts`](Self::to_parts)).
    /// `None` if the bytes are not a valid note (e.g. an off-curve recipient or a
    /// commitment that does not exist) — the same validity check Orchard applies.
    pub fn from_parts(
        recipient: [u8; 43],
        value: u64,
        rho: [u8; 32],
        rseed: [u8; 32],
    ) -> Option<Self> {
        let recipient =
            Option::<orchard::Address>::from(Address::from_raw_address_bytes(&recipient))?;
        let rho = Option::<Rho>::from(Rho::from_bytes(&rho))?;
        let rseed = Option::<RandomSeed>::from(RandomSeed::from_bytes(rseed, &rho))?;
        let note = Option::<Note>::from(Note::from_parts(
            recipient,
            NoteValue::from_raw(value),
            rho,
            rseed,
        ))?;
        Some(ReceivedNote { note })
    }
}

/// Recover the notes in `bundle` that belong to `key`, by trial-decrypting each
/// action with the key's incoming viewing key. Returns the notes the key can
/// spend — exactly the real wallet "scan" operation. A key that owns none of the
/// outputs gets an empty vector.
pub fn recover_outputs(key: &ShieldedKey, bundle: &ShieldedBundle) -> Vec<ReceivedNote> {
    let ivk = key.prepared_ivk();
    let mut out = Vec::new();
    for action in bundle.inner().actions().iter() {
        let domain = OrchardDomain::for_action(action);
        if let Some((note, _addr, _memo)) = try_note_decryption(&domain, &ivk, action) {
            out.push(ReceivedNote { note });
        }
    }
    out
}

/// Build a Merkle witness (path + anchor) for the **last** commitment in
/// `commitment_bytes`, treating that slice as the full, ordered set of note
/// commitments currently in the tree.
///
/// This is sufficient to spend the most-recently-added note. Witnessing an
/// arbitrary older note requires a persistent witnessing tree (e.g.
/// `bridgetree`) that marks notes as they arrive — a wallet refinement; the
/// consensus tree ([`ShieldedState`](crate::ShieldedState)) deliberately does
/// not witness. Returns `None` for an empty input or a malformed commitment.
pub fn witness_latest(commitment_bytes: &[[u8; 32]]) -> Option<(MerklePath, Anchor)> {
    if commitment_bytes.is_empty() {
        return None;
    }
    let mut frontier = Frontier::<MerkleHashOrchard, DEPTH>::empty();
    for b in commitment_bytes {
        let cmx = Option::<ExtractedNoteCommitment>::from(ExtractedNoteCommitment::from_bytes(b))?;
        if !frontier.append(MerkleHashOrchard::from_cmx(&cmx)) {
            return None; // tree full
        }
    }
    let imt_path = frontier
        .witness(|addr| Some(MerkleHashOrchard::empty_root(addr.level())))
        .ok()
        .flatten()?;
    let anchor = Anchor::from(frontier.root());
    Some((MerklePath::from(imt_path), anchor))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pool::mint_to_shielded;
    use crate::state::ShieldedState;
    use crate::transfer::unshield;
    use crate::ShieldedParams;
    use std::collections::{HashMap, HashSet};

    /// The exact wallet scan the GUI runs: from bundles in chain order,
    /// reconstruct the tree, find `key`'s notes + their positions (matched by
    /// commitment), and collect the spent-nullifier set.
    #[allow(clippy::type_complexity)]
    fn scan(
        key: &ShieldedKey,
        bundles: &[&ShieldedBundle],
    ) -> (NoteWitnessTree, Vec<(ReceivedNote, u64)>, HashSet<[u8; 32]>) {
        let mut tree = NoteWitnessTree::new();
        let mut mine: Vec<(ReceivedNote, u64)> = Vec::new();
        let mut spent: HashSet<[u8; 32]> = HashSet::new();
        for &b in bundles {
            for nf in b.nullifier_bytes() {
                spent.insert(nf);
            }
            let by_cmx: HashMap<[u8; 32], ReceivedNote> = recover_outputs(key, b)
                .into_iter()
                .map(|n| (n.commitment(), n))
                .collect();
            for cmx in b.note_commitment_bytes() {
                let pos = tree.append(&cmx).expect("append");
                if let Some(note) = by_cmx.get(&cmx) {
                    tree.mark().expect("mark");
                    mine.push((note.clone(), pos));
                }
            }
        }
        (tree, mine, spent)
    }

    fn unspent_balance(
        key: &ShieldedKey,
        mine: &[(ReceivedNote, u64)],
        spent: &HashSet<[u8; 32]>,
    ) -> u64 {
        mine.iter()
            .filter(|(n, _)| !spent.contains(&n.nullifier(key)))
            .map(|(n, _)| n.value())
            .sum()
    }

    #[test]
    fn wallet_scans_balance_then_deshields_an_arbitrary_old_note() {
        let params = ShieldedParams::build();
        let alice = ShieldedKey::from_seed([7u8; 32]).unwrap();
        let bob = ShieldedKey::from_seed([8u8; 32]).unwrap();

        // Three shields applied to consensus in chain order: alice 30, bob 99
        // (a decoy alice cannot decrypt), alice 70.
        let mut state = ShieldedState::new();
        let b0 = mint_to_shielded(&params, &alice.address(), 30).unwrap();
        let b1 = mint_to_shielded(&params, &bob.address(), 99).unwrap();
        let b2 = mint_to_shielded(&params, &alice.address(), 70).unwrap();
        for b in [&b0, &b1, &b2] {
            state.apply_bundle(b).unwrap();
        }

        // Alice scans: she owns exactly two notes (30 + 70); none spent.
        let (tree, mine, spent) = scan(&alice, &[&b0, &b1, &b2]);
        assert_eq!(mine.len(), 2, "alice recovers her two notes, not bob's");
        assert_eq!(unspent_balance(&alice, &mine, &spent), 100);

        // De-shield the 30-note — an OLD note (position 0), not the tip — by
        // witnessing its position; consensus accepts it (anchor is a held root,
        // nullifier is fresh, proof verifies).
        let (note, pos) = mine.iter().find(|(n, _)| n.value() == 30).cloned().unwrap();
        let (path, anchor) = tree.witness(pos).expect("witness the old note");
        let out = unshield(&params, &alice, &note, path, anchor).unwrap();
        assert!(out.verify(&params), "de-shield proof verifies");
        state
            .apply_bundle(&out)
            .expect("consensus accepts the de-shield (known anchor, fresh nullifier)");

        // Re-scan with the de-shield included: the 30-note's nullifier is now
        // seen, so alice's unspent pool balance is 70.
        let (_t, mine2, spent2) = scan(&alice, &[&b0, &b1, &b2, &out]);
        assert_eq!(unspent_balance(&alice, &mine2, &spent2), 70);
    }

    #[test]
    fn scan_after_a_shielded_transfer_with_change_drops_the_spent_note() {
        use crate::transfer::shielded_transfer_with_change;

        let params = ShieldedParams::build();
        let dev = ShieldedKey::from_seed([3u8; 32]).unwrap();
        let founder = ShieldedKey::from_seed([4u8; 32]).unwrap();

        // Dev shields 100 into the pool.
        let mut state = ShieldedState::new();
        let shield = mint_to_shielded(&params, &dev.address(), 100).unwrap();
        state.apply_bundle(&shield).unwrap();

        // Dev scans: one note, 100 unspent.
        let (tree, mine, spent) = scan(&dev, &[&shield]);
        assert_eq!(unspent_balance(&dev, &mine, &spent), 100);
        let (note, pos) = mine.first().cloned().unwrap();
        let (path, anchor) = tree.witness(pos).expect("witness dev's note");

        // Dev sends 40 privately to founder; 60 change returns to dev.
        let transfer = shielded_transfer_with_change(
            &params,
            &dev,
            &note,
            path,
            anchor,
            &founder.address(),
            40,
        )
        .unwrap();
        state.apply_bundle(&transfer).unwrap();

        // THE BUG UNDER TEST: after the transfer, dev's ORIGINAL 100-note must be
        // gone (its nullifier is now published) and only the 60 change remains —
        // the note must NOT "stay behind".
        let (_t, dmine, dspent) = scan(&dev, &[&shield, &transfer]);
        assert_eq!(
            unspent_balance(&dev, &dmine, &dspent),
            60,
            "dev keeps only the change; the spent note must not linger"
        );
        // Founder receives exactly the 40.
        let (_t2, fmine, fspent) = scan(&founder, &[&shield, &transfer]);
        assert_eq!(unspent_balance(&founder, &fmine, &fspent), 40);
    }
}
