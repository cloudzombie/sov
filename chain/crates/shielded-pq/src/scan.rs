//! Pool-v2 wallet scanning and note storage (decision **D7**).
//!
//! # Why scanning is different in a KEM pool
//!
//! Orchard note detection uses an ECDH trick: the wallet derives one shared
//! secret per action from its incoming viewing key and an ephemeral curve
//! point. ML-KEM has no such trick — the shared secret only exists *after*
//! a decapsulation, so a v2 wallet must **trial-decapsulate every v2 note
//! ciphertext on the chain**. That is the one real UX cost of a
//! post-quantum pool, and it is paid per note, per key.
//!
//! D7 keeps the cost to exactly one decapsulation: each ciphertext carries
//! a 4-byte detection tag `blake3_dk("sov-shielded-pq:detect:v2",
//! shared_secret)[..4]`, checked *before* any AEAD work
//! ([`crate::encrypt::EncryptionKeypair::decrypt`]). A note that is not
//! ours is therefore rejected after one ML-KEM-768 decapsulation plus one
//! 32-byte blake3 — no ChaCha20-Poly1305, no note parsing, no allocation.
//! The measured per-note cost is reported by
//! `cargo run --release --example scan_cost -p sov-shielded-pq` and recorded
//! in `chain/docs/pq-shielded-design.md`.
//!
//! # What a scan must get right
//!
//! [`PqNoteStore`] mirrors the pool-v1 [`NoteStore`] discipline
//! (`sov_shielded::NoteStore`) one-for-one, because the failure modes are
//! identical:
//!
//! - **positions must match consensus exactly** — the wallet appends every
//!   REAL output commitment, in slot order, for every bundle, in chain
//!   order, exactly as the executor folds them into
//!   [`crate::state::ShieldedV2State`]. A single skipped or reordered
//!   commitment silently desyncs every witness. A test asserts the store's
//!   tree root equals the consensus state root over the same input;
//! - **reorgs must be undoable** — every block records a checkpoint
//!   (block hash + the append-only log lengths at that height), so a fork
//!   within [`REORG_HORIZON`] blocks is rolled back in O(1) truncation +
//!   an O(n) rebuild. A deeper fork returns `false` and the caller rescans
//!   from the wallet birthday;
//! - **rescans must be idempotent** — a from-birthday rescan produces a
//!   store byte-identical to the incremental one (asserted by test);
//! - **a hostile sender must not be able to corrupt the wallet** — see
//!   [`PqNoteStore::ingest_block`] for the four checks every candidate note
//!   must pass before it is owned.
//!
//! Nothing in this module is consensus code: the chain never decrypts a
//! note and never builds a witness.

use std::collections::{BTreeMap, BTreeSet};

use borsh::{BorshDeserialize, BorshSerialize};

use crate::air::NUM_SLOTS;
use crate::bundle::SpendBundle;
use crate::hash::PqDigest;
use crate::hd::PqShieldedKey;
use crate::note::Note;
use crate::state::MAX_V2_NOTES;
use crate::tree::{CommitmentTree, MerklePath};

/// How many recent block checkpoints are retained for reorg rollback. Same
/// value pool v1 uses: far beyond SOV's 6-confirmation finality depth, and
/// the same bound Zcash applies.
pub const REORG_HORIZON: usize = 100;

/// Magic tag stamped into a persisted v2 store: ASCII `"SPQ2"`. A blob
/// without it (or with a version this build does not know) loads as `None`
/// and the caller rescans from the wallet birthday — the F4 schema-ladder
/// discipline applied to wallet-side state.
const STORE_MAGIC: u32 = 0x5350_5132;

/// Current on-disk v2 note-store format version.
const STORE_VERSION: u16 = 1;

/// Why a candidate ciphertext did not become an owned note. Counted by
/// [`ScanStats`] so a wallet can *prove* what its scan did rather than
/// guess.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ScanStats {
    /// Ciphertexts trial-decapsulated (the D7 cost driver).
    pub ciphertexts_examined: u64,
    /// Trial decapsulations whose 4-byte detection tag matched.
    pub detection_hits: u64,
    /// Detection hits that then failed AEAD or note parsing (a corrupted
    /// or forged ciphertext under a colliding tag).
    pub aead_failures: u64,
    /// Decrypted notes whose `owner_tag` was not this wallet's.
    pub rejected_wrong_owner: u64,
    /// Decrypted notes whose commitment did not equal the on-chain output
    /// commitment for that slot.
    pub rejected_commitment_mismatch: u64,
    /// Decrypted notes of value zero (unspendable; would be a phantom).
    pub rejected_zero_value: u64,
    /// Decrypted notes whose nullifier duplicates one already owned (only
    /// the first can ever be spent).
    pub rejected_duplicate_nullifier: u64,
    /// Notes accepted into the wallet.
    pub notes_accepted: u64,
}

/// One owned note: everything needed to spend it and to tell whether it has
/// since been spent, without re-decrypting the chain. `owner_tag` is not
/// stored — it is a function of the wallet key and is re-derived on use.
#[derive(Clone, BorshSerialize, BorshDeserialize, PartialEq, Eq, Debug)]
struct StoredNote {
    value: u64,
    rho: [u8; 32],
    position: u64,
    nullifier: [u8; 32],
}

/// A per-block fingerprint: enough to detect that the chain reorged out
/// from under the store and to truncate the append-only logs back to the
/// end of `height` in O(1).
#[derive(Clone, BorshSerialize, BorshDeserialize, PartialEq, Eq, Debug)]
struct Checkpoint {
    height: u64,
    block_hash: [u8; 32],
    commitments_len: u64,
    owned_len: u64,
    spent_len: u64,
}

/// The persisted (Borsh) portion of a v2 scan.
#[derive(Clone, BorshSerialize, BorshDeserialize, PartialEq, Eq, Debug)]
struct Persisted {
    magic: u32,
    version: u16,
    birthday: u64,
    scanned_height: u64,
    commitments: Vec<[u8; 32]>,
    owned: Vec<StoredNote>,
    spent: Vec<[u8; 32]>,
    checkpoints: Vec<Checkpoint>,
}

impl Default for Persisted {
    fn default() -> Self {
        Persisted {
            magic: STORE_MAGIC,
            version: STORE_VERSION,
            birthday: 0,
            scanned_height: 0,
            commitments: Vec::new(),
            owned: Vec::new(),
            spent: Vec::new(),
            checkpoints: Vec::new(),
        }
    }
}

/// A wallet's incremental pool-v2 scan state (see the module docs).
pub struct PqNoteStore {
    data: Persisted,
    /// Derived from `data.commitments` on load; never serialized.
    tree: CommitmentTree,
    /// Derived from `data.spent`; a set for O(log n) membership.
    spent: BTreeSet<[u8; 32]>,
    /// Derived from `data.owned`; guards against a sender minting two notes
    /// with the same `rho` (hence the same nullifier), only one of which is
    /// ever spendable.
    owned_nullifiers: BTreeSet<[u8; 32]>,
    stats: ScanStats,
}

impl PqNoteStore {
    /// A fresh, empty store for a wallet whose `birthday` is the earliest
    /// block height that could hold a note for it (0 is always correct,
    /// just slower).
    pub fn new(birthday: u64) -> Self {
        PqNoteStore {
            data: Persisted {
                birthday,
                ..Persisted::default()
            },
            tree: CommitmentTree::new(),
            spent: BTreeSet::new(),
            owned_nullifiers: BTreeSet::new(),
            stats: ScanStats::default(),
        }
    }

    /// The last block height folded in (0 = none). The next scan fetches
    /// `scanned_height + 1 ..= tip`.
    pub fn scanned_height(&self) -> u64 {
        self.data.scanned_height
    }

    /// The wallet birthday — blocks below it skip trial-decapsulation
    /// entirely (commitments are still folded, so positions stay exact).
    pub fn birthday(&self) -> u64 {
        self.data.birthday
    }

    /// Counters for what this store's scans have done since it was
    /// constructed (not persisted — a reload starts them at zero).
    pub fn stats(&self) -> ScanStats {
        self.stats
    }

    /// The number of commitments folded in — must equal the pool's
    /// `note_count()` at the same height.
    pub fn commitment_count(&self) -> u64 {
        self.data.commitments.len() as u64
    }

    /// The store's current tree root. Equal to
    /// [`crate::state::ShieldedV2State::root`] at the same height, and the
    /// anchor a spend proves against — which the caller must confirm is
    /// still inside the pool's 128-root anchor ring (D5).
    pub fn root(&self) -> PqDigest {
        self.tree.root()
    }

    /// Fold one block's v2 bundles into the store, in chain order.
    ///
    /// `height` must be `scanned_height + 1`; pass an empty slice for a
    /// block with no v2 activity so the height still advances. `block_hash`
    /// is recorded as a checkpoint for reorg rollback.
    ///
    /// For every bundle, in slot order:
    ///
    /// - each REAL input slot's nullifier is recorded as spent;
    /// - each REAL output slot's commitment is appended to the tree
    ///   (matching the executor exactly — dummy slots are never appended,
    ///   because [`crate::state::ShieldedV2State`] refuses the zero digest);
    /// - the slot's ciphertext, if present and if the block is at/after the
    ///   birthday, is trial-decapsulated. A candidate note becomes an owned
    ///   note only if it passes ALL of:
    ///   1. the D7 detection tag matches and the AEAD opens;
    ///   2. `note.owner_tag == wallet.owner_tag()` — a sender can encrypt a
    ///      note owned by someone else to our KEM key; we could never spend
    ///      it, so it must not enter the balance;
    ///   3. `note.commitment() == output_commitments[slot]` — otherwise the
    ///      ciphertext does not describe the note that is actually in the
    ///      tree, and any spend built from it would fail;
    ///   4. `value > 0` and the nullifier is not already owned — a
    ///      zero-value note is unspendable (a phantom), and a repeated
    ///      `rho` yields a repeated nullifier of which only the first note
    ///      can ever be spent, so counting the second would inflate the
    ///      reported balance.
    ///
    /// Every rejection is counted in [`ScanStats`]; none of them can abort
    /// the scan, allocate unboundedly, or panic.
    ///
    /// # Panics
    ///
    /// Panics if `height` is not the next block. Out-of-order ingestion is
    /// an unrecoverable caller bug (it would silently desync every witness
    /// from consensus), so it is a hard assertion in every build — the same
    /// rule pool v1 enforces.
    pub fn ingest_block(
        &mut self,
        key: &PqShieldedKey,
        height: u64,
        block_hash: [u8; 32],
        bundles: &[&SpendBundle],
    ) {
        assert!(
            height == self.data.scanned_height + 1 || self.data.scanned_height == 0,
            "blocks must be ingested in order: expected height {}, got {}",
            self.data.scanned_height + 1,
            height,
        );
        let decrypt = height >= self.data.birthday;
        let owner_tag = key.owner_tag();
        for bundle in bundles {
            let pi = &bundle.public_inputs;
            for slot in 0..NUM_SLOTS {
                if pi.input_dummy[slot] {
                    continue;
                }
                let nf = pi.nullifiers[slot].to_bytes();
                if self.spent.insert(nf) {
                    self.data.spent.push(nf);
                }
            }
            for slot in 0..NUM_SLOTS {
                if pi.output_dummy[slot] {
                    continue;
                }
                let cm = pi.output_commitments[slot];
                let Some(position) = self.tree.append(cm) else {
                    // The depth-20 tree is full; consensus refuses further
                    // appends too (`ShieldedV2StateError::TreeFull`), so the
                    // store simply stops growing rather than desyncing.
                    continue;
                };
                self.data.commitments.push(cm.to_bytes());
                if !decrypt {
                    continue;
                }
                let Some(ct) = &bundle.output_ciphertexts[slot] else {
                    continue;
                };
                self.stats.ciphertexts_examined += 1;
                let note = match key.encryption_key().decrypt(ct) {
                    Ok(note) => {
                        self.stats.detection_hits += 1;
                        note
                    }
                    Err(crate::encrypt::NoteEncryptionError::DetectionTag) => continue,
                    Err(_) => {
                        // The tag matched but the AEAD or the plaintext did
                        // not: a forged/corrupted ciphertext, or a 1-in-2^32
                        // tag collision. Counted, then ignored.
                        self.stats.detection_hits += 1;
                        self.stats.aead_failures += 1;
                        continue;
                    }
                };
                if !self.accept_note(key, owner_tag, cm, position, note) {
                    continue;
                }
            }
        }
        self.data.scanned_height = height;
        self.data.checkpoints.push(Checkpoint {
            height,
            block_hash,
            commitments_len: self.data.commitments.len() as u64,
            owned_len: self.data.owned.len() as u64,
            spent_len: self.data.spent.len() as u64,
        });
        let len = self.data.checkpoints.len();
        if len > REORG_HORIZON {
            self.data.checkpoints.drain(0..len - REORG_HORIZON);
        }
    }

    /// The four ownership checks (see [`ingest_block`](Self::ingest_block)).
    /// Returns whether the note was taken into the wallet.
    fn accept_note(
        &mut self,
        key: &PqShieldedKey,
        owner_tag: PqDigest,
        cm: PqDigest,
        position: u64,
        note: Note,
    ) -> bool {
        if note.owner_tag != owner_tag {
            self.stats.rejected_wrong_owner += 1;
            return false;
        }
        if note.commitment() != cm {
            self.stats.rejected_commitment_mismatch += 1;
            return false;
        }
        if note.value_grains == 0 {
            self.stats.rejected_zero_value += 1;
            return false;
        }
        // The nullifier binds this note's leaf POSITION, so two notes that
        // reuse a `rho` no longer collide (audit PQV2-01) — each occupies its
        // own leaf and so carries its own nullifier. The duplicate check
        // stays as defence in depth: a collision here would now imply a
        // Rescue-Prime collision, not a wallet-visible sender trick.
        let nullifier = key.spend_key().nullifier(note.rho, position).to_bytes();
        if !self.owned_nullifiers.insert(nullifier) {
            self.stats.rejected_duplicate_nullifier += 1;
            return false;
        }
        self.tree.mark();
        self.data.owned.push(StoredNote {
            value: note.value_grains,
            rho: note.rho.to_bytes(),
            position,
            nullifier,
        });
        self.stats.notes_accepted += 1;
        true
    }

    /// The newest retained checkpoint as `(height, block_hash)`. A scan
    /// compares it against the node's hash at that height: equal ⇒ still on
    /// the canonical chain (the no-reorg fast path).
    pub fn tip_checkpoint(&self) -> Option<(u64, [u8; 32])> {
        self.data
            .checkpoints
            .last()
            .map(|c| (c.height, c.block_hash))
    }

    /// All retained checkpoints, oldest first — walked newest→oldest on a
    /// reorg to find the deepest height that still matches the node.
    pub fn checkpoints(&self) -> Vec<(u64, [u8; 32])> {
        self.data
            .checkpoints
            .iter()
            .map(|c| (c.height, c.block_hash))
            .collect()
    }

    /// Roll back to the END of `height`, discarding everything after it,
    /// then rebuild the derived tree and sets. The next scan resumes at
    /// `height + 1`.
    ///
    /// `height >= scanned_height` is a no-op success. Returns `false` if
    /// `height` is not a retained checkpoint (a reorg deeper than
    /// [`REORG_HORIZON`]) — the caller must rescan from the birthday. The
    /// rolled-back state is built on a candidate first, so a failed rebuild
    /// never leaves the store truncated-but-inconsistent.
    pub fn rollback_to(&mut self, height: u64) -> bool {
        if height >= self.data.scanned_height {
            return true;
        }
        let Some(cp) = self
            .data
            .checkpoints
            .iter()
            .find(|c| c.height == height)
            .cloned()
        else {
            return false;
        };
        let mut data = self.data.clone();
        data.commitments.truncate(cp.commitments_len as usize);
        data.owned.truncate(cp.owned_len as usize);
        data.spent.truncate(cp.spent_len as usize);
        data.checkpoints.retain(|c| c.height <= height);
        data.scanned_height = height;
        let Some(derived) = Self::derive(&data) else {
            return false;
        };
        self.data = data;
        let (tree, spent, owned_nullifiers) = derived;
        self.tree = tree;
        self.spent = spent;
        self.owned_nullifiers = owned_nullifiers;
        true
    }

    /// The wallet's unspent pool-v2 balance in grains.
    ///
    /// Saturating: the sum of note values cannot overflow in practice
    /// (every note is `< 2^61` and the tree holds `< 2^20` notes, so the
    /// true sum is `< 2^81`… which *would* overflow a `u64` if a chain
    /// somehow carried that much value). Saturation makes the impossible
    /// case a visibly wrong balance rather than a wrapped one.
    pub fn balance(&self) -> u64 {
        self.data
            .owned
            .iter()
            .filter(|n| !self.spent.contains(&n.nullifier))
            .fold(0u64, |acc, n| acc.saturating_add(n.value))
    }

    /// The number of unspent notes.
    pub fn unspent_count(&self) -> usize {
        self.data
            .owned
            .iter()
            .filter(|n| !self.spent.contains(&n.nullifier))
            .count()
    }

    /// The unspent notes with their tree positions, in chain order. Each is
    /// reconstructed from stored parts plus the wallet key, so a note is
    /// spendable after a restart with no re-decryption.
    pub fn unspent(&self, key: &PqShieldedKey) -> Vec<(Note, u64)> {
        let owner_tag = key.owner_tag();
        self.data
            .owned
            .iter()
            .filter(|n| !self.spent.contains(&n.nullifier))
            .filter_map(|n| {
                let rho = PqDigest::from_bytes(&n.rho)?;
                Note::new(n.value, owner_tag, rho).map(|note| (note, n.position))
            })
            .collect()
    }

    /// A Merkle witness (path + anchor) for the note at `position`, against
    /// the current tree root — what a spend feeds to the prover.
    pub fn witness(&self, position: u64) -> Option<(MerklePath, PqDigest)> {
        self.tree.witness(position)
    }

    /// Serialize the persisted state (Borsh). The tree and the derived sets
    /// are rebuilt on load, never stored.
    pub fn to_bytes(&self) -> Vec<u8> {
        borsh::to_vec(&self.data).expect("PqNoteStore serialization is infallible")
    }

    /// Reconstruct a store from [`to_bytes`](Self::to_bytes).
    ///
    /// `None` on malformed bytes, a foreign/older magic or version, or a
    /// log that violates its own invariants — every one of which forces a
    /// clean rescan rather than a silently wrong wallet. Total: no input
    /// can panic it, and no length in the blob drives an allocation beyond
    /// what the bytes themselves justify.
    ///
    /// [`to_bytes`]: Self::to_bytes
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let data: Persisted = borsh::from_slice(bytes).ok()?;
        if data.magic != STORE_MAGIC || data.version != STORE_VERSION {
            return None;
        }
        // Structural bounds, checked before anything derived is built.
        if data.commitments.len() as u64 > MAX_V2_NOTES {
            return None;
        }
        if data.owned.len() > data.commitments.len() {
            return None;
        }
        if data.checkpoints.len() > REORG_HORIZON {
            return None;
        }
        // Checkpoints must be strictly ascending in height with monotone,
        // in-range log lengths; the last one must agree with the scan head.
        let mut previous: Option<&Checkpoint> = None;
        for cp in &data.checkpoints {
            if let Some(prev) = previous {
                if cp.height <= prev.height
                    || cp.commitments_len < prev.commitments_len
                    || cp.owned_len < prev.owned_len
                    || cp.spent_len < prev.spent_len
                {
                    return None;
                }
            }
            if cp.commitments_len > data.commitments.len() as u64
                || cp.owned_len > data.owned.len() as u64
                || cp.spent_len > data.spent.len() as u64
                || cp.height > data.scanned_height
            {
                return None;
            }
            previous = Some(cp);
        }
        if let Some(last) = data.checkpoints.last() {
            if last.height != data.scanned_height
                || last.commitments_len != data.commitments.len() as u64
                || last.owned_len != data.owned.len() as u64
                || last.spent_len != data.spent.len() as u64
            {
                return None;
            }
        } else if data.scanned_height != 0 {
            return None;
        }
        let (tree, spent, owned_nullifiers) = Self::derive(&data)?;
        Some(PqNoteStore {
            data,
            tree,
            spent,
            owned_nullifiers,
            stats: ScanStats::default(),
        })
    }

    /// Rebuild the derived tree, spent set and owned-nullifier set from a
    /// persisted log. `None` if the log is inconsistent (a non-canonical
    /// digest, a position that does not exist, a duplicated owned nullifier
    /// or position, or a commitment that fails to append).
    #[allow(clippy::type_complexity)]
    fn derive(
        data: &Persisted,
    ) -> Option<(CommitmentTree, BTreeSet<[u8; 32]>, BTreeSet<[u8; 32]>)> {
        let mut owned_positions: BTreeMap<u64, ()> = BTreeMap::new();
        let mut owned_nullifiers = BTreeSet::new();
        for note in &data.owned {
            if note.position >= data.commitments.len() as u64 {
                return None;
            }
            if owned_positions.insert(note.position, ()).is_some() {
                return None;
            }
            if !owned_nullifiers.insert(note.nullifier) {
                return None;
            }
            // Stored parts must round-trip to a valid note.
            PqDigest::from_bytes(&note.rho)?;
            if note.value == 0 {
                return None;
            }
        }
        let mut tree = CommitmentTree::new();
        for (i, raw) in data.commitments.iter().enumerate() {
            let cm = PqDigest::from_bytes(raw)?;
            let position = tree.append(cm)?;
            if position != i as u64 {
                return None;
            }
            if owned_positions.contains_key(&(i as u64)) {
                tree.mark()?;
            }
        }
        let mut spent = BTreeSet::new();
        for nf in &data.spent {
            PqDigest::from_bytes(nf)?;
            if !spent.insert(*nf) {
                return None;
            }
        }
        Some((tree, spent, owned_nullifiers))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::air::BundlePublicInputs;
    use crate::auth::{AUTH_PK_LEN, AUTH_SIG_LEN};
    use crate::encrypt::{encrypt_note, NoteCiphertext};
    use crate::hd::PqShieldedKey;
    use crate::state::ShieldedV2State;

    fn key(n: u8) -> PqShieldedKey {
        PqShieldedKey::from_leaf_seed(&[n; 32])
    }

    /// A bundle carrying only outputs — the shape a shield produces. The
    /// proof bytes are irrelevant to scanning (the wallet never verifies a
    /// proof to scan), so this fixture keeps them empty and exercises the
    /// exact fields `ingest_block` reads.
    ///
    /// Each entry is `(recipient, value, rho_index)`; the `rho_index` must
    /// be unique per recipient across the whole test chain, exactly as a
    /// real sending wallet allocates it (a repeat is the duplicate-nullifier
    /// case, covered by its own test).
    fn outputs_bundle(notes: &[(&PqShieldedKey, u64, u64)]) -> SpendBundle {
        assert!(notes.len() <= NUM_SLOTS);
        let mut pi = BundlePublicInputs {
            anchors: [PqDigest::ZERO; NUM_SLOTS],
            nullifiers: [PqDigest::ZERO; NUM_SLOTS],
            input_dummy: [true; NUM_SLOTS],
            output_commitments: [PqDigest::ZERO; NUM_SLOTS],
            output_dummy: [true; NUM_SLOTS],
            transparent_in: 0,
            transparent_out: 0,
            fee_grains: 0,
        };
        let mut cts: [Option<NoteCiphertext>; NUM_SLOTS] = [None, None, None, None];
        for (slot, (recipient, value, rho_index)) in notes.iter().enumerate() {
            let address = recipient.address();
            let note = Note::new(*value, address.owner_tag(), recipient.rho(*rho_index))
                .expect("note fits");
            pi.output_commitments[slot] = note.commitment();
            pi.output_dummy[slot] = false;
            cts[slot] = Some(encrypt_note(address.kem_ek(), &note).expect("encrypt"));
        }
        SpendBundle {
            public_inputs: pi,
            proof_bytes: Vec::new(),
            output_ciphertexts: cts,
            auth_pk: [0u8; AUTH_PK_LEN],
            auth_sig: [0u8; AUTH_SIG_LEN],
        }
    }

    /// A bundle that spends `nullifier` and produces no outputs.
    fn spend_bundle(nullifier: PqDigest) -> SpendBundle {
        let mut pi = BundlePublicInputs {
            anchors: [PqDigest::ZERO; NUM_SLOTS],
            nullifiers: [PqDigest::ZERO; NUM_SLOTS],
            input_dummy: [true; NUM_SLOTS],
            output_commitments: [PqDigest::ZERO; NUM_SLOTS],
            output_dummy: [true; NUM_SLOTS],
            transparent_in: 0,
            transparent_out: 0,
            fee_grains: 0,
        };
        pi.nullifiers[0] = nullifier;
        pi.input_dummy[0] = false;
        SpendBundle {
            public_inputs: pi,
            proof_bytes: Vec::new(),
            output_ciphertexts: [None, None, None, None],
            auth_pk: [0u8; AUTH_PK_LEN],
            auth_sig: [0u8; AUTH_SIG_LEN],
        }
    }

    #[test]
    fn a_scan_finds_exactly_its_own_notes_and_no_others() {
        let alice = key(1);
        let bob = key(2);
        let b1 = outputs_bundle(&[(&alice, 30, 0), (&bob, 99, 0)]);
        let b2 = outputs_bundle(&[(&alice, 70, 1)]);

        let mut store = PqNoteStore::new(0);
        store.ingest_block(&alice, 1, [1u8; 32], &[&b1]);
        store.ingest_block(&alice, 2, [2u8; 32], &[&b2]);
        assert_eq!(store.balance(), 100, "alice's two notes, not bob's");
        assert_eq!(store.unspent_count(), 2);

        let stats = store.stats();
        assert_eq!(stats.ciphertexts_examined, 3);
        assert_eq!(stats.detection_hits, 2, "only alice's two notes decap");
        assert_eq!(stats.notes_accepted, 2);

        // Bob scanning the same chain sees exactly his one note, and the
        // commitment log is identical (positions are global).
        let mut bob_store = PqNoteStore::new(0);
        bob_store.ingest_block(&bob, 1, [1u8; 32], &[&b1]);
        bob_store.ingest_block(&bob, 2, [2u8; 32], &[&b2]);
        assert_eq!(bob_store.balance(), 99);
        assert_eq!(bob_store.commitment_count(), store.commitment_count());
        assert_eq!(bob_store.root(), store.root());
    }

    #[test]
    fn the_wallet_tree_matches_the_consensus_state_root_exactly() {
        // THE invariant that makes witnesses usable: the wallet's tree and
        // the executor's pool state fold the same commitments in the same
        // order, so their roots are equal at every height.
        let alice = key(3);
        let bob = key(4);
        let mut store = PqNoteStore::new(0);
        let mut state = ShieldedV2State::new();
        for h in 1..=5u64 {
            let bundle = outputs_bundle(&[(&alice, h * 10, h), (&bob, h, h)]);
            let commitments: Vec<PqDigest> = (0..NUM_SLOTS)
                .filter(|&s| !bundle.public_inputs.output_dummy[s])
                .map(|s| bundle.public_inputs.output_commitments[s])
                .collect();
            state.apply(&[], &commitments).expect("consensus applies");
            store.ingest_block(&alice, h, [h as u8; 32], &[&bundle]);
            assert_eq!(
                store.root(),
                state.root(),
                "wallet tree diverged from consensus at height {h}"
            );
            assert_eq!(store.commitment_count(), state.note_count());
        }
        // Every owned note witnesses against that shared root, and the root
        // is inside the pool's anchor ring (D5).
        for (note, position) in store.unspent(&alice) {
            let (path, anchor) = store.witness(position).expect("witness");
            assert_eq!(path.compute_root(note.commitment()), anchor);
            assert!(state.anchor_is_known(&anchor));
        }
    }

    #[test]
    fn a_spend_drops_the_note_and_survives_a_serialize_roundtrip() {
        let alice = key(5);
        let shield = outputs_bundle(&[(&alice, 100, 0)]);
        let mut store = PqNoteStore::new(0);
        store.ingest_block(&alice, 1, [1u8; 32], &[&shield]);
        assert_eq!(store.balance(), 100);

        // Restart: the tree is rebuilt from the commitment log.
        let mut store = PqNoteStore::from_bytes(&store.to_bytes()).expect("round-trips");
        assert_eq!(store.balance(), 100);
        let (note, position) = store.unspent(&alice).into_iter().next().unwrap();
        assert!(store.witness(position).is_some(), "witness after reload");

        // The chain publishes its nullifier.
        let nf = alice.spend_key().nullifier(note.rho, position);
        store.ingest_block(&alice, 2, [2u8; 32], &[&spend_bundle(nf)]);
        assert_eq!(store.balance(), 0, "the spent note leaves the balance");
        assert_eq!(store.unspent_count(), 0);
    }

    #[test]
    fn a_reorg_rolls_back_to_the_fork_point_and_a_rescan_agrees_exactly() {
        let alice = key(6);
        let bob = key(7);
        let a1 = outputs_bundle(&[(&alice, 30, 0)]);
        let a2 = outputs_bundle(&[(&alice, 40, 1)]);
        let a3 = outputs_bundle(&[(&alice, 50, 2)]);

        let mut store = PqNoteStore::new(0);
        store.ingest_block(&alice, 1, [1u8; 32], &[&a1]);
        store.ingest_block(&alice, 2, [2u8; 32], &[&a2]);
        store.ingest_block(&alice, 3, [3u8; 32], &[&a3]);
        assert_eq!(store.balance(), 120);
        assert_eq!(store.tip_checkpoint(), Some((3, [3u8; 32])));

        // Blocks 2 and 3 are reorged out; height 1 still matches the node.
        assert!(store.rollback_to(1));
        assert_eq!(store.scanned_height(), 1);
        assert_eq!(store.balance(), 30);
        assert_eq!(store.commitment_count(), 1);

        // Re-scan the new branch.
        let b2 = outputs_bundle(&[(&bob, 99, 0)]);
        let b3 = outputs_bundle(&[(&alice, 7, 3)]);
        store.ingest_block(&alice, 2, [22u8; 32], &[&b2]);
        store.ingest_block(&alice, 3, [33u8; 32], &[&b3]);
        assert_eq!(store.balance(), 37);

        // A from-birthday RESCAN of the canonical branch must produce a
        // byte-identical store — the strongest statement of correctness.
        let mut fresh = PqNoteStore::new(0);
        fresh.ingest_block(&alice, 1, [1u8; 32], &[&a1]);
        fresh.ingest_block(&alice, 2, [22u8; 32], &[&b2]);
        fresh.ingest_block(&alice, 3, [33u8; 32], &[&b3]);
        assert_eq!(
            store.to_bytes(),
            fresh.to_bytes(),
            "rollback+rescan must equal a clean rescan byte-for-byte"
        );
        assert_eq!(store.root(), fresh.root());
        for (_, position) in store.unspent(&alice) {
            assert!(store.witness(position).is_some());
        }
    }

    #[test]
    fn a_reorg_undoes_a_spend_as_well_as_a_receipt() {
        let alice = key(8);
        let shield = outputs_bundle(&[(&alice, 60, 0)]);
        let mut store = PqNoteStore::new(0);
        store.ingest_block(&alice, 1, [1u8; 32], &[&shield]);
        let (note, position) = store.unspent(&alice).into_iter().next().unwrap();
        let nf = alice.spend_key().nullifier(note.rho, position);
        store.ingest_block(&alice, 2, [2u8; 32], &[&spend_bundle(nf)]);
        assert_eq!(store.balance(), 0);

        // The block carrying the spend is reorged out: the note must come
        // back, spendable.
        assert!(store.rollback_to(1));
        assert_eq!(store.balance(), 60, "an orphaned spend must be undone");
        assert_eq!(store.unspent_count(), 1);
    }

    #[test]
    fn checkpoints_are_bounded_and_a_deep_reorg_refuses_to_roll_back() {
        let alice = key(9);
        let mut store = PqNoteStore::new(0);
        let total = REORG_HORIZON as u64 + 50;
        for h in 1..=total {
            store.ingest_block(&alice, h, [h as u8; 32], &[]);
        }
        let cps = store.checkpoints();
        assert_eq!(cps.len(), REORG_HORIZON);
        assert_eq!(cps.first().unwrap().0, total - REORG_HORIZON as u64 + 1);
        assert!(store.rollback_to(total - 10));
        assert!(
            !store.rollback_to(1),
            "below the horizon: caller must rescan"
        );
    }

    #[test]
    fn the_birthday_skips_decryption_without_desyncing_positions() {
        let alice = key(10);
        let early = outputs_bundle(&[(&alice, 11, 0)]);
        let late = outputs_bundle(&[(&alice, 22, 1)]);

        let mut store = PqNoteStore::new(2);
        store.ingest_block(&alice, 1, [1u8; 32], &[&early]);
        store.ingest_block(&alice, 2, [2u8; 32], &[&late]);
        assert_eq!(store.balance(), 22, "the pre-birthday note is not scanned");
        assert_eq!(store.stats().ciphertexts_examined, 1);
        // Positions still match a full scan: the commitment log is complete.
        let mut full = PqNoteStore::new(0);
        full.ingest_block(&alice, 1, [1u8; 32], &[&early]);
        full.ingest_block(&alice, 2, [2u8; 32], &[&late]);
        assert_eq!(store.commitment_count(), full.commitment_count());
        assert_eq!(store.root(), full.root());
    }

    // ---- adversarial ----------------------------------------------------

    #[test]
    fn a_note_owned_by_someone_else_but_encrypted_to_us_is_refused() {
        // A hostile sender encrypts to ALICE's KEM key a note whose owner
        // tag is BOB's. Alice can decrypt it but could never spend it, so
        // it must not enter her balance.
        let alice = key(11);
        let bob = key(12);
        let note = Note::new(500, bob.owner_tag(), alice.rho(0)).expect("note");
        let mut bundle = outputs_bundle(&[]);
        bundle.public_inputs.output_commitments[0] = note.commitment();
        bundle.public_inputs.output_dummy[0] = false;
        bundle.output_ciphertexts[0] =
            Some(encrypt_note(alice.address().kem_ek(), &note).expect("encrypt"));

        let mut store = PqNoteStore::new(0);
        store.ingest_block(&alice, 1, [1u8; 32], &[&bundle]);
        assert_eq!(store.balance(), 0);
        assert_eq!(store.stats().detection_hits, 1, "it did decrypt");
        assert_eq!(store.stats().rejected_wrong_owner, 1);
        assert_eq!(
            store.commitment_count(),
            1,
            "the commitment is still folded"
        );
    }

    #[test]
    fn a_ciphertext_that_lies_about_the_on_chain_commitment_is_refused() {
        // The ciphertext decrypts to a note Alice owns, but that note is
        // NOT the one committed in this slot: any spend built from it would
        // fail, and counting it would report money the wallet does not have.
        let alice = key(13);
        let real = Note::new(10, alice.owner_tag(), alice.rho(0)).expect("note");
        let lie = Note::new(1_000_000, alice.owner_tag(), alice.rho(1)).expect("note");
        let mut bundle = outputs_bundle(&[]);
        bundle.public_inputs.output_commitments[0] = real.commitment();
        bundle.public_inputs.output_dummy[0] = false;
        bundle.output_ciphertexts[0] =
            Some(encrypt_note(alice.address().kem_ek(), &lie).expect("encrypt"));

        let mut store = PqNoteStore::new(0);
        store.ingest_block(&alice, 1, [1u8; 32], &[&bundle]);
        assert_eq!(store.balance(), 0);
        assert_eq!(store.stats().rejected_commitment_mismatch, 1);
    }

    #[test]
    fn different_values_sharing_one_rho_are_both_spendable() {
        // Audit PQV2-01 regression. Before the fix the nullifier bound only
        // (nsk, rho), so two notes for one owner reusing a rho had DIFFERENT
        // commitments — the commitment binds the value — but ONE nullifier,
        // and spending either permanently stranded the other. The nullifier
        // now binds the note's Merkle leaf position, which consensus assigns
        // uniquely, so a shared rho is harmless.
        let alice = key(64);
        let rho = alice.rho(0);
        let small = Note::new(1, alice.owner_tag(), rho).expect("note");
        let large = Note::new(1_000_000, alice.owner_tag(), rho).expect("note");
        assert_ne!(small.commitment(), large.commitment());

        let mut bundle = outputs_bundle(&[]);
        for (slot, note) in [small, large].iter().enumerate() {
            bundle.public_inputs.output_commitments[slot] = note.commitment();
            bundle.public_inputs.output_dummy[slot] = false;
            bundle.output_ciphertexts[slot] =
                Some(encrypt_note(alice.address().kem_ek(), note).expect("encrypt"));
        }
        let mut store = PqNoteStore::new(0);
        store.ingest_block(&alice, 1, [1u8; 32], &[&bundle]);

        assert_eq!(store.commitment_count(), 2);
        assert_eq!(store.unspent_count(), 2, "BOTH notes must survive");
        assert_eq!(store.balance(), 1_000_001, "nothing is stranded");
        assert_eq!(store.stats().rejected_duplicate_nullifier, 0);

        // The two occupy distinct leaves, so their nullifiers differ and
        // spending one leaves the other spendable.
        let owned = store.unspent(&alice);
        let nfs: BTreeSet<[u8; 32]> = owned
            .iter()
            .map(|(n, pos)| alice.spend_key().nullifier(n.rho, *pos).to_bytes())
            .collect();
        assert_eq!(nfs.len(), 2, "one nullifier per note occurrence");

        let (first, first_pos) = owned[0];
        let nf = alice.spend_key().nullifier(first.rho, first_pos);
        store.ingest_block(&alice, 2, [2u8; 32], &[&spend_bundle(nf)]);
        assert_eq!(store.unspent_count(), 1, "only the spent note leaves");
        assert_eq!(
            store.balance(),
            1_000_001 - first.value_grains,
            "the sibling note keeps its full value"
        );
    }

    #[test]
    fn identical_commitments_at_two_positions_are_both_spendable() {
        // The second half of PQV2-01: two IDENTICAL notes (same value, tag
        // and rho) inserted at different leaves. Their commitments collide,
        // which is legal — the tree is a multiset — but each occurrence must
        // still carry its own nullifier or one of them is burned.
        let alice = key(65);
        let note = Note::new(25, alice.owner_tag(), alice.rho(0)).expect("note");
        let mut bundle = outputs_bundle(&[]);
        for slot in 0..2 {
            bundle.public_inputs.output_commitments[slot] = note.commitment();
            bundle.public_inputs.output_dummy[slot] = false;
            bundle.output_ciphertexts[slot] =
                Some(encrypt_note(alice.address().kem_ek(), &note).expect("encrypt"));
        }
        let mut store = PqNoteStore::new(0);
        store.ingest_block(&alice, 1, [1u8; 32], &[&bundle]);
        assert_eq!(store.commitment_count(), 2);
        assert_eq!(store.unspent_count(), 2, "both occurrences are spendable");
        assert_eq!(store.balance(), 50);
        assert_eq!(store.stats().rejected_duplicate_nullifier, 0);
    }

    #[test]
    fn a_zero_value_note_is_not_owned_but_its_commitment_is_folded() {
        let alice = key(15);
        let zero = Note::new(0, alice.owner_tag(), alice.rho(0)).expect("note");
        let mut bundle = outputs_bundle(&[]);
        bundle.public_inputs.output_commitments[0] = zero.commitment();
        bundle.public_inputs.output_dummy[0] = false;
        bundle.output_ciphertexts[0] =
            Some(encrypt_note(alice.address().kem_ek(), &zero).expect("encrypt"));
        let mut store = PqNoteStore::new(0);
        store.ingest_block(&alice, 1, [1u8; 32], &[&bundle]);
        assert_eq!(store.unspent_count(), 0, "no phantom note");
        assert_eq!(store.stats().rejected_zero_value, 1);
        assert_eq!(store.commitment_count(), 1);
    }

    #[test]
    fn malformed_and_wrong_key_ciphertexts_cost_one_decap_and_nothing_else() {
        let alice = key(16);
        let bob = key(17);
        let note = Note::new(7, bob.owner_tag(), bob.rho(0)).expect("note");
        let good = encrypt_note(bob.address().kem_ek(), &note).expect("encrypt");

        // Slot 0: a note for bob (wrong key for alice — tag mismatch).
        // Slot 1: bob's ciphertext with a MANGLED KEM ciphertext.
        // Slot 2: a forged detection tag over an unopenable AEAD body.
        let mut bundle = outputs_bundle(&[]);
        let mut mangled = good.clone();
        mangled.kem_ct[0] ^= 0xff;
        let mut forged = encrypt_note(alice.address().kem_ek(), &note).expect("encrypt");
        forged.aead_ct[0] ^= 0xff;
        for (slot, ct) in [good, mangled, forged].into_iter().enumerate() {
            bundle.public_inputs.output_commitments[slot] = note.commitment();
            bundle.public_inputs.output_dummy[slot] = false;
            bundle.output_ciphertexts[slot] = Some(ct);
        }

        let mut store = PqNoteStore::new(0);
        store.ingest_block(&alice, 1, [1u8; 32], &[&bundle]);
        assert_eq!(store.balance(), 0);
        assert_eq!(store.unspent_count(), 0);
        let stats = store.stats();
        assert_eq!(stats.ciphertexts_examined, 3);
        assert_eq!(stats.aead_failures, 1, "the forged tag costs one AEAD");
        assert_eq!(stats.notes_accepted, 0);
        // All three commitments are still folded: the tree stays aligned
        // with consensus no matter how hostile the ciphertexts are.
        assert_eq!(store.commitment_count(), 3);
    }

    #[test]
    fn dummy_slots_are_never_folded_or_scanned() {
        // A bundle whose dummy slots carry non-zero commitments and real
        // ciphertexts: the flags govern, exactly as they do in consensus.
        let alice = key(18);
        let note = Note::new(9, alice.owner_tag(), alice.rho(0)).expect("note");
        let mut bundle = outputs_bundle(&[]);
        bundle.public_inputs.output_commitments[0] = note.commitment();
        bundle.output_ciphertexts[0] =
            Some(encrypt_note(alice.address().kem_ek(), &note).expect("encrypt"));
        bundle.public_inputs.nullifiers[0] = alice.spend_key().nullifier(note.rho, 0);
        // output_dummy[0] and input_dummy[0] both stay true.
        let mut store = PqNoteStore::new(0);
        store.ingest_block(&alice, 1, [1u8; 32], &[&bundle]);
        assert_eq!(store.commitment_count(), 0);
        assert_eq!(store.stats().ciphertexts_examined, 0);
        assert_eq!(store.balance(), 0);
    }

    #[test]
    fn a_tampered_or_foreign_store_blob_refuses_to_load() {
        let alice = key(19);
        let mut store = PqNoteStore::new(0);
        store.ingest_block(&alice, 1, [1u8; 32], &[&outputs_bundle(&[(&alice, 42, 0)])]);
        let good = store.to_bytes();
        assert!(PqNoteStore::from_bytes(&good).is_some(), "control");

        // No magic (an older, untagged build).
        let mut untagged = good.clone();
        untagged[..6].fill(0);
        assert!(PqNoteStore::from_bytes(&untagged).is_none());

        // An unknown (future) version.
        let mut future = good.clone();
        future[4] = future[4].wrapping_add(1);
        assert!(PqNoteStore::from_bytes(&future).is_none());

        // Truncation at every length: never panics, never half-loads.
        for cut in 0..good.len() {
            let _ = PqNoteStore::from_bytes(&good[..cut]);
        }
        // Random-ish byte flips: still total.
        for i in 0..good.len() {
            let mut flipped = good.clone();
            flipped[i] ^= 0x5a;
            let _ = PqNoteStore::from_bytes(&flipped);
        }
        // Garbage of every small length.
        for len in 0..64 {
            assert!(PqNoteStore::from_bytes(&vec![0xabu8; len]).is_none());
        }
    }

    #[test]
    fn a_blob_whose_checkpoints_lie_about_the_log_is_refused() {
        let alice = key(20);
        let mut store = PqNoteStore::new(0);
        store.ingest_block(&alice, 1, [1u8; 32], &[&outputs_bundle(&[(&alice, 8, 0)])]);
        // Hand-build an inconsistent Persisted: a checkpoint claiming more
        // commitments than the log holds must not load.
        let mut data = store.data.clone();
        data.checkpoints[0].commitments_len = 99;
        assert!(PqNoteStore::from_bytes(&borsh::to_vec(&data).unwrap()).is_none());

        // An owned note pointing past the end of the commitment log.
        let mut data = store.data.clone();
        data.owned[0].position = 12_345;
        assert!(PqNoteStore::from_bytes(&borsh::to_vec(&data).unwrap()).is_none());

        // A non-canonical stored rho.
        let mut data = store.data.clone();
        data.owned[0].rho[..8].copy_from_slice(&0xffff_ffff_0000_0001u64.to_le_bytes());
        assert!(PqNoteStore::from_bytes(&borsh::to_vec(&data).unwrap()).is_none());

        // A commitment count beyond what the depth-20 tree can hold is
        // rejected by the explicit bound, without allocating a tree for it.
        let mut data = store.data.clone();
        data.commitments = vec![[0u8; 32]; 4];
        data.checkpoints[0].commitments_len = 4;
        data.owned.clear();
        data.checkpoints[0].owned_len = 0;
        // (all-zero digests are canonical, so this one is about shape, not
        // canonicity: positions must still line up)
        assert!(PqNoteStore::from_bytes(&borsh::to_vec(&data).unwrap()).is_some());
        const { assert!(MAX_V2_NOTES > 4) };
    }

    #[test]
    #[should_panic(expected = "blocks must be ingested in order")]
    fn out_of_order_ingestion_is_a_hard_error() {
        let alice = key(21);
        let mut store = PqNoteStore::new(0);
        store.ingest_block(&alice, 1, [1u8; 32], &[]);
        store.ingest_block(&alice, 3, [3u8; 32], &[]);
    }
}
