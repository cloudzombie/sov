//! Incremental, persistent wallet scan state — the Zcash light-wallet model.
//!
//! The naive scan replays the whole chain (RPC + trial-decryption) on every
//! call. A [`NoteStore`] instead persists what a wallet needs and scans only
//! **new** blocks:
//!
//! - `scanned_height` — the last block folded in, so subsequent scans start
//!   right after it (no re-fetching, no re-decrypting old blocks);
//! - the **note-commitment log** (every commitment in chain order) — enough to
//!   rebuild the global witness tree locally, so the wallet can witness any of
//!   its notes against the same root consensus holds;
//! - the wallet's **owned notes** (by their raw Orchard parts + tree position +
//!   nullifier), so they are spendable after a restart without re-decryption;
//! - the seen **nullifier set**, so spent notes drop out of the balance.
//!
//! The whole thing serializes (Borsh); the witness tree is *derived* — rebuilt
//! from the commitment log on load — so it is never persisted directly. A
//! wallet's `birthday` skips trial-decryption before the height it was created
//! (no notes can exist for it earlier), while commitments are always folded from
//! genesis so tree positions and roots match consensus exactly.

use std::collections::BTreeSet;

use borsh::{BorshDeserialize, BorshSerialize};
use orchard::tree::{Anchor, MerklePath};

use crate::keys::ShieldedKey;
use crate::pool::ShieldedBundle;
use crate::wallet::{recover_outputs, NoteWitnessTree, ReceivedNote};

/// How many recent block checkpoints to retain for reorg rollback. A reorg
/// deeper than this forces a full rebuild from the wallet birthday. 100 blocks is
/// well beyond SOV's 6-confirmation finality depth (Nakamoto consensus) and
/// matches Zcash's reorg limit, so a deeper rollback should never be needed.
const REORG_HORIZON: usize = 100;

/// Magic tag stamped into a persisted note store so a blob written by an older,
/// unversioned build is rejected on load (deserializes to `None`) and the caller
/// falls back to a fresh rescan — which heals any phantom (value-0) or failed-tx
/// contamination a pre-fix build may have stored. ASCII `"SNS1"`.
const STORE_MAGIC: u32 = 0x534e_5331;

/// Current on-disk note-store format version. Bump on any breaking change to
/// [`Persisted`]; a blob whose `magic`/`version` do not match loads as `None`,
/// forcing a clean rebuild from the wallet birthday.
const STORE_VERSION: u16 = 1;

/// One owned note, stored by its raw Orchard parts plus its tree position and
/// (precomputed) nullifier — everything needed to spend it and to tell whether
/// it has since been spent, without re-decrypting the chain.
#[derive(Clone, BorshSerialize, BorshDeserialize)]
struct StoredNote {
    recipient: [u8; 43],
    value: u64,
    rho: [u8; 32],
    rseed: [u8; 32],
    position: u64,
    nullifier: [u8; 32],
}

/// A per-block fingerprint: enough to (a) detect that the chain reorged out from
/// under the cache — the canonical block hash at `height` no longer matches —
/// and (b) roll the append-only logs back to the end of `height` in O(1) by
/// truncating to the recorded lengths. Retained as a rolling window of the most
/// recent [`REORG_HORIZON`] blocks.
#[derive(Clone, BorshSerialize, BorshDeserialize)]
struct Checkpoint {
    height: u64,
    block_hash: [u8; 32],
    commitments_len: u64,
    owned_len: u64,
    spent_len: u64,
}

/// The persisted (Borsh) portion of a wallet's shielded scan.
///
/// `magic`/`version` are the first fields so a blob written by an older,
/// unversioned build is caught on load: either Borsh mis-parses the shifted
/// layout (returning `None`), or the tag check in [`NoteStore::from_bytes`]
/// rejects the mismatch — both paths force a clean rescan.
#[derive(Clone, BorshSerialize, BorshDeserialize)]
struct Persisted {
    magic: u32,
    version: u16,
    birthday: u64,
    scanned_height: u64,
    commitments: Vec<[u8; 32]>,
    owned: Vec<StoredNote>,
    spent: Vec<[u8; 32]>,
    /// Rolling window of the most recent block fingerprints, ascending by
    /// height, for reorg detection and rollback.
    checkpoints: Vec<Checkpoint>,
}

impl Default for Persisted {
    /// A fresh, correctly-versioned store. Every construction path funnels
    /// through here (via `..Persisted::default()`), so `magic`/`version` are
    /// never left at a zeroed default that would fail its own load check.
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

/// A wallet's incremental shielded scan state (see module docs).
pub struct NoteStore {
    data: Persisted,
    /// Derived from `data.commitments` on load; never serialized.
    tree: NoteWitnessTree,
    /// Derived from `data.spent` on load (a set for O(1) membership).
    spent: BTreeSet<[u8; 32]>,
}

impl NoteStore {
    /// A fresh, empty store for a wallet whose `birthday` is the earliest block
    /// height that could hold a note for it (use 0 if unknown — always correct,
    /// just slower on the first scan).
    pub fn new(birthday: u64) -> Self {
        NoteStore {
            data: Persisted {
                birthday,
                ..Persisted::default()
            },
            tree: NoteWitnessTree::new(),
            spent: BTreeSet::new(),
        }
    }

    /// The last block height folded into this store (0 = none yet). The next scan
    /// should fetch blocks `scanned_height + 1 ..= tip`.
    pub fn scanned_height(&self) -> u64 {
        self.data.scanned_height
    }

    /// The wallet birthday — blocks below it skip trial-decryption.
    pub fn birthday(&self) -> u64 {
        self.data.birthday
    }

    /// Fold one block's shielded bundles into the store, in chain order. `height`
    /// must be `scanned_height + 1` (the next block); pass an empty slice for a
    /// block with no shielded activity so `scanned_height` still advances.
    /// `block_hash` is the canonical block id (header hash) — recorded as a
    /// checkpoint so a later scan can detect a reorg and [`rollback_to`] the fork.
    ///
    /// For each bundle: every published nullifier is recorded (spends), and every
    /// output commitment is appended to the tree (keeping global positions). A
    /// commitment the wallet's `key` can decrypt is marked and stored as a
    /// spendable owned note.
    ///
    /// [`rollback_to`]: Self::rollback_to
    pub fn ingest_block(
        &mut self,
        key: &ShieldedKey,
        height: u64,
        block_hash: [u8; 32],
        bundles: &[&ShieldedBundle],
    ) {
        // Blocks MUST be folded in chain order: the commitment/owned/spent logs
        // are append-only and their positions are global, so a gap or reorder
        // would silently desync the witness tree from consensus. Enforce it in
        // every build (a hard, always-on assertion — not a debug-only one), since
        // a violated ordering is an unrecoverable caller bug, not a data anomaly.
        assert!(
            height == self.data.scanned_height + 1 || self.data.scanned_height == 0,
            "blocks must be ingested in order: expected height {}, got {}",
            self.data.scanned_height + 1,
            height,
        );
        let decrypt = height >= self.data.birthday;
        for bundle in bundles {
            for nf in bundle.nullifier_bytes() {
                if self.spent.insert(nf) {
                    self.data.spent.push(nf);
                }
            }
            // Only trial-decrypt at/after the birthday; commitments are always
            // folded so the tree stays aligned with consensus.
            let mine: std::collections::HashMap<[u8; 32], ReceivedNote> = if decrypt {
                recover_outputs(key, bundle)
                    .into_iter()
                    .map(|n| (n.commitment(), n))
                    .collect()
            } else {
                std::collections::HashMap::new()
            };
            for cmx in bundle.note_commitment_bytes() {
                let Some(pos) = self.tree.append(&cmx) else {
                    continue;
                };
                self.data.commitments.push(cmx);
                if let Some(note) = mine.get(&cmx) {
                    // Skip a value-0 owned output. Spend selection requires
                    // `value >= amount > 0`, so a zero-value note can never be
                    // spent — its nullifier never publishes — and owning/marking
                    // it only creates a phantom note that inflates the count
                    // forever ("1 note, 0 XUS"). The commitment is still appended
                    // above, so the tree stays aligned with consensus; rescanning
                    // an existing store therefore heals any prior phantom.
                    if note.value() > 0 {
                        self.tree.mark();
                        let (recipient, value, rho, rseed) = note.to_parts();
                        self.data.owned.push(StoredNote {
                            recipient,
                            value,
                            rho,
                            rseed,
                            position: pos,
                            nullifier: note.nullifier(key),
                        });
                    }
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

    /// The newest retained checkpoint as `(height, block_hash)`, or `None` if
    /// nothing is scanned. A scan compares this against the node's hash at that
    /// height: equal ⇒ still on the canonical chain (the no-reorg fast path).
    pub fn tip_checkpoint(&self) -> Option<(u64, [u8; 32])> {
        self.data
            .checkpoints
            .last()
            .map(|c| (c.height, c.block_hash))
    }

    /// All retained checkpoints as `(height, block_hash)`, oldest first — walked
    /// newest→oldest on a reorg to find the deepest height that still matches the
    /// node (the fork point).
    pub fn checkpoints(&self) -> Vec<(u64, [u8; 32])> {
        self.data
            .checkpoints
            .iter()
            .map(|c| (c.height, c.block_hash))
            .collect()
    }

    /// Roll the store back to the END of `height` (keep ≤ height, discard
    /// everything after): truncate the commitment log, owned notes, spent set,
    /// and checkpoints to the lengths recorded at `height`, then rebuild the
    /// derived witness tree + nullifier set. The next scan resumes at
    /// `height + 1`, so an orphaned branch's notes/spends are cleanly undone.
    ///
    /// `height >= scanned_height` is a no-op success. Returns `false` if `height`
    /// predates every retained checkpoint (a reorg deeper than `REORG_HORIZON`,
    /// or not a checkpointed height) — the caller must rebuild from the birthday.
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
        // Build the rolled-back state on a candidate first, so a failed rebuild
        // never leaves the store truncated-but-inconsistent.
        let mut data = self.data.clone();
        data.commitments.truncate(cp.commitments_len as usize);
        data.owned.truncate(cp.owned_len as usize);
        data.spent.truncate(cp.spent_len as usize);
        data.checkpoints.retain(|c| c.height <= height);
        data.scanned_height = height;
        let Some((tree, spent)) = Self::derive(&data) else {
            return false;
        };
        self.data = data;
        self.tree = tree;
        self.spent = spent;
        true
    }

    /// The wallet's unspent shielded balance, in the pool's smallest units.
    pub fn balance(&self) -> u64 {
        self.data
            .owned
            .iter()
            .filter(|n| !self.spent.contains(&n.nullifier))
            .map(|n| n.value)
            .sum()
    }

    /// The number of unspent notes.
    pub fn unspent_count(&self) -> usize {
        self.data
            .owned
            .iter()
            .filter(|n| !self.spent.contains(&n.nullifier))
            .count()
    }

    /// The unspent notes, reconstructed and paired with their tree position (for
    /// witnessing). A note whose parts no longer reconstruct is skipped (cannot
    /// happen for notes this store itself ingested).
    pub fn unspent(&self) -> Vec<(ReceivedNote, u64)> {
        self.data
            .owned
            .iter()
            .filter(|n| !self.spent.contains(&n.nullifier))
            .filter_map(|n| {
                ReceivedNote::from_parts(n.recipient, n.value, n.rho, n.rseed)
                    .map(|note| (note, n.position))
            })
            .collect()
    }

    /// A Merkle witness (path + anchor) for the note at `position`, against the
    /// current tree root — what a spend feeds to the prover.
    pub fn witness(&self, position: u64) -> Option<(MerklePath, Anchor)> {
        self.tree.witness(position)
    }

    /// Serialize the persisted state (Borsh). The witness tree is rebuilt from
    /// this on [`from_bytes`](Self::from_bytes), never stored.
    pub fn to_bytes(&self) -> Vec<u8> {
        borsh::to_vec(&self.data).expect("NoteStore serialization is infallible")
    }

    /// Reconstruct a store from [`to_bytes`](Self::to_bytes): re-derive the
    /// witness tree by replaying the commitment log and re-marking owned
    /// positions, and rebuild the nullifier set. `None` on malformed bytes or a
    /// commitment that fails to append (a corrupt log).
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let data: Persisted = borsh::from_slice(bytes).ok()?;
        // Reject a blob from an older/unknown format. A pre-versioning build
        // wrote no `magic`/`version`, so its bytes either fail to parse above or
        // land here with a mismatched tag; either way we return `None` and the
        // caller rebuilds from the birthday — purging any phantom/failed-tx
        // contamination a pre-fix store may hold.
        if data.magic != STORE_MAGIC || data.version != STORE_VERSION {
            return None;
        }
        let (tree, spent) = Self::derive(&data)?;
        Some(NoteStore { data, tree, spent })
    }

    /// Rebuild the derived witness tree (replaying the commitment log + re-marking
    /// owned positions) and the nullifier set from a persisted log. `None` if a
    /// commitment fails to append (a corrupt/inconsistent log). Shared by
    /// [`from_bytes`](Self::from_bytes) and [`rollback_to`](Self::rollback_to).
    fn derive(data: &Persisted) -> Option<(NoteWitnessTree, BTreeSet<[u8; 32]>)> {
        let owned_positions: BTreeSet<u64> = data.owned.iter().map(|n| n.position).collect();
        let mut tree = NoteWitnessTree::new();
        for (i, cmx) in data.commitments.iter().enumerate() {
            let pos = tree.append(cmx)?;
            debug_assert_eq!(pos, i as u64, "commitment log is contiguous from 0");
            if owned_positions.contains(&(i as u64)) {
                tree.mark();
            }
        }
        let spent = data.spent.iter().copied().collect();
        Some((tree, spent))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pool::mint_to_shielded;
    use crate::state::ShieldedState;
    use crate::transfer::shielded_transfer_with_change;
    use crate::ShieldedParams;

    /// Fold a list of (height, bundles) blocks into a store, simulating a scan.
    /// Each block gets a synthetic, height-derived fingerprint.
    fn scan_blocks(
        store: &mut NoteStore,
        key: &ShieldedKey,
        blocks: &[(u64, Vec<&ShieldedBundle>)],
    ) {
        for (h, bundles) in blocks {
            store.ingest_block(key, *h, [*h as u8; 32], bundles);
        }
    }

    #[test]
    fn incremental_scan_matches_a_full_scan_and_survives_serialization() {
        let params = ShieldedParams::build();
        let alice = ShieldedKey::from_seed([21u8; 32]).unwrap();
        let bob = ShieldedKey::from_seed([22u8; 32]).unwrap();

        // Blocks 1..=3: shield 30 to alice, 99 to bob (decoy), 70 to alice.
        let b1 = mint_to_shielded(&params, &alice.address(), 30).unwrap();
        let b2 = mint_to_shielded(&params, &bob.address(), 99).unwrap();
        let b3 = mint_to_shielded(&params, &alice.address(), 70).unwrap();

        // Scan blocks 1 and 2 only.
        let mut store = NoteStore::new(0);
        scan_blocks(&mut store, &alice, &[(1, vec![&b1]), (2, vec![&b2])]);
        assert_eq!(store.scanned_height(), 2);
        assert_eq!(store.balance(), 30, "alice has only her first note so far");

        // Round-trip the store through bytes (simulating a restart) — the witness
        // tree is rebuilt from the commitment log.
        let store = NoteStore::from_bytes(&store.to_bytes()).expect("round-trips");
        assert_eq!(store.scanned_height(), 2);
        assert_eq!(store.balance(), 30);

        // Incrementally fold ONLY the new block 3.
        let mut store = store;
        store.ingest_block(&alice, 3, [3u8; 32], &[&b3]);
        assert_eq!(store.scanned_height(), 3);
        assert_eq!(store.balance(), 100, "now both alice notes");
        assert_eq!(store.unspent_count(), 2);

        // A from-scratch full scan of all three blocks must agree exactly.
        let mut full = NoteStore::new(0);
        scan_blocks(
            &mut full,
            &alice,
            &[(1, vec![&b1]), (2, vec![&b2]), (3, vec![&b3])],
        );
        assert_eq!(full.balance(), store.balance());
        assert_eq!(full.unspent_count(), store.unspent_count());
    }

    #[test]
    fn a_spend_drops_the_note_and_witnessing_still_works_after_reload() {
        let params = ShieldedParams::build();
        let alice = ShieldedKey::from_seed([23u8; 32]).unwrap();
        let bob = ShieldedKey::from_seed([24u8; 32]).unwrap();

        // Shield 100 to alice; apply to consensus too (for a real anchor).
        let mut state = ShieldedState::new();
        let shield = mint_to_shielded(&params, &alice.address(), 100).unwrap();
        state.apply_bundle(&shield).unwrap();

        let mut store = NoteStore::new(0);
        store.ingest_block(&alice, 1, [1u8; 32], &[&shield]);
        assert_eq!(store.balance(), 100);

        // Reload from bytes, then spend the note (witnessed from the rebuilt tree).
        let store = NoteStore::from_bytes(&store.to_bytes()).unwrap();
        let (note, pos) = store.unspent().into_iter().next().unwrap();
        let (path, anchor) = store.witness(pos).expect("witness from rebuilt tree");
        let transfer =
            shielded_transfer_with_change(&params, &alice, &note, path, anchor, &bob.address(), 40)
                .unwrap();
        state
            .apply_bundle(&transfer)
            .expect("consensus accepts the spend");

        // Fold the spend block in: alice keeps only the 60 change; bob holds 40.
        let mut store = store;
        store.ingest_block(&alice, 2, [2u8; 32], &[&transfer]);
        assert_eq!(store.balance(), 60, "spent note dropped; change remains");

        let mut bob_store = NoteStore::new(0);
        bob_store.ingest_block(&bob, 1, [1u8; 32], &[&shield]);
        bob_store.ingest_block(&bob, 2, [2u8; 32], &[&transfer]);
        assert_eq!(bob_store.balance(), 40);
    }

    #[test]
    fn a_reorg_rolls_back_to_the_fork_point_then_rescans_the_new_branch() {
        let params = ShieldedParams::build();
        let alice = ShieldedKey::from_seed([31u8; 32]).unwrap();
        let bob = ShieldedKey::from_seed([32u8; 32]).unwrap();

        // Branch A: shield 30 (h1), 40 (h2), 50 (h3), all to alice.
        let a1 = mint_to_shielded(&params, &alice.address(), 30).unwrap();
        let a2 = mint_to_shielded(&params, &alice.address(), 40).unwrap();
        let a3 = mint_to_shielded(&params, &alice.address(), 50).unwrap();

        let mut store = NoteStore::new(0);
        store.ingest_block(&alice, 1, [1u8; 32], &[&a1]);
        store.ingest_block(&alice, 2, [2u8; 32], &[&a2]);
        store.ingest_block(&alice, 3, [3u8; 32], &[&a3]);
        assert_eq!(store.balance(), 120);
        assert_eq!(store.unspent_count(), 3);
        assert_eq!(store.tip_checkpoint(), Some((3, [3u8; 32])));

        // A reorg replaces blocks 2 and 3; height 1 (hash [1;32]) still matches
        // the node, so it is the fork point. Roll back to it.
        assert!(store.rollback_to(1));
        assert_eq!(store.scanned_height(), 1);
        assert_eq!(store.balance(), 30, "only the pre-fork note survives");
        assert_eq!(store.unspent_count(), 1);

        // Re-scan the NEW branch B: 2' shields 99 to bob (not ours), 3' shields 7
        // to alice. Distinct hashes — a genuinely different branch.
        let b2 = mint_to_shielded(&params, &bob.address(), 99).unwrap();
        let b3 = mint_to_shielded(&params, &alice.address(), 7).unwrap();
        store.ingest_block(&alice, 2, [22u8; 32], &[&b2]);
        store.ingest_block(&alice, 3, [33u8; 32], &[&b3]);
        assert_eq!(store.balance(), 37, "pre-fork 30 + new-branch 7");

        // Must equal a from-scratch scan of the canonical branch [a1, b2, b3].
        let mut fresh = NoteStore::new(0);
        fresh.ingest_block(&alice, 1, [1u8; 32], &[&a1]);
        fresh.ingest_block(&alice, 2, [22u8; 32], &[&b2]);
        fresh.ingest_block(&alice, 3, [33u8; 32], &[&b3]);
        assert_eq!(store.balance(), fresh.balance());
        assert_eq!(store.unspent_count(), fresh.unspent_count());

        // Witnessing still works after the rollback+rescan (tree rebuilt twice).
        for (_, pos) in store.unspent() {
            assert!(store.witness(pos).is_some(), "witness from rebuilt tree");
        }

        // Survives a serialize round-trip with the new checkpoints in place.
        let store = NoteStore::from_bytes(&store.to_bytes()).expect("round-trips");
        assert_eq!(store.balance(), 37);
        assert_eq!(store.tip_checkpoint(), Some((3, [33u8; 32])));
    }

    #[test]
    fn checkpoints_are_bounded_and_deep_reorgs_cannot_roll_back() {
        // Empty bundles: advances height + records checkpoints without proofs.
        let key = ShieldedKey::from_seed([41u8; 32]).unwrap();
        let mut store = NoteStore::new(0);
        let total = REORG_HORIZON as u64 + 50;
        for h in 1..=total {
            store.ingest_block(&key, h, [h as u8; 32], &[]);
        }
        // Only the most recent REORG_HORIZON checkpoints are retained.
        let cps = store.checkpoints();
        assert_eq!(cps.len(), REORG_HORIZON);
        assert_eq!(cps.first().unwrap().0, total - REORG_HORIZON as u64 + 1);
        assert_eq!(cps.last().unwrap().0, total);

        // A fork within the window rolls back; one below it cannot (caller must
        // rebuild from the birthday).
        let within = total - 10;
        assert!(store.rollback_to(within));
        assert_eq!(store.scanned_height(), within);
        assert!(
            !store.rollback_to(1),
            "height 1 is pruned beyond the horizon"
        );
    }

    /// An exact-value private send (amount == the note's whole value) must leave
    /// the sender with a genuinely empty balance — no zero-value change "phantom"
    /// note. Before the `if change > 0` gate in `shielded_transfer_with_change`,
    /// this minted a value-0 change note back to the sender that the wallet
    /// stored + counted forever ("1 note, 0 XUS"), so this test failed on
    /// `unspent_count()`.
    #[test]
    fn exact_value_transfer_leaves_the_sender_with_no_phantom_note() {
        let params = ShieldedParams::build();
        let alice = ShieldedKey::from_seed([51u8; 32]).unwrap();
        let bob = ShieldedKey::from_seed([52u8; 32]).unwrap();

        // Shield 50 to alice; apply to consensus too for a real anchor.
        let mut state = ShieldedState::new();
        let shield = mint_to_shielded(&params, &alice.address(), 50).unwrap();
        state.apply_bundle(&shield).unwrap();

        let mut store = NoteStore::new(0);
        store.ingest_block(&alice, 1, [1u8; 32], &[&shield]);
        assert_eq!(store.balance(), 50);
        assert_eq!(store.unspent_count(), 1);

        // Alice sends the ENTIRE note value to bob — change is exactly 0.
        let (note, pos) = store.unspent().into_iter().next().unwrap();
        let (path, anchor) = store.witness(pos).unwrap();
        let transfer =
            shielded_transfer_with_change(&params, &alice, &note, path, anchor, &bob.address(), 50)
                .unwrap();
        state
            .apply_bundle(&transfer)
            .expect("consensus accepts the exact-value spend");

        // Fold the spend block: alice's note is spent and NO zero-value change
        // note is minted, so count and balance agree at zero.
        store.ingest_block(&alice, 2, [2u8; 32], &[&transfer]);
        assert_eq!(
            store.unspent_count(),
            0,
            "no phantom zero-value change note is owned"
        );
        assert_eq!(store.balance(), 0);

        // Bob receives the full 50 — value was preserved, not lost to the gate.
        let mut bob_store = NoteStore::new(0);
        bob_store.ingest_block(&bob, 1, [1u8; 32], &[&shield]);
        bob_store.ingest_block(&bob, 2, [2u8; 32], &[&transfer]);
        assert_eq!(bob_store.balance(), 50);
    }

    /// Ingesting a block whose owned output has value 0 must NOT increment the
    /// owned/unspent count, yet the commitment MUST still be appended so the
    /// witness tree stays aligned with consensus — proven here by the tree root
    /// (the witness anchor of an earlier note) advancing after the zero-value
    /// commitment is folded in. This heals any pre-fix phantom on rescan.
    #[test]
    fn a_value_zero_owned_output_is_not_owned_but_its_commitment_is_appended() {
        let params = ShieldedParams::build();
        let alice = ShieldedKey::from_seed([61u8; 32]).unwrap();

        // Block 1: a real 30-value note to alice at position 0.
        let real = mint_to_shielded(&params, &alice.address(), 30).unwrap();
        let mut store = NoteStore::new(0);
        store.ingest_block(&alice, 1, [1u8; 32], &[&real]);
        assert_eq!(store.balance(), 30);
        assert_eq!(store.unspent_count(), 1);
        let (_, pos0) = store.unspent().into_iter().next().unwrap();
        let (_, root_before) = store.witness(pos0).expect("witness the real note");

        // Block 2: a value-0 output that alice CAN decrypt (a mint of 0 to her).
        let zero = mint_to_shielded(&params, &alice.address(), 0).unwrap();
        store.ingest_block(&alice, 2, [2u8; 32], &[&zero]);

        // The zero-value note is not owned/counted...
        assert_eq!(
            store.unspent_count(),
            1,
            "a value-0 output must not be owned"
        );
        assert_eq!(
            store.balance(),
            30,
            "balance unchanged by the value-0 output"
        );

        // ...but its commitment WAS appended: the tree grew, so the earlier
        // note's witness anchor (the root) advanced. A skipped commitment would
        // have left the root untouched.
        let (_, root_after) = store.witness(pos0).expect("still witnessable");
        assert_ne!(
            root_before, root_after,
            "the value-0 commitment must be appended, advancing the tree root"
        );
    }

    /// A note store written by an older, unversioned build must fail to load and
    /// return `None`, so the caller falls back to a clean rescan (which purges any
    /// phantom/failed-tx contamination). A blob with an unknown version is
    /// likewise rejected; a current, correctly-tagged blob still loads.
    #[test]
    fn a_versioned_store_rejects_old_or_unknown_blobs_forcing_a_rescan() {
        let params = ShieldedParams::build();
        let alice = ShieldedKey::from_seed([71u8; 32]).unwrap();

        let shield = mint_to_shielded(&params, &alice.address(), 42).unwrap();
        let mut store = NoteStore::new(0);
        store.ingest_block(&alice, 1, [1u8; 32], &[&shield]);
        assert_eq!(store.balance(), 42);

        // Positive control: a current, correctly-tagged blob round-trips.
        let good = store.to_bytes();
        assert!(
            NoteStore::from_bytes(&good).is_some(),
            "a current blob loads"
        );

        // A pre-versioning blob carried no magic/version tag — its first bytes
        // were the birthday (0 for a fresh store), i.e. NOT our magic. Simulate
        // by clearing the tag region (magic: bytes 0..4, version: bytes 4..6).
        let mut legacy = good.clone();
        for b in legacy.iter_mut().take(6) {
            *b = 0;
        }
        assert!(
            NoteStore::from_bytes(&legacy).is_none(),
            "an untagged/old blob is rejected"
        );

        // A blob tagged with an unknown (future) version is also rejected.
        let mut future = good.clone();
        future[4] = future[4].wrapping_add(1); // bump the low byte of `version`
        assert!(
            NoteStore::from_bytes(&future).is_none(),
            "an unknown version is rejected"
        );

        // The documented fallback works: a from-birthday rescan rebuilds cleanly.
        let mut rebuilt = NoteStore::new(0);
        rebuilt.ingest_block(&alice, 1, [1u8; 32], &[&shield]);
        assert_eq!(rebuilt.balance(), 42);
        assert_eq!(rebuilt.unspent_count(), 1);
    }
}
