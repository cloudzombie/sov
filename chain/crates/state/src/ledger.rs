//! The ledger: the authoritative account state plus its Merkle commitment.
//!
//! A [`Ledger`] keeps two synchronized views of the same data:
//! - a `BTreeMap<AccountId, Account>` — the queryable state store, used to read
//!   and iterate accounts; and
//! - a [`SparseMerkleTree`] — the authenticated commitment, yielding a 32-byte
//!   [`state_root`](Ledger::state_root) and Merkle proofs.
//!
//! Every mutation updates both, so the root always reflects the stored state.
//! This mirrors how production chains separate a fast state database from the
//! authenticated trie that commits to it.

use std::collections::BTreeMap;
use std::path::Path;

use borsh::{BorshDeserialize, BorshSerialize};
use sov_compliance::{CompliancePolicy, SpendWindow};
use sov_crypto::PublicKey;
use sov_primitives::{AccountId, Balance, Hash};
use sov_shielded::{ShieldedBundle, ShieldedError, ShieldedState};

use crate::account::Account;
use crate::smt::{MerkleProof, SparseMerkleTree};

/// A persisted account entry.
type AccountEntry = (AccountId, Account);
/// A persisted contract-storage entry: `((contract, key), value)`.
type ContractEntry = ((AccountId, Vec<u8>), Vec<u8>);
/// A persisted hash-time-locked contract, keyed by its id.
type HtlcEntry = (Hash, Htlc);
/// A persisted native asset's issuance record, keyed by its asset id.
type TokenEntry = (Hash, TokenInfo);
/// A persisted token balance: `((asset id, holder), balance)`.
type TokenBalanceEntry = ((Hash, AccountId), Balance);
/// A persisted per-asset compliance policy, keyed by asset id.
type TokenPolicyEntry = (Hash, CompliancePolicy);
/// A persisted spend-velocity window: `((asset id, holder), window)`.
type TokenWindowEntry = ((Hash, AccountId), SpendWindow);
/// A persisted NFT collection: `(collection id, class)`.
type NftClassEntry = (Hash, NftClass);
/// A persisted NFT item: `((collection id, token id), token)`.
type NftEntry = ((Hash, Vec<u8>), NftToken);
/// A persisted multisig policy: `(account, policy)`.
type MultisigEntry = (AccountId, Multisig);

/// Domain tag for native-asset id derivation. Versioned so any future change to
/// the derivation is a *new* domain rather than a silent redefinition.
const ASSET_ID_DOMAIN: &[u8] = b"sov:asset:v1";

/// The id of the native asset `symbol` issued by `issuer`:
/// `Blake3("sov:asset:v1" ‖ issuer ‖ 0x00 ‖ symbol)`.
///
/// The derivation is **injective over (issuer, symbol)**: the domain tag is
/// fixed-length, and the `0x00` separator cannot occur inside an [`AccountId`]
/// (charset `a-z 0-9 - _ .`), so distinct (issuer, symbol) pairs always hash
/// distinct preimages. Under Blake3 collision resistance this binds every asset
/// id to exactly one issuer — issuance authorization is enforced by the hash,
/// not by a mutable registry.
pub fn token_asset_id(issuer: &AccountId, symbol: &str) -> Hash {
    let issuer = issuer.as_str().as_bytes();
    let mut buf = Vec::with_capacity(ASSET_ID_DOMAIN.len() + issuer.len() + 1 + symbol.len());
    buf.extend_from_slice(ASSET_ID_DOMAIN);
    buf.extend_from_slice(issuer);
    buf.push(0x00);
    buf.extend_from_slice(symbol.as_bytes());
    Hash::digest(&buf)
}

/// The issuance record of one native asset. The `issuer` and `symbol` are
/// immutable for the life of the asset (re-checked by `sov-verify` on every
/// transition); `issued` and `burned` are monotonic counters, so the asset's
/// circulating supply is exactly `issued − burned` — the same
/// counter-accounted conservation discipline as native SOV.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct TokenInfo {
    /// The account that created the asset — the only account whose
    /// [`token_asset_id`] derivation can reach this id, hence the only one that
    /// can ever mint it.
    pub issuer: AccountId,
    /// The asset's symbol (1–16 ASCII alphanumeric bytes), unique per issuer.
    pub symbol: String,
    /// Cumulative units ever minted. Monotonic; committed to the state root.
    pub issued: Balance,
    /// Cumulative units ever burned. Monotonic; committed to the state root.
    pub burned: Balance,
}

impl TokenInfo {
    /// The asset's circulating supply: `issued − burned`. The verifier holds
    /// `burned ≤ issued` as an invariant, so this never underflows on a valid
    /// chain; `None` if the record is corrupt.
    pub fn supply(&self) -> Option<Balance> {
        self.issued.checked_sub(self.burned)
    }
}

/// An **opt-in M-of-N threshold authorization policy** for an account. Present
/// only when an account has explicitly converted to multisig (via
/// `Action::SetMultisig`); a normal account has no policy and is single-key. When
/// present, single-key spends are disabled — every action must be approved by
/// `threshold` of the `signers` through `Action::MultisigExec`. Held in a separate
/// absent-when-empty map, so adding multisig does not change any account's
/// encoding (the genesis root is unaffected).
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, serde::Serialize)]
pub struct Multisig {
    /// The authorized signer keys (N). Order is significant: an approval refers to
    /// a signer by its index here.
    pub signers: Vec<PublicKey>,
    /// How many distinct signers must approve (M, with `1 ≤ M ≤ N`).
    pub threshold: u16,
}

/// A **non-fungible token collection** (ERC-721-style): a named set of unique
/// items bound to its `issuer`. The collection id is derived from (issuer,
/// symbol) — see [`nft_class_id`] — so under collision resistance no other
/// account can mint into it. `minted` is monotonic (count of items ever minted).
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, serde::Serialize)]
pub struct NftClass {
    /// The account that created the collection — the only one that may mint into
    /// it (the id derivation binds it).
    pub issuer: AccountId,
    /// The collection's symbol (1–32 ASCII bytes), unique per issuer.
    pub symbol: String,
    /// Items ever minted into the collection. Monotonic; committed to the root.
    pub minted: u64,
}

/// One **non-fungible token** instance: a unique item identified by
/// `(collection, token_id)`. `owner` holds it; `metadata` is opaque per-item data
/// (for SNS names this carries the resolver target). Committed to the state root.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, serde::Serialize)]
pub struct NftToken {
    /// The account that owns this item.
    pub owner: AccountId,
    /// Opaque per-item metadata (e.g. an SNS resolver target, or a content
    /// pointer). Empty by default.
    pub metadata: Vec<u8>,
    /// Block height at which the item was minted.
    pub minted_height: u64,
}

/// The resolver view of an SNS name (a non-fungible token in the reserved SNS
/// collection): who owns/controls it and when it was registered. Built from the
/// underlying [`NftToken`] for RPC/explorer consumers.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, serde::Serialize)]
pub struct NameRecord {
    /// The account this name resolves to and that controls it.
    pub owner: AccountId,
    /// Block height at which the name was (most recently) registered.
    pub registered_height: u64,
}

/// Domain tag for NFT collection-id derivation (versioned, like assets).
const NFT_CLASS_DOMAIN: &[u8] = b"sov:nft:v1";

/// The collection id of NFT `symbol` issued by `issuer`:
/// `Blake3("sov:nft:v1" ‖ issuer ‖ 0x00 ‖ symbol)`. Injective over
/// (issuer, symbol) by the same argument as [`token_asset_id`], so a collection
/// is cryptographically bound to its issuer.
pub fn nft_class_id(issuer: &AccountId, symbol: &str) -> Hash {
    let issuer = issuer.as_str().as_bytes();
    let mut buf = Vec::with_capacity(NFT_CLASS_DOMAIN.len() + issuer.len() + 1 + symbol.len());
    buf.extend_from_slice(NFT_CLASS_DOMAIN);
    buf.extend_from_slice(issuer);
    buf.push(0x00);
    buf.extend_from_slice(symbol.as_bytes());
    Hash::digest(&buf)
}

/// The reserved, protocol-level NFT collection that holds **SNS names**. Not
/// issuer-bound (no account can generic-`NftMint` into it — names are minted only
/// via [`Action::RegisterName`], which enforces the `.sov`/fee/first-come rules).
/// `Blake3("sov:sns:v1")`.
pub fn sns_class() -> Hash {
    Hash::digest(b"sov:sns:v1")
}

/// A **hash-time-locked contract** escrow — the SOV half of a trustless
/// cross-chain atomic swap. `amount` is locked out of `locker`'s balance and is
/// claimable by `recipient` only by revealing a preimage whose SHA-256 equals
/// `hashlock` (the same hash that locks the counterparty's Bitcoin/Zcash HTLC),
/// before block `timeout_height`; after the timeout it is refundable to `locker`.
/// Revealing the preimage on one chain lets the counterparty claim on the other,
/// which is what makes the swap atomic — no custodian, oracle, or bridge.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Htlc {
    /// Who locked the funds (and who is refunded after the timeout).
    pub locker: AccountId,
    /// Who may claim the funds with the correct preimage.
    pub recipient: AccountId,
    /// The escrowed amount.
    pub amount: Balance,
    /// SHA-256 of the secret preimage that unlocks the funds.
    pub hashlock: [u8; 32],
    /// Block height at/after which the locker may refund.
    pub timeout_height: u64,
}

/// A single reversible state change captured while the ledger is recording an undo
/// log (see [`Ledger::begin_undo`]). Each variant holds the **pre-image** of one
/// field write — enough to restore that field exactly. Applying a block's ops in
/// reverse order returns the ledger to its pre-block state bit-for-bit (same
/// `state_root`), which is what lets a reorg DISCONNECT blocks in O(reorg depth)
/// instead of replaying the whole chain from genesis. The log is in-memory and
/// transient (never serialized, never part of the state root).
#[derive(Clone)]
enum UndoOp {
    // `Account` is boxed because it carries the ~2 KB hybrid post-quantum public key;
    // keeping it off the inline enum keeps every journal entry small.
    Account(AccountId, Option<Box<Account>>),
    Contract(AccountId, Vec<u8>, Option<Vec<u8>>),
    Token(Hash, Option<TokenInfo>),
    TokenBalance(Hash, AccountId, Option<Balance>),
    TokenPolicy(Hash, Option<CompliancePolicy>),
    TokenWindow(Hash, AccountId, Option<SpendWindow>),
    Htlc(Hash, Option<Htlc>),
    NftClass(Hash, Option<NftClass>),
    Nft(Hash, Vec<u8>, Option<NftToken>),
    Multisig(AccountId, Option<Multisig>),
    /// `intent_id` was absent before being consumed ⇒ undo removes it.
    Intent(Hash),
    /// The whole shielded sub-state, captured before a bundle was applied.
    Shielded(Box<ShieldedState>),
    MinedEmitted(Balance),
    ShieldedValue(Balance),
    HtlcLocked(Balance),
    DeshieldWindow(u64, Balance),
}

/// A captured undo log for one block — replay it with [`Ledger::apply_undo`] to
/// disconnect that block. Ordered as the writes happened; applied in reverse.
#[derive(Clone, Default)]
pub struct UndoLog(Vec<UndoOp>);

impl UndoLog {
    /// Whether the block changed no state (e.g. an empty block's coinbase that
    /// minted nothing) — nothing to undo.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// The world state: all accounts and their Merkle commitment.
#[derive(Clone, Default)]
pub struct Ledger {
    /// In-memory undo journal: when `Some`, every state write records its pre-image
    /// here so the block can be disconnected (reorg) without a genesis replay. Never
    /// serialized; not part of the state root; cleared between blocks. `None` = off
    /// (the default — boot replay, query-only ledgers, and tests pay nothing).
    undo: Option<Vec<UndoOp>>,
    accounts: BTreeMap<AccountId, Account>,
    /// Per-contract key/value storage, keyed by `(contract account, key)`. Each
    /// entry is also committed to the Merkle tree, so contract state is part of
    /// the authenticated `state_root`.
    contract_storage: BTreeMap<(AccountId, Vec<u8>), Vec<u8>>,
    /// Cumulative SOV minted by proof-of-work mining. Monotonic, committed to the
    /// state root, and clamped by the mining budget. Tracked explicitly because it
    /// cannot be recovered from balances once minted coins move.
    mined_emitted: Balance,
    /// Net value (grains) held in the shielded pool — value that has moved from
    /// transparent balances into shielded notes (a shield), minus value that has
    /// moved back out (a de-shield). Committed to the state root and counted in
    /// [`total_supply`](Ledger::total_supply), so shielding is supply-neutral.
    shielded_value: Balance,
    /// The shielded pool's consensus state (note-commitment tree + nullifier set).
    /// Its digest folds into the state root, but only once non-empty — a chain
    /// with no shielded activity has exactly the state root it would without it.
    shielded: ShieldedState,
    /// Open hash-time-locked contracts (atomic-swap escrows), keyed by id.
    htlcs: BTreeMap<Hash, Htlc>,
    /// Total value (grains) escrowed across all open HTLCs. Counted in
    /// [`total_supply`](Ledger::total_supply), so locking/claiming is
    /// supply-neutral; committed to the state root.
    htlc_locked: Balance,
    /// Native assets, keyed by their derived asset id. Token units are a
    /// separate denomination from SOV — they never enter
    /// [`total_supply`](Ledger::total_supply); each asset carries its own
    /// conservation invariant (`sum(balances) == issued − burned`).
    tokens: BTreeMap<Hash, TokenInfo>,
    /// Token balances, keyed by `(asset id, holder)`. Zero balances are removed
    /// so the commitment stays canonical. Each entry is committed to the Merkle
    /// tree, so token holdings are part of the authenticated `state_root`.
    token_balances: BTreeMap<(Hash, AccountId), Balance>,
    /// Per-asset compliance policies (issuer-set; absent = unrestricted).
    /// Committed to the state root: enforcement is consensus, not node policy.
    token_policies: BTreeMap<Hash, CompliancePolicy>,
    /// Per-(asset, holder) rolling spend-velocity windows, used only while the
    /// asset's policy has a spend limit. Default (zero) windows are removed so
    /// the commitment stays canonical.
    token_windows: BTreeMap<(Hash, AccountId), SpendWindow>,
    /// Intent ids that have been settled or cancelled — each id is consumable
    /// exactly once (the swap analog of the shielded pool's nullifier set).
    /// Committed to the state root; monotone (never pruned).
    consumed_intents: std::collections::BTreeSet<Hash>,
    /// The shielded pool's rolling de-shield window: (window start height,
    /// grains de-shielded within it). Committed to the state root; enforced by
    /// the runtime when the policy's drain limiter is on. Defense in depth for
    /// the proof system: bounds how fast even a forged proof could drain the
    /// pool.
    deshield_window: (u64, Balance),
    /// Non-fungible token collections (ERC-721-style), keyed by collection id.
    nft_classes: BTreeMap<Hash, NftClass>,
    /// Non-fungible token items, keyed by `(collection id, token id)`. The
    /// **SNS name registry** lives here as the reserved [`sns_class`] collection
    /// (a name is the NFT whose token id is the name's bytes). Both digests fold
    /// into the state root only once non-empty — a chain with no NFTs (and no
    /// names) keeps the exact state root it would have without the feature.
    nfts: BTreeMap<(Hash, Vec<u8>), NftToken>,
    /// Opt-in M-of-N multisig policies, keyed by account. Absent for normal
    /// (single-key) accounts; its digest folds into the state root only once
    /// non-empty, so a chain with no multisig accounts has the exact root it would
    /// have without the feature.
    multisig: BTreeMap<AccountId, Multisig>,
    commitment: SparseMerkleTree,
}

impl Ledger {
    /// An empty ledger (no accounts; the empty state root).
    pub fn new() -> Self {
        Ledger::default()
    }

    /// The Merkle slot for an account: the hash of its id bytes.
    fn slot(id: &AccountId) -> Hash {
        Hash::digest(id.as_str().as_bytes())
    }

    /// The Merkle slot for a contract storage entry. Domain-separated from
    /// account slots (a `0x01` tag plus the key) so the two never collide.
    fn contract_slot(id: &AccountId, key: &[u8]) -> Hash {
        let mut buf = Vec::with_capacity(id.as_str().len() + 1 + key.len());
        buf.extend_from_slice(id.as_str().as_bytes());
        buf.push(0x01);
        buf.extend_from_slice(key);
        Hash::digest(&buf)
    }

    /// Reserved Merkle slot name for the cumulative mined-emission counter.
    const MINED_SLOT: &'static [u8] = b"sov:mined_emitted";
    /// Reserved Merkle slot name for the shielded-pool commitment digest.
    const SHIELDED_SLOT: &'static [u8] = b"sov:shielded";
    /// Reserved Merkle slot name for the net shielded-pool value counter.
    const SHIELDED_VALUE_SLOT: &'static [u8] = b"sov:shielded_value";
    /// Reserved Merkle slot name for the open-HTLC-set digest.
    const HTLC_SLOT: &'static [u8] = b"sov:htlcs";
    /// Reserved Merkle slot name for the total HTLC-escrowed value counter.
    const HTLC_LOCKED_SLOT: &'static [u8] = b"sov:htlc_locked";
    /// Reserved Merkle slot name for the rolling de-shield window.
    const DESHIELD_WINDOW_SLOT: &'static [u8] = b"sov:deshield_window";
    /// Reserved Merkle slot name for the NFT-collections digest.
    const NFT_CLASSES_SLOT: &'static [u8] = b"sov:nft_classes";
    /// Reserved Merkle slot name for the NFT-items digest (includes SNS names).
    const NFTS_SLOT: &'static [u8] = b"sov:nfts";
    /// Reserved Merkle slot name for the multisig-policies digest.
    const MULTISIG_SLOT: &'static [u8] = b"sov:multisig";

    /// A reserved Merkle slot for a protocol-level scalar (not an account or a
    /// contract entry). Domain-separated by a `0x02` tag: no [`AccountId`] preimage
    /// (charset `a-z 0-9 - _ .`, none of which is the byte `0x02`) and no contract
    /// slot (`0x01`-tagged) can collide with it.
    fn reserved_slot(name: &[u8]) -> Hash {
        let mut buf = Vec::with_capacity(1 + name.len());
        buf.push(0x02);
        buf.extend_from_slice(name);
        Hash::digest(&buf)
    }

    /// The Merkle slot for a native asset's issuance record. Domain-separated by
    /// a leading `0x03` tag (account slots start with an `AccountId` byte,
    /// contract slots embed a `0x01` tag, reserved slots a `0x02` tag), followed
    /// by the fixed-width 32-byte asset id — so distinct assets always occupy
    /// distinct slots.
    fn token_slot(asset: &Hash) -> Hash {
        let mut buf = Vec::with_capacity(1 + 32);
        buf.push(0x03);
        buf.extend_from_slice(asset.as_bytes());
        Hash::digest(&buf)
    }

    /// The Merkle slot for one holder's balance of one asset. Domain-separated
    /// by a leading `0x04` tag, then the fixed-width asset id, then the holder —
    /// fixed-width prefixes make the encoding injective.
    fn token_balance_slot(asset: &Hash, holder: &AccountId) -> Hash {
        let holder = holder.as_str().as_bytes();
        let mut buf = Vec::with_capacity(1 + 32 + holder.len());
        buf.push(0x04);
        buf.extend_from_slice(asset.as_bytes());
        buf.extend_from_slice(holder);
        Hash::digest(&buf)
    }

    /// The Merkle slot for an asset's compliance policy (`0x05` tag).
    fn token_policy_slot(asset: &Hash) -> Hash {
        let mut buf = Vec::with_capacity(1 + 32);
        buf.push(0x05);
        buf.extend_from_slice(asset.as_bytes());
        Hash::digest(&buf)
    }

    /// The Merkle slot for one holder's spend-velocity window of one asset
    /// (`0x06` tag, fixed-width asset id, then the holder — injective).
    fn token_window_slot(asset: &Hash, holder: &AccountId) -> Hash {
        let holder = holder.as_str().as_bytes();
        let mut buf = Vec::with_capacity(1 + 32 + holder.len());
        buf.push(0x06);
        buf.extend_from_slice(asset.as_bytes());
        buf.extend_from_slice(holder);
        Hash::digest(&buf)
    }

    /// The Merkle slot for a consumed intent id (`0x07` tag).
    fn intent_slot(intent_id: &Hash) -> Hash {
        let mut buf = Vec::with_capacity(1 + 32);
        buf.push(0x07);
        buf.extend_from_slice(intent_id.as_bytes());
        Hash::digest(&buf)
    }

    /// Commit a monotonic emission counter to its reserved slot. A zero value is
    /// removed, so an untouched ledger keeps the canonical empty root.
    fn commit_counter(&mut self, name: &'static [u8], value: Balance) {
        let slot = Self::reserved_slot(name);
        if value == Balance::ZERO {
            self.commitment.remove(&slot);
        } else {
            let encoded = borsh::to_vec(&value).expect("Balance serialization is infallible");
            self.commitment.insert(slot, encoded);
        }
    }

    /// Re-commit the shielded pool's digest to its reserved slot. An empty pool
    /// contributes nothing (the slot is removed), so a chain with no shielded
    /// activity keeps the exact state root it would have without the pool.
    fn recommit_shielded(&mut self) {
        let slot = Self::reserved_slot(Self::SHIELDED_SLOT);
        if self.shielded.is_empty() {
            self.commitment.remove(&slot);
        } else {
            self.commitment
                .insert(slot, self.shielded.commitment().to_vec());
        }
    }

    /// Re-commit the open-HTLC set's digest to its reserved slot. With no open
    /// HTLCs the slot is removed, so a chain that has never used an HTLC keeps the
    /// exact state root it would have without the feature.
    fn recommit_htlcs(&mut self) {
        let slot = Self::reserved_slot(Self::HTLC_SLOT);
        if self.htlcs.is_empty() {
            self.commitment.remove(&slot);
        } else {
            let entries: Vec<HtlcEntry> = self.htlcs.iter().map(|(k, v)| (*k, v.clone())).collect();
            let digest = Hash::digest(
                &borsh::to_vec(&entries).expect("HTLC set serialization is infallible"),
            );
            self.commitment.insert(slot, digest.as_bytes().to_vec());
        }
    }

    /// Re-commit the NFT-collections digest. Empty ⇒ slot removed (canonical).
    fn recommit_nft_classes(&mut self) {
        let slot = Self::reserved_slot(Self::NFT_CLASSES_SLOT);
        if self.nft_classes.is_empty() {
            self.commitment.remove(&slot);
        } else {
            let entries: Vec<NftClassEntry> = self
                .nft_classes
                .iter()
                .map(|(k, v)| (*k, v.clone()))
                .collect();
            let digest = Hash::digest(
                &borsh::to_vec(&entries).expect("NFT classes serialization is infallible"),
            );
            self.commitment.insert(slot, digest.as_bytes().to_vec());
        }
    }

    /// Re-commit the NFT-items digest (this includes SNS names, which live in the
    /// reserved SNS collection). Empty ⇒ slot removed, so a chain with no NFTs and
    /// no names keeps the exact state root it would have without the feature. The
    /// digest is over the items in `(collection, token_id)` order (canonical).
    fn recommit_nfts(&mut self) {
        let slot = Self::reserved_slot(Self::NFTS_SLOT);
        if self.nfts.is_empty() {
            self.commitment.remove(&slot);
        } else {
            let entries: Vec<NftEntry> = self
                .nfts
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            let digest = Hash::digest(
                &borsh::to_vec(&entries).expect("NFT items serialization is infallible"),
            );
            self.commitment.insert(slot, digest.as_bytes().to_vec());
        }
    }

    /// Re-commit the multisig-policies digest. Empty ⇒ slot removed, so a chain
    /// with no multisig accounts keeps the exact root it would have without it.
    fn recommit_multisig(&mut self) {
        let slot = Self::reserved_slot(Self::MULTISIG_SLOT);
        if self.multisig.is_empty() {
            self.commitment.remove(&slot);
        } else {
            let entries: Vec<MultisigEntry> = self
                .multisig
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            let digest = Hash::digest(
                &borsh::to_vec(&entries).expect("multisig serialization is infallible"),
            );
            self.commitment.insert(slot, digest.as_bytes().to_vec());
        }
    }

    /// The account at `id`, or the default empty account if it has no state.
    /// Reading an absent account never errors — it simply hasn't been funded.
    pub fn account(&self, id: &AccountId) -> Account {
        self.accounts.get(id).cloned().unwrap_or_default()
    }

    /// Whether `id` has any stored state.
    pub fn exists(&self, id: &AccountId) -> bool {
        self.accounts.contains_key(id)
    }

    /// Start recording an undo log for the block about to be applied: every state
    /// write now captures its pre-image. Pair with [`take_undo`](Ledger::take_undo)
    /// once the block has executed. Off by default, so boot replay and query-only
    /// ledgers pay nothing.
    pub fn begin_undo(&mut self) {
        self.undo = Some(Vec::new());
    }

    /// Stop recording and take the block's captured undo log (its reverse patch).
    /// Empty if recording was never started.
    pub fn take_undo(&mut self) -> UndoLog {
        UndoLog(self.undo.take().unwrap_or_default())
    }

    /// Whether undo recording is currently on.
    pub fn is_recording_undo(&self) -> bool {
        self.undo.is_some()
    }

    /// Record one pre-image (the single choke point every mutator calls before it
    /// writes). No-op when recording is off.
    fn record(&mut self, op: UndoOp) {
        if let Some(j) = self.undo.as_mut() {
            j.push(op);
        }
    }

    /// **Disconnect a block:** reverse its writes in LIFO order, restoring the exact
    /// pre-block state — same `state_root`, bit-for-bit. Recording is suspended
    /// during the restore (the undo itself is never journaled). This is what lets a
    /// reorg roll back in O(reorg depth) instead of replaying the chain from genesis.
    pub fn apply_undo(&mut self, log: UndoLog) {
        let saved = self.undo.take();
        for op in log.0.into_iter().rev() {
            self.undo_one(op);
        }
        self.undo = saved;
    }

    /// Restore one field write's pre-image, manipulating the store + commitment
    /// directly — mirroring each setter's own commit logic exactly so the resulting
    /// `state_root` is identical to "the write never happened".
    fn undo_one(&mut self, op: UndoOp) {
        match op {
            UndoOp::Account(id, prev) => {
                let slot = Self::slot(&id);
                match prev.map(|b| *b) {
                    Some(a) if !a.is_empty() => {
                        let encoded =
                            borsh::to_vec(&a).expect("Account serialization is infallible");
                        self.commitment.insert(slot, encoded);
                        self.accounts.insert(id, a);
                    }
                    _ => {
                        self.accounts.remove(&id);
                        self.commitment.remove(&slot);
                    }
                }
            }
            UndoOp::Contract(contract, key, prev) => {
                let slot = Self::contract_slot(&contract, &key);
                let map_key = (contract, key);
                match prev {
                    Some(v) if !v.is_empty() => {
                        self.commitment.insert(slot, v.clone());
                        self.contract_storage.insert(map_key, v);
                    }
                    _ => {
                        self.contract_storage.remove(&map_key);
                        self.commitment.remove(&slot);
                    }
                }
            }
            UndoOp::Token(asset, prev) => match prev {
                Some(info) => {
                    let encoded =
                        borsh::to_vec(&info).expect("TokenInfo serialization is infallible");
                    self.commitment.insert(Self::token_slot(&asset), encoded);
                    self.tokens.insert(asset, info);
                }
                None => {
                    self.tokens.remove(&asset);
                    self.commitment.remove(&Self::token_slot(&asset));
                }
            },
            UndoOp::TokenBalance(asset, holder, prev) => {
                let slot = Self::token_balance_slot(&asset, &holder);
                let key = (asset, holder);
                match prev {
                    Some(b) if b != Balance::ZERO => {
                        let encoded =
                            borsh::to_vec(&b).expect("Balance serialization is infallible");
                        self.commitment.insert(slot, encoded);
                        self.token_balances.insert(key, b);
                    }
                    _ => {
                        self.token_balances.remove(&key);
                        self.commitment.remove(&slot);
                    }
                }
            }
            UndoOp::TokenPolicy(asset, prev) => match prev {
                Some(p) => {
                    let encoded =
                        borsh::to_vec(&p).expect("CompliancePolicy serialization is infallible");
                    self.commitment.insert(Self::token_policy_slot(&asset), encoded);
                    self.token_policies.insert(asset, p);
                }
                None => {
                    self.token_policies.remove(&asset);
                    self.commitment.remove(&Self::token_policy_slot(&asset));
                }
            },
            UndoOp::TokenWindow(asset, holder, prev) => {
                let slot = Self::token_window_slot(&asset, &holder);
                let key = (asset, holder);
                match prev {
                    Some(w) if w != SpendWindow::default() => {
                        let encoded =
                            borsh::to_vec(&w).expect("SpendWindow serialization is infallible");
                        self.commitment.insert(slot, encoded);
                        self.token_windows.insert(key, w);
                    }
                    _ => {
                        self.token_windows.remove(&key);
                        self.commitment.remove(&slot);
                    }
                }
            }
            UndoOp::Htlc(id, prev) => {
                match prev {
                    Some(h) => {
                        self.htlcs.insert(id, h);
                    }
                    None => {
                        self.htlcs.remove(&id);
                    }
                }
                self.recommit_htlcs();
            }
            UndoOp::NftClass(id, prev) => {
                match prev {
                    Some(c) => {
                        self.nft_classes.insert(id, c);
                    }
                    None => {
                        self.nft_classes.remove(&id);
                    }
                }
                self.recommit_nft_classes();
            }
            UndoOp::Nft(collection, token_id, prev) => {
                let key = (collection, token_id);
                match prev {
                    Some(t) => {
                        self.nfts.insert(key, t);
                    }
                    None => {
                        self.nfts.remove(&key);
                    }
                }
                self.recommit_nfts();
            }
            UndoOp::Multisig(account, prev) => {
                match prev {
                    Some(m) => {
                        self.multisig.insert(account, m);
                    }
                    None => {
                        self.multisig.remove(&account);
                    }
                }
                self.recommit_multisig();
            }
            UndoOp::Intent(intent_id) => {
                self.consumed_intents.remove(&intent_id);
                self.commitment.remove(&Self::intent_slot(&intent_id));
            }
            UndoOp::Shielded(prev) => {
                self.shielded = *prev;
                self.recommit_shielded();
            }
            UndoOp::MinedEmitted(prev) => {
                self.mined_emitted = prev;
                self.commit_counter(Self::MINED_SLOT, prev);
            }
            UndoOp::ShieldedValue(prev) => {
                self.shielded_value = prev;
                self.commit_counter(Self::SHIELDED_VALUE_SLOT, prev);
            }
            UndoOp::HtlcLocked(prev) => {
                self.htlc_locked = prev;
                self.commit_counter(Self::HTLC_LOCKED_SLOT, prev);
            }
            UndoOp::DeshieldWindow(start, spent) => {
                self.deshield_window = (start, spent);
                let slot = Self::reserved_slot(Self::DESHIELD_WINDOW_SLOT);
                if start == 0 && spent == Balance::ZERO {
                    self.commitment.remove(&slot);
                } else {
                    let encoded = borsh::to_vec(&self.deshield_window)
                        .expect("window serialization is infallible");
                    self.commitment.insert(slot, encoded);
                }
            }
        }
    }

    /// Write `account` to `id`, updating both the store and the commitment. An
    /// account equal to the default empty state is removed, keeping the root
    /// canonical (an explicitly-zeroed account commits identically to an absent
    /// one).
    pub fn set_account(&mut self, id: &AccountId, account: Account) {
        if self.undo.is_some() {
            let prev = self.accounts.get(id).cloned().map(Box::new);
            self.record(UndoOp::Account(id.clone(), prev));
        }
        let slot = Self::slot(id);
        if account.is_empty() {
            self.accounts.remove(id);
            self.commitment.remove(&slot);
        } else {
            let encoded = borsh::to_vec(&account).expect("Account serialization is infallible");
            self.commitment.insert(slot, encoded);
            self.accounts.insert(id.clone(), account);
        }
    }

    /// Read a contract storage entry.
    pub fn contract_value(&self, contract: &AccountId, key: &[u8]) -> Option<&[u8]> {
        self.contract_storage
            .get(&(contract.clone(), key.to_vec()))
            .map(Vec::as_slice)
    }

    /// Write (or, with an empty value, clear) a contract storage entry, updating
    /// both the store and the commitment.
    pub fn set_contract_value(&mut self, contract: &AccountId, key: Vec<u8>, value: Vec<u8>) {
        if self.undo.is_some() {
            let prev = self.contract_value(contract, &key).map(<[u8]>::to_vec);
            self.record(UndoOp::Contract(contract.clone(), key.clone(), prev));
        }
        let slot = Self::contract_slot(contract, &key);
        let map_key = (contract.clone(), key);
        if value.is_empty() {
            self.contract_storage.remove(&map_key);
            self.commitment.remove(&slot);
        } else {
            self.commitment.insert(slot, value.clone());
            self.contract_storage.insert(map_key, value);
        }
    }

    /// All storage entries of `contract`, in key order.
    pub fn contract_entries(&self, contract: &AccountId) -> Vec<(Vec<u8>, Vec<u8>)> {
        self.contract_storage
            .range((contract.clone(), Vec::new())..)
            .take_while(|((c, _), _)| c == contract)
            .map(|((_, k), v)| (k.clone(), v.clone()))
            .collect()
    }

    /// The state root committing to every account and contract storage entry.
    pub fn state_root(&self) -> Hash {
        self.commitment.root()
    }

    /// A Merkle proof of `id`'s account (inclusion) or its absence (exclusion),
    /// verifiable against [`state_root`](Ledger::state_root).
    pub fn prove(&self, id: &AccountId) -> MerkleProof {
        self.commitment.prove(&Self::slot(id))
    }

    /// Iterate all non-empty accounts in id order.
    pub fn iter(&self) -> impl Iterator<Item = (&AccountId, &Account)> {
        self.accounts.iter()
    }

    /// Number of non-empty accounts.
    pub fn account_count(&self) -> usize {
        self.accounts.len()
    }

    /// Total of all liquid + vesting-locked balances across every account. This is the
    /// circulating supply; the runtime asserts it is conserved by transfers and
    /// never exceeds the protocol cap. `None` on overflow (impossible under the
    /// cap, but checked rather than assumed).
    pub fn total_supply(&self) -> Option<Balance> {
        let mut sum = Balance::ZERO;
        for account in self.accounts.values() {
            sum = sum.checked_add(account.total()?)?;
        }
        // Value parked in the shielded pool or escrowed in an HTLC is still
        // supply — it just lives outside account balances. Counting it makes
        // every hold/release/refund supply-neutral.
        sum.checked_add(self.shielded_value)?
            .checked_add(self.htlc_locked)
    }

    /// The shielded pool's consensus state (read-only): note-commitment tree,
    /// anchor history, and nullifier set.
    pub fn shielded(&self) -> &ShieldedState {
        &self.shielded
    }

    /// Net value currently held in the shielded pool (grains).
    pub fn shielded_value(&self) -> Balance {
        self.shielded_value
    }

    /// Apply an authorized shielded bundle to the pool: insert its nullifiers
    /// (rejecting double-spends) and append its output commitments, then
    /// re-commit the pool digest into the state root. The caller must already
    /// have verified the bundle's proof and that its anchor is known.
    pub fn apply_shielded_bundle(&mut self, bundle: &ShieldedBundle) -> Result<(), ShieldedError> {
        // Snapshot the pool ONLY if recording, and record it ONLY after the apply
        // succeeds — a rejected bundle must not leave a spurious undo entry.
        let prev = self.undo.is_some().then(|| self.shielded.clone());
        self.shielded.apply_bundle(bundle)?;
        if let Some(p) = prev {
            self.record(UndoOp::Shielded(Box::new(p)));
        }
        self.recommit_shielded();
        Ok(())
    }

    /// Increase the net shielded-pool value (a shield moves transparent value in).
    /// `None` on overflow. Commits the counter to the state root.
    pub fn add_shielded_value(&mut self, amount: Balance) -> Option<()> {
        let next = self.shielded_value.checked_add(amount)?;
        self.record(UndoOp::ShieldedValue(self.shielded_value));
        self.shielded_value = next;
        self.commit_counter(Self::SHIELDED_VALUE_SLOT, self.shielded_value);
        Some(())
    }

    /// Decrease the net shielded-pool value (a de-shield moves value back out).
    /// `None` if the pool holds less than `amount`. Commits the counter.
    pub fn sub_shielded_value(&mut self, amount: Balance) -> Option<()> {
        let next = self.shielded_value.checked_sub(amount)?;
        self.record(UndoOp::ShieldedValue(self.shielded_value));
        self.shielded_value = next;
        self.commit_counter(Self::SHIELDED_VALUE_SLOT, self.shielded_value);
        Some(())
    }

    /// An open hash-time-locked contract by id, if present.
    pub fn htlc(&self, id: &Hash) -> Option<&Htlc> {
        self.htlcs.get(id)
    }

    /// Total value currently escrowed across all open HTLCs (grains).
    pub fn htlc_locked(&self) -> Balance {
        self.htlc_locked
    }

    /// Open an HTLC: record it and add its amount to the escrowed total (committed
    /// to the state root). The caller must already have debited the locker.
    /// `None` if the id already exists or the escrow total would overflow.
    pub fn lock_htlc(&mut self, id: Hash, htlc: Htlc) -> Option<()> {
        if self.htlcs.contains_key(&id) {
            return None;
        }
        let next_locked = self.htlc_locked.checked_add(htlc.amount)?;
        self.record(UndoOp::HtlcLocked(self.htlc_locked));
        self.record(UndoOp::Htlc(id, None)); // id was absent (checked above)
        self.htlc_locked = next_locked;
        self.commit_counter(Self::HTLC_LOCKED_SLOT, self.htlc_locked);
        self.htlcs.insert(id, htlc);
        self.recommit_htlcs();
        Some(())
    }

    /// Settle (remove) an HTLC, returning it and releasing its escrow. The caller
    /// then credits the recipient (on claim) or the locker (on refund) with
    /// `htlc.amount`. `None` if no such HTLC is open.
    pub fn settle_htlc(&mut self, id: &Hash) -> Option<Htlc> {
        let htlc = self.htlcs.remove(id)?;
        if self.undo.is_some() {
            self.record(UndoOp::HtlcLocked(self.htlc_locked));
            self.record(UndoOp::Htlc(*id, Some(htlc.clone())));
        }
        self.htlc_locked = self
            .htlc_locked
            .checked_sub(htlc.amount)
            .unwrap_or(Balance::ZERO);
        self.commit_counter(Self::HTLC_LOCKED_SLOT, self.htlc_locked);
        self.recommit_htlcs();
        Some(htlc)
    }

    // ── SNS names: the reserved, protocol-level NFT collection ────────────────
    // A name IS the non-fungible token whose token id is the name's bytes, living
    // in the [`sns_class`] collection. These façades keep their original
    // signatures (so RPC/GUI/explorer are unchanged) but read/write the NFT store.

    /// The resolver record for `name`, if registered (built from its NFT).
    pub fn name_record(&self, name: &str) -> Option<NameRecord> {
        self.nfts
            .get(&(sns_class(), name.as_bytes().to_vec()))
            .map(|t| NameRecord {
                owner: t.owner.clone(),
                registered_height: t.minted_height,
            })
    }

    /// Resolve `name` to the account it points to — the SNS lookup. A name's NFT
    /// metadata carries an optional resolver target; unset (or invalid) ⇒ the name
    /// resolves to its owner.
    pub fn resolve_name(&self, name: &str) -> Option<AccountId> {
        let token = self.nfts.get(&(sns_class(), name.as_bytes().to_vec()))?;
        if token.metadata.is_empty() {
            return Some(token.owner.clone());
        }
        let target = std::str::from_utf8(&token.metadata)
            .ok()
            .and_then(|s| AccountId::new(s).ok());
        Some(target.unwrap_or_else(|| token.owner.clone()))
    }

    /// Whether `name` is already registered.
    pub fn name_taken(&self, name: &str) -> bool {
        self.nfts
            .contains_key(&(sns_class(), name.as_bytes().to_vec()))
    }

    /// Register `name` → `owner` at `height` by minting its NFT in the reserved
    /// SNS collection. `None` if already registered (first-come). Name shape and
    /// shadow checks are the caller's (consensus) responsibility.
    pub fn register_name(&mut self, name: String, owner: AccountId, height: u64) -> Option<()> {
        self.mint_nft(sns_class(), name.into_bytes(), owner, Vec::new(), height)
    }

    /// Reassign `name`'s owner (a name transfer) — i.e. transfer its NFT. `None`
    /// if the name is not registered.
    pub fn transfer_name(&mut self, name: &str, new_owner: AccountId) -> Option<()> {
        self.transfer_nft(sns_class(), name.as_bytes(), new_owner)
    }

    /// All names owned by `account`, in id order — the reverse lookup.
    pub fn names_owned_by(&self, account: &AccountId) -> Vec<String> {
        let sns = sns_class();
        self.nfts
            .range((sns, Vec::new())..)
            .take_while(move |((c, _), _)| *c == sns)
            .filter(|(_, t)| &t.owner == account)
            .filter_map(|((_, id), _)| String::from_utf8(id.clone()).ok())
            .collect()
    }

    /// Number of registered names.
    pub fn name_count(&self) -> usize {
        let sns = sns_class();
        self.nfts
            .range((sns, Vec::new())..)
            .take_while(move |((c, _), _)| *c == sns)
            .count()
    }

    /// The id of the reserved SNS collection (so callers can tell SNS-name NFTs
    /// apart from generic NFTs without importing the free function).
    pub fn sns_collection(&self) -> Hash {
        sns_class()
    }

    /// Iterate all registered names in id order — for paged explorer listings.
    pub fn names_iter(&self) -> impl Iterator<Item = (String, NameRecord)> + '_ {
        let sns = sns_class();
        self.nfts
            .range((sns, Vec::new())..)
            .take_while(move |((c, _), _)| *c == sns)
            .filter_map(|((_, id), t)| {
                String::from_utf8(id.clone()).ok().map(|name| {
                    (
                        name,
                        NameRecord {
                            owner: t.owner.clone(),
                            registered_height: t.minted_height,
                        },
                    )
                })
            })
    }

    // ── Generic non-fungible tokens ───────────────────────────────────────────

    /// The multisig policy controlling `account`, if it has opted into multisig.
    /// `None` means the account is single-key (the default).
    pub fn multisig_of(&self, account: &AccountId) -> Option<&Multisig> {
        self.multisig.get(account)
    }

    /// Set (or replace) `account`'s multisig policy, committing it to the root.
    pub fn set_multisig(&mut self, account: AccountId, policy: Multisig) {
        if self.undo.is_some() {
            let prev = self.multisig.get(&account).cloned();
            self.record(UndoOp::Multisig(account.clone(), prev));
        }
        self.multisig.insert(account, policy);
        self.recommit_multisig();
    }

    /// Number of accounts under multisig control.
    pub fn multisig_count(&self) -> usize {
        self.multisig.len()
    }

    /// An NFT collection by id, if it exists.
    pub fn nft_class(&self, id: &Hash) -> Option<&NftClass> {
        self.nft_classes.get(id)
    }

    /// Record (insert/replace) an NFT collection, committing it to the root.
    pub fn set_nft_class(&mut self, id: Hash, class: NftClass) {
        if self.undo.is_some() {
            let prev = self.nft_classes.get(&id).cloned();
            self.record(UndoOp::NftClass(id, prev));
        }
        self.nft_classes.insert(id, class);
        self.recommit_nft_classes();
    }

    /// An NFT item by `(collection, token_id)`, if it exists.
    pub fn nft(&self, collection: &Hash, token_id: &[u8]) -> Option<&NftToken> {
        self.nfts.get(&(*collection, token_id.to_vec()))
    }

    /// The owner of an NFT item, if it exists.
    pub fn nft_owner(&self, collection: &Hash, token_id: &[u8]) -> Option<AccountId> {
        self.nfts
            .get(&(*collection, token_id.to_vec()))
            .map(|t| t.owner.clone())
    }

    /// Mint a unique item. `None` if `(collection, token_id)` already exists —
    /// non-fungibility is enforced.
    pub fn mint_nft(
        &mut self,
        collection: Hash,
        token_id: Vec<u8>,
        owner: AccountId,
        metadata: Vec<u8>,
        height: u64,
    ) -> Option<()> {
        let key = (collection, token_id);
        if self.nfts.contains_key(&key) {
            return None;
        }
        if self.undo.is_some() {
            self.record(UndoOp::Nft(key.0, key.1.clone(), None));
        }
        self.nfts.insert(
            key,
            NftToken {
                owner,
                metadata,
                minted_height: height,
            },
        );
        self.recommit_nfts();
        Some(())
    }

    /// Transfer an item to `new_owner`. `None` if it does not exist.
    pub fn transfer_nft(
        &mut self,
        collection: Hash,
        token_id: &[u8],
        new_owner: AccountId,
    ) -> Option<()> {
        let key = (collection, token_id.to_vec());
        if !self.nfts.contains_key(&key) {
            return None;
        }
        if self.undo.is_some() {
            let prev = self.nfts.get(&key).cloned();
            self.record(UndoOp::Nft(collection, token_id.to_vec(), prev));
        }
        let token = self.nfts.get_mut(&key).expect("present");
        token.owner = new_owner;
        self.recommit_nfts();
        Some(())
    }

    /// Replace an item's metadata (the resolver/records hook). `None` if absent.
    pub fn set_nft_meta(
        &mut self,
        collection: Hash,
        token_id: &[u8],
        metadata: Vec<u8>,
    ) -> Option<()> {
        let key = (collection, token_id.to_vec());
        if !self.nfts.contains_key(&key) {
            return None;
        }
        if self.undo.is_some() {
            let prev = self.nfts.get(&key).cloned();
            self.record(UndoOp::Nft(collection, token_id.to_vec(), prev));
        }
        let token = self.nfts.get_mut(&key).expect("present");
        token.metadata = metadata;
        self.recommit_nfts();
        Some(())
    }

    /// All items owned by `account`, as `(collection, token_id)`, in key order.
    pub fn nfts_owned_by(&self, account: &AccountId) -> Vec<(Hash, Vec<u8>)> {
        self.nfts
            .iter()
            .filter(|(_, t)| &t.owner == account)
            .map(|(k, _)| k.clone())
            .collect()
    }

    /// Iterate all NFT items in `(collection, token_id)` order — paged listings.
    pub fn nfts_iter(&self) -> impl Iterator<Item = (&(Hash, Vec<u8>), &NftToken)> {
        self.nfts.iter()
    }

    /// A native asset's issuance record, if the asset exists.
    pub fn token(&self, asset: &Hash) -> Option<&TokenInfo> {
        self.tokens.get(asset)
    }

    /// Write a native asset's issuance record, updating both the store and the
    /// commitment. Assets are never deleted (their burn history is part of the
    /// chain's accounting), so this only inserts or overwrites.
    pub fn set_token(&mut self, asset: Hash, info: TokenInfo) {
        if self.undo.is_some() {
            let prev = self.tokens.get(&asset).cloned();
            self.record(UndoOp::Token(asset, prev));
        }
        let encoded = borsh::to_vec(&info).expect("TokenInfo serialization is infallible");
        self.commitment.insert(Self::token_slot(&asset), encoded);
        self.tokens.insert(asset, info);
    }

    /// `holder`'s balance of `asset`. An absent entry reads as zero, exactly
    /// like an absent account.
    pub fn token_balance(&self, asset: &Hash, holder: &AccountId) -> Balance {
        self.token_balances
            .get(&(*asset, holder.clone()))
            .copied()
            .unwrap_or(Balance::ZERO)
    }

    /// Write `holder`'s balance of `asset`, updating both the store and the
    /// commitment. A zero balance is removed, keeping the root canonical (an
    /// explicitly-zeroed holding commits identically to an absent one).
    pub fn set_token_balance(&mut self, asset: &Hash, holder: &AccountId, balance: Balance) {
        if self.undo.is_some() {
            let prev = self.token_balances.get(&(*asset, holder.clone())).copied();
            self.record(UndoOp::TokenBalance(*asset, holder.clone(), prev));
        }
        let slot = Self::token_balance_slot(asset, holder);
        let key = (*asset, holder.clone());
        if balance == Balance::ZERO {
            self.token_balances.remove(&key);
            self.commitment.remove(&slot);
        } else {
            let encoded = borsh::to_vec(&balance).expect("Balance serialization is infallible");
            self.commitment.insert(slot, encoded);
            self.token_balances.insert(key, balance);
        }
    }

    /// An asset's compliance policy, if its issuer has set one. An absent
    /// policy means the asset is unrestricted.
    pub fn token_policy(&self, asset: &Hash) -> Option<&CompliancePolicy> {
        self.token_policies.get(asset)
    }

    /// Set (or replace) an asset's compliance policy, updating the store and
    /// the commitment. Replacing a policy **clears the asset's spend-velocity
    /// windows** — a new policy starts with fresh accounting, and stale windows
    /// never linger in the committed state.
    pub fn set_token_policy(&mut self, asset: Hash, policy: CompliancePolicy) {
        if self.undo.is_some() {
            // The policy itself, plus every spend window this call is about to clear.
            self.record(UndoOp::TokenPolicy(asset, self.token_policies.get(&asset).cloned()));
            let cleared: Vec<((Hash, AccountId), SpendWindow)> = self
                .token_windows
                .iter()
                .filter(|((a, _), _)| *a == asset)
                .map(|(k, v)| (k.clone(), *v))
                .collect();
            for ((a, holder), w) in cleared {
                self.record(UndoOp::TokenWindow(a, holder, Some(w)));
            }
        }
        let encoded = borsh::to_vec(&policy).expect("CompliancePolicy serialization is infallible");
        self.commitment
            .insert(Self::token_policy_slot(&asset), encoded);
        self.token_policies.insert(asset, policy);
        // Clear every window of this asset (store + commitment).
        let stale: Vec<(Hash, AccountId)> = self
            .token_windows
            .keys()
            .filter(|(a, _)| *a == asset)
            .cloned()
            .collect();
        for (a, holder) in stale {
            self.commitment
                .remove(&Self::token_window_slot(&a, &holder));
            self.token_windows.remove(&(a, holder));
        }
    }

    /// `holder`'s rolling spend window for `asset` (zero if never spent under
    /// a velocity limit).
    pub fn token_window(&self, asset: &Hash, holder: &AccountId) -> SpendWindow {
        self.token_windows
            .get(&(*asset, holder.clone()))
            .copied()
            .unwrap_or_default()
    }

    /// Write `holder`'s rolling spend window for `asset`, updating the store
    /// and the commitment. A default (zero) window is removed, keeping the
    /// root canonical.
    pub fn set_token_window(&mut self, asset: &Hash, holder: &AccountId, window: SpendWindow) {
        if self.undo.is_some() {
            let prev = self.token_windows.get(&(*asset, holder.clone())).copied();
            self.record(UndoOp::TokenWindow(*asset, holder.clone(), prev));
        }
        let slot = Self::token_window_slot(asset, holder);
        let key = (*asset, holder.clone());
        if window == SpendWindow::default() {
            self.token_windows.remove(&key);
            self.commitment.remove(&slot);
        } else {
            let encoded = borsh::to_vec(&window).expect("SpendWindow serialization is infallible");
            self.commitment.insert(slot, encoded);
            self.token_windows.insert(key, window);
        }
    }

    /// The rolling de-shield window: `(window_start_height, spent)`. A fresh
    /// chain reads `(0, 0)`.
    pub fn deshield_window(&self) -> (u64, Balance) {
        self.deshield_window
    }

    /// Write the rolling de-shield window, committing it to the state root.
    /// The default `(0, 0)` window is removed, keeping the root canonical.
    pub fn set_deshield_window(&mut self, window_start: u64, spent: Balance) {
        if self.undo.is_some() {
            let (s, sp) = self.deshield_window;
            self.record(UndoOp::DeshieldWindow(s, sp));
        }
        self.deshield_window = (window_start, spent);
        let slot = Self::reserved_slot(Self::DESHIELD_WINDOW_SLOT);
        if window_start == 0 && spent == Balance::ZERO {
            self.commitment.remove(&slot);
        } else {
            let encoded =
                borsh::to_vec(&self.deshield_window).expect("window serialization is infallible");
            self.commitment.insert(slot, encoded);
        }
    }

    /// Whether `intent_id` has already been settled or cancelled.
    pub fn intent_consumed(&self, intent_id: &Hash) -> bool {
        self.consumed_intents.contains(intent_id)
    }

    /// Mark `intent_id` consumed (settled or cancelled), committing the marker
    /// to the state root. Idempotent; the runtime checks
    /// [`intent_consumed`](Ledger::intent_consumed) first and rejects reuse.
    pub fn consume_intent(&mut self, intent_id: Hash) {
        if self.undo.is_some() && !self.consumed_intents.contains(&intent_id) {
            self.record(UndoOp::Intent(intent_id));
        }
        self.commitment
            .insert(Self::intent_slot(&intent_id), vec![1u8]);
        self.consumed_intents.insert(intent_id);
    }

    /// Iterate all consumed intent ids in order.
    pub fn consumed_intent_iter(&self) -> impl Iterator<Item = &Hash> {
        self.consumed_intents.iter()
    }

    /// Iterate all per-asset compliance policies in asset-id order.
    pub fn token_policy_iter(&self) -> impl Iterator<Item = (&Hash, &CompliancePolicy)> {
        self.token_policies.iter()
    }

    /// Iterate all non-default spend windows in (asset id, holder) order.
    pub fn token_window_iter(&self) -> impl Iterator<Item = (&(Hash, AccountId), &SpendWindow)> {
        self.token_windows.iter()
    }

    /// Iterate all native assets in asset-id order.
    pub fn token_iter(&self) -> impl Iterator<Item = (&Hash, &TokenInfo)> {
        self.tokens.iter()
    }

    /// Iterate all non-zero token balances in (asset id, holder) order.
    pub fn token_balance_iter(&self) -> impl Iterator<Item = (&(Hash, AccountId), &Balance)> {
        self.token_balances.iter()
    }

    /// Cumulative SOV minted by proof-of-work mining (committed to the state root).
    pub fn mined_emitted(&self) -> Balance {
        self.mined_emitted
    }

    /// Record `amount` of freshly mined SOV against the committed counter.
    /// `None` on overflow (unreachable under the mining budget, but checked).
    pub fn add_mined_emitted(&mut self, amount: Balance) -> Option<()> {
        let next = self.mined_emitted.checked_add(amount)?;
        self.record(UndoOp::MinedEmitted(self.mined_emitted));
        self.mined_emitted = next;
        self.commit_counter(Self::MINED_SLOT, self.mined_emitted);
        Some(())
    }

    /// Persist the ledger to `path` as a Borsh-encoded snapshot of its accounts
    /// and contract storage. The Merkle commitment is *not* stored — it is
    /// deterministically rebuilt on [`load`](Ledger::load), so a reloaded ledger
    /// is guaranteed to reproduce the exact same `state_root`. This makes the
    /// trie-backed store durable across restarts.
    pub fn save(&self, path: impl AsRef<Path>) -> std::io::Result<()> {
        std::fs::write(path, self.to_snapshot_bytes())
    }

    /// Serialize the full ledger state to a Borsh snapshot blob — the same content
    /// [`save`](Ledger::save) writes, exposed so a caller can bundle it into a larger
    /// atomic snapshot file. The Merkle commitment is omitted (rebuilt on load), so
    /// the blob alone deterministically reproduces the `state_root`.
    pub fn to_snapshot_bytes(&self) -> Vec<u8> {
        let accounts: Vec<AccountEntry> = self
            .accounts
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let storage: Vec<ContractEntry> = self
            .contract_storage
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let (shielded_commitments, shielded_nullifiers) = self.shielded.snapshot();
        let htlcs: Vec<HtlcEntry> = self.htlcs.iter().map(|(k, v)| (*k, v.clone())).collect();
        let tokens: Vec<TokenEntry> = self.tokens.iter().map(|(k, v)| (*k, v.clone())).collect();
        let token_balances: Vec<TokenBalanceEntry> = self
            .token_balances
            .iter()
            .map(|(k, v)| (k.clone(), *v))
            .collect();
        let token_policies: Vec<TokenPolicyEntry> = self
            .token_policies
            .iter()
            .map(|(k, v)| (*k, v.clone()))
            .collect();
        let token_windows: Vec<TokenWindowEntry> = self
            .token_windows
            .iter()
            .map(|(k, v)| (k.clone(), *v))
            .collect();
        let consumed_intents: Vec<Hash> = self.consumed_intents.iter().copied().collect();
        let deshield_window = self.deshield_window;
        let nft_classes: Vec<NftClassEntry> = self
            .nft_classes
            .iter()
            .map(|(k, v)| (*k, v.clone()))
            .collect();
        let nfts: Vec<NftEntry> = self
            .nfts
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let multisig: Vec<MultisigEntry> = self
            .multisig
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        borsh::to_vec(&(
            accounts,
            storage,
            self.mined_emitted,
            self.shielded_value,
            shielded_commitments,
            shielded_nullifiers,
            self.htlc_locked,
            htlcs,
            tokens,
            token_balances,
            token_policies,
            token_windows,
            consumed_intents,
            deshield_window,
            nft_classes,
            nfts,
            multisig,
        ))
        .expect("ledger snapshot serialization is infallible")
    }

    /// Load a ledger previously written by [`save`](Ledger::save), rebuilding the
    /// Merkle commitment from the stored accounts and contract storage.
    pub fn load(path: impl AsRef<Path>) -> std::io::Result<Ledger> {
        Self::from_snapshot_bytes(&std::fs::read(path)?)
    }

    /// Rebuild a ledger from a [`to_snapshot_bytes`](Ledger::to_snapshot_bytes) blob,
    /// reconstructing the Merkle commitment so the loaded ledger reproduces the exact
    /// `state_root` the snapshot was taken at.
    pub fn from_snapshot_bytes(bytes: &[u8]) -> std::io::Result<Ledger> {
        #[allow(clippy::type_complexity)]
        let (
            accounts,
            storage,
            mined,
            shielded_value,
            sc,
            sn,
            htlc_locked,
            htlcs,
            tokens,
            token_balances,
            token_policies,
            token_windows,
            consumed_intents,
            deshield_window,
            nft_classes,
            nfts,
            multisig,
        ): (
            Vec<AccountEntry>,
            Vec<ContractEntry>,
            Balance,
            Balance,
            Vec<[u8; 32]>,
            Vec<[u8; 32]>,
            Balance,
            Vec<HtlcEntry>,
            Vec<TokenEntry>,
            Vec<TokenBalanceEntry>,
            Vec<TokenPolicyEntry>,
            Vec<TokenWindowEntry>,
            Vec<Hash>,
            (u64, Balance),
            Vec<NftClassEntry>,
            Vec<NftEntry>,
            Vec<MultisigEntry>,
        ) = borsh::from_slice(bytes)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let mut ledger = Ledger::new();
        for (id, account) in accounts {
            ledger.set_account(&id, account);
        }
        for ((contract, key), value) in storage {
            ledger.set_contract_value(&contract, key, value);
        }
        ledger.mined_emitted = mined;
        ledger.commit_counter(Self::MINED_SLOT, mined);
        ledger.shielded_value = shielded_value;
        ledger.commit_counter(Self::SHIELDED_VALUE_SLOT, shielded_value);
        ledger.shielded = ShieldedState::restore(&sc, &sn)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        ledger.recommit_shielded();
        ledger.htlc_locked = htlc_locked;
        ledger.commit_counter(Self::HTLC_LOCKED_SLOT, htlc_locked);
        ledger.htlcs = htlcs.into_iter().collect();
        ledger.recommit_htlcs();
        for (asset, info) in tokens {
            ledger.set_token(asset, info);
        }
        for ((asset, holder), balance) in token_balances {
            ledger.set_token_balance(&asset, &holder, balance);
        }
        for (asset, policy) in token_policies {
            ledger.set_token_policy(asset, policy);
        }
        // Windows AFTER policies: set_token_policy clears an asset's windows.
        for ((asset, holder), window) in token_windows {
            ledger.set_token_window(&asset, &holder, window);
        }
        for intent_id in consumed_intents {
            ledger.consume_intent(intent_id);
        }
        ledger.set_deshield_window(deshield_window.0, deshield_window.1);
        ledger.nft_classes = nft_classes.into_iter().collect();
        ledger.recommit_nft_classes();
        ledger.nfts = nfts.into_iter().collect();
        ledger.recommit_nfts();
        ledger.multisig = multisig.into_iter().collect();
        ledger.recommit_multisig();
        Ok(ledger)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(s: &str) -> AccountId {
        AccountId::new(s).unwrap()
    }

    #[test]
    fn absent_account_reads_as_default() {
        let ledger = Ledger::new();
        assert_eq!(ledger.account(&id("usa.reserve.sov")), Account::default());
        assert!(!ledger.exists(&id("usa.reserve.sov")));
        assert_eq!(ledger.total_supply().unwrap(), Balance::ZERO);
    }

    #[test]
    fn set_account_updates_root_and_store() {
        let mut ledger = Ledger::new();
        let empty_root = ledger.state_root();
        ledger.set_account(
            &id("usa.reserve.sov"),
            Account::with_balance(Balance::from_sov(100).unwrap()),
        );
        assert_ne!(ledger.state_root(), empty_root);
        assert!(ledger.exists(&id("usa.reserve.sov")));
        assert_eq!(
            ledger.account(&id("usa.reserve.sov")).balance,
            Balance::from_sov(100).unwrap()
        );
        assert_eq!(
            ledger.total_supply().unwrap(),
            Balance::from_sov(100).unwrap()
        );
    }

    #[test]
    fn root_is_order_independent() {
        let mut a = Ledger::new();
        a.set_account(
            &id("aaa.sov"),
            Account::with_balance(Balance::from_sov(1).unwrap()),
        );
        a.set_account(
            &id("bbb.sov"),
            Account::with_balance(Balance::from_sov(2).unwrap()),
        );

        let mut b = Ledger::new();
        b.set_account(
            &id("bbb.sov"),
            Account::with_balance(Balance::from_sov(2).unwrap()),
        );
        b.set_account(
            &id("aaa.sov"),
            Account::with_balance(Balance::from_sov(1).unwrap()),
        );

        assert_eq!(a.state_root(), b.state_root());
    }

    #[test]
    fn zeroing_account_matches_absent_root() {
        let mut ledger = Ledger::new();
        let empty_root = ledger.state_root();
        ledger.set_account(
            &id("x.sov"),
            Account::with_balance(Balance::from_sov(5).unwrap()),
        );
        ledger.set_account(&id("x.sov"), Account::default());
        assert_eq!(ledger.state_root(), empty_root);
        assert_eq!(ledger.account_count(), 0);
    }

    #[test]
    fn undo_restores_exact_state_for_every_mutation_kind() {
        use sov_compliance::{SpendLimit, TransferControl};
        // The reorg-correctness linchpin: after recording a block's writes, applying
        // the undo log must restore the ledger BIT-FOR-BIT (same state root AND same
        // serialized state). This exercises overwrite / create / remove across every
        // one of the ~16 mutation kinds, so a missed pre-image anywhere fails here.
        let issuer = id("usa.reserve.sov");
        let asset = token_asset_id(&issuer, "USD1");
        let coll = nft_class_id(&issuer, "ART");
        let deny = || TransferControl::DenyList([id("bad.sov")].into_iter().collect());
        let pk = |s: u8| sov_crypto::Keypair::from_seed([s; 32]).public_key();

        // ── Baseline state, so undos restore PRIOR values, not just absence ──
        let mut l = Ledger::new();
        l.set_account(&id("alice.sov"), Account::with_balance(Balance::from_sov(100).unwrap()));
        l.set_contract_value(&id("c.sov"), b"k".to_vec(), b"v0".to_vec());
        l.set_token(asset, TokenInfo { issuer: issuer.clone(), symbol: "USD1".into(), issued: Balance::from_sov(50).unwrap(), burned: Balance::ZERO });
        l.set_token_balance(&asset, &id("alice.sov"), Balance::from_sov(20).unwrap());
        l.set_token_policy(asset, CompliancePolicy { frozen: false, transfer_control: deny(), spend_limit: Some(SpendLimit { max_per_window: Balance::from_sov(9).unwrap(), window_blocks: 5 }) });
        l.set_token_window(&asset, &id("alice.sov"), SpendWindow { window_start: 3, spent: Balance::from_sov(2).unwrap() });
        l.set_nft_class(coll, NftClass { issuer: issuer.clone(), symbol: "ART".into(), minted: 1 });
        l.mint_nft(coll, b"item1".to_vec(), id("alice.sov"), b"meta0".to_vec(), 1).unwrap();
        l.lock_htlc(Hash::digest(b"h0"), Htlc { locker: id("alice.sov"), recipient: id("bob.sov"), amount: Balance::from_sov(5).unwrap(), hashlock: [0u8; 32], timeout_height: 100 }).unwrap();
        l.set_multisig(id("alice.sov"), Multisig { signers: vec![pk(1)], threshold: 1 });
        l.add_mined_emitted(Balance::from_sov(12).unwrap()).unwrap();
        l.add_shielded_value(Balance::from_sov(7).unwrap()).unwrap();
        l.set_deshield_window(2, Balance::from_sov(1).unwrap());
        l.consume_intent(Hash::digest(b"intent0"));

        let root0 = l.state_root();
        let snap0 = l.to_snapshot_bytes();

        // ── A recorded "block": overwrite, create, AND remove across every kind ──
        l.begin_undo();
        l.set_account(&id("alice.sov"), Account::with_balance(Balance::from_sov(999).unwrap())); // overwrite
        l.set_account(&id("carol.sov"), Account::with_balance(Balance::from_sov(1).unwrap()));   // create
        l.set_contract_value(&id("c.sov"), b"k".to_vec(), b"v1".to_vec()); // overwrite
        l.set_contract_value(&id("c.sov"), b"k".to_vec(), Vec::new());     // clear
        let asset2 = token_asset_id(&id("ecb.reserve.sov"), "EUR1");
        l.set_token(asset2, TokenInfo { issuer: id("ecb.reserve.sov"), symbol: "EUR1".into(), issued: Balance::from_sov(1).unwrap(), burned: Balance::ZERO }); // create
        l.set_token_balance(&asset, &id("alice.sov"), Balance::ZERO);     // remove
        l.set_token_balance(&asset, &id("bob.sov"), Balance::from_sov(8).unwrap()); // create
        l.set_token_policy(asset, CompliancePolicy { frozen: true, transfer_control: deny(), spend_limit: None }); // overwrite + cascades (clears alice's window)
        l.set_token_window(&asset, &id("bob.sov"), SpendWindow { window_start: 9, spent: Balance::from_sov(4).unwrap() }); // create
        l.mint_nft(coll, b"item2".to_vec(), id("bob.sov"), Vec::new(), 2).unwrap(); // create
        l.transfer_nft(coll, b"item1", id("carol.sov")).unwrap();         // transfer
        l.set_nft_meta(coll, b"item1", b"meta1".to_vec()).unwrap();       // meta
        l.set_nft_class(coll, NftClass { issuer: issuer.clone(), symbol: "ART".into(), minted: 2 }); // overwrite
        l.settle_htlc(&Hash::digest(b"h0")).unwrap();                     // remove htlc
        l.lock_htlc(Hash::digest(b"h1"), Htlc { locker: id("carol.sov"), recipient: id("alice.sov"), amount: Balance::from_sov(3).unwrap(), hashlock: [1u8; 32], timeout_height: 200 }).unwrap(); // create
        l.set_multisig(id("alice.sov"), Multisig { signers: vec![pk(1), pk(2)], threshold: 2 }); // overwrite
        l.set_multisig(id("dave.sov"), Multisig { signers: vec![pk(3)], threshold: 1 });          // create
        l.add_mined_emitted(Balance::from_sov(1).unwrap()).unwrap();
        l.add_shielded_value(Balance::from_sov(2).unwrap()).unwrap();
        l.sub_shielded_value(Balance::from_sov(1).unwrap()).unwrap();
        l.set_deshield_window(5, Balance::from_sov(3).unwrap());
        l.consume_intent(Hash::digest(b"intent1"));

        let undo = l.take_undo();
        assert!(!undo.is_empty());
        assert_ne!(l.state_root(), root0, "the recorded block must have changed state");

        // ── Disconnect: undo must restore the pre-block state EXACTLY ──
        l.apply_undo(undo);
        assert_eq!(l.state_root(), root0, "undo restores the exact state root");
        assert_eq!(l.to_snapshot_bytes(), snap0, "undo restores the exact serialized state");
    }

    #[test]
    fn save_and_load_preserves_state_root() {
        let mut ledger = Ledger::new();
        ledger.set_account(
            &id("usa.reserve.sov"),
            Account::with_balance(Balance::from_sov(1_000).unwrap()),
        );
        ledger.set_account(
            &id("ecb.reserve.sov"),
            Account::with_balance(Balance::from_sov(250).unwrap()),
        );
        let root = ledger.state_root();
        let supply = ledger.total_supply().unwrap();

        let path = std::env::temp_dir().join(format!(
            "sov-ledger-{}-{:?}.bin",
            std::process::id(),
            std::thread::current().id()
        ));
        ledger.save(&path).unwrap();
        let loaded = Ledger::load(&path).unwrap();
        std::fs::remove_file(&path).ok();

        // The reloaded state reproduces the exact root and balances.
        assert_eq!(loaded.state_root(), root);
        assert_eq!(loaded.total_supply().unwrap(), supply);
        assert_eq!(
            loaded.account(&id("usa.reserve.sov")).balance,
            Balance::from_sov(1_000).unwrap()
        );
        assert_eq!(loaded.account_count(), 2);
    }

    #[test]
    fn emission_counters_commit_and_persist() {
        let mut ledger = Ledger::new();
        let empty_root = ledger.state_root();
        assert_eq!(ledger.mined_emitted(), Balance::ZERO);

        // Minting moves the counter and changes the committed root.
        ledger
            .add_mined_emitted(Balance::from_sov(50).unwrap())
            .unwrap();
        assert_eq!(ledger.mined_emitted(), Balance::from_sov(50).unwrap());
        assert_ne!(ledger.state_root(), empty_root);
        let root = ledger.state_root();

        // Counters survive a save/load round-trip, reproducing the exact root.
        let path = std::env::temp_dir().join(format!(
            "sov-ledger-emit-{}-{:?}.bin",
            std::process::id(),
            std::thread::current().id()
        ));
        ledger.save(&path).unwrap();
        let loaded = Ledger::load(&path).unwrap();
        std::fs::remove_file(&path).ok();
        assert_eq!(loaded.mined_emitted(), Balance::from_sov(50).unwrap());
        assert_eq!(loaded.state_root(), root);
    }

    #[test]
    fn token_asset_id_is_injective_over_issuer_and_symbol() {
        // Different issuers, same symbol — different assets.
        assert_ne!(
            token_asset_id(&id("usa.reserve.sov"), "USD1"),
            token_asset_id(&id("ecb.reserve.sov"), "USD1")
        );
        // Same issuer, different symbols — different assets.
        assert_ne!(
            token_asset_id(&id("usa.reserve.sov"), "USD1"),
            token_asset_id(&id("usa.reserve.sov"), "USD2")
        );
        // Splice attack: moving bytes across the issuer/symbol boundary cannot
        // collide, because an AccountId can never contain the 0x00 separator.
        assert_ne!(
            token_asset_id(&id("a.sovx"), "YZ"),
            token_asset_id(&id("a.sov"), "xYZ")
        );
        // Deterministic.
        assert_eq!(
            token_asset_id(&id("usa.reserve.sov"), "USD1"),
            token_asset_id(&id("usa.reserve.sov"), "USD1")
        );
    }

    #[test]
    fn token_state_commits_to_the_root_and_zero_balances_are_canonical() {
        let mut ledger = Ledger::new();
        let empty_root = ledger.state_root();
        let asset = token_asset_id(&id("usa.reserve.sov"), "USD1");

        ledger.set_token(
            asset,
            TokenInfo {
                issuer: id("usa.reserve.sov"),
                symbol: "USD1".into(),
                issued: Balance::from_sov(100).unwrap(),
                burned: Balance::ZERO,
            },
        );
        let info_only_root = ledger.state_root();
        assert_ne!(
            info_only_root, empty_root,
            "the issuance record is committed"
        );

        ledger.set_token_balance(&asset, &id("a.sov"), Balance::from_sov(100).unwrap());
        assert_ne!(
            ledger.state_root(),
            info_only_root,
            "balances are committed"
        );

        // Zeroing a balance restores the exact root it had before — an
        // explicitly-zeroed holding commits identically to an absent one.
        ledger.set_token_balance(&asset, &id("a.sov"), Balance::ZERO);
        assert_eq!(ledger.state_root(), info_only_root);

        // Token units never count toward native SOV supply.
        assert_eq!(ledger.total_supply().unwrap(), Balance::ZERO);
    }

    #[test]
    fn save_and_load_preserves_token_state_and_root() {
        let mut ledger = Ledger::new();
        let asset = token_asset_id(&id("usa.reserve.sov"), "USD1");
        ledger.set_token(
            asset,
            TokenInfo {
                issuer: id("usa.reserve.sov"),
                symbol: "USD1".into(),
                issued: Balance::from_sov(1_000).unwrap(),
                burned: Balance::from_sov(50).unwrap(),
            },
        );
        ledger.set_token_balance(&asset, &id("a.sov"), Balance::from_sov(700).unwrap());
        ledger.set_token_balance(&asset, &id("b.sov"), Balance::from_sov(250).unwrap());
        let root = ledger.state_root();

        let path = std::env::temp_dir().join(format!(
            "sov-ledger-token-{}-{:?}.bin",
            std::process::id(),
            std::thread::current().id()
        ));
        ledger.save(&path).unwrap();
        let loaded = Ledger::load(&path).unwrap();
        std::fs::remove_file(&path).ok();

        assert_eq!(loaded.state_root(), root);
        let info = loaded.token(&asset).unwrap();
        assert_eq!(info.issued, Balance::from_sov(1_000).unwrap());
        assert_eq!(info.burned, Balance::from_sov(50).unwrap());
        assert_eq!(info.supply().unwrap(), Balance::from_sov(950).unwrap());
        assert_eq!(
            loaded.token_balance(&asset, &id("a.sov")),
            Balance::from_sov(700).unwrap()
        );
        assert_eq!(
            loaded.token_balance(&asset, &id("b.sov")),
            Balance::from_sov(250).unwrap()
        );
    }

    #[test]
    fn token_policy_and_windows_commit_persist_and_reset_on_replacement() {
        use sov_compliance::{CompliancePolicy, SpendLimit, SpendWindow, TransferControl};

        let mut ledger = Ledger::new();
        let asset = token_asset_id(&id("usa.reserve.sov"), "USD1");
        ledger.set_token(
            asset,
            TokenInfo {
                issuer: id("usa.reserve.sov"),
                symbol: "USD1".into(),
                issued: Balance::from_sov(100).unwrap(),
                burned: Balance::ZERO,
            },
        );
        ledger.set_token_balance(&asset, &id("a.sov"), Balance::from_sov(100).unwrap());
        let unregulated_root = ledger.state_root();

        // Installing a policy changes the committed root; so does a window.
        let policy = CompliancePolicy {
            frozen: false,
            transfer_control: TransferControl::DenyList([id("bad.sov")].into_iter().collect()),
            spend_limit: Some(SpendLimit {
                max_per_window: Balance::from_sov(10).unwrap(),
                window_blocks: 5,
            }),
        };
        ledger.set_token_policy(asset, policy.clone());
        let policy_root = ledger.state_root();
        assert_ne!(
            policy_root, unregulated_root,
            "the policy is consensus state"
        );
        ledger.set_token_window(
            &asset,
            &id("a.sov"),
            SpendWindow {
                window_start: 7,
                spent: Balance::from_sov(3).unwrap(),
            },
        );
        assert_ne!(ledger.state_root(), policy_root);

        // Persistence round-trips policy + window with the identical root.
        let path = std::env::temp_dir().join(format!(
            "sov-ledger-policy-{}-{:?}.bin",
            std::process::id(),
            std::thread::current().id()
        ));
        ledger.save(&path).unwrap();
        let loaded = Ledger::load(&path).unwrap();
        std::fs::remove_file(&path).ok();
        assert_eq!(loaded.state_root(), ledger.state_root());
        assert_eq!(loaded.token_policy(&asset), Some(&policy));
        assert_eq!(
            loaded.token_window(&asset, &id("a.sov")).spent,
            Balance::from_sov(3).unwrap()
        );

        // Replacing the policy clears the asset's windows — root returns to
        // exactly the fresh-policy state, no stale accounting lingers.
        ledger.set_token_policy(asset, policy);
        assert_eq!(ledger.state_root(), policy_root);
        assert_eq!(
            ledger.token_window(&asset, &id("a.sov")),
            SpendWindow::default()
        );
    }

    #[test]
    fn consumed_intents_commit_to_the_root_and_persist() {
        let mut ledger = Ledger::new();
        let empty_root = ledger.state_root();
        let intent_id = Hash::digest(b"intent-terms");
        assert!(!ledger.intent_consumed(&intent_id));

        ledger.consume_intent(intent_id);
        assert!(ledger.intent_consumed(&intent_id));
        assert_ne!(
            ledger.state_root(),
            empty_root,
            "a consumed intent is consensus state"
        );
        let root = ledger.state_root();

        let path = std::env::temp_dir().join(format!(
            "sov-ledger-intent-{}-{:?}.bin",
            std::process::id(),
            std::thread::current().id()
        ));
        ledger.save(&path).unwrap();
        let loaded = Ledger::load(&path).unwrap();
        std::fs::remove_file(&path).ok();
        assert!(loaded.intent_consumed(&intent_id));
        assert_eq!(loaded.state_root(), root);
    }

    #[test]
    fn deshield_window_commits_persists_and_default_is_canonical() {
        let mut ledger = Ledger::new();
        let empty_root = ledger.state_root();
        assert_eq!(ledger.deshield_window(), (0, Balance::ZERO));

        // A recorded outflow is consensus state.
        ledger.set_deshield_window(7, Balance::from_sov(33).unwrap());
        assert_ne!(ledger.state_root(), empty_root);
        let root = ledger.state_root();

        // Round-trips through persistence with the identical root.
        let path = std::env::temp_dir().join(format!(
            "sov-ledger-deshield-{}-{:?}.bin",
            std::process::id(),
            std::thread::current().id()
        ));
        ledger.save(&path).unwrap();
        let loaded = Ledger::load(&path).unwrap();
        std::fs::remove_file(&path).ok();
        assert_eq!(
            loaded.deshield_window(),
            (7, Balance::from_sov(33).unwrap())
        );
        assert_eq!(loaded.state_root(), root);

        // Resetting to the default window restores the canonical empty root.
        ledger.set_deshield_window(0, Balance::ZERO);
        assert_eq!(ledger.state_root(), empty_root);
    }

    #[test]
    fn proofs_track_state_root() {
        let mut ledger = Ledger::new();
        ledger.set_account(
            &id("usa.reserve.sov"),
            Account::with_balance(Balance::from_sov(9).unwrap()),
        );
        let acct = ledger.account(&id("usa.reserve.sov"));
        let encoded = borsh::to_vec(&acct).unwrap();
        let proof = ledger.prove(&id("usa.reserve.sov"));
        assert!(proof.verify(
            ledger.state_root(),
            &Ledger::slot(&id("usa.reserve.sov")),
            Some(&encoded)
        ));
        // Absent account proves exclusion.
        let missing = ledger.prove(&id("nope.sov"));
        assert!(missing.verify(ledger.state_root(), &Ledger::slot(&id("nope.sov")), None));
    }

    #[test]
    fn name_registry_commits_to_the_root_and_survives_save_load() {
        let mut ledger = Ledger::new();
        // An empty registry contributes NOTHING to the root (absent-when-empty),
        // so this root equals a bare ledger's.
        let empty_root = ledger.state_root();
        assert_eq!(empty_root, Ledger::new().state_root());

        // Registering a name changes the root and is resolvable.
        assert!(ledger
            .register_name("treasury.sov".into(), id("usa.reserve.sov"), 7)
            .is_some());
        assert_ne!(ledger.state_root(), empty_root, "names fold into the root");
        assert_eq!(
            ledger.resolve_name("treasury.sov"),
            Some(id("usa.reserve.sov"))
        );
        // A second registration of the same name is refused (first-come).
        assert!(ledger
            .register_name("treasury.sov".into(), id("ecb.reserve.sov"), 9)
            .is_none());

        let root = ledger.state_root();
        let path = std::env::temp_dir().join(format!(
            "sov-names-{}-{:?}.bin",
            std::process::id(),
            std::thread::current().id()
        ));
        ledger.save(&path).unwrap();
        let loaded = Ledger::load(&path).unwrap();
        std::fs::remove_file(&path).ok();

        // Reloaded ledger reproduces the exact root and the registry.
        assert_eq!(loaded.state_root(), root);
        assert_eq!(
            loaded.resolve_name("treasury.sov"),
            Some(id("usa.reserve.sov"))
        );
        assert_eq!(
            loaded
                .name_record("treasury.sov")
                .unwrap()
                .registered_height,
            7
        );
        assert_eq!(loaded.name_count(), 1);

        // Removing the only name (via transfer back to an empty registry is not a
        // thing; instead verify the digest is canonical): a fresh ledger that
        // registers the same name reaches the same root.
        let mut twin = Ledger::new();
        twin.register_name("treasury.sov".into(), id("usa.reserve.sov"), 7);
        assert_eq!(twin.state_root(), root);
    }

    #[test]
    fn multisig_policy_commits_to_the_root_and_survives_save_load() {
        let mut ledger = Ledger::new();
        let empty_root = ledger.state_root();
        // An empty multisig map contributes NOTHING (absent-when-empty), so opting
        // in is the only thing that changes the root — proving normal accounts are
        // unaffected (no reset).
        assert_eq!(empty_root, Ledger::new().state_root());

        let signers = vec![
            sov_crypto::Keypair::from_seed([1; 32]).public_key(),
            sov_crypto::Keypair::from_seed([2; 32]).public_key(),
            sov_crypto::Keypair::from_seed([3; 32]).public_key(),
        ];
        ledger.set_multisig(
            id("usa.reserve.sov"),
            Multisig {
                signers: signers.clone(),
                threshold: 2,
            },
        );
        assert_ne!(ledger.state_root(), empty_root);
        assert_eq!(ledger.multisig_count(), 1);
        let root = ledger.state_root();

        let path = std::env::temp_dir().join(format!(
            "sov-ms-{}-{:?}.bin",
            std::process::id(),
            std::thread::current().id()
        ));
        ledger.save(&path).unwrap();
        let loaded = Ledger::load(&path).unwrap();
        std::fs::remove_file(&path).ok();

        assert_eq!(loaded.state_root(), root);
        let p = loaded.multisig_of(&id("usa.reserve.sov")).unwrap();
        assert_eq!(p.threshold, 2);
        assert_eq!(p.signers, signers);
    }
}
