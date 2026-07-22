//! Transactions: the unit of state change, and the only way value moves.
//!
//! A [`Transaction`] is the unsigned intent — who is acting, their nonce, and
//! what they want to do. A [`SignedTransaction`] binds that intent to an Ed25519
//! signature. The canonical bytes that get hashed and signed are the **Borsh**
//! encoding of the [`Transaction`] (deterministic, length-prefixed), so a given
//! transaction always yields the same id and the same signing payload.

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use sov_compliance::CompliancePolicy;
use sov_crypto::{Keypair, PublicKey, Signature};
use sov_intents::{Intent, Settlement};
use sov_primitives::{AccountId, Balance, Hash, SigningDomain, TxDomainMode};

/// What a transaction does. Kept as a closed enum so every state transition is
/// explicit; new capabilities (govern, bridge, assets) are added as variants in
/// later phases rather than as opaque payloads.
///
/// **Issuance is NOT a transaction.** Under Nakamoto consensus the block
/// coinbase mints the scheduled reward to the block's miner as part of the
/// state transition itself; the pre-Nakamoto `Mine`/`MineShielded` mint
/// transactions were removed (one planned encoding break, before any public
/// network existed).
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Action {
    /// Move `amount` from the transaction's signer to `to`.
    Transfer {
        /// Recipient account.
        to: AccountId,
        /// Amount to transfer.
        amount: Balance,
    },
    /// Move vested funds (an early allocation's lockup) into the liquid balance,
    /// permitted only at or after the vesting unlock height.
    ClaimVesting,
    /// Deploy WebAssembly contract `code` to the signer's account, turning it
    /// into a contract that anyone can `Call`.
    Deploy {
        /// The contract's WASM bytecode.
        code: Vec<u8>,
    },
    /// Invoke the `call` entry point of the contract account `contract`, with up
    /// to `gas_limit` gas and `calldata` as the call's input bytes (ABI v2 —
    /// readable by the contract via the `calldata` host function, priced per
    /// byte and bounded by the BIP-110 data cap). The signer (caller) pays the
    /// resulting gas fee.
    Call {
        /// The contract account to invoke.
        contract: AccountId,
        /// Maximum gas (wasmi fuel) the call may consume.
        gas_limit: u64,
        /// Opaque input bytes passed to the contract.
        calldata: Vec<u8>,
    },
    /// A shielded-pool action carrying a serialized Orchard/Halo2 bundle (see
    /// `sov-shielded`'s `ShieldedBundle::to_bytes`). Executing it verifies the
    /// zero-knowledge proof, checks the anchor and nullifiers, applies the bundle
    /// to the shielded pool, and moves the bundle's net value balance between the
    /// signer's transparent balance and the shielded pool (shield / transfer /
    /// de-shield). Added last so existing Borsh action discriminants are stable.
    Shielded {
        /// The canonical byte encoding of the shielded bundle.
        bundle: Vec<u8>,
    },
    /// Lock `amount` into a **hash-time-locked contract** — the SOV half of a
    /// trustless cross-chain atomic swap. The escrow is claimable by `recipient`
    /// only by revealing a preimage whose SHA-256 equals `hashlock` (the same hash
    /// that locks the counterparty's Bitcoin/Zcash HTLC), before block
    /// `timeout_height`; at/after the timeout the signer (locker) may refund. No
    /// custodian, oracle, or bridge — atomicity comes from the shared secret.
    HtlcLock {
        /// Who may claim the escrow with the correct preimage.
        recipient: AccountId,
        /// Amount to escrow out of the signer's balance.
        amount: Balance,
        /// SHA-256 of the secret preimage that unlocks the escrow. A [`Hash`](struct@Hash) so JSON-RPC
        /// renders it as a hex string, consistent with every other 32-byte field
        /// (account-ids, tx-ids); Borsh (the signed/consensus form) is byte-identical to a
        /// bare `[u8; 32]`, so signatures, tx-ids, and genesis are unchanged.
        hashlock: Hash,
        /// Block height at/after which the locker may refund.
        timeout_height: u64,
    },
    /// Claim a hash-time-locked contract by revealing the secret `preimage`
    /// (SHA-256(preimage) must equal the HTLC's hashlock, before its timeout).
    /// Revealing the preimage on-chain is what lets the swap counterparty claim on
    /// the other chain — completing the atomic swap. The HTLC id is the id of the
    /// `HtlcLock` transaction that created it.
    HtlcClaim {
        /// The id of the `HtlcLock` transaction that opened the escrow.
        htlc_id: Hash,
        /// The secret preimage.
        preimage: Vec<u8>,
    },
    /// Refund a hash-time-locked contract to its locker, permitted only at/after
    /// its `timeout_height` (if the counterparty never claimed).
    HtlcRefund {
        /// The id of the `HtlcLock` transaction that opened the escrow.
        htlc_id: Hash,
    },
    /// Mint `amount` units of the signer's native asset named `symbol` to `to`.
    /// The asset id is *derived* — `Blake3("sov:asset:v1" ‖ issuer ‖ 0x00 ‖
    /// symbol)` — so an asset is cryptographically bound to its issuer: under
    /// Blake3 collision resistance, no other account can ever issue under the
    /// same id. The first issue creates the asset (recording the signer as its
    /// immutable issuer); later issues by the same signer mint more. Token units
    /// are their own denomination — they never count toward, or against, the
    /// 21M SOV supply, but they obey the same per-asset conservation theorem:
    /// `sum(balances) == issued − burned`, checked after every block.
    TokenIssue {
        /// The asset's symbol (1–16 ASCII alphanumeric bytes), namespaced under
        /// the issuer — `("usa.reserve.sov", "USD1")` and `("ecb.reserve.sov",
        /// "USD1")` are different assets with different ids.
        symbol: String,
        /// Units to mint (grains; the same 10^8 fixed-point scale as SOV).
        amount: Balance,
        /// Recipient of the freshly minted units.
        to: AccountId,
    },
    /// Move `amount` units of the existing asset `asset` from the signer to
    /// `to`. Token transfers follow the exact rules of native transfers —
    /// signature, key authorization, nonce, checked arithmetic, atomic
    /// rejection — and pay their fee in native SOV.
    TokenTransfer {
        /// The asset id (see [`Action::TokenIssue`] for its derivation).
        asset: Hash,
        /// Recipient account.
        to: AccountId,
        /// Units to transfer.
        amount: Balance,
    },
    /// Permanently destroy `amount` units of `asset` from the signer's own
    /// balance, shrinking the asset's supply (recorded in its monotonic burn
    /// counter). This is the redemption path for reserve-backed assets: the
    /// issuer (or any holder) burns units on-chain when off-chain collateral
    /// is released.
    TokenBurn {
        /// The asset id.
        asset: Hash,
        /// Units to burn.
        amount: Balance,
    },
    /// Set (or replace) the compliance policy of `asset` — the regulated-
    /// issuance path (e.g. a USDC-style reserve asset). **Only the asset's
    /// issuer** may execute this: the same hash binding that authorizes
    /// issuance authorizes regulation. The policy (freeze/pause, allow- or
    /// deny-listed accounts, per-holder spend velocity) is committed to the
    /// state root and enforced by consensus on every token movement of that
    /// asset. Native SOV never consults a compliance policy — regulation is
    /// strictly per-asset and issuer-opt-in.
    TokenSetPolicy {
        /// The asset id.
        asset: Hash,
        /// The policy to install. Replacing a policy resets the asset's
        /// spend-velocity accounting.
        policy: CompliancePolicy,
    },
    /// Atomically settle a signed swap intent — the on-chain liquidity rail.
    /// The intent's **owner** signed a declarative offer off-chain ("give X of
    /// asset A, receive at least Y of asset B, until height H"); the
    /// **solver** (this transaction's signer) fills it on-chain. Execution
    /// verifies the owner's Ed25519 signature against the owner account's
    /// registered on-chain key, enforces expiry, consumes the intent id
    /// exactly once (no replay), gates both token legs through the assets'
    /// compliance policies, and moves both legs atomically — both or neither.
    /// No custodian, oracle, order book, or off-chain trust: the owner's
    /// terms are enforced by consensus.
    IntentSettle {
        /// The signed intent plus the solver's delivery terms.
        settlement: Settlement,
    },
    /// Cancel (consume) one of the signer's own intents before it is filled.
    /// Marks the intent id as consumed so no later `IntentSettle` can execute
    /// it. Only the intent's owner may cancel.
    IntentCancel {
        /// The intent body to cancel (its id is derived from these exact
        /// terms; canceling terms that were never signed is harmless).
        intent: Intent,
    },
    /// Re-key the signer's account: replace its controlling key with
    /// `new_key`, **without moving funds**. This is the protocol's key-
    /// migration vehicle (Phase 18): when a stronger scheme ships as a new
    /// key variant, every account rotates to it with one transaction.
    ///
    /// Two signatures authorize a rotation: the *current* key signs the
    /// transaction (only the present owner can rotate), and the **new key
    /// proves possession** by signing the domain-tagged rotation message
    /// ([`rotation_signing_bytes`]) binding (signer, nonce, new_key) — so an
    /// account can never be rotated to a key nobody holds, and a possession
    /// proof can never be replayed for another account or nonce. The old key
    /// is dead the moment the rotation commits.
    RotateKey {
        /// The new controlling key.
        new_key: PublicKey,
        /// The new key's signature over [`rotation_signing_bytes`].
        proof: Signature,
    },
    /// Register a human-readable **name** in the on-chain name registry, binding
    /// it to the signer's account (ENS/SNS-style). The name is an alias: it
    /// *resolves* to the signer's account, so others can pay `treasury.sov`
    /// instead of a 64-hex address, while the signer's funds never move and stay
    /// in their own account. First-come — an unclaimed, well-formed `*.sov` name
    /// that does not shadow an existing keyed account may be claimed by paying a
    /// one-time registration fee (on top of the gas fee); the fee is an ordinary
    /// fee earned by miners (split miner/treasury/dev like every fee), not burned.
    /// Added after `RotateKey` so existing Borsh action discriminants are stable.
    RegisterName {
        /// The name to claim — a valid account id ending in `.sov`, e.g.
        /// `treasury.sov`. Must not be a 64-hex implicit id, already registered,
        /// or an existing keyed account.
        name: String,
    },
    /// Reassign ownership of a name the signer currently owns to `to` — a name
    /// transfer/sale. The name then resolves to (and is controlled by) `to`.
    /// Only the current owner may transfer; the registry entry must exist.
    ///
    /// SNS names are **non-fungible tokens**: this is the `NftTransfer` of a name
    /// in the reserved SNS collection, kept as a named convenience action.
    TransferName {
        /// The owned name to reassign.
        name: String,
        /// The account that becomes the new owner (and resolution target).
        to: AccountId,
    },
    /// Mint a **non-fungible token** (NFT): create a unique item `token_id` in the
    /// signer's collection `symbol`, owned by `to`. The first mint of a symbol
    /// creates the collection and binds the signer as its immutable issuer (the
    /// collection id is `blake3("sov:nft:v1" ‖ issuer ‖ 0x00 ‖ symbol)`, so under
    /// collision resistance no other account can mint into it). Fails if the item
    /// `(collection, token_id)` already exists — non-fungibility is enforced.
    /// Added after the name actions so existing Borsh discriminants are stable.
    NftMint {
        /// The collection symbol (1–32 ASCII bytes), namespaced under the issuer.
        symbol: String,
        /// The item's unique id within the collection (opaque bytes).
        token_id: Vec<u8>,
        /// The account that owns the freshly minted item.
        to: AccountId,
        /// Opaque per-item metadata (e.g. a resolver record or content pointer).
        metadata: Vec<u8>,
    },
    /// Transfer a non-fungible token to `to`. Only the item's current owner may
    /// transfer it; the item must exist.
    NftTransfer {
        /// The collection id the item belongs to.
        collection: Hash,
        /// The item's id within the collection.
        token_id: Vec<u8>,
        /// The account that becomes the new owner.
        to: AccountId,
    },
    /// Set (replace) a non-fungible token's metadata — the resolver/records hook.
    /// Only the item's current owner may set it.
    NftSetMeta {
        /// The collection id the item belongs to.
        collection: Hash,
        /// The item's id within the collection.
        token_id: Vec<u8>,
        /// The new opaque metadata.
        metadata: Vec<u8>,
    },
    /// **Opt into (or replace) M-of-N multisig** for the signer's account. After
    /// this, single-key spends are disabled — every action must be approved by
    /// `threshold` of `signers` via [`Action::MultisigExec`]. The initial opt-in is
    /// authorized by the account's current key; a later change must itself come
    /// through `MultisigExec` (the existing M-of-N authorizes the new policy).
    /// Added after the NFT actions so existing Borsh discriminants are stable.
    SetMultisig {
        /// The authorized signer keys (N). Index order is significant — an
        /// approval references a signer by its position here.
        signers: Vec<PublicKey>,
        /// Required approvals (M); must satisfy `1 ≤ threshold ≤ signers.len()`.
        threshold: u16,
    },
    /// Execute `action` on a multisig account, authorized by `approvals` from the
    /// account's policy signers. The outer transaction is the *submitter's*
    /// envelope (a policy member relays it and pays the fee); the approvals each
    /// sign [`multisig_signing_bytes`] over `(account, nonce, action)`, so they are
    /// bound to this exact operation and cannot be replayed. Execution requires
    /// `threshold` distinct valid approvals; nesting and `RotateKey` are refused.
    MultisigExec {
        /// The inner action to perform as the multisig account.
        #[borsh(deserialize_with = "bounded_nested_action")]
        action: Box<Action>,
        /// Approvals from distinct policy signers over `multisig_signing_bytes`.
        approvals: Vec<MultisigApproval>,
    },
    /// ON-CHAIN multisig coordination (the ergonomic path; the chain is the
    /// coordinator). A policy member PROPOSES a spend from a multisig `account`: the
    /// proposal is stored pending, with the proposer counted as its first approval.
    /// The transaction is the *member's own* (their key, their nonce, their fee), so
    /// the member's signature on it IS their authenticated approval — no detached
    /// approval blobs. Appended at the tail so existing Borsh discriminants are stable.
    ProposeMultisig {
        /// The multisig account the spend draws from.
        account: AccountId,
        /// The action to perform as `account` once enough members approve. May not be
        /// `MultisigExec`, `RotateKey`, or another multisig-coordination action.
        #[borsh(deserialize_with = "bounded_nested_action")]
        action: Box<Action>,
    },
    /// A policy member APPROVES a pending proposal on `account`. Signed by the
    /// member's own key (their signature is the approval). When the approvals reach
    /// the policy threshold, the chain executes the proposal's action AS `account`
    /// and clears it.
    ApproveMultisig {
        /// The multisig account the proposal draws from.
        account: AccountId,
        /// The pending proposal's id.
        proposal: Hash,
    },
    /// A policy member CANCELS a pending proposal on `account` (it is removed without
    /// executing). Signed by the member's own key.
    CancelMultisig {
        /// The multisig account the proposal draws from.
        account: AccountId,
        /// The pending proposal's id.
        proposal: Hash,
    },
    /// Lock `amount` XUS from the signer's liquid balance into their CDP vault as
    /// collateral for xUSD. Supply-neutral: the XUS moves out of the balance into
    /// the vault (still counted in total supply). Appended at the tail so existing
    /// Borsh action discriminants stay stable.
    VaultDeposit {
        /// XUS grains to lock as collateral.
        amount: Balance,
    },
    /// Mint `amount` xUSD against the signer's vault collateral, up to the minimum
    /// collateral ratio at the current oracle price. Fails if it would leave the
    /// vault under-collateralized.
    VaultMint {
        /// xUSD grains to mint.
        amount: Balance,
    },
    /// Burn `amount` xUSD to repay the signer's vault debt (reducing what must be
    /// covered before collateral can be withdrawn). Burns real xUSD supply.
    VaultBurn {
        /// xUSD grains to repay.
        amount: Balance,
    },
    /// Withdraw `amount` XUS collateral from the signer's vault back to their
    /// liquid balance, permitted only while the vault stays at/above the minimum
    /// collateral ratio afterward.
    VaultWithdraw {
        /// XUS grains of collateral to release.
        amount: Balance,
    },
    /// Publish a new XUS/USD oracle price (USD per XUS, 10^8 fixed point). Accepted
    /// only from the authorized oracle account; every other signer is rejected.
    OracleUpdate {
        /// The new price: USD per 1 XUS in 10^8 fixed point.
        price: u128,
    },
    /// A **fee-auction envelope** (v0.1.98): pay `tip` to the block's miner ON TOP of
    /// the normal fixed intrinsic fee, bidding for earlier inclusion, then execute
    /// `inner`. Appended LAST so every existing action's Borsh discriminant — and thus
    /// genesis `cb0272ff` and every KAT vector — is byte-identical. Dormant until the
    /// miner-signaled `fee-auction` deployment is `Active`: rejected at mempool
    /// admission, block import, and execution before then, so pre-activation behavior
    /// is unchanged. `inner` must NOT itself be `Tipped` (no nested tips).
    Tipped {
        /// Priority tip paid to the block's miner, on top of the intrinsic fee.
        tip: Balance,
        /// The action actually performed once the tip is charged.
        #[borsh(deserialize_with = "bounded_nested_action")]
        inner: Box<Action>,
    },
}

/// Maximum nesting depth accepted when Borsh-**decoding** an [`Action`].
///
/// [`Action`] is recursive through three `Box<Action>` fields
/// ([`Action::MultisigExec`], [`Action::ProposeMultisig`], [`Action::Tipped`]).
/// A derived Borsh decoder recurses once per nesting level, so a maliciously
/// deep payload (~2000 levels, ~34 KB — far under the P2P frame cap) would
/// overflow the stack and **abort the process**: a remote crash-DoS. Bounding
/// the *decode* depth turns that payload into a clean decode error instead.
///
/// The bound is decode-only and generous: consensus itself refuses *any*
/// nesting of `MultisigExec`/`Tipped` and restricts `ProposeMultisig`'s inner
/// action, so every honest transaction has depth ≤ 2. Serialization, the byte
/// format, JSON, tx-ids, genesis `cb0272ff…`, and every KAT vector are
/// unchanged — only pathologically deep *inputs* (which no honest node ever
/// produced, and which previously crashed the decoder) are now rejected, and
/// identically so on every node.
pub const MAX_ACTION_DEPTH: u32 = 16;

mod action_depth {
    use std::cell::Cell;

    thread_local! {
        static DEPTH: Cell<u32> = const { Cell::new(0) };
    }

    /// RAII decode-depth guard. Construction (`enter`) checks and increments the
    /// thread-local depth; `Drop` **always** decrements — on `?` propagation,
    /// early return, and unwinding alike — so a rejected over-deep decode can
    /// never leak depth into a later, unrelated decode (which would make this
    /// node falsely reject a valid transaction and diverge from its peers).
    pub(super) struct DepthGuard(());

    impl DepthGuard {
        pub(super) fn enter() -> Result<Self, borsh::io::Error> {
            DEPTH.with(|d| {
                let next = d.get().saturating_add(1);
                if next > super::MAX_ACTION_DEPTH {
                    return Err(borsh::io::Error::new(
                        borsh::io::ErrorKind::InvalidData,
                        "Action nesting exceeds MAX_ACTION_DEPTH",
                    ));
                }
                d.set(next);
                Ok(DepthGuard(()))
            })
        }
    }

    impl Drop for DepthGuard {
        fn drop(&mut self) {
            DEPTH.with(|d| d.set(d.get().saturating_sub(1)));
        }
    }
}

/// Depth-bounded Borsh decode for the recursive `Box<Action>` fields (wired in
/// via `#[borsh(deserialize_with)]`). Reads the exact same bytes as the default
/// `BorshDeserialize::deserialize_reader` — the wire format is untouched — but
/// rejects inputs nested deeper than [`MAX_ACTION_DEPTH`] with a decode error
/// instead of recursing to a stack overflow.
fn bounded_nested_action<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Box<Action>> {
    let _guard = action_depth::DepthGuard::enter()?;
    borsh::BorshDeserialize::deserialize_reader(reader)
}

/// One signer's approval of a [`Action::MultisigExec`]: the signer's index into
/// the account's policy `signers`, and its signature over [`multisig_signing_bytes`].
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct MultisigApproval {
    /// Index into the account's multisig policy `signers`.
    pub signer: u16,
    /// Signature over [`multisig_signing_bytes`] for this operation.
    pub signature: Signature,
}

/// The canonical message each approver signs for [`Action::MultisigExec`]:
/// `"sov:multisig:v1" ‖ 0x00 ‖ account ‖ 0x00 ‖ le64(nonce) ‖ borsh(action)`.
/// Binding the account and nonce makes an approval single-use for one account at
/// one nonce; the account id cannot contain `0x00`, so the encoding is injective.
pub fn multisig_signing_bytes(account: &AccountId, nonce: u64, action: &Action) -> Vec<u8> {
    let action_bytes =
        borsh::to_vec(action).expect("Borsh serialization of an Action is infallible");
    let id_bytes = account.as_str().as_bytes();
    let mut buf = Vec::with_capacity(16 + 1 + id_bytes.len() + 1 + 8 + action_bytes.len());
    buf.extend_from_slice(b"sov:multisig:v1");
    buf.push(0x00);
    buf.extend_from_slice(id_bytes);
    buf.push(0x00);
    buf.extend_from_slice(&nonce.to_le_bytes());
    buf.extend_from_slice(&action_bytes);
    buf
}

/// The canonical message a new key signs to prove possession in
/// [`Action::RotateKey`]: `"sov:rotate:v1" ‖ 0x00 ‖ signer ‖ 0x00 ‖
/// le64(nonce) ‖ borsh(new_key)`. The account id cannot contain `0x00`, so
/// the encoding is injective; binding the signer and nonce makes each proof
/// single-use for a single account.
pub fn rotation_signing_bytes(signer: &AccountId, nonce: u64, new_key: &PublicKey) -> Vec<u8> {
    let key_bytes =
        borsh::to_vec(new_key).expect("Borsh serialization of a PublicKey is infallible");
    let id_bytes = signer.as_str().as_bytes();
    let mut buf = Vec::with_capacity(14 + 1 + id_bytes.len() + 1 + 8 + key_bytes.len());
    buf.extend_from_slice(b"sov:rotate:v1");
    buf.push(0x00);
    buf.extend_from_slice(id_bytes);
    buf.push(0x00);
    buf.extend_from_slice(&nonce.to_le_bytes());
    buf.extend_from_slice(&key_bytes);
    buf
}

/// The unsigned body of a transaction.
///
/// The `nonce` is the signer's monotonic counter: it makes each transaction
/// unique and gives the execution layer a total order per account, which is how
/// replay is prevented. The `public_key` is committed to here (inside the signed
/// bytes) so a transaction names exactly which key authorizes it.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct Transaction {
    /// Account authorizing and paying for this transaction.
    pub signer: AccountId,
    /// The public key whose signature authorizes this transaction.
    pub public_key: PublicKey,
    /// Per-signer monotonic counter for replay protection and ordering.
    pub nonce: u64,
    /// The state change to apply.
    pub action: Action,
}

/// Domain tag for transaction signatures under the miner-signaled `tx-domain`
/// hard fork: the framed signing preimage is
/// `"sov:tx:v1" ‖ 0x00 ‖ chain_id ‖ 0x00 ‖ genesis(32) ‖ borsh(Transaction)`.
/// Distinct from the intra-chain `sov:multisig:v1` / `sov:rotate:v1` tags and from
/// [`sov_intents`]'s `sov:intent:v1`, so the four preimages can never collide.
pub const TX_SIGNING_DOMAIN_TAG: &[u8] = b"sov:tx:v1";

impl Transaction {
    /// The canonical signing/hashing payload: the deterministic Borsh encoding.
    pub fn signing_bytes(&self) -> Vec<u8> {
        borsh::to_vec(self).expect("Borsh serialization of a Transaction is infallible")
    }

    /// The signing preimage under an optional network [`SigningDomain`].
    ///
    /// `None` reproduces [`signing_bytes`](Self::signing_bytes) **exactly** — the
    /// pre-fork bytes — so pre-activation behavior (and the genesis hash and every
    /// KAT vector) is byte-identical. `Some(domain)` binds the signature to that
    /// network, closing cross-network replay. The transaction *id* is deliberately
    /// unaffected — it stays the hash of the un-framed
    /// [`signing_bytes`](Self::signing_bytes) — so ids remain stable across the
    /// fork and only the *signature* gains the binding.
    pub fn signing_bytes_in(&self, domain: Option<&SigningDomain>) -> Vec<u8> {
        match domain {
            None => self.signing_bytes(),
            Some(d) => d.frame(TX_SIGNING_DOMAIN_TAG, &self.signing_bytes()),
        }
    }

    /// The transaction id: the Blake3 hash of [`Transaction::signing_bytes`].
    /// Independent of the signature (and of any signing domain), so it is stable
    /// and non-malleable.
    pub fn id(&self) -> Hash {
        Hash::digest(&self.signing_bytes())
    }
}

/// A transaction together with the signature that authorizes it.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct SignedTransaction {
    /// The signed body.
    pub transaction: Transaction,
    /// Ed25519 signature over [`Transaction::signing_bytes`].
    pub signature: Signature,
}

impl SignedTransaction {
    /// Sign `transaction` with `keypair`.
    ///
    /// Errors if the keypair's public key does not match the one named in the
    /// transaction — refusing to produce a transaction that names one key but is
    /// signed by another.
    pub fn sign(transaction: Transaction, keypair: &Keypair) -> Result<Self, TxError> {
        Self::sign_in(transaction, keypair, None)
    }

    /// Sign `transaction` under an optional network [`SigningDomain`].
    ///
    /// `None` is the legacy signature (byte-identical to [`sign`](Self::sign));
    /// `Some(domain)` produces a signature bound to that network — required once
    /// the `tx-domain` fork is active. Errors on the same key mismatch as
    /// [`sign`](Self::sign).
    pub fn sign_in(
        transaction: Transaction,
        keypair: &Keypair,
        domain: Option<&SigningDomain>,
    ) -> Result<Self, TxError> {
        if keypair.public_key() != transaction.public_key {
            return Err(TxError::KeyMismatch);
        }
        let signature = keypair.sign(&transaction.signing_bytes_in(domain));
        Ok(Self {
            transaction,
            signature,
        })
    }

    /// The id of the underlying transaction.
    pub fn id(&self) -> Hash {
        self.transaction.id()
    }

    /// The transaction's canonical serialized size in bytes (its Borsh encoding). A
    /// block's size is its header plus the length-prefixed concatenation of its
    /// transactions' encodings, so summing this is how the producer keeps an assembled
    /// block within the elastic block-size cap.
    pub fn serialized_size(&self) -> usize {
        borsh::to_vec(self)
            .expect("Borsh serialization of a SignedTransaction is infallible")
            .len()
    }

    /// Whether the signature verifies against the transaction's committed
    /// public key over its canonical (legacy, un-bound) signing bytes.
    #[must_use]
    pub fn verify_signature(&self) -> bool {
        self.verify_signature_in(None)
    }

    /// Whether the signature verifies under an optional network [`SigningDomain`].
    ///
    /// `None` verifies the legacy preimage — byte-identical to
    /// [`verify_signature`](Self::verify_signature). `Some(domain)` requires the
    /// signature to bind to that network: a legacy (un-bound) signature, or one
    /// bound to a *different* network, is rejected — which is precisely what
    /// closes cross-network replay once the `tx-domain` fork is active.
    #[must_use]
    pub fn verify_signature_in(&self, domain: Option<&SigningDomain>) -> bool {
        self.transaction
            .public_key
            .verify(&self.transaction.signing_bytes_in(domain), &self.signature)
    }

    /// Whether the signature verifies under a resolved [`TxDomainMode`] — the
    /// three-state (`Legacy` / `Grace` / `Bound`) regime of the `tx-domain`
    /// fork's grace window. `Legacy` is byte-identical to
    /// [`verify_signature_in`](Self::verify_signature_in)`(None)`; `Grace(d)`
    /// accepts a legacy OR a `d`-bound signature; `Bound(d)` accepts only a
    /// `d`-bound signature.
    #[must_use]
    pub fn verify_signature_mode(&self, mode: &TxDomainMode) -> bool {
        mode.verifies(|domain| self.verify_signature_in(domain))
    }
}

/// Errors constructing or handling transactions.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TxError {
    /// The signing keypair does not match the transaction's `public_key`.
    #[error("signing key does not match the transaction's public key")]
    KeyMismatch,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn transfer_tx(signer_seed: [u8; 32], nonce: u64) -> (Transaction, Keypair) {
        let kp = Keypair::from_seed(signer_seed);
        let tx = Transaction {
            signer: AccountId::new("usa.reserve.sov").unwrap(),
            public_key: kp.public_key(),
            nonce,
            action: Action::Transfer {
                to: AccountId::new("ecb.reserve.sov").unwrap(),
                amount: Balance::from_sov(5).unwrap(),
            },
        };
        (tx, kp)
    }

    #[test]
    fn sign_and_verify() {
        let (tx, kp) = transfer_tx([1u8; 32], 0);
        let signed = SignedTransaction::sign(tx, &kp).unwrap();
        assert!(signed.verify_signature());
    }

    #[test]
    fn signing_with_wrong_key_is_rejected() {
        let (tx, _) = transfer_tx([1u8; 32], 0);
        let attacker = Keypair::from_seed([2u8; 32]);
        assert_eq!(
            SignedTransaction::sign(tx, &attacker),
            Err(TxError::KeyMismatch)
        );
    }

    #[test]
    fn legacy_and_domain_none_are_byte_identical() {
        // The dormant invariant: the pre-fork path (`verify_signature`) and the
        // explicit `None` domain compute the SAME preimage and verdict, so a chain
        // that never activates the fork is byte-identical to before it existed.
        let (tx, kp) = transfer_tx([9u8; 32], 3);
        assert_eq!(tx.signing_bytes(), tx.signing_bytes_in(None));
        let signed = SignedTransaction::sign(tx, &kp).unwrap();
        assert!(signed.verify_signature());
        assert!(signed.verify_signature_in(None));
    }

    #[test]
    fn domain_bound_signature_rejects_legacy_and_cross_network() {
        let mainnet = SigningDomain::new("sov-mainnet", Hash::digest(b"genesis-main"));
        let testnet = SigningDomain::new("sov-testnet", Hash::digest(b"genesis-test"));
        let (tx, kp) = transfer_tx([7u8; 32], 0);

        // Signed FOR mainnet.
        let signed = SignedTransaction::sign_in(tx, &kp, Some(&mainnet)).unwrap();
        // Verifies only under mainnet's domain.
        assert!(signed.verify_signature_in(Some(&mainnet)));
        // A post-activation node on ANOTHER network rejects it (cross-network replay).
        assert!(!signed.verify_signature_in(Some(&testnet)));
        // A post-activation node rejects it as a *legacy* (un-bound) signature too,
        // and a legacy verifier rejects the bound signature — the fork is a clean
        // break in both directions.
        assert!(!signed.verify_signature_in(None));
        assert!(!signed.verify_signature());
    }

    #[test]
    fn domain_framing_is_byte_exact() {
        // Byte-for-byte: the bound preimage is EXACTLY
        // tag ‖ 0x00 ‖ chain_id ‖ 0x00 ‖ genesis(32) ‖ legacy-signing-bytes.
        let (tx, _) = transfer_tx([2u8; 32], 4);
        let genesis = Hash::digest(b"genesis");
        let domain = SigningDomain::new("sov-mainnet", genesis);
        let got = tx.signing_bytes_in(Some(&domain));

        let mut expected = Vec::new();
        expected.extend_from_slice(TX_SIGNING_DOMAIN_TAG);
        expected.push(0x00);
        expected.extend_from_slice(b"sov-mainnet");
        expected.push(0x00);
        expected.extend_from_slice(genesis.as_bytes());
        expected.extend_from_slice(&tx.signing_bytes());
        assert_eq!(got, expected);
        // The legacy bytes are a suffix — the framing is a pure prefix, so the tx
        // id (hash of the legacy bytes) is unaffected by the domain.
        assert!(got.ends_with(&tx.signing_bytes()));
    }

    #[test]
    fn signing_is_deterministic() {
        // Pure functions: identical inputs → identical bytes and (per RFC 8032,
        // Ed25519 is deterministic) identical signatures, every call.
        let (tx, kp) = transfer_tx([6u8; 32], 2);
        let domain = SigningDomain::new("sov-mainnet", Hash::digest(b"g"));
        assert_eq!(
            tx.signing_bytes_in(Some(&domain)),
            tx.signing_bytes_in(Some(&domain))
        );
        let a = SignedTransaction::sign_in(tx.clone(), &kp, Some(&domain)).unwrap();
        let b = SignedTransaction::sign_in(tx, &kp, Some(&domain)).unwrap();
        assert_eq!(a.signature, b.signature, "signing is deterministic");
    }

    #[test]
    fn concurrent_verification_is_race_free() {
        // verify_signature_in takes &self and mutates nothing, so it is safe to
        // fan out across threads: a shared signed tx verified concurrently under
        // the same domain yields the same verdict every time, with no data race.
        use std::sync::Arc;
        let (tx, kp) = transfer_tx([8u8; 32], 0);
        let domain = Arc::new(SigningDomain::new("sov-mainnet", Hash::digest(b"g")));
        let signed = Arc::new(SignedTransaction::sign_in(tx, &kp, Some(&domain)).unwrap());
        let mut handles = Vec::new();
        for _ in 0..16 {
            let (s, d) = (Arc::clone(&signed), Arc::clone(&domain));
            handles.push(std::thread::spawn(move || {
                // `&*d` derefs Arc<SigningDomain> -> &SigningDomain unambiguously.
                s.verify_signature_in(Some(&*d)) && !s.verify_signature_in(None)
            }));
        }
        for h in handles {
            assert!(
                h.join().unwrap(),
                "concurrent verification must be consistent"
            );
        }
    }

    #[test]
    fn legacy_signature_is_rejected_once_domain_is_active() {
        // A signature captured pre-activation must NOT slip through a post-activation
        // verifier: no silent fallback to the legacy preimage.
        let (tx, kp) = transfer_tx([5u8; 32], 1);
        let legacy = SignedTransaction::sign(tx, &kp).unwrap();
        let domain = SigningDomain::new("sov-mainnet", Hash::digest(b"g"));
        assert!(legacy.verify_signature()); // still valid pre-activation
        assert!(!legacy.verify_signature_in(Some(&domain))); // rejected post-activation
    }

    #[test]
    fn tampering_invalidates_signature() {
        let (tx, kp) = transfer_tx([1u8; 32], 0);
        let mut signed = SignedTransaction::sign(tx, &kp).unwrap();
        // Mutate the body after signing.
        signed.transaction.nonce = 99;
        assert!(!signed.verify_signature());
    }

    #[test]
    fn id_is_stable_and_content_sensitive() {
        let (tx0, _) = transfer_tx([1u8; 32], 0);
        let (tx0_again, _) = transfer_tx([1u8; 32], 0);
        let (tx1, _) = transfer_tx([1u8; 32], 1);
        assert_eq!(tx0.id(), tx0_again.id());
        assert_ne!(tx0.id(), tx1.id());
    }

    #[test]
    fn json_roundtrip_and_amount_is_string() {
        let (tx, kp) = transfer_tx([3u8; 32], 7);
        let signed = SignedTransaction::sign(tx, &kp).unwrap();
        let json = serde_json::to_string(&signed).unwrap();
        // Amount must serialize as a string for JS-safe precision (5 SOV, 8 decimals).
        assert!(json.contains("\"500000000\""));
        // Action is tagged for readability.
        assert!(json.contains("\"type\":\"transfer\""));
        let back: SignedTransaction = serde_json::from_str(&json).unwrap();
        assert_eq!(back, signed);
        assert!(back.verify_signature());
    }

    #[test]
    fn borsh_roundtrip() {
        let (tx, kp) = transfer_tx([4u8; 32], 1);
        let signed = SignedTransaction::sign(tx, &kp).unwrap();
        let bytes = borsh::to_vec(&signed).unwrap();
        assert_eq!(
            borsh::from_slice::<SignedTransaction>(&bytes).unwrap(),
            signed
        );
    }

    // ── Bounded Action decode depth (crash-DoS fix) ─────────────────────────

    fn sample_transfer() -> Action {
        Action::Transfer {
            to: AccountId::new("ecb.reserve.sov").unwrap(),
            amount: Balance::from_sov(5).unwrap(),
        }
    }

    /// Split a shallow one-level-nested encoding into the bytes BEFORE and AFTER
    /// its embedded inner-`Transfer` encoding, so a depth-`n` payload can be
    /// synthesized as `pre*n ‖ transfer ‖ post*n` WITHOUT ever materializing (or
    /// recursively dropping) a deep in-memory value.
    fn split_around_inner(shallow: &[u8], inner: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let pos = shallow
            .windows(inner.len())
            .position(|w| w == inner)
            .expect("inner Transfer encoding must appear in the shallow encoding");
        (
            shallow[..pos].to_vec(),
            shallow[pos + inner.len()..].to_vec(),
        )
    }

    /// Synthesized encoded bytes of the given recursive variant nested `depth`
    /// times around a `Transfer` (depth 1 == the shallow value itself).
    fn deep_bytes(shallow: &Action, depth: usize) -> Vec<u8> {
        let inner = borsh::to_vec(&sample_transfer()).unwrap();
        let shallow_bytes = borsh::to_vec(shallow).unwrap();
        let (pre, post) = split_around_inner(&shallow_bytes, &inner);
        let mut out = Vec::with_capacity(depth * (pre.len() + post.len()) + inner.len());
        for _ in 0..depth {
            out.extend_from_slice(&pre);
        }
        out.extend_from_slice(&inner);
        for _ in 0..depth {
            out.extend_from_slice(&post);
        }
        out
    }

    fn recursive_samples() -> Vec<Action> {
        vec![
            Action::MultisigExec {
                action: Box::new(sample_transfer()),
                approvals: Vec::new(),
            },
            Action::ProposeMultisig {
                account: AccountId::new("usa.reserve.sov").unwrap(),
                action: Box::new(sample_transfer()),
            },
            Action::Tipped {
                tip: Balance::from_sov(1).unwrap(),
                inner: Box::new(sample_transfer()),
            },
        ]
    }

    #[test]
    fn shallow_recursive_actions_roundtrip_byte_identical() {
        // (a) The fix must not disturb ANY legitimate encoding: serialize →
        // deserialize → re-serialize is the identity for every recursive variant.
        for action in recursive_samples() {
            let bytes = borsh::to_vec(&action).unwrap();
            let back: Action = borsh::from_slice(&bytes).unwrap();
            assert_eq!(back, action);
            assert_eq!(borsh::to_vec(&back).unwrap(), bytes, "re-encode identical");
            // And the synthesized depth-1 bytes are EXACTLY the real encoding —
            // proving the deep-payload synthesizer below builds honest bytes.
            assert_eq!(deep_bytes(&action, 1), bytes);
        }
    }

    #[test]
    fn deeply_nested_payload_is_rejected_not_a_crash() {
        // (b) ~depth-5000 payloads (which previously stack-overflowed → SIGABRT)
        // must now come back as a clean decode Err, for ALL THREE recursive fields.
        for action in recursive_samples() {
            let bytes = deep_bytes(&action, 5000);
            let res: Result<Action, _> = borsh::from_slice(&bytes);
            assert!(res.is_err(), "over-deep payload must be rejected");
        }
    }

    #[test]
    fn depth_bound_is_exact_and_deterministic() {
        // Every node must draw the SAME line: depth == MAX_ACTION_DEPTH decodes,
        // depth == MAX_ACTION_DEPTH + 1 is rejected.
        for action in recursive_samples() {
            let at_cap = deep_bytes(&action, MAX_ACTION_DEPTH as usize);
            let decoded: Action = borsh::from_slice(&at_cap).expect("depth at cap must decode");
            assert_eq!(borsh::to_vec(&decoded).unwrap(), at_cap);
            let over = deep_bytes(&action, MAX_ACTION_DEPTH as usize + 1);
            assert!(borsh::from_slice::<Action>(&over).is_err());
        }
    }

    #[test]
    fn rejected_deep_decode_leaks_no_depth() {
        // (c) The RAII guard must unwind fully on the error path: after MANY
        // rejected deep decodes on this thread, a normal transaction — including
        // one at the exact depth cap — must still decode. A leaked counter here
        // would make this node falsely reject later valid txs (consensus split).
        for _ in 0..100 {
            for action in recursive_samples() {
                let bytes = deep_bytes(&action, 5000);
                assert!(borsh::from_slice::<Action>(&bytes).is_err());
            }
        }
        // Plain transfer still decodes…
        let transfer = sample_transfer();
        let bytes = borsh::to_vec(&transfer).unwrap();
        assert_eq!(borsh::from_slice::<Action>(&bytes).unwrap(), transfer);
        // …and so does a value at the FULL depth budget (any leak would shrink it).
        let ms = &recursive_samples()[0];
        let at_cap = deep_bytes(ms, MAX_ACTION_DEPTH as usize);
        assert!(borsh::from_slice::<Action>(&at_cap).is_ok());
        // A full SignedTransaction round-trip still works too.
        let (tx, kp) = transfer_tx([4u8; 32], 1);
        let signed = SignedTransaction::sign(tx, &kp).unwrap();
        let bytes = borsh::to_vec(&signed).unwrap();
        assert_eq!(
            borsh::from_slice::<SignedTransaction>(&bytes).unwrap(),
            signed
        );
    }

    #[test]
    fn recursive_actions_serde_json_unchanged() {
        // (d) serde is untouched by the borsh-only fix: shallow values keep their
        // exact tagged-JSON shape and round-trip.
        let ms = Action::MultisigExec {
            action: Box::new(sample_transfer()),
            approvals: Vec::new(),
        };
        let json = serde_json::to_string(&ms).unwrap();
        assert!(json.contains("\"type\":\"multisig_exec\""));
        assert!(json.contains("\"type\":\"transfer\""));
        assert_eq!(serde_json::from_str::<Action>(&json).unwrap(), ms);

        let tipped = Action::Tipped {
            tip: Balance::from_sov(1).unwrap(),
            inner: Box::new(sample_transfer()),
        };
        let json = serde_json::to_string(&tipped).unwrap();
        assert!(json.contains("\"type\":\"tipped\""));
        assert_eq!(serde_json::from_str::<Action>(&json).unwrap(), tipped);
    }
}
