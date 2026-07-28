//! The blockspace auction, from the **wallet's** side.
//!
//! SOV v0.1.98 turned block inclusion into a Bitcoin-style auction: a transaction
//! may carry an [`Action::Tipped`](sov_types::Action::Tipped) envelope whose `tip`
//! is its bid, the node publishes a live *floor* (the marginal bid the forming
//! block's cheapest slot is paying), and a stuck transaction can be repriced in
//! place by replace-by-fee. Before this module, sov-station knew none of it: it
//! read only the base fee, so under congestion it built a transaction that sat
//! below the floor and waited — with no lever to rescue it.
//!
//! Everything here is PURE: parsing the node's answers, the tip/fee/affordability
//! arithmetic, and the replacement-price rule. No egui, no I/O, no clock. The GUI
//! layer ([`crate::gui`]) polls, renders, signs, and submits; this module decides
//! the numbers, so the numbers are testable on their own.
//!
//! # The rules are read from consensus, never restated
//!
//! [`MIN_RBF_BUMP_GRAINS`] is re-exported from `sov_mempool` rather than copied.
//! If the node's anti-churn increment ever changes, this wallet's bump moves with
//! it in the same compile — a wallet that hard-coded the number would start
//! producing replacements the network refuses, silently, at exactly the moment a
//! user is trying to unstick a payment.

use serde_json::Value;

/// The minimum tip increase a replace-by-fee must add over the transaction it
/// displaces, straight from the mempool that enforces it: a replacement is
/// admitted only when `new_tip >= old_tip + MIN_RBF_BUMP_GRAINS`.
///
/// Re-exported, not restated — see the module docs.
pub use sov_mempool::MIN_RBF_BUMP_GRAINS;

/// The extra gas a [`Action::Tipped`](sov_types::Action::Tipped) envelope costs
/// on top of the action it wraps — one bookkeeping unit, for charging the tip.
///
/// This exists because of a real gap in the node's API: `sov_estimateFee` prices
/// a *route* (`transfer` / `tokenTransfer` / `shielded`) and has no way to say
/// "…wrapped in a tip envelope". A wallet that showed the bare-route fee for a
/// tipped send would understate the cost, and — worse — could reserve too little
/// and build a transaction that cannot pay for itself. Read from the schedule
/// consensus actually charges (`sov_runtime::gas`), never restated.
pub use sov_runtime::gas::BOOKKEEPING_GAS as TIP_ENVELOPE_GAS;

/// The deployment (miner-signaled fork) that makes a tip legal at all.
///
/// Below its activation height an `Action::Tipped` is a HARD execution error
/// (`FeatureInactive`), which invalidates any block carrying it — so a wallet
/// that tips on a chain where this is dormant does not merely overpay, it builds
/// a transaction that can never be mined. Station gates the whole tip control on
/// this being `Active`.
pub const FEE_AUCTION_DEPLOYMENT: &str = "fee-auction";

/// One fee-rate bucket of the READY (mineable) mempool, as served by
/// `sov_getMempoolHistogram`.
///
/// `min_tip_grains` is the bucket's LOWER edge: every transaction in it bids at
/// least that much. The node buckets by absolute effective tip because that is
/// the key its selector actually orders by.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FeeBucket {
    /// Lower edge of the bucket, in grains (10⁻⁸ XUS).
    pub min_tip_grains: u128,
    /// How many pooled transactions bid in this bucket.
    pub tx_count: u64,
    /// Their combined serialized size, in bytes — a block is bounded by bytes as
    /// well as by transaction count, so a client projecting inclusion needs both.
    pub total_bytes: u64,
}

/// A live reading of the blockspace auction, assembled from
/// `sov_getMempoolHistogram`, `sov_getMempoolInfo`, and `sov_getDeployments`.
///
/// [`available`](Self::available) is the honesty bit and the reason this is not
/// just a bag of numbers: a node too old to serve the mempool methods, or one
/// that is simply unreachable, leaves every figure at zero — and "zero floor"
/// and "unknown floor" are opposite pieces of advice. The UI must render the
/// unknown case as unknown, never as "the auction is clear".
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Auction {
    /// True only when the node ANSWERED the mempool queries this poll.
    pub available: bool,
    /// True when the `fee-auction` deployment is `Active` on this chain, i.e. a
    /// tipped transaction is legal. False while dormant OR unknown — the safe
    /// direction, since tipping on a dormant chain builds an unmineable tx.
    pub fee_auction_active: bool,
    /// What a new transaction must EXCEED to take a slot in the next block. Zero
    /// means the forming block still has free room: nothing to outbid.
    pub next_block_floor_grains: u128,
    /// What a transaction must exceed to be POOLED at all when the pool is full.
    pub pool_floor_grains: u128,
    /// Ready (mineable) transactions in the pool.
    pub ready_txs: u64,
    /// Queued (future-nonce, not yet mineable) transactions.
    pub queued_txs: u64,
    /// This node's per-block transaction cap, for projecting inclusion.
    pub max_block_txs: u64,
    /// How long the oldest ready transaction has been waiting, in ms.
    pub oldest_pending_age_ms: Option<u64>,
    /// Fee-rate buckets, HIGHEST first (the order the node serves them in).
    pub buckets: Vec<FeeBucket>,
}

/// How contested blockspace is right now — the one-glance state behind the
/// status chip in the send form.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pressure {
    /// The node did not tell us. Renders as "—", never as "clear".
    Unknown,
    /// The next block has free room: a zero tip confirms.
    Clear,
    /// Slots are contested; the floor is the price of the cheapest one.
    Contested,
}

/// What a given tip is likely to buy, judged against the pooled competition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outlook {
    /// No live reading — say so rather than guess.
    Unknown,
    /// The bid clears the next block's floor (or there is no floor to clear).
    NextBlock,
    /// Outbid. `txs_ahead` is a LOWER BOUND on how many pooled transactions are
    /// ahead: only buckets whose lower edge already exceeds the bid are counted,
    /// so the bucket the bid falls inside is never counted against it.
    Behind { txs_ahead: u64 },
}

/// Read a decimal-string grains field (the codebase's large-integer convention),
/// falling back to a JSON number, else 0.
fn grains(v: &Value, key: &str) -> u128 {
    match v.get(key) {
        Some(Value::String(s)) => s.parse::<u128>().unwrap_or(0),
        Some(Value::Number(n)) => n.as_u64().map(u128::from).unwrap_or(0),
        _ => 0,
    }
}

/// Read an unsigned integer field, else 0.
fn count(v: &Value, key: &str) -> u64 {
    v.get(key).and_then(Value::as_u64).unwrap_or(0)
}

impl Auction {
    /// Assemble a reading from the node's raw answers. Either RPC may be `None`
    /// (an older node that does not serve it, or a failed call); the result is
    /// [`available`](Self::available) only when at least one answered, and every
    /// field an absent method would have supplied stays at its zero — which
    /// `available == false` marks as UNKNOWN rather than as data.
    pub fn from_rpc(
        histogram: Option<&Value>,
        info: Option<&Value>,
        fee_auction_active: bool,
    ) -> Self {
        let mut a = Auction {
            fee_auction_active,
            ..Auction::default()
        };
        if let Some(h) = histogram {
            a.available = true;
            a.next_block_floor_grains = grains(h, "floorGrains");
            a.pool_floor_grains = grains(h, "poolFloorGrains");
            a.ready_txs = count(h, "txCount");
            a.max_block_txs = count(h, "maxBlockTxs");
            if let Some(Value::Array(rows)) = h.get("buckets") {
                a.buckets = rows
                    .iter()
                    .map(|b| FeeBucket {
                        min_tip_grains: grains(b, "feeRateGrains"),
                        tx_count: count(b, "txCount"),
                        total_bytes: count(b, "totalBytes"),
                    })
                    .collect();
            }
        }
        if let Some(i) = info {
            a.available = true;
            // `sov_getMempoolInfo` is the richer source for the shared fields;
            // prefer it so the two readings can never disagree on screen.
            a.next_block_floor_grains = grains(i, "nextBlockFloorGrains");
            a.pool_floor_grains = grains(i, "poolFloorGrains");
            a.ready_txs = count(i, "txCount");
            a.queued_txs = count(i, "queuedCount");
            a.max_block_txs = count(i, "maxBlockTxs");
            a.oldest_pending_age_ms = i.get("oldestPendingAgeMs").and_then(Value::as_u64);
        }
        a
    }

    /// How contested the next block is.
    pub fn pressure(&self) -> Pressure {
        if !self.available {
            Pressure::Unknown
        } else if self.next_block_floor_grains == 0 {
            Pressure::Clear
        } else {
            Pressure::Contested
        }
    }

    /// The tip Station offers by default — DERIVED from the live pool, never a
    /// guessed constant, and zero whenever a tip would buy nothing.
    ///
    /// - Auction dormant, or no live reading ⇒ **0**. Tipping a chain that
    ///   rejects tips builds an unmineable transaction; bidding against an
    ///   unknown floor is inventing a price. Both are refusals, not defaults.
    /// - Floor 0 (the next block has room) ⇒ **0**. There is nothing to outbid,
    ///   so the honest default is to pay nothing.
    /// - Otherwise ⇒ `floor + MIN_RBF_BUMP_GRAINS`. The floor is the marginal
    ///   slot's price and inclusion requires strictly EXCEEDING it, so the bid
    ///   must clear it by something; one anti-churn increment (0.00001 XUS) is
    ///   the smallest step this network already treats as an economically real
    ///   raise, which makes it the cheapest honest overbid rather than an
    ///   arbitrary multiplier of the user's money.
    pub fn suggested_tip_grains(&self) -> u128 {
        if !self.available || !self.fee_auction_active {
            return 0;
        }
        match self.next_block_floor_grains {
            0 => 0,
            floor => floor.saturating_add(MIN_RBF_BUMP_GRAINS),
        }
    }

    /// What `tip_grains` is likely to buy right now.
    pub fn outlook(&self, tip_grains: u128) -> Outlook {
        if !self.available {
            return Outlook::Unknown;
        }
        if self.next_block_floor_grains == 0 || tip_grains > self.next_block_floor_grains {
            return Outlook::NextBlock;
        }
        let txs_ahead = self
            .buckets
            .iter()
            .filter(|b| b.min_tip_grains > tip_grains)
            .map(|b| b.tx_count)
            .sum();
        Outlook::Behind { txs_ahead }
    }
}

/// The full cost of one send, split into the three amounts a spender must see
/// separately: what the recipient gets, what consensus charges, and what the
/// spender chose to bid.
///
/// The reason this is a type and not three loose `u128`s: the affordability
/// check must include the tip. It did not before — Station reserved only
/// `amount + fee` — and a send built that way is one the sender cannot pay for,
/// which consensus rejects HARD (`CannotAffordFee`) rather than merely failing.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SendCost {
    /// What the recipient receives.
    pub amount_grains: u128,
    /// The network fee consensus charges for this route (`sov_estimateFee`).
    pub fee_grains: u128,
    /// The auction bid, paid signer → miner on inclusion.
    pub tip_grains: u128,
}

impl SendCost {
    /// Everything that leaves the sender's balance.
    pub fn total_grains(&self) -> u128 {
        self.amount_grains
            .saturating_add(self.fee_grains)
            .saturating_add(self.tip_grains)
    }

    /// Whether `balance_grains` covers the whole send.
    pub fn affordable(&self, balance_grains: u128) -> bool {
        self.total_grains() <= balance_grains
    }

    /// The balance left afterwards (saturating, so an unaffordable send shows 0
    /// rather than wrapping).
    pub fn balance_after(&self, balance_grains: u128) -> u128 {
        balance_grains.saturating_sub(self.total_grains())
    }
}

/// The network fee this send will ACTUALLY be charged: the bare route's fee from
/// `sov_estimateFee`, plus the tip envelope's gas when a tip is attached.
///
/// A tip is not free of gas — wrapping an action costs [`TIP_ENVELOPE_GAS`] more
/// to execute — and that difference has to land in the affordability reservation,
/// not just in the display, or the wallet can build a send that consensus rejects
/// as `CannotAffordFee`.
pub fn route_fee_grains(base_fee_grains: u128, gas_price_grains: u128, tip_grains: u128) -> u128 {
    if tip_grains == 0 {
        base_fee_grains
    } else {
        base_fee_grains
            .saturating_add(u128::from(TIP_ENVELOPE_GAS).saturating_mul(gas_price_grains))
    }
}

/// The most that can be SENT while still leaving room for the fee and the tip —
/// what the "Max" button fills in.
pub fn max_sendable_grains(balance_grains: u128, fee_grains: u128, tip_grains: u128) -> u128 {
    balance_grains
        .saturating_sub(fee_grains)
        .saturating_sub(tip_grains)
}

/// The tip a replacement must carry to displace a pooled transaction bidding
/// `old_tip_grains`, exactly as the mempool computes it.
pub fn rbf_required_tip_grains(old_tip_grains: u128) -> u128 {
    old_tip_grains.saturating_add(MIN_RBF_BUMP_GRAINS)
}

/// The tip a "bump" should actually carry: the mempool's replacement price, and
/// no lower than what the live floor says a slot currently costs.
///
/// Both bounds matter and neither implies the other. Meeting only the RBF price
/// gets the replacement ADMITTED but leaves it just as stuck if the floor has
/// risen far above the original bid; meeting only the floor may not out-bid the
/// wallet's own pooled transaction, and the node would refuse the replacement
/// (`RbfUnderpriced`) — the bump would appear to do nothing.
///
/// Because [`MIN_RBF_BUMP_GRAINS`] is nonzero, the result is ALWAYS strictly
/// greater than `old_tip_grains`, so a bump can never be a silent no-op.
pub fn bump_tip_grains(old_tip_grains: u128, auction: &Auction) -> u128 {
    rbf_required_tip_grains(old_tip_grains).max(auction.suggested_tip_grains())
}

/// Where a submitted send stands. Station tracks this itself because the node
/// exposes no "list my pooled transactions" query — and a bump the user cannot
/// see the target of is a bump they will not trust.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SendState {
    /// Submitted, not yet mined.
    Pending,
    /// Mined and applied.
    Confirmed,
    /// Mined but rejected on-chain (the receipt carries the reason).
    Failed,
    /// Replaced by a bump this wallet issued. The original will never confirm —
    /// its nonce slot now belongs to the replacement.
    Replaced,
    /// The signer's on-chain nonce advanced past this transaction without a
    /// receipt for it: something else took the slot. Distinct from
    /// [`Replaced`](Self::Replaced), which is a replacement *we* made.
    Superseded,
}

impl SendState {
    /// Whether this send is still live in the pool (and therefore bumpable).
    pub fn is_pending(self) -> bool {
        matches!(self, SendState::Pending)
    }

    /// Short label for the status chip.
    pub fn label(self) -> &'static str {
        match self {
            SendState::Pending => "PENDING",
            SendState::Confirmed => "CONFIRMED",
            SendState::Failed => "FAILED",
            SendState::Replaced => "REPLACED",
            SendState::Superseded => "SUPERSEDED",
        }
    }
}

/// One transaction this wallet submitted, with everything needed to REBUILD it
/// at the same nonce for a replace-by-fee bump.
///
/// `to` is the RESOLVED recipient (post name-resolution) exactly as submitted, so
/// a bump can never pay a different party than the original — a `.sov` name that
/// is re-pointed between the send and the bump must not silently redirect funds.
#[derive(Clone, Debug)]
pub struct SentTx {
    /// Transaction id hex, as returned by the node.
    pub txid: String,
    /// The signing account.
    pub from_account: String,
    /// The resolved recipient, exactly as submitted.
    pub to: String,
    /// What the recipient receives.
    pub amount_grains: u128,
    /// The nonce slot this send occupies — a replacement MUST reuse it.
    pub nonce: u64,
    /// The tip it currently bids.
    pub tip_grains: u128,
    /// True when the route pays into the shielded pool (an `Action::Shielded`
    /// mint), false for a transparent `Action::Transfer`.
    pub shielded_route: bool,
    /// When it was submitted (unix ms), for the "waiting Ns" readout.
    pub submitted_ms: u64,
    /// Where it stands.
    pub state: SendState,
    /// Free-text detail for the terminal states (an on-chain failure reason).
    pub note: String,
}

impl SentTx {
    /// Whether a bump is offerable for this entry: still pooled, and on a chain
    /// where a tip is legal at all.
    pub fn bumpable(&self, auction: &Auction) -> bool {
        self.state.is_pending() && auction.fee_auction_active
    }
}

/// Decide a pending send's new state from what the node reports.
///
/// `receipt` is `Some` iff the node ANSWERED `sov_getReceipt` — which it does
/// with JSON `null` for a transaction no active block contains. `None` means the
/// call itself failed (offline, timeout), which is not evidence of anything.
/// `onchain_nonce` is the signer's committed nonce (`sov_getNonce`), i.e. the
/// next nonce the chain will accept.
///
/// The nonce test is what closes the "silently gone" hole: a transaction that is
/// evicted, replaced, or beaten to its slot never produces a receipt at all, so
/// receipt-polling alone would show it Pending forever. It is deliberately gated
/// on the receipt query having ANSWERED — a transaction mined during a poll whose
/// receipt call happened to fail would otherwise be reported as superseded when
/// it in fact confirmed.
pub fn resolve_state(receipt: Option<&Value>, onchain_nonce: Option<u64>, nonce: u64) -> SendState {
    let Some(r) = receipt else {
        // The node did not answer. Claim nothing.
        return SendState::Pending;
    };
    match r
        .get("status")
        .and_then(|s| s.get("status"))
        .and_then(Value::as_str)
    {
        Some("success") => return SendState::Confirmed,
        Some("failed") => return SendState::Failed,
        _ => {}
    }
    // Answered, and there is no receipt for us. If the account's nonce has moved
    // past our slot, something that is not us already spent it.
    if onchain_nonce.is_some_and(|n| n > nonce) {
        return SendState::Superseded;
    }
    SendState::Pending
}

/// The on-chain failure reason from a receipt, if it carries one.
pub fn receipt_failure_reason(receipt: &Value) -> Option<String> {
    let status = receipt.get("status")?;
    if status.get("status").and_then(Value::as_str) != Some("failed") {
        return None;
    }
    Some(
        status
            .get("reason")
            .and_then(Value::as_str)
            .unwrap_or("rejected on-chain")
            .to_string(),
    )
}

/// Whether `deployments` (the `sov_getDeployments` answer) reports `name` as
/// `Active`. Absent method, absent deployment, or any other state ⇒ false: the
/// safe direction, since a tip on a chain that has not activated the auction is
/// a hard consensus rejection, not an overpayment.
pub fn deployment_active(deployments: &Value, name: &str) -> bool {
    deployments
        .get("deployments")
        .and_then(Value::as_array)
        .is_some_and(|rows| {
            rows.iter().any(|d| {
                d.get("name").and_then(Value::as_str) == Some(name)
                    && d.get("state").and_then(Value::as_str) == Some("Active")
            })
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use sov_crypto::Keypair;
    use sov_primitives::{AccountId, Balance};
    use sov_types::{Action, SignedTransaction, Transaction};

    fn histogram(floor: u128, buckets: &[(u128, u64)]) -> Value {
        json!({
            "txCount": buckets.iter().map(|b| b.1).sum::<u64>(),
            "maxBlockTxs": 4u64,
            "maxBlockBytes": 1_000_000u64,
            "floorGrains": floor.to_string(),
            "poolFloorGrains": "0",
            "buckets": buckets.iter().map(|(rate, n)| json!({
                "feeRateGrains": rate.to_string(),
                "txCount": n,
                "totalBytes": 250u64 * n,
            })).collect::<Vec<_>>(),
        })
    }

    fn info(floor: u128, ready: u64, queued: u64) -> Value {
        json!({
            "txCount": ready,
            "queuedCount": queued,
            "capacity": 16_384u64,
            "maxBlockTxs": 4u64,
            "nextBlockFloorGrains": floor.to_string(),
            "poolFloorGrains": "7",
            "oldestPendingAgeMs": 4_200u64,
        })
    }

    /// An ACTIVE auction with a real floor — the state every arithmetic test
    /// below runs against, so none of them can pass merely because the feature
    /// declined to engage.
    fn live_auction(floor: u128) -> Auction {
        let a = Auction::from_rpc(
            Some(&histogram(floor, &[(9_000, 2), (5_000, 3)])),
            Some(&info(floor, 5, 1)),
            true,
        );
        assert!(a.available && a.fee_auction_active, "the fixture is LIVE");
        assert_eq!(a.next_block_floor_grains, floor);
        a
    }

    /// Both mempool RPCs parse, and `sov_getMempoolInfo` wins the fields both
    /// serve so the two readings can never contradict each other on screen.
    #[test]
    fn parses_both_mempool_rpcs_and_prefers_info_for_shared_fields() {
        let a = Auction::from_rpc(
            Some(&histogram(5_000, &[(9_000, 2), (5_000, 3)])),
            Some(&info(6_000, 5, 1)),
            true,
        );
        assert!(a.available);
        assert_eq!(a.next_block_floor_grains, 6_000, "info wins the floor");
        assert_eq!(a.pool_floor_grains, 7, "info wins the pool floor");
        assert_eq!(a.ready_txs, 5);
        assert_eq!(a.queued_txs, 1);
        assert_eq!(a.max_block_txs, 4);
        assert_eq!(a.oldest_pending_age_ms, Some(4_200));
        // The distribution still comes from the histogram, highest bucket first.
        assert_eq!(a.buckets.len(), 2);
        assert_eq!(a.buckets[0].min_tip_grains, 9_000);
        assert_eq!(a.buckets[0].tx_count, 2);
        assert_eq!(a.buckets[0].total_bytes, 500);
        assert_eq!(a.buckets[1].min_tip_grains, 5_000);
    }

    /// An older node serves neither method. That must read as UNKNOWN — not as
    /// "the floor is zero, tip nothing", which is the same numbers with the
    /// opposite meaning.
    #[test]
    fn an_old_node_reads_unknown_not_clear() {
        let a = Auction::from_rpc(None, None, true);
        assert!(!a.available);
        assert_eq!(a.pressure(), Pressure::Unknown);
        assert_eq!(a.outlook(0), Outlook::Unknown);
        assert_eq!(
            a.suggested_tip_grains(),
            0,
            "no reading ⇒ no bid is invented"
        );

        // ... whereas a node that ANSWERS with a zero floor really is clear.
        let clear = Auction::from_rpc(None, Some(&info(0, 0, 0)), true);
        assert!(clear.available);
        assert_eq!(clear.pressure(), Pressure::Clear);
        assert_eq!(clear.suggested_tip_grains(), 0);
        assert_eq!(clear.outlook(0), Outlook::NextBlock);
    }

    /// The default tip is derived from the live floor and always strictly clears
    /// it — a bid EQUAL to the floor does not take the slot.
    #[test]
    fn the_default_tip_is_derived_from_the_floor_and_clears_it() {
        let a = live_auction(5_000);
        let tip = a.suggested_tip_grains();
        assert_eq!(tip, 5_000 + MIN_RBF_BUMP_GRAINS);
        assert!(tip > a.next_block_floor_grains, "strictly clears the floor");
        assert_eq!(a.pressure(), Pressure::Contested);
        assert_eq!(a.outlook(tip), Outlook::NextBlock);
        // A floor-equal bid does NOT get in, and the outlook counts only the
        // buckets strictly above it (the 9_000 bucket's 2 txs; the 5_000 bucket
        // the bid sits inside is not counted against it).
        assert_eq!(a.outlook(5_000), Outlook::Behind { txs_ahead: 2 });
        assert_eq!(a.outlook(0), Outlook::Behind { txs_ahead: 5 });
    }

    /// A dormant `fee-auction` deployment must suppress the default bid: a
    /// tipped transaction there is a HARD consensus rejection, so "0" is the
    /// only correct suggestion even with a floor on screen.
    #[test]
    fn a_dormant_deployment_suppresses_the_tip() {
        let dormant = Auction::from_rpc(None, Some(&info(5_000, 9, 0)), false);
        assert!(dormant.available, "we still show the pool");
        assert_eq!(dormant.next_block_floor_grains, 5_000);
        assert_eq!(dormant.suggested_tip_grains(), 0);
    }

    /// `sov_getDeployments` gating, including the shapes that must NOT read as
    /// active.
    #[test]
    fn deployment_activation_is_read_exactly() {
        let active = json!({"height": 11_600, "deployments": [
            {"name": "tx-domain", "state": "Active"},
            {"name": "fee-auction", "state": "Active"},
        ]});
        assert!(deployment_active(&active, FEE_AUCTION_DEPLOYMENT));

        let locked = json!({"deployments": [{"name": "fee-auction", "state": "LockedIn"}]});
        assert!(!deployment_active(&locked, FEE_AUCTION_DEPLOYMENT));
        let missing = json!({"deployments": [{"name": "tx-domain", "state": "Active"}]});
        assert!(!deployment_active(&missing, FEE_AUCTION_DEPLOYMENT));
        // An older node that does not serve the method at all.
        assert!(!deployment_active(&json!({}), FEE_AUCTION_DEPLOYMENT));
    }

    /// Amount + base fee + tip is the reservation. The tip used to be missing
    /// from it, and a send that cannot pay its own tip is a HARD consensus
    /// reject (`CannotAffordFee`), not a slow confirmation.
    #[test]
    fn the_reservation_includes_the_tip() {
        let balance = 10_000_000u128; // 0.1 XUS
        let cost = SendCost {
            amount_grains: 9_990_000,
            fee_grains: 8_000,
            tip_grains: 2_000,
        };
        assert_eq!(cost.total_grains(), 10_000_000);
        assert!(cost.affordable(balance), "exactly affordable");
        assert_eq!(cost.balance_after(balance), 0);

        // One grain more of tip and it no longer fits — the old amount+fee-only
        // check would have waved this through.
        let over = SendCost {
            tip_grains: 2_001,
            ..cost
        };
        assert!(!over.affordable(balance));
        assert!(
            over.amount_grains + over.fee_grains <= balance,
            "amount+fee alone still 'fits' — which is exactly the old bug"
        );
        assert_eq!(over.balance_after(balance), 0, "saturates, never wraps");
    }

    /// A tipped send is charged MORE gas than the bare route `sov_estimateFee`
    /// prices, and the wallet must reserve that difference too.
    ///
    /// This is a real gap in the node's API — `sov_estimateFee` takes a route,
    /// not "route wrapped in a tip envelope" — closed here by adding the schedule
    /// consensus actually charges rather than by shipping a number that is a
    /// little bit wrong in the direction of "your transaction was rejected".
    #[test]
    fn a_tip_costs_gas_too_and_the_reservation_pays_for_it() {
        let (base, gas_price) = (8_000u128, 10u128);
        assert_eq!(
            route_fee_grains(base, gas_price, 0),
            base,
            "no tip ⇒ no envelope ⇒ exactly the bare route's fee"
        );
        let tipped = route_fee_grains(base, gas_price, 5_000);
        assert_eq!(tipped, base + u128::from(TIP_ENVELOPE_GAS) * gas_price);
        assert!(tipped > base, "the envelope is not free");
        // A fee-free chain (gas price 0) stays fee-free even with a tip: the tip
        // is a value transfer to the miner, not a gas cost.
        assert_eq!(route_fee_grains(0, 0, 5_000), 0);

        // And the reservation is built from the TIPPED fee, so a send sized against
        // it can always pay for itself.
        let balance = 1_000_000u128;
        let max = max_sendable_grains(balance, tipped, 5_000);
        let cost = SendCost {
            amount_grains: max,
            fee_grains: tipped,
            tip_grains: 5_000,
        };
        assert!(cost.affordable(balance));
        assert_eq!(cost.balance_after(balance), 0);
        // Sizing it against the BARE fee instead — the bug this closes — would
        // overshoot by exactly the envelope's gas.
        let naive = max_sendable_grains(balance, base, 5_000);
        assert_eq!(naive - max, u128::from(TIP_ENVELOPE_GAS) * gas_price);
        assert!(!SendCost {
            amount_grains: naive,
            ..cost
        }
        .affordable(balance));
    }

    /// "Max" leaves room for BOTH the fee and the tip, and the result is exactly
    /// affordable — never one grain over.
    #[test]
    fn max_sendable_leaves_room_for_fee_and_tip() {
        let balance = 5_000_000u128;
        let (fee, tip) = (8_000u128, 6_000u128);
        let max = max_sendable_grains(balance, fee, tip);
        assert_eq!(max, 5_000_000 - 8_000 - 6_000);
        let cost = SendCost {
            amount_grains: max,
            fee_grains: fee,
            tip_grains: tip,
        };
        assert!(cost.affordable(balance));
        assert_eq!(cost.balance_after(balance), 0);
        assert!(
            !SendCost {
                amount_grains: max + 1,
                ..cost
            }
            .affordable(balance),
            "Max is the largest affordable amount"
        );
        // A balance smaller than the overhead yields 0, not an underflow.
        assert_eq!(max_sendable_grains(1_000, fee, tip), 0);
    }

    /// The bump price satisfies the mempool's rule AND the live floor, and is
    /// always a strict raise so it can never be a silent no-op.
    #[test]
    fn a_bump_clears_both_the_rbf_rule_and_the_live_floor() {
        // Case 1: the floor is low; the RBF rule binds.
        let quiet = live_auction(100);
        let old_tip = 50_000u128;
        let bumped = bump_tip_grains(old_tip, &quiet);
        assert_eq!(bumped, old_tip + MIN_RBF_BUMP_GRAINS);
        assert!(bumped >= rbf_required_tip_grains(old_tip), "admissible");
        assert!(bumped > quiet.next_block_floor_grains, "and competitive");

        // Case 2: the floor rocketed past the original bid; the floor binds.
        let busy = live_auction(900_000);
        let bumped = bump_tip_grains(old_tip, &busy);
        assert_eq!(bumped, 900_000 + MIN_RBF_BUMP_GRAINS);
        assert!(
            bumped >= rbf_required_tip_grains(old_tip),
            "still admissible — meeting the floor never undercuts the RBF rule"
        );
        assert_eq!(busy.outlook(bumped), Outlook::NextBlock);

        // Case 3: no live reading at all. The bump still has to be admissible,
        // so it falls back to exactly the mempool's price.
        let blind = Auction::from_rpc(None, None, true);
        assert_eq!(
            bump_tip_grains(old_tip, &blind),
            old_tip + MIN_RBF_BUMP_GRAINS
        );

        // In every case a bump STRICTLY raises the bid — a replacement that only
        // matched the old tip would be refused as `NonceTaken` and the user's
        // click would appear to do nothing.
        for floor in [0u128, 1, 100, 900_000] {
            let a = live_auction(floor.max(1));
            for old in [0u128, 1, 999, MIN_RBF_BUMP_GRAINS, u128::MAX - 1] {
                assert!(bump_tip_grains(old, &a) > old, "floor {floor}, old {old}");
            }
        }
    }

    /// The tip Station puts on the wire is EXACTLY the bid the mempool reads off
    /// it. This is the end-to-end pin: the arithmetic above is worthless if the
    /// envelope Station builds is not the one the auction keys on.
    #[test]
    fn the_envelope_station_builds_is_the_bid_the_mempool_reads() {
        let kp = Keypair::from_seed([3u8; 32]);
        let signer = kp.public_key().implicit_account_id();
        let auction = live_auction(5_000);
        let tip = auction.suggested_tip_grains();
        let build = |tip_grains: u128| {
            let inner = Action::Transfer {
                to: AccountId::new("usa.reserve.sov").unwrap(),
                amount: Balance::from_grains(7),
            };
            let action = if tip_grains == 0 {
                inner
            } else {
                Action::Tipped {
                    tip: Balance::from_grains(tip_grains),
                    inner: Box::new(inner),
                }
            };
            let tx = Transaction {
                signer: signer.clone(),
                public_key: kp.public_key(),
                nonce: 11,
                action,
            };
            SignedTransaction::sign_in(tx, &kp, None).unwrap()
        };

        let stx = build(tip);
        assert_eq!(
            sov_mempool::effective_tip(&stx).grains(),
            tip,
            "the mempool's auction key reads back the tip Station chose"
        );

        // A zero tip must produce a BARE action, not `Tipped { tip: 0 }`: the
        // bare form is byte-identical to what Station sent before this feature
        // and is legal on a chain where the auction is still dormant.
        let untipped = build(0);
        assert!(
            matches!(untipped.transaction.action, Action::Transfer { .. }),
            "no tip ⇒ no envelope"
        );
        assert_eq!(sov_mempool::effective_tip(&untipped).grains(), 0);

        // And the replacement really does out-bid the original by the pool's rule.
        let replacement = build(bump_tip_grains(tip, &auction));
        assert!(
            sov_mempool::effective_tip(&replacement).grains()
                >= sov_mempool::effective_tip(&stx).grains() + MIN_RBF_BUMP_GRAINS,
            "the replacement satisfies new_tip >= old_tip + MIN_RBF_BUMP_GRAINS"
        );
        assert_eq!(
            replacement.transaction.nonce, stx.transaction.nonce,
            "a bump REPLACES: same signer, same nonce — never a second payment"
        );
    }

    /// A pooled send is not stuck-forever-silent: the nonce test catches the
    /// cases that never produce a receipt for our id.
    #[test]
    fn pending_state_resolves_from_receipt_or_the_nonce() {
        let ok = json!({"status": {"status": "success"}});
        let bad = json!({"status": {"status": "failed", "reason": "insufficient balance"}});

        assert_eq!(resolve_state(Some(&ok), Some(5), 5), SendState::Confirmed);
        assert_eq!(resolve_state(Some(&bad), Some(5), 5), SendState::Failed);
        assert_eq!(
            receipt_failure_reason(&bad).as_deref(),
            Some("insufficient balance")
        );
        assert_eq!(receipt_failure_reason(&ok), None);

        // The node ANSWERS `sov_getReceipt` with JSON null for an unmined tx.
        let unmined = Value::Null;
        // Answered, no receipt, nonce not yet consumed ⇒ genuinely still waiting.
        assert_eq!(
            resolve_state(Some(&unmined), Some(9), 9),
            SendState::Pending
        );
        // Answered, no receipt, but the slot is spent ⇒ something else took it.
        // Without this the entry would read Pending forever and offer a bump the
        // node can only refuse.
        assert_eq!(
            resolve_state(Some(&unmined), Some(10), 9),
            SendState::Superseded
        );
        // The RPC itself failed: claim NOTHING. A transaction mined during a poll
        // whose receipt call happened to time out must not be reported as
        // superseded when it in fact confirmed.
        assert_eq!(resolve_state(None, Some(10), 9), SendState::Pending);
        assert_eq!(resolve_state(None, None, 9), SendState::Pending);
    }

    /// A bump is offered only where it can work.
    #[test]
    fn bump_is_offered_only_for_a_pending_send_on_an_active_auction() {
        let live = live_auction(5_000);
        let dormant = Auction::from_rpc(None, Some(&info(5_000, 1, 0)), false);
        let mut sent = SentTx {
            txid: "ab".repeat(32),
            from_account: "usa.reserve.sov".to_string(),
            to: "ecb.reserve.sov".to_string(),
            amount_grains: 1_000,
            nonce: 4,
            tip_grains: 0,
            shielded_route: false,
            submitted_ms: 0,
            state: SendState::Pending,
            note: String::new(),
        };
        assert!(sent.bumpable(&live));
        assert!(!sent.bumpable(&dormant), "tips are illegal while dormant");
        for terminal in [
            SendState::Confirmed,
            SendState::Failed,
            SendState::Replaced,
            SendState::Superseded,
        ] {
            sent.state = terminal;
            assert!(!sent.bumpable(&live), "{}", terminal.label());
        }
    }
}
