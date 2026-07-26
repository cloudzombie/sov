//! Transaction and block **weight**: one integer that bounds what a block
//! costs the network to move and to check.
//!
//! # Why weight, and not a transaction count
//!
//! Block capacity used to be reasoned about in two unrelated units. Consensus
//! bounds a block's serialized **bytes** (the elastic block-size cap in
//! `sov_chain`, hard-ceilinged at 4 MiB, which is what keeps every block
//! inside the 8 MiB P2P frame). The block *producer* separately stops at
//! `max_block_txs` transactions — a **count**. A count is not a resource: at
//! today's ~300-byte transfers 4,096 transactions is ~1.2 MB, but a block of
//! 4,096 pool-v2 transactions would be ~270 MB if bytes were not *also*
//! bounded. The byte cap is what makes that safe; the count never was.
//!
//! Weight makes the real bound explicit and gives it a single unit that also
//! carries **verification cost**, so a future action whose bytes are cheap but
//! whose checking is expensive cannot slip past a purely byte-shaped limit.
//!
//! # The weight function
//!
//! ```text
//! weight(tx)    = tx.serialized_size() + verify_weight(tx.action)
//! weight(block) = block.serialized_size() + Σ verify_weight(tx.action)
//! ```
//!
//! One weight unit is **one byte of block space**. Verification cost is
//! converted into that same unit by an explicit exchange rate
//! ([`WEIGHT_UNITS_PER_VERIFY_MS`]), so the two resources add.
//!
//! # Byte-identity (this is why it is safe to ship on a live chain)
//!
//! [`verify_weight`] is **zero for every action that exists on mainnet
//! today**. It is nonzero only for [`Action::ShieldedV2`], which is DORMANT:
//! the `shielded-v2` deployment (signal bit 2) is defined but not armed, so
//! execution rejects that variant as `FeatureInactive` and no valid block on
//! any live chain can contain one. Therefore, for every block in mainnet
//! history and every block a node will accept before activation:
//!
//! ```text
//! block_weight(b) == b.serialized_size()
//! ```
//!
//! exactly. A weight-denominated block limit is byte-for-byte the same rule as
//! the existing size-denominated one until bit 2 activates — which is what the
//! mainnet log replay proves.
//!
//! # Where the constants come from
//!
//! Nothing here is a guessed number. See [`WEIGHT_UNITS_PER_VERIFY_MS`] and
//! [`SHIELDED_V2_VERIFY_WEIGHT`] for the derivations, and
//! `sov-shielded-pq/tests/verify_cost.rs` for the measurement they rest on.

use crate::{Action, Block, SignedTransaction};

/// Exchange rate between verification time and block space: how many weight
/// units one millisecond of verification is charged.
///
/// # Derivation
///
/// The two resources a block consumes are bandwidth (bytes) and CPU
/// (verification). To add them we need a rate, and the rate is fixed by a
/// stated policy budget rather than taste:
///
/// - A block may occupy at most [`MAX_BLOCK_WEIGHT`] = 4 MiB = 4,194,304 weight
///   units (the existing consensus hard ceiling on block size).
/// - Policy: **a maximally-expensive block must verify in well under the
///   target block interval** of 150,000 ms (2.5 minutes), on the slowest node
///   in the fleet. Taking one tenth of the interval — 15,000 ms — as the
///   verification budget for a completely full block gives
///   `4,194,304 / 15,000 = 279.6` units per millisecond.
/// - Rounded UP to the next power of two, **512**. Rounding up is the
///   conservative direction (verification is charged *more*, so less of it
///   fits in a block). 512 units/ms implies a full-block verification budget
///   of `4,194,304 / 512 = 8,192 ms` — 5.5% of the block interval, i.e. an
///   18× margin against the interval itself.
///
/// This rate is only ever used to *derive* the per-action constants below at
/// authoring time; it is not multiplied by any runtime measurement (weight
/// must be identical on every machine, so it can never depend on a clock).
pub const WEIGHT_UNITS_PER_VERIFY_MS: u64 = 512;

/// Weight charged for verifying one pool-v2 (`ShieldedV2`) STARK bundle, on
/// top of its serialized bytes.
///
/// # Derivation
///
/// `sov-shielded-pq/tests/verify_cost.rs` measures a real, honestly-proven
/// 4-in/4-out bundle (the padded worst-case circuit shape) on release-build
/// Apple-Silicon hardware:
///
/// | quantity | measured |
/// |---|---|
/// | serialized proof | 55,054 bytes |
/// | verify, median of 11 | **0.90 ms** |
/// | verify, slowest sample | 3.24 ms |
///
/// The proof size is not attacker-controlled: the verifier pins the exact
/// `proof_options()` via `AcceptableOptions::OptionSet`, so a proof that
/// verifies at all is ~55 KB — an attacker cannot submit a *small* bundle that
/// still costs a full verification.
///
/// The budget charged is **16 ms** — 18× the measured median and ~5× the
/// slowest observed sample, which covers the fleet's weakest hardware (shared-
/// vCPU cloud nodes, realistically 3–4× slower than the measurement box) with
/// margin left over. At [`WEIGHT_UNITS_PER_VERIFY_MS`]:
///
/// ```text
/// 16 ms × 512 units/ms = 8,192 units
/// ```
///
/// # What this bounds
///
/// A realistic v2 carrier transaction is ~66 KB of bytes (bundle ~65.5 KB plus
/// the transaction envelope), so its weight is ~74 KB and a full 4 MiB block
/// holds at most `4,194,304 / 74,000 ≈ 56` of them. Verifying that block costs
/// `56 × 16 ms = 896 ms` against the budget, and `56 × 0.9 ms ≈ 50 ms`
/// measured — **0.03% of the 150-second block interval**. Bytes, not CPU, are
/// the binding resource for pool v2 by three orders of magnitude; this term
/// exists so that remains *structurally* true rather than incidentally true,
/// and so a future costlier `proof_version` is bounded by construction.
pub const SHIELDED_V2_VERIFY_WEIGHT: u64 = 16 * WEIGHT_UNITS_PER_VERIFY_MS;

/// Absolute ceiling on a block's weight — the hard upper bound on what any
/// block can ever cost, mirroring `sov_chain`'s `BLOCK_SIZE_CEILING`.
///
/// Kept well under the P2P transport's 8 MiB `MAX_FRAME` so that **every valid
/// block fits in a single gossip message and in a sync batch**. This is the
/// constant that prevents a rerun of the cold-sync frame-cap outage: a block
/// that cannot be framed is a block that wedges every syncing peer forever.
pub const MAX_BLOCK_WEIGHT: u64 = 4 * 1024 * 1024;

/// Ceiling on a single transaction's weight.
///
/// A transaction must be small enough that a block can hold a useful number of
/// them, and small enough to relay on its own. This is set to one sixteenth of
/// [`MAX_BLOCK_WEIGHT`] = **256 KiB**, which:
///
/// - admits the largest bundle the `ShieldedV2` decoder will accept
///   (`MAX_SHIELDED_V2_BUNDLE_BYTES` = 144 KiB) plus a full post-quantum
///   hybrid signature envelope (~5.3 KB) plus [`SHIELDED_V2_VERIFY_WEIGHT`],
///   with ~100 KiB to spare;
/// - matches the long-standing BIP-110 arbitrary-data cap already enforced on
///   `Deploy`/`Call` payloads (`MiningPolicy::max_code_bytes` = 256 KiB), so
///   the two limits agree instead of contradicting each other;
/// - guarantees at least 16 transactions fit in a maximum block, so one
///   transaction can never monopolize block space.
pub const MAX_TX_WEIGHT: u64 = MAX_BLOCK_WEIGHT / 16;

/// The verification-cost component of an action's weight, in weight units.
///
/// **Zero for every action on mainnet today.** The recursion through the three
/// carrier variants (`MultisigExec`, `ProposeMultisig`, `Tipped`) mirrors how
/// `find_inactive_feature` walks carriers in the execution layer, so a
/// `ShieldedV2` smuggled inside a carrier is priced exactly like a bare one —
/// a wrapper is never a discount.
///
/// Depth is bounded by `MAX_ACTION_DEPTH` at *decode* (an over-deep payload is
/// a clean decode error and never reaches here), but this function is also
/// written to terminate on any value that could be constructed in-process: it
/// recurses on a strictly smaller sub-action and Rust's ownership rules make a
/// cyclic `Action` unconstructable.
pub fn verify_weight(action: &Action) -> u64 {
    match action {
        Action::ShieldedV2 { .. } => SHIELDED_V2_VERIFY_WEIGHT,
        // Carriers price whatever they carry — wrapping is never a discount.
        Action::Tipped { inner, .. } => verify_weight(inner),
        Action::MultisigExec { action, .. } => verify_weight(action),
        Action::ProposeMultisig { action, .. } => verify_weight(action),
        // Everything else — every action that exists on the live chain today —
        // costs nothing beyond its bytes. This arm is deliberately exhaustive
        // by exclusion: adding a new expensive action forces a decision here
        // only if the author writes an arm, so the audit rule is "any new
        // action with a heavy verification MUST get an arm above".
        _ => 0,
    }
}

/// The weight of a signed transaction: its serialized bytes plus the
/// verification cost of its action.
///
/// For every transaction type on the live chain this is exactly
/// `serialized_size()`.
pub fn tx_weight(stx: &SignedTransaction) -> u64 {
    (stx.serialized_size() as u64).saturating_add(verify_weight(&stx.transaction.action))
}

/// The weight of a block: its serialized bytes plus the verification cost of
/// every transaction it carries.
///
/// Note this is **not** the sum of [`tx_weight`] over the block's
/// transactions: `block.serialized_size()` already includes each transaction's
/// bytes *plus* the header and length prefixes, so summing `tx_weight` would
/// double-count the bytes. Bytes come from the block once; verification cost
/// is added per transaction.
///
/// For every block in mainnet history this is exactly `serialized_size()`.
pub fn block_weight(block: &Block) -> u64 {
    let bytes = block.serialized_size() as u64;
    block.transactions.iter().fold(bytes, |acc, stx| {
        acc.saturating_add(verify_weight(&stx.transaction.action))
    })
}

/// The **fee rate** of a transaction in the blockspace auction: bid grains per
/// 1,000 weight units, rounded down.
///
/// # Why a rate, and why scaled
///
/// The auction must compare a 140 KB shielded transaction against a 300-byte
/// transfer honestly *in both directions*. Ranking by the raw bid lets a fat
/// transaction outbid a small one by a single grain while consuming 480× the
/// block space; ranking by rate makes each transaction bid for the space it
/// actually takes.
///
/// The rate is scaled by [`FEE_RATE_WEIGHT_SCALE`] before dividing so that
/// ordinary bids do not all collapse to zero: a 300-byte transfer tipping
/// 1,000 grains has a raw ratio of 3.3 grains/unit, which integer division
/// would floor to 3 and lose most of the ordering. Per 1,000 units it is
/// 3,333 — enough resolution that realistic bids stay distinguishable.
///
/// Integer arithmetic only, no floating point: this value orders a consensus-
/// adjacent schedule and must be identical on every machine.
pub fn fee_rate(bid_grains: u128, weight: u64) -> u128 {
    // `weight` includes the transaction's serialized bytes, which are never
    // zero for a real transaction; guard anyway so this is total.
    let w = weight.max(1) as u128;
    bid_grains
        .saturating_mul(FEE_RATE_WEIGHT_SCALE as u128)
        .checked_div(w)
        .unwrap_or(0)
}

/// Weight-unit denominator for [`fee_rate`]: bids are expressed per this many
/// weight units. 1,000 gives realistic bids ~3 decimal digits of ordering
/// resolution against a minimum-sized transaction (see [`fee_rate`]).
pub const FEE_RATE_WEIGHT_SCALE: u64 = 1_000;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::MAX_SHIELDED_V2_BUNDLE_BYTES;
    use sov_primitives::{AccountId, Balance, Hash};

    fn account() -> AccountId {
        AccountId::new("ab".repeat(32)).expect("64-hex implicit id")
    }

    fn transfer() -> Action {
        Action::Transfer {
            to: account(),
            amount: Balance::from_grains(1),
        }
    }

    #[test]
    fn every_live_action_has_zero_verify_weight() {
        // The byte-identity argument rests entirely on this: if any action
        // that can appear in a pre-activation block had nonzero verify
        // weight, a weight-denominated block limit would NOT equal the
        // byte-denominated one and the replay would diverge.
        let live: Vec<Action> = vec![
            transfer(),
            Action::ClaimVesting,
            Action::Deploy { code: vec![0; 32] },
            Action::Call {
                contract: account(),
                calldata: vec![0; 32],
                gas_limit: 1,
            },
            // The v1 (Orchard/Halo2) pool: its verification is genuinely
            // expensive, but it is priced by the FROZEN gas schedule on the
            // live chain and MUST stay weightless, or the weight-denominated
            // block limit would differ from the byte-denominated one for real
            // mainnet blocks and the replay would diverge.
            Action::Shielded {
                bundle: vec![0; 64],
            },
            Action::HtlcClaim {
                htlc_id: Hash::from_bytes([1u8; 32]),
                preimage: vec![0; 32],
            },
            Action::TokenTransfer {
                asset: Hash::from_bytes([2u8; 32]),
                to: account(),
                amount: Balance::from_grains(1),
            },
            Action::OracleUpdate { price: 1 },
            Action::RegisterName {
                name: "a.sov".into(),
            },
        ];
        for a in &live {
            assert_eq!(verify_weight(a), 0, "live action {a:?} must be weightless");
        }
    }

    #[test]
    fn shielded_v2_is_the_only_weighted_action_and_carriers_do_not_discount_it() {
        let v2 = Action::ShieldedV2 {
            bundle: vec![0u8; 1024],
        };
        assert_eq!(verify_weight(&v2), SHIELDED_V2_VERIFY_WEIGHT);
        assert_eq!(SHIELDED_V2_VERIFY_WEIGHT, 8_192);

        // Wrapping in each carrier prices identically — a wrapper is never a
        // way to pay less for the same verification.
        let tipped = Action::Tipped {
            tip: Balance::from_grains(5),
            inner: Box::new(v2.clone()),
        };
        assert_eq!(verify_weight(&tipped), SHIELDED_V2_VERIFY_WEIGHT);
        let ms = Action::MultisigExec {
            action: Box::new(v2.clone()),
            approvals: vec![],
        };
        assert_eq!(verify_weight(&ms), SHIELDED_V2_VERIFY_WEIGHT);

        // And a plain transfer in the same carrier still costs nothing.
        let tipped_transfer = Action::Tipped {
            tip: Balance::from_grains(5),
            inner: Box::new(transfer()),
        };
        assert_eq!(verify_weight(&tipped_transfer), 0);
    }

    #[test]
    fn the_largest_decodable_v2_transaction_fits_the_per_tx_weight_cap() {
        // The decode cap (144 KiB) plus the verification surcharge plus a
        // maximal hybrid PQ signature envelope must still fit MAX_TX_WEIGHT,
        // or the pool would be unusable the moment it activated.
        let worst = MAX_SHIELDED_V2_BUNDLE_BYTES as u64
            + SHIELDED_V2_VERIFY_WEIGHT
            // hybrid Ed25519 + ML-DSA-65 public key and signature, generously
            // over-counted along with the rest of the transaction envelope.
            + 8 * 1024;
        assert!(
            worst < MAX_TX_WEIGHT,
            "worst-case v2 tx weight {worst} must fit MAX_TX_WEIGHT {MAX_TX_WEIGHT}"
        );
        // ...and a maximum block must still hold a useful number of them.
        assert!(MAX_BLOCK_WEIGHT / worst >= 16);
    }

    #[test]
    fn a_max_weight_block_always_fits_a_sync_batch_and_a_frame() {
        // The cold-sync outage in one assertion. `size_capped_batch_len`
        // always serves AT LEAST one block even if it busts the batch
        // budget, so the frame ceiling must bound a single MAXIMUM block,
        // not just the batch.
        const SYNC_BATCH_MAX_BYTES: u64 = 6 * 1024 * 1024;
        const MAX_FRAME: u64 = 8 * 1024 * 1024;
        assert!(MAX_BLOCK_WEIGHT <= SYNC_BATCH_MAX_BYTES);
        assert!(MAX_BLOCK_WEIGHT < MAX_FRAME);
        // Two maximum blocks exceed the batch budget, so the size cap is
        // load-bearing (a count-only cap of 256 would be 1 GiB).
        assert!(2 * MAX_BLOCK_WEIGHT > SYNC_BATCH_MAX_BYTES);
    }

    #[test]
    fn max_tx_weight_boundary() {
        assert_eq!(MAX_TX_WEIGHT, 256 * 1024);
        assert!(MAX_TX_WEIGHT - 1 < MAX_TX_WEIGHT);
        assert!(MAX_TX_WEIGHT <= MAX_TX_WEIGHT);
        assert!(MAX_TX_WEIGHT + 1 > MAX_TX_WEIGHT);
    }

    #[test]
    fn fee_rate_ranks_a_fat_transaction_honestly_in_both_directions() {
        // A 300-byte transfer tipping 1,000 grains vs a 140 KiB shielded tx.
        let small_w = 300u64;
        let fat_w = 140 * 1024u64;

        // Direction 1: the fat tx bids 1 grain more in ABSOLUTE terms and
        // must NOT win — it consumes ~480x the space.
        assert!(fee_rate(1_000, small_w) > fee_rate(1_001, fat_w));

        // Direction 2: the fat tx bids proportionally MORE per unit of space
        // and MUST win — the ranking is not a blanket penalty on size. At
        // 3,000 grains the small tx rates 10,000/1,000-units; the fat tx must
        // clear 3,000 × (143,360/300) = 1,433,600 grains to beat it, and
        // 1,500,000 does.
        assert_eq!(fee_rate(3_000, small_w), 10_000);
        assert!(fee_rate(1_500_000, fat_w) > fee_rate(3_000, small_w));
        // Just under that break-even it must LOSE, so the crossover is real
        // and not an artifact of a generous margin.
        assert!(fee_rate(1_400_000, fat_w) < fee_rate(3_000, small_w));

        // Equal rates compare equal (the tie-break lives in the mempool, not
        // in the rate).
        assert_eq!(fee_rate(2_000, 2_000), fee_rate(1_000, 1_000));
    }

    #[test]
    fn fee_rate_keeps_resolution_on_realistic_bids() {
        // Without the scale, a 300-byte tx tipping 1,000 grains and one
        // tipping 1,100 would both floor to 3 and become indistinguishable.
        assert_ne!(fee_rate(1_000, 300), fee_rate(1_100, 300));
        // A zero bid rates zero at any weight; a zero-weight input is
        // clamped rather than dividing by zero.
        assert_eq!(fee_rate(0, 1), 0);
        assert_eq!(fee_rate(7, 0), 7 * FEE_RATE_WEIGHT_SCALE as u128);
    }

    #[test]
    fn fee_rate_cannot_overflow_on_an_absurd_bid() {
        // A bid near u128::MAX must saturate, not wrap: a wrapped rate would
        // let a nonsense bid rank BELOW an honest one (or above it).
        let r = fee_rate(u128::MAX, 1);
        assert_eq!(r, u128::MAX);
        assert!(r >= fee_rate(1_000, 300));
    }

    #[test]
    fn weight_units_per_verify_ms_is_conservative_against_the_stated_budget() {
        // The rate must be at or above the strict budget (4 MiB per 15,000
        // ms), because rounding the other way would let MORE verification
        // into a block than the policy allows.
        let strict = MAX_BLOCK_WEIGHT / 15_000;
        assert!(
            WEIGHT_UNITS_PER_VERIFY_MS >= strict,
            "{WEIGHT_UNITS_PER_VERIFY_MS} must be >= the strict budget {strict}"
        );
        // The implied full-block verification budget stays a small fraction
        // of the 150,000 ms block interval.
        let implied_ms = MAX_BLOCK_WEIGHT / WEIGHT_UNITS_PER_VERIFY_MS;
        assert!(implied_ms * 10 < 150_000, "{implied_ms} ms is not << 150 s");
    }
}
