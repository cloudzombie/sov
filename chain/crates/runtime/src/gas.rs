//! Gas metering.
//!
//! Gas measures the work a transaction costs the network: every transaction pays
//! a flat intrinsic cost plus per-byte/per-verify surcharges. The fee charged is
//! `gas_used × gas_price` (see [`MiningPolicy::gas_price`](sov_mining)).
//!
//! ⚠️ **FROZEN — CONSENSUS-CRITICAL.** These gas constants are part of mainnet
//! consensus: the fee they produce is debited from the sender and credited to the
//! miner inside the STF, so it enters the **state root**. Changing ANY value here
//! (or `gas_price`) changes balances → the state root → and every node that runs the
//! new schedule computes a different chain from every node that runs the old one — a
//! hard fork / chain restart. These are NOT "tune later" values. Do not modify them
//! on the live chain; a change is only possible via a coordinated network upgrade.

use sov_types::Action;

/// Flat cost charged for admitting any transaction, covering signature
/// verification, nonce handling, and state access. The value mirrors the
/// long-standing 21,000-gas intrinsic cost convention for a basic transfer.
pub const INTRINSIC_GAS: u64 = 21_000;

/// Extra gas for ledger-bookkeeping operations (escrow/token/registry moves:
/// a couple of committed map writes plus counter updates).
pub const BOOKKEEPING_GAS: u64 = 30_000;

/// Per-byte gas for storing deployed contract code.
pub const DEPLOY_GAS_PER_BYTE: u64 = 200;

/// Per-byte gas for contract calldata — transient input, far cheaper than
/// stored code but priced so block space cannot be filled for free (the value
/// mirrors Ethereum's long-standing 16 gas/byte calldata cost).
pub const CALLDATA_GAS_PER_BYTE: u64 = 16;

/// Extra gas for verifying a shielded bundle's Halo2 zero-knowledge proof —
/// substantial, reflecting the real cost of zk-SNARK verification (the most
/// expensive verification the chain performs).
pub const SHIELDED_VERIFY_GAS: u64 = 500_000;

/// The intrinsic (non-VM) gas of a transaction, before any contract execution.
/// A `Call`'s VM gas is metered separately by the runtime and added on top.
pub fn gas_for(action: &Action) -> u64 {
    match action {
        // A plain balance transfer costs only the intrinsic amount.
        Action::Transfer { .. } => INTRINSIC_GAS,
        // Claiming vested funds is a simple balance move.
        Action::ClaimVesting => INTRINSIC_GAS,
        // Deploying pays per byte of code stored.
        Action::Deploy { code } => INTRINSIC_GAS + code.len() as u64 * DEPLOY_GAS_PER_BYTE,
        // The intrinsic cost of a call plus its per-byte calldata price; VM gas
        // is added by the runtime.
        Action::Call { calldata, .. } => {
            INTRINSIC_GAS + calldata.len() as u64 * CALLDATA_GAS_PER_BYTE
        }
        // A shielded action additionally pays for zk-SNARK proof verification.
        Action::Shielded { .. } => INTRINSIC_GAS + SHIELDED_VERIFY_GAS,
        // HTLC escrow operations are simple state moves (plus a hash on claim).
        Action::HtlcLock { .. } | Action::HtlcClaim { .. } | Action::HtlcRefund { .. } => {
            INTRINSIC_GAS + BOOKKEEPING_GAS
        }
        // Native-asset operations are ledger bookkeeping.
        Action::TokenIssue { .. } | Action::TokenTransfer { .. } | Action::TokenBurn { .. } => {
            INTRINSIC_GAS + BOOKKEEPING_GAS
        }
        // Setting an asset's compliance policy pays per allow/deny-list entry —
        // each entry is committed state, priced like stored data.
        Action::TokenSetPolicy { policy, .. } => {
            INTRINSIC_GAS + BOOKKEEPING_GAS + policy_entries(policy) * POLICY_GAS_PER_ENTRY
        }
        // Settling an intent verifies a second Ed25519 signature (the owner's)
        // on top of the transaction's own, then performs two ledger moves.
        Action::IntentSettle { .. } => INTRINSIC_GAS + BOOKKEEPING_GAS + INTENT_VERIFY_GAS,
        // Cancelling consumes one committed marker.
        Action::IntentCancel { .. } => INTRINSIC_GAS + BOOKKEEPING_GAS,
        // A key rotation verifies the new key's possession proof (a second
        // signature verification beyond the transaction's own).
        Action::RotateKey { .. } => INTRINSIC_GAS + BOOKKEEPING_GAS + INTENT_VERIFY_GAS,
        // Name registry operations are committed-state bookkeeping. The one-time
        // anti-squat *registration fee* is charged separately by the runtime (it
        // is a fee earned by miners, not gas), so the gas here is just the write.
        Action::RegisterName { .. } | Action::TransferName { .. } => {
            INTRINSIC_GAS + BOOKKEEPING_GAS
        }
        // NFT mint prices the stored bytes (token id + metadata) like calldata, on
        // top of the bookkeeping write; transfer/set-meta are plain state edits.
        Action::NftMint {
            token_id, metadata, ..
        } => {
            INTRINSIC_GAS
                + BOOKKEEPING_GAS
                + (token_id.len() + metadata.len()) as u64 * CALLDATA_GAS_PER_BYTE
        }
        Action::NftTransfer { .. } => INTRINSIC_GAS + BOOKKEEPING_GAS,
        Action::NftSetMeta { metadata, .. } => {
            INTRINSIC_GAS + BOOKKEEPING_GAS + metadata.len() as u64 * CALLDATA_GAS_PER_BYTE
        }
        // Setting a policy commits N keys; price per signer like stored data.
        Action::SetMultisig { signers, .. } => {
            INTRINSIC_GAS + BOOKKEEPING_GAS + signers.len() as u64 * POLICY_GAS_PER_ENTRY
        }
        // A multisig exec verifies one signature per approval (each ~an INTENT
        // verify) and then performs the inner action's own work. The inner action
        // is never itself a MultisigExec (execution rejects nesting); guard the
        // recursion at one level so a malformed nested payload can't blow the stack
        // during gas estimation.
        Action::MultisigExec { action, approvals } => {
            let inner = if matches!(**action, Action::MultisigExec { .. }) {
                INTRINSIC_GAS
            } else {
                gas_for(action)
            };
            INTRINSIC_GAS + approvals.len() as u64 * INTENT_VERIFY_GAS + inner
        }
        // On-chain multisig coordination: each is a member-signed bookkeeping tx
        // (propose stores a proposal; approve may execute it; cancel removes it).
        Action::ProposeMultisig { .. }
        | Action::ApproveMultisig { .. }
        | Action::CancelMultisig { .. } => INTRINSIC_GAS + BOOKKEEPING_GAS,
        // xUSD vault operations: each is a bookkeeping state update (move balance
        // ↔ collateral, mint/burn xUSD, or record a price). Priced like a token op.
        Action::VaultDeposit { .. }
        | Action::VaultMint { .. }
        | Action::VaultBurn { .. }
        | Action::VaultWithdraw { .. }
        | Action::OracleUpdate { .. } => INTRINSIC_GAS + BOOKKEEPING_GAS,
        // A fee-auction envelope: the inner action's own gas plus one bookkeeping unit
        // for charging the tip. The tip itself is a value transfer to the miner, not a
        // gas cost. Recurse at MOST one level — mirroring the `MultisigExec` guard
        // above — so a maliciously deep-nested `Tipped{Tipped{…}}` can never blow the
        // stack during gas estimation (which runs before the execution-layer reject).
        // Nested tips are rejected at execution anyway; here we only need a bounded,
        // non-crashing price.
        Action::Tipped { inner, .. } => {
            let g = if matches!(**inner, Action::Tipped { .. }) {
                INTRINSIC_GAS
            } else {
                gas_for(inner)
            };
            g.saturating_add(BOOKKEEPING_GAS)
        }
        // A bounded creation-time envelope: the inner action's own gas plus one
        // bookkeeping unit for the extra 8 declared bytes and the two bound
        // comparisons. Recurse at MOST one level — mirroring the `Tipped` and
        // `MultisigExec` guards above — so a maliciously deep-nested
        // `Timestamped{Timestamped{…}}` can never blow the stack during gas
        // estimation (which runs before the execution-layer reject). Nesting is
        // rejected at execution anyway; here we only need a bounded, non-crashing
        // price. Not free, so wrapping is never a way to buy blockspace cheaply.
        Action::Timestamped { inner, .. } => {
            let g = if matches!(**inner, Action::Timestamped { .. }) {
                INTRINSIC_GAS
            } else {
                gas_for(inner)
            };
            g.saturating_add(BOOKKEEPING_GAS)
        }
        // Pool v2 (post-quantum shielded): pays for STARK proof verification
        // plus its (large, ~40-62 KB) bundle bytes priced like calldata. NOT
        // yet consensus-live: execution hard-rejects `ShieldedV2` as
        // `FeatureInactive` while the `shielded-v2` deployment is unarmed, so
        // this price is never charged on any chain today. Slice S2d owns the
        // final weight/fee audit and may retune this BEFORE the arming
        // release — after arming it is frozen like everything above.
        Action::ShieldedV2 { bundle } => INTRINSIC_GAS
            .saturating_add(SHIELDED_V2_VERIFY_GAS)
            .saturating_add((bundle.len() as u64).saturating_mul(CALLDATA_GAS_PER_BYTE)),
    }
}

/// Extra gas for verifying a pool-v2 bundle's STARK proof. Native STARK
/// verification is measured ~0.7 ms — the same order as the work
/// [`SHIELDED_VERIFY_GAS`] prices for v1's Halo2 — so v2 keeps the same
/// surcharge; the bundle's much larger byte footprint is priced separately,
/// per byte (see [`gas_for`]). Dormant until the `shielded-v2` deployment is
/// armed and active; final calibration is slice S2d's, before arming.
pub const SHIELDED_V2_VERIFY_GAS: u64 = 500_000;

/// Extra gas for verifying a settlement's embedded intent signature (a second
/// Ed25519 verification beyond the transaction's own).
pub const INTENT_VERIFY_GAS: u64 = 30_000;

/// Extra gas for a transaction's signature envelope **beyond the V1
/// baseline**. A hybrid (Ed25519 + ML-DSA-65) key and signature occupy
/// ~5.3 KB of block space versus V1's 98 bytes; the excess is priced per byte
/// like calldata, plus a surcharge for the ML-DSA verification itself. V1
/// transactions pay nothing extra (their envelope is part of the intrinsic
/// cost), so existing fee behavior is unchanged.
pub fn envelope_gas(key: &sov_crypto::PublicKey) -> u64 {
    match key {
        sov_crypto::PublicKey::V1Ed25519(_) => 0,
        sov_crypto::PublicKey::V2HybridMlDsa65 { .. } => hybrid_envelope_gas(),
    }
}

/// The envelope surcharge for a hybrid (Ed25519 + ML-DSA-65) signature, beyond the
/// V1 baseline — the single source of truth for `envelope_gas`'s V2 arm, exposed so
/// a fee estimator can price the station's post-quantum wallets without a key in
/// hand (every sov-station wallet signs hybrid).
pub fn hybrid_envelope_gas() -> u64 {
    let extra_bytes = (sov_crypto::ML_DSA_65_PK_LEN + sov_crypto::ML_DSA_65_SIG_LEN) as u64;
    extra_bytes * CALLDATA_GAS_PER_BYTE + ML_DSA_VERIFY_GAS
}

/// Extra gas for one ML-DSA-65 verification (lattice arithmetic — materially
/// more work than an Ed25519 check, far less than a zk-SNARK).
pub const ML_DSA_VERIFY_GAS: u64 = 60_000;

/// Per-entry gas for an allow/deny-list account in a compliance policy
/// (roughly the deploy price of the bytes one entry commits).
pub const POLICY_GAS_PER_ENTRY: u64 = 2_000;

/// Number of allow/deny-list entries in a compliance policy.
pub fn policy_entries(policy: &sov_compliance::CompliancePolicy) -> u64 {
    use sov_compliance::TransferControl;
    match &policy.transfer_control {
        TransferControl::Unrestricted => 0,
        TransferControl::AllowList(set) | TransferControl::DenyList(set) => set.len() as u64,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sov_crypto::Keypair;

    #[test]
    fn hybrid_envelope_gas_matches_envelope_gas_for_a_hybrid_key() {
        // The exposed helper (used by the fee estimator without a key in hand) must
        // equal what `envelope_gas` charges a real hybrid key — one source of truth.
        let pk = Keypair::hybrid_from_seed([7u8; 32]).public_key();
        assert_eq!(envelope_gas(&pk), hybrid_envelope_gas());
        // A V1 (Ed25519) key pays no envelope surcharge.
        let v1 = Keypair::from_seed([7u8; 32]).public_key();
        assert_eq!(envelope_gas(&v1), 0);
    }

    #[test]
    fn pool_v2_exhaustion_has_a_pinned_fee_floor() {
        // Audit PQV2-04: filling the commitment tree to exhaust it. With the
        // tree deepened to the horizon-safe depth 32, this pins the FLOOR on
        // what exhaustion costs in fees so a future gas retune (slice S2d may
        // retune BEFORE arming) can never silently make griefing the pool cheap.
        //
        // Threat model: bit 2 is armed and active. An attacker fills the tree's
        // `MAX_V2_NOTES` = 2^32-1 usable leaves so no further notes can be added
        // — a permanent pool DoS. Each `ShieldedV2` bundle carries at most
        // `NUM_SLOTS` real output commitments (leaves). At depth 32 the fee
        // floor to do so exceeds the ENTIRE XUS money supply by a wide margin,
        // so exhaustion is not merely expensive but economically impossible.
        use sov_mining::MiningPolicy;
        use sov_primitives::GRAINS_PER_SOV;
        use sov_shielded_pq::{air::NUM_SLOTS, MAX_V2_NOTES};

        // The mainnet fee schedule the attack is priced against.
        let gas_price = MiningPolicy::mainnet_like().gas_price.grains();
        assert_eq!(gas_price, 10, "mainnet charges 10 grains per gas unit");
        assert_eq!(
            SHIELDED_V2_VERIFY_GAS, 500_000,
            "verify-gas floor is pinned"
        );

        // A GUARANTEED per-bundle gas floor, independent of bundle bytes and of
        // the carrier's signature scheme: intrinsic + the STARK-verify
        // surcharge. A real bundle also pays for its ~55+ KB proof bytes
        // (× CALLDATA_GAS_PER_BYTE) and, for a PQ carrier, the hybrid envelope —
        // all strictly ON TOP of this — so this is a conservative lower bound.
        let min_gas_per_bundle = INTRINSIC_GAS + SHIELDED_V2_VERIFY_GAS; // 521,000
        let empty = Action::ShieldedV2 { bundle: vec![] };
        assert!(
            gas_for(&empty) >= min_gas_per_bundle,
            "a v2 bundle always costs at least intrinsic + verify gas"
        );

        // Cost floor to fill every usable leaf.
        let bundles_to_fill = MAX_V2_NOTES.div_ceil(NUM_SLOTS as u64); // 1,073,741,824
        assert_eq!(bundles_to_fill, 1_073_741_824);
        let min_fee_grains = (min_gas_per_bundle as u128) * gas_price * (bundles_to_fill as u128);
        let min_fee_xus = min_fee_grains / GRAINS_PER_SOV;
        // ~55.9 MILLION XUS in fees PAID TO MINERS just to grief the pool, with
        // no financial gain to the attacker (fees are not burned — they enrich
        // the very miners securing the chain). That EXCEEDS the entire ~21M-XUS
        // money supply by ~2.6x, so at depth 32 the attack cannot be funded at
        // all — it is economically impossible, not merely expensive. (Proof
        // bytes are strictly on top of this floor.)
        assert_eq!(min_fee_xus, 55_941_949);
        assert!(
            min_fee_xus >= 50_000_000,
            "filling the depth-32 tree costs tens of millions of XUS in fees, got {min_fee_xus}"
        );
    }

    #[test]
    fn wallet_route_intrinsic_gas_is_stable() {
        // These payload-independent sums are what the `sov_estimateFee` RPC reuses for
        // the wallet's three send routes; pin them so the RPC can never drift.
        use sov_primitives::{AccountId, Balance, Hash};
        let to = AccountId::new("ab".repeat(32)).expect("64-hex implicit id");
        assert_eq!(
            gas_for(&Action::Transfer {
                to: to.clone(),
                amount: Balance::from_grains(1),
            }),
            INTRINSIC_GAS
        );
        assert_eq!(
            gas_for(&Action::TokenTransfer {
                asset: Hash::from_bytes([2u8; 32]),
                to,
                amount: Balance::from_grains(1),
            }),
            INTRINSIC_GAS + BOOKKEEPING_GAS
        );
    }
}
