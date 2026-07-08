//! Transaction execution: the state transition function.
//!
//! [`apply_transaction`] is the heart of the protocol — the single place where
//! value moves. It enforces, in order:
//!
//! 1. **Authentication** — the signature must verify against the transaction's
//!    public key, or the transaction is rejected (never included).
//! 2. **Authorization** — that public key must be the signer account's
//!    registered controlling key, so only the account's owner can spend its
//!    funds.
//! 3. **Ordering / replay protection** — the nonce must equal the signer's
//!    current nonce, or the transaction is rejected.
//! 4. **Execution** — once admitted, the nonce is consumed (incremented) even if
//!    the action then fails (e.g. insufficient funds), so a rejected payment
//!    still cannot be replayed.
//!
//! A transfer only ever moves value between existing balances; nothing here
//! mints SOV, so total supply is conserved and the protocol cap — established at
//! genesis — holds inductively over every block. All arithmetic is checked.

use sov_compliance::SpendWindow;
use sov_mining::MiningPolicy;
use sov_primitives::{AccountId, Balance, Hash};
use sov_shielded::ShieldedBundle;
use sov_state::{Htlc, Ledger, TokenInfo};
use sov_types::{Action, Event, ExecutionStatus, Receipt, SignedTransaction};
use sov_vm::{ContractStorage, ExecContext, VmError};

use crate::gas::gas_for;

/// The block-level context execution needs beyond the transaction itself.
///
/// Several actions depend on block-level facts: the mining policy meters fees
/// and data caps; [`Action::ClaimVesting`] and the HTLC actions need the
/// current height (to check locks and timeouts).
pub struct BlockContext<'a> {
    /// Height of the block being produced/imported.
    pub height: u64,
    /// Hash of the parent block — the head this block extends.
    pub prev_hash: Hash,
    /// The chain's mining difficulty and emission policy.
    pub mining: &'a MiningPolicy,
    /// Price charged per unit of gas, in grains (mirrors `mining.gas_price`).
    /// `0` disables fees.
    pub gas_price: Balance,
    /// The block's miner — the account its proof-of-work pays. Receives the miner
    /// share (the remainder after the treasury/dev tax) of both the coinbase
    /// subsidy and every transaction fee.
    pub miner: AccountId,
    /// The resolved post-quantum sunset schedule, once the miner-signaled
    /// `pq-sunset` deployment has activated (`None` before activation). See
    /// [`sov_mining::PqSchedule`] for the exact phase semantics.
    pub pq: Option<sov_mining::PqSchedule>,
}

/// Reasons a transaction is *rejected* — not admitted to a block at all. These
/// are distinct from execution *failure* (recorded in a [`Receipt`]): a rejected
/// transaction never appears on chain.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ExecutionError {
    /// The signature did not verify against the transaction's public key.
    #[error("invalid transaction signature")]
    InvalidSignature,
    /// The transaction's public key is not the signer account's controlling key
    /// (or the account has no key and cannot spend).
    #[error("unauthorized: key does not control account {account}")]
    Unauthorized {
        /// The account the transaction tried to act for.
        account: String,
    },
    /// The nonce did not match the signer's current nonce.
    #[error("bad nonce: account is at {expected}, transaction used {got}")]
    BadNonce {
        /// The signer's current nonce.
        expected: u64,
        /// The nonce the transaction carried.
        got: u64,
    },
    /// A balance computation overflowed `u128` (unreachable under the supply cap,
    /// but checked rather than assumed).
    #[error("balance arithmetic overflow")]
    Overflow,
    /// The signer cannot afford the transaction's gas fee.
    #[error("account {account} cannot afford the transaction fee")]
    CannotAffordFee {
        /// The account that could not cover the fee.
        account: String,
    },
    /// The transaction carries more arbitrary data than the protocol allows
    /// (BIP-110: block space is reserved for monetary use, not data storage).
    #[error("transaction data too large: limit {limit} bytes, got {got}")]
    DataTooLarge {
        /// The configured maximum bytes.
        limit: usize,
        /// The size the transaction carried.
        got: usize,
    },
    /// The post-quantum rotation window is open and this account exceeds the
    /// threshold: its legacy (Ed25519) key may only execute a `RotateKey` to a
    /// hybrid key until it migrates.
    #[error("post-quantum rotation required: account {account} must rotate to a hybrid key before any other action")]
    PqRotationRequired {
        /// The account that must rotate.
        account: String,
    },
    /// The post-quantum sunset has passed: legacy (Ed25519) signatures no
    /// longer prove ownership and are rejected for every action. Un-rotated
    /// funds are frozen — protected from quantum forgery.
    #[error("post-quantum sunset: legacy Ed25519 keys are frozen; account {account} did not rotate in time")]
    PqSunset {
        /// The frozen account.
        account: String,
    },
}

/// Apply one signed transaction to `ledger` in `ctx`, returning its [`Receipt`].
///
/// Returns `Err` only if the transaction is *rejected* (bad signature, wrong
/// key, or bad nonce); an admitted-but-failed transaction returns `Ok` with a
/// [`ExecutionStatus::Failed`] receipt and a consumed nonce.
pub fn apply_transaction(
    ledger: &mut Ledger,
    stx: &SignedTransaction,
    ctx: &BlockContext<'_>,
) -> Result<Receipt, ExecutionError> {
    if !stx.verify_signature() {
        return Err(ExecutionError::InvalidSignature);
    }
    let tx = &stx.transaction;

    let mut signer = ledger.account(&tx.signer);

    // Authorization. Three account shapes:
    //
    // - **Keyed**: must be addressed by its bound key.
    // - **Keyless implicit** (id = `hex(blake3(key))`, what a coinbase pays and a
    //   wallet's own id): *self-certifying*, like an account whose address IS its
    //   key. The key whose hash equals the id may act for it directly — ANY action,
    //   no separate "activation" — and the key binds on first use. Any other key
    //   is rejected, so mined funds stay claimable only by their miner and an
    //   implicit id can never be squatted.
    // - **Keyless named** (a human name like `treasury.sov`): must be *claimed*
    //   first via `RotateKey` (first-come), which binds a key before any spend.
    // - **Multisig** (opt-in): once an account has an M-of-N policy, single-key
    //   spends are DISABLED — only a `MultisigExec` relayed by a policy member is
    //   admissible here (the threshold of approvals is verified during execution).
    if let Some(policy) = ledger.multisig_of(&tx.signer) {
        let member = policy.signers.contains(&tx.public_key);
        let is_exec = matches!(tx.action, Action::MultisigExec { .. });
        if !(member && is_exec) {
            return Err(ExecutionError::Unauthorized {
                account: tx.signer.to_string(),
            });
        }
    } else {
        match (&signer.key, &tx.action) {
            (Some(key), _) if *key == tx.public_key => {}
            (Some(_), _) => {
                return Err(ExecutionError::Unauthorized {
                    account: tx.signer.to_string(),
                })
            }
            (None, action) => {
                let unauthorized = || ExecutionError::Unauthorized {
                    account: tx.signer.to_string(),
                };
                if tx.signer.is_implicit() {
                    // Self-certifying: only the key whose hash is the id, for any action.
                    if tx.public_key.implicit_account_id() != tx.signer {
                        return Err(unauthorized());
                    }
                } else if !matches!(action, Action::RotateKey { .. }) {
                    // A keyless human-named account must be claimed (RotateKey) first.
                    return Err(unauthorized());
                }
                // Bind the key on first use (implicit self-claim, or named first-come).
                signer.key = Some(tx.public_key);
            }
        }
    }

    if tx.nonce != signer.nonce {
        return Err(ExecutionError::BadNonce {
            expected: signer.nonce,
            got: tx.nonce,
        });
    }

    // The post-quantum sunset gate (Q-day runbook as consensus policy). Once
    // the miner-signaled schedule is active, legacy (V1 Ed25519) signatures
    // are progressively retired: first the highest-value accounts may only
    // rotate to a hybrid key, then — at the sunset — a V1 signature stops
    // proving ownership entirely and is rejected for every action. Hybrid
    // (V2) transactions are never touched.
    if let Some(pq) = &ctx.pq {
        let legacy = matches!(tx.public_key, sov_crypto::PublicKey::V1Ed25519(_));
        if legacy && ctx.height >= pq.sunset_height {
            return Err(ExecutionError::PqSunset {
                account: tx.signer.to_string(),
            });
        }
        if legacy
            && ctx.height >= pq.rotation_only_height
            && signer
                .total()
                .map(|t| t.grains() >= pq.threshold_grains)
                .unwrap_or(true)
        {
            // The ONLY admissible action is a rotation to a non-legacy key —
            // a V1 -> V1 rotation would evade the sunset and is refused.
            let rotating_to_hybrid = matches!(
                &tx.action,
                Action::RotateKey { new_key, .. }
                    if !matches!(new_key, sov_crypto::PublicKey::V1Ed25519(_))
            );
            if !rotating_to_hybrid {
                return Err(ExecutionError::PqRotationRequired {
                    account: tx.signer.to_string(),
                });
            }
        }
    }

    // BIP-110: cap the arbitrary data a transaction may carry (contract code on
    // Deploy, calldata on Call), keeping block space reserved for monetary use
    // rather than data storage.
    let data_len = match &tx.action {
        Action::Deploy { code } => Some(code.len()),
        Action::Call { calldata, .. } => Some(calldata.len()),
        _ => None,
    };
    if let Some(got) = data_len {
        let limit = ctx.mining.max_code_bytes as usize;
        if limit != 0 && got > limit {
            return Err(ExecutionError::DataTooLarge { limit, got });
        }
    }

    // Intrinsic gas, plus the signature-envelope surcharge for schemes larger
    // than the V1 baseline (a hybrid PQ envelope occupies ~5.3 KB of block
    // space and a costlier verification); a contract Call adds its VM gas on
    // top below.
    let mut gas_used = gas_for(&tx.action) + crate::gas::envelope_gas(&tx.public_key);

    // The transaction fee (gas × price). The intrinsic fee must be affordable
    // up front, or the transaction is rejected (never included; the nonce is
    // not consumed). Issuance pays no fee because issuance is the coinbase —
    // not a transaction at all.
    let charges_fee = ctx.gas_price != Balance::ZERO;
    let intrinsic_fee = if charges_fee {
        let grains = (gas_used as u128)
            .checked_mul(ctx.gas_price.grains())
            .ok_or(ExecutionError::Overflow)?;
        Balance::from_grains(grains)
    } else {
        Balance::ZERO
    };
    if intrinsic_fee != Balance::ZERO && signer.balance.checked_sub(intrinsic_fee).is_none() {
        return Err(ExecutionError::CannotAffordFee {
            account: tx.signer.to_string(),
        });
    }

    // Admitted: consume the nonce regardless of whether the action succeeds.
    let tx_nonce = tx.nonce;
    signer.nonce = signer
        .nonce
        .checked_add(1)
        .ok_or(ExecutionError::Overflow)?;

    // Contract-call outputs (ABI v2), recorded in the receipt on success.
    let mut return_data: Vec<u8> = Vec::new();
    let mut events: Vec<Event> = Vec::new();

    // Reserve the intrinsic fee up front (paid even if the action then fails).
    let mut fee_paid = Balance::ZERO;
    if intrinsic_fee != Balance::ZERO {
        signer.balance = signer
            .balance
            .checked_sub(intrinsic_fee)
            .ok_or(ExecutionError::Overflow)?;
        fee_paid = intrinsic_fee;
    }

    // Resolve the action to execute. A `MultisigExec` unwraps to its inner action
    // once `threshold` distinct policy-signer approvals verify over the canonical
    // `(account, nonce, inner)` message; everything else executes directly. A
    // pre-execution failure (illegal inner, or too few valid approvals) is carried
    // in `ms_error` and short-circuits to a Failed receipt (the fee is still paid).
    let mut ms_error: Option<String> = None;
    let effective_action: &Action = match &tx.action {
        Action::MultisigExec { action, approvals } => {
            let inner = action.as_ref();
            if matches!(
                inner,
                Action::MultisigExec { .. } | Action::RotateKey { .. }
            ) {
                ms_error =
                    Some("multisig: inner action may not be MultisigExec or RotateKey".into());
            } else if let Some(policy) = ledger.multisig_of(&tx.signer).cloned() {
                let msg = sov_types::multisig_signing_bytes(&tx.signer, tx_nonce, inner);
                // Count DISTINCT signer indices with a valid signature (a repeated
                // index cannot inflate the count toward the threshold).
                let mut approved = std::collections::BTreeSet::new();
                for ap in approvals {
                    if let Some(pk) = policy.signers.get(ap.signer as usize) {
                        if pk.verify(&msg, &ap.signature) {
                            approved.insert(ap.signer);
                        }
                    }
                }
                if (approved.len() as u16) < policy.threshold {
                    ms_error = Some(format!(
                        "multisig: {} valid approval(s), need {}",
                        approved.len(),
                        policy.threshold
                    ));
                }
            } else {
                ms_error = Some("multisig: account has no multisig policy".into());
            }
            inner
        }
        other => other,
    };

    let status = if let Some(reason) = ms_error {
        ExecutionStatus::Failed { reason }
    } else {
        match effective_action {
            Action::Transfer { to, amount } => {
                do_transfer(ledger, &tx.signer, &mut signer, to, *amount)?
            }
            Action::ClaimVesting => {
                if !signer.can_claim_vesting(ctx.height) {
                    ExecutionStatus::Failed {
                        reason: "no vested funds to claim yet".into(),
                    }
                } else {
                    let vested = signer.locked;
                    signer.balance = signer
                        .balance
                        .checked_add(vested)
                        .ok_or(ExecutionError::Overflow)?;
                    signer.locked = Balance::ZERO;
                    signer.unlock_height = 0;
                    ExecutionStatus::Success
                }
            }
            Action::Deploy { code } => {
                if code.is_empty() {
                    ExecutionStatus::Failed {
                        reason: "empty contract code".into(),
                    }
                } else {
                    // The signer's account becomes a contract.
                    signer.code = Some(code.clone());
                    ExecutionStatus::Success
                }
            }
            Action::Call {
                contract,
                gas_limit,
                calldata,
            } => {
                match ledger.account(contract).code {
                    None => ExecutionStatus::Failed {
                        reason: "target account is not a contract".into(),
                    },
                    Some(code) => {
                        // Materialize the contract's committed storage for the VM.
                        let mut storage = ContractStorage::new();
                        for (k, v) in ledger.contract_entries(contract) {
                            storage.set(k, v);
                        }
                        // ABI v2: hand the VM the block height, the authenticated
                        // caller, the contract's own address and calldata, and the
                        // contract's OWN token balances — the only token state a
                        // contract can observe or spend.
                        let mut token_balances = std::collections::BTreeMap::new();
                        for ((asset, holder), balance) in ledger.token_balance_iter() {
                            if holder == contract {
                                token_balances.insert(*asset.as_bytes(), balance.grains());
                            }
                        }
                        let vm_ctx = ExecContext {
                            block_height: ctx.height,
                            caller: tx.signer.to_string(),
                            contract: contract.to_string(),
                            calldata: calldata.clone(),
                            token_balances,
                        };
                        match sov_vm::execute(&code, "call", *gas_limit, vm_ctx, &mut storage) {
                            Ok(outcome) => {
                                // VM gas fee, charged on top of the intrinsic fee. The
                                // unified distribution at the end burns + splits it.
                                let vm_fee = Balance::from_grains(
                                    (outcome.gas_used as u128)
                                        .checked_mul(ctx.gas_price.grains())
                                        .ok_or(ExecutionError::Overflow)?,
                                );
                                match signer.balance.checked_sub(vm_fee) {
                                    None => ExecutionStatus::Failed {
                                        reason: "cannot afford gas fee".into(),
                                    },
                                    Some(remaining) => {
                                        signer.balance = remaining;
                                        fee_paid = fee_paid
                                            .checked_add(vm_fee)
                                            .ok_or(ExecutionError::Overflow)?;
                                        gas_used = gas_used.saturating_add(outcome.gas_used);
                                        // Re-validate the contract's queued token
                                        // transfers against the real ledger; commit
                                        // them and the storage writes only if every
                                        // command is sound — all or nothing. The fee
                                        // stays charged either way (work was done).
                                        match settle_contract_token_transfers(
                                            ledger,
                                            contract,
                                            &outcome.token_transfers,
                                            ctx.height,
                                        ) {
                                            Err(reason) => ExecutionStatus::Failed { reason },
                                            Ok(()) => {
                                                // Commit contract storage changes.
                                                for (k, v) in storage.iter() {
                                                    ledger.set_contract_value(
                                                        contract,
                                                        k.clone(),
                                                        v.clone(),
                                                    );
                                                }
                                                return_data = outcome.return_data;
                                                events = outcome
                                                    .events
                                                    .into_iter()
                                                    .map(|e| Event {
                                                        topic: e.topic,
                                                        data: e.data,
                                                    })
                                                    .collect();
                                                ExecutionStatus::Success
                                            }
                                        }
                                    }
                                }
                            }
                            Err(VmError::OutOfGas) => ExecutionStatus::Failed {
                                reason: "contract ran out of gas".into(),
                            },
                            Err(e) => ExecutionStatus::Failed {
                                reason: format!("contract trap: {e}"),
                            },
                        }
                    }
                }
            }
            Action::Shielded { bundle } => {
                // Decode the bundle; a malformed encoding fails the action (the nonce
                // is consumed and the fee paid) rather than rejecting the whole block.
                match ShieldedBundle::from_bytes(bundle) {
                    Err(_) => ExecutionStatus::Failed {
                        reason: "malformed shielded bundle".into(),
                    },
                    Ok(sb) if !sb.verify_cached() => ExecutionStatus::Failed {
                        reason: "invalid shielded proof".into(),
                    },
                    Ok(sb) if !ledger.shielded().anchor_is_known(&sb.anchor()) => {
                        ExecutionStatus::Failed {
                            reason: "unknown shielded anchor".into(),
                        }
                    }
                    Ok(sb) => {
                        // The net value crossing the transparent/shielded boundary:
                        // vb < 0 shields (debit signer, pool grows); vb > 0 de-shields
                        // (pool shrinks, credit signer); vb == 0 is a private transfer.
                        let vb = sb.value_balance();
                        let mag = Balance::from_grains(u128::from(vb.unsigned_abs()));
                        // Pre-check the transparent effect so the action never
                        // half-applies — validate fully before mutating anything.
                        let affordable = if vb < 0 {
                            signer.balance.checked_sub(mag).is_some()
                        } else if vb > 0 {
                            ledger.shielded_value().checked_sub(mag).is_some()
                        } else {
                            true
                        };
                        // Drain limiter (defense in depth for the proof system):
                        // a de-shield must also fit the rolling per-window cap, so
                        // even a forged proof cannot drain the pool faster than
                        // `deshield_limit_grains` per `deshield_window_blocks`.
                        // Computed before any mutation; persisted only on success.
                        let mut window_update: Option<(u64, Balance)> = None;
                        let mut over_limit = false;
                        if vb > 0 && ctx.mining.deshield_window_blocks != 0 {
                            let (start, spent) = ledger.deshield_window();
                            let elapsed = ctx.height.saturating_sub(start)
                                >= ctx.mining.deshield_window_blocks;
                            let (base_start, base_spent) = if elapsed {
                                (ctx.height, Balance::ZERO)
                            } else {
                                (start, spent)
                            };
                            match base_spent.checked_add(mag) {
                                Some(new_spent)
                                    if new_spent.grains() <= ctx.mining.deshield_limit_grains =>
                                {
                                    window_update = Some((base_start, new_spent));
                                }
                                _ => over_limit = true,
                            }
                        }
                        if over_limit {
                            ExecutionStatus::Failed {
                                reason: "de-shield rate limit exceeded for this window".into(),
                            }
                        } else if !affordable {
                            ExecutionStatus::Failed {
                                reason: "insufficient balance for shielded value".into(),
                            }
                        } else {
                            // Apply atomically (double-spend check + tree append); on a
                            // nullifier conflict nothing is mutated.
                            match ledger.apply_shielded_bundle(&sb) {
                                Err(_) => ExecutionStatus::Failed {
                                    reason: "shielded double-spend".into(),
                                },
                                Ok(()) => {
                                    // Commit the pre-checked transparent movement.
                                    if vb < 0 {
                                        signer.balance = signer
                                            .balance
                                            .checked_sub(mag)
                                            .ok_or(ExecutionError::Overflow)?;
                                        ledger
                                            .add_shielded_value(mag)
                                            .ok_or(ExecutionError::Overflow)?;
                                    } else if vb > 0 {
                                        ledger
                                            .sub_shielded_value(mag)
                                            .ok_or(ExecutionError::Overflow)?;
                                        signer.balance = signer
                                            .balance
                                            .checked_add(mag)
                                            .ok_or(ExecutionError::Overflow)?;
                                        // Account the de-shield against the window.
                                        if let Some((start, spent)) = window_update {
                                            ledger.set_deshield_window(start, spent);
                                        }
                                    }
                                    ExecutionStatus::Success
                                }
                            }
                        }
                    }
                }
            }
            Action::HtlcLock {
                recipient,
                amount,
                hashlock,
                timeout_height,
            } => {
                // Escrow `amount` from the signer into a new HTLC keyed by this
                // transaction's id. Validate the debit before mutating anything.
                match signer.balance.checked_sub(*amount) {
                    None => ExecutionStatus::Failed {
                        reason: "insufficient balance".into(),
                    },
                    Some(remaining) => {
                        let htlc = Htlc {
                            locker: tx.signer.clone(),
                            recipient: recipient.clone(),
                            amount: *amount,
                            hashlock: *hashlock,
                            timeout_height: *timeout_height,
                        };
                        match ledger.lock_htlc(stx.id(), htlc) {
                            None => ExecutionStatus::Failed {
                                reason: "duplicate HTLC or escrow overflow".into(),
                            },
                            Some(()) => {
                                signer.balance = remaining;
                                ExecutionStatus::Success
                            }
                        }
                    }
                }
            }
            Action::HtlcClaim { htlc_id, preimage } => {
                // The recipient claims by revealing a preimage matching the hashlock,
                // before the timeout. Revealing it on-chain is what unlocks the
                // counterparty's side of the atomic swap.
                match ledger.htlc(htlc_id).cloned() {
                    None => ExecutionStatus::Failed {
                        reason: "no such HTLC".into(),
                    },
                    Some(htlc) if tx.signer != htlc.recipient => ExecutionStatus::Failed {
                        reason: "only the recipient may claim".into(),
                    },
                    Some(htlc) if ctx.height >= htlc.timeout_height => ExecutionStatus::Failed {
                        reason: "HTLC has timed out".into(),
                    },
                    Some(htlc) if sha256(preimage) != htlc.hashlock => ExecutionStatus::Failed {
                        reason: "preimage does not match hashlock".into(),
                    },
                    Some(htlc) => {
                        ledger.settle_htlc(htlc_id);
                        signer.balance = signer
                            .balance
                            .checked_add(htlc.amount)
                            .ok_or(ExecutionError::Overflow)?;
                        ExecutionStatus::Success
                    }
                }
            }
            Action::HtlcRefund { htlc_id } => {
                // The locker reclaims the escrow once the timeout has passed.
                match ledger.htlc(htlc_id).cloned() {
                    None => ExecutionStatus::Failed {
                        reason: "no such HTLC".into(),
                    },
                    Some(htlc) if tx.signer != htlc.locker => ExecutionStatus::Failed {
                        reason: "only the locker may refund".into(),
                    },
                    Some(htlc) if ctx.height < htlc.timeout_height => ExecutionStatus::Failed {
                        reason: "HTLC has not timed out yet".into(),
                    },
                    Some(htlc) => {
                        ledger.settle_htlc(htlc_id);
                        signer.balance = signer
                            .balance
                            .checked_add(htlc.amount)
                            .ok_or(ExecutionError::Overflow)?;
                        ExecutionStatus::Success
                    }
                }
            }
            Action::TokenIssue { symbol, amount, to } => {
                // The asset id is DERIVED from (signer, symbol), so only the signer
                // can ever reach this id — issuance authorization is enforced by
                // Blake3 collision resistance, not a registry. Unlike SOV (whose
                // 21M cap makes overflow unreachable), a token's cumulative
                // issuance can genuinely approach u128::MAX, so overflow here is a
                // graceful action failure — it can never invalidate a block.
                if !valid_token_symbol(symbol) {
                    ExecutionStatus::Failed {
                        reason: "invalid token symbol (1-16 ASCII alphanumeric bytes)".into(),
                    }
                } else if *amount == Balance::ZERO {
                    ExecutionStatus::Failed {
                        reason: "cannot issue zero".into(),
                    }
                } else if sov_state::token_asset_id(&tx.signer, symbol)
                    == sov_state::vault::xusd_asset_id()
                {
                    // Defense in depth: xUSD is protocol-minted (vault system) only.
                    // Its reserved issuer holds no key, so this is already
                    // unreachable — reject explicitly regardless.
                    ExecutionStatus::Failed {
                        reason: "xUSD is a reserved protocol asset".into(),
                    }
                } else {
                    let asset = sov_state::token_asset_id(&tx.signer, symbol);
                    let mut info = ledger.token(&asset).cloned().unwrap_or(TokenInfo {
                        issuer: tx.signer.clone(),
                        symbol: symbol.clone(),
                        issued: Balance::ZERO,
                        burned: Balance::ZERO,
                    });
                    // Compliance: a paused asset mints nothing; a restricted asset
                    // mints only to permitted recipients. (Minting is incoming for
                    // the recipient, so no velocity window applies.)
                    let compliance_block = ledger.token_policy(&asset).and_then(|policy| {
                        if policy.frozen {
                            Some("compliance: asset is paused".to_string())
                        } else if !policy.transfer_control.permits(to) {
                            Some(format!(
                                "compliance: account {to} is blocked for this asset"
                            ))
                        } else {
                            None
                        }
                    });
                    // Defense in depth: the derivation already binds the id to the
                    // signer; a mismatch would mean a Blake3 collision.
                    if info.issuer != tx.signer {
                        ExecutionStatus::Failed {
                            reason: "asset is bound to a different issuer".into(),
                        }
                    } else if let Some(reason) = compliance_block {
                        ExecutionStatus::Failed { reason }
                    } else {
                        let recipient_balance = ledger.token_balance(&asset, to);
                        match (
                            info.issued.checked_add(*amount),
                            recipient_balance.checked_add(*amount),
                        ) {
                            (Some(issued), Some(credited)) => {
                                info.issued = issued;
                                ledger.set_token(asset, info);
                                ledger.set_token_balance(&asset, to, credited);
                                ExecutionStatus::Success
                            }
                            _ => ExecutionStatus::Failed {
                                reason: "token supply overflow".into(),
                            },
                        }
                    }
                }
            }
            Action::TokenTransfer { asset, to, amount } => {
                // Resolve a `.sov` name to the owner's safe account (an SNS alias); an
                // implicit id / existing / fresh account passes through unchanged.
                let dest = resolve_recipient(ledger, to);
                let to = &dest;
                // Token transfers obey the exact discipline of native transfers:
                // validate fully (compliance gate first, then funds), then apply
                // atomically with checked arithmetic. The velocity window is
                // persisted only together with the movement it accounts for.
                match ledger.token(asset) {
                    None => ExecutionStatus::Failed {
                        reason: "no such asset".into(),
                    },
                    Some(_) => {
                        match check_token_outgoing(
                            ledger, asset, &tx.signer, to, *amount, ctx.height,
                        ) {
                            Err(reason) => ExecutionStatus::Failed { reason },
                            Ok(window) => {
                                let sender_balance = ledger.token_balance(asset, &tx.signer);
                                match sender_balance.checked_sub(*amount) {
                                    None => ExecutionStatus::Failed {
                                        reason: "insufficient token balance".into(),
                                    },
                                    Some(remaining) => {
                                        if to == &tx.signer {
                                            // Self-transfer: units stay put; only
                                            // the nonce advanced. No movement, so
                                            // no window update either.
                                            ExecutionStatus::Success
                                        } else {
                                            match ledger
                                                .token_balance(asset, to)
                                                .checked_add(*amount)
                                            {
                                                None => ExecutionStatus::Failed {
                                                    reason: "token balance overflow".into(),
                                                },
                                                Some(credited) => {
                                                    ledger.set_token_balance(
                                                        asset, &tx.signer, remaining,
                                                    );
                                                    ledger.set_token_balance(asset, to, credited);
                                                    if let Some(w) = window {
                                                        ledger
                                                            .set_token_window(asset, &tx.signer, w);
                                                    }
                                                    ExecutionStatus::Success
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            Action::TokenBurn { asset, amount } => {
                // Any holder may burn their own units; the burn is recorded in the
                // asset's monotonic counter so supply (issued − burned) shrinks by
                // exactly the burned amount — the redemption path for
                // reserve-backed assets. A burn is an outgoing movement, so the
                // compliance gate (freeze, account block, velocity) applies with
                // the sender as its own counterparty.
                match ledger.token(asset).cloned() {
                    None => ExecutionStatus::Failed {
                        reason: "no such asset".into(),
                    },
                    Some(mut info) => match check_token_outgoing(
                        ledger, asset, &tx.signer, &tx.signer, *amount, ctx.height,
                    ) {
                        Err(reason) => ExecutionStatus::Failed { reason },
                        Ok(window) => {
                            let holder_balance = ledger.token_balance(asset, &tx.signer);
                            match holder_balance.checked_sub(*amount) {
                                None => ExecutionStatus::Failed {
                                    reason: "insufficient token balance".into(),
                                },
                                Some(remaining) => {
                                    // burned' = burned + amount ≤ burned + sum(balances)
                                    // = issued, so this cannot overflow on a valid
                                    // ledger; checked anyway.
                                    match info.burned.checked_add(*amount) {
                                        None => ExecutionStatus::Failed {
                                            reason: "token burn overflow".into(),
                                        },
                                        Some(burned) => {
                                            info.burned = burned;
                                            ledger.set_token(*asset, info);
                                            ledger.set_token_balance(asset, &tx.signer, remaining);
                                            if let Some(w) = window {
                                                ledger.set_token_window(asset, &tx.signer, w);
                                            }
                                            ExecutionStatus::Success
                                        }
                                    }
                                }
                            }
                        }
                    },
                }
            }
            Action::IntentSettle { settlement } => {
                let intent = &settlement.intent.intent;
                let intent_id = intent.id();
                // Authorization is DOUBLE: the solver authorizes by signing this
                // transaction (already verified above); the owner authorized by
                // signing the intent, and that signature must verify against the
                // owner account's REGISTERED on-chain key — an intent naming an
                // account but signed by any other key is a forgery and dies here.
                if settlement.solver != tx.signer {
                    ExecutionStatus::Failed {
                        reason: "only the settlement's named solver may submit it".into(),
                    }
                } else if intent.owner == tx.signer {
                    ExecutionStatus::Failed {
                        reason: "an owner cannot fill their own intent".into(),
                    }
                } else if ledger.account(&intent.owner).key != Some(intent.public_key) {
                    ExecutionStatus::Failed {
                        reason: "intent key is not the owner account's registered key".into(),
                    }
                } else if !settlement.intent.verify() {
                    ExecutionStatus::Failed {
                        reason: "invalid intent signature".into(),
                    }
                } else if ctx.height > intent.expiry_height {
                    ExecutionStatus::Failed {
                        reason: "intent has expired".into(),
                    }
                } else if ledger.intent_consumed(&intent_id) {
                    ExecutionStatus::Failed {
                        reason: "intent already settled or cancelled".into(),
                    }
                } else if intent.give_asset == intent.want_asset {
                    ExecutionStatus::Failed {
                        reason: "degenerate swap: give and want assets are identical".into(),
                    }
                } else if settlement.deliver_amount < intent.min_receive {
                    ExecutionStatus::Failed {
                        reason: "delivery is below the intent's minimum".into(),
                    }
                } else {
                    match settle_intent_legs(
                        ledger,
                        &mut signer,
                        &tx.signer,
                        settlement,
                        ctx.height,
                    )? {
                        Err(reason) => ExecutionStatus::Failed { reason },
                        Ok(()) => {
                            ledger.consume_intent(intent_id);
                            ExecutionStatus::Success
                        }
                    }
                }
            }
            Action::IntentCancel { intent } => {
                // Only the owner can take their own intent off the table; the id
                // binds to the exact signed terms, so cancellation is precise.
                if intent.owner != tx.signer {
                    ExecutionStatus::Failed {
                        reason: "only the intent's owner may cancel it".into(),
                    }
                } else if ledger.intent_consumed(&intent.id()) {
                    ExecutionStatus::Failed {
                        reason: "intent already settled or cancelled".into(),
                    }
                } else {
                    ledger.consume_intent(intent.id());
                    ExecutionStatus::Success
                }
            }
            Action::RotateKey { new_key, proof } => {
                // The current key already authorized this transaction (the
                // signature/authorization gates above), so only the present owner
                // reaches here. The NEW key must prove possession by signing the
                // domain-tagged rotation message bound to (signer, nonce) — an
                // account can never be rotated to a key nobody holds, and the
                // proof is single-use. The old key is dead on commit.
                let msg = sov_types::rotation_signing_bytes(&tx.signer, tx_nonce, new_key);
                if !new_key.verify(&msg, proof) {
                    ExecutionStatus::Failed {
                        reason: "rotation proof does not verify under the new key".into(),
                    }
                } else {
                    signer.key = Some(*new_key);
                    ExecutionStatus::Success
                }
            }
            Action::TokenSetPolicy { asset, policy } => {
                // The regulated-issuance path: ONLY the asset's issuer may install
                // or replace its compliance policy — the same hash binding that
                // authorizes minting (Theorem 19) authorizes regulation. The
                // policy's list size is bounded explicitly (it is committed state)
                // and priced per entry in gas.
                match ledger.token(asset) {
                    None => ExecutionStatus::Failed {
                        reason: "no such asset".into(),
                    },
                    Some(info) if info.issuer != tx.signer => ExecutionStatus::Failed {
                        reason: "only the asset's issuer may set its compliance policy".into(),
                    },
                    Some(_) if crate::gas::policy_entries(policy) as usize > MAX_POLICY_ENTRIES => {
                        ExecutionStatus::Failed {
                            reason: format!(
                                "compliance policy exceeds {MAX_POLICY_ENTRIES} list entries"
                            ),
                        }
                    }
                    Some(_) => {
                        ledger.set_token_policy(*asset, policy.clone());
                        ExecutionStatus::Success
                    }
                }
            }
            Action::RegisterName { name } => {
                // ENS/SNS-style claim: bind a human-readable `*.sov` name to the
                // signer's account so it *resolves* to that account. The signer's
                // funds never move — the name is a pure alias.
                match AccountId::new(name) {
                    Err(_) => ExecutionStatus::Failed {
                        reason: "invalid name".into(),
                    },
                    Ok(id) if !id.is_registrable_name() => ExecutionStatus::Failed {
                        reason: "name must be a *.sov id, not a 64-hex implicit id".into(),
                    },
                    Ok(id) if ledger.name_taken(name) => {
                        // First-come: a registered name cannot be re-registered.
                        let _ = id;
                        ExecutionStatus::Failed {
                            reason: "name already registered".into(),
                        }
                    }
                    Ok(id) if ledger.exists(&id) => ExecutionStatus::Failed {
                        // Never let a name shadow an existing account (a genesis
                        // reserve/tax account, or any account already holding state).
                        reason: "name shadows an existing account".into(),
                    },
                    Ok(_) => {
                        // Charge the one-time anti-squat registration fee. It is added
                        // to fee_paid, so distribute_fee splits it to the miner
                        // (treasury/dev get their standing cut) — value-conserving, not
                        // burned. Paid on top of the gas fee already reserved above.
                        let reg_fee = Balance::from_grains(NAME_REGISTRATION_FEE_GRAINS);
                        match signer.balance.checked_sub(reg_fee) {
                            None => ExecutionStatus::Failed {
                                reason: "cannot afford the name registration fee".into(),
                            },
                            Some(remaining) => {
                                signer.balance = remaining;
                                fee_paid = fee_paid
                                    .checked_add(reg_fee)
                                    .ok_or(ExecutionError::Overflow)?;
                                // Resolves to the signer's own account.
                                ledger.register_name(name.clone(), tx.signer.clone(), ctx.height);
                                ExecutionStatus::Success
                            }
                        }
                    }
                }
            }
            Action::TransferName { name, to } => {
                // Reassign a name the signer owns to `to` (a transfer/sale). Only the
                // current owner may transfer; afterwards the name resolves to `to`.
                let current_owner = ledger.name_record(name).map(|r| r.owner.clone());
                match current_owner {
                    None => ExecutionStatus::Failed {
                        reason: "no such registered name".into(),
                    },
                    Some(owner) if owner != tx.signer => ExecutionStatus::Failed {
                        reason: "only the name's owner may transfer it".into(),
                    },
                    Some(_) => {
                        ledger.transfer_name(name, to.clone());
                        ExecutionStatus::Success
                    }
                }
            }
            Action::NftMint {
                symbol,
                token_id,
                to,
                metadata,
            } => {
                // Mint a unique NFT into the signer's collection `symbol`. The first
                // mint binds the signer as the collection's immutable issuer (by the
                // id derivation); non-fungibility rejects a duplicate item.
                let symbol_ok = (1..=32).contains(&symbol.len())
                    && symbol.bytes().all(|b| b.is_ascii_graphic());
                if !symbol_ok {
                    ExecutionStatus::Failed {
                        reason: "nft collection symbol must be 1–32 printable ASCII bytes".into(),
                    }
                } else {
                    let class_id = sov_state::nft_class_id(&tx.signer, symbol);
                    let existing = ledger.nft_class(&class_id).cloned();
                    if existing.as_ref().is_some_and(|c| c.issuer != tx.signer) {
                        ExecutionStatus::Failed {
                            reason: "only the collection's issuer may mint into it".into(),
                        }
                    } else {
                        match ledger.mint_nft(
                            class_id,
                            token_id.clone(),
                            to.clone(),
                            metadata.clone(),
                            ctx.height,
                        ) {
                            None => ExecutionStatus::Failed {
                                reason: "nft item already exists".into(),
                            },
                            Some(()) => {
                                let class = existing.unwrap_or(sov_state::NftClass {
                                    issuer: tx.signer.clone(),
                                    symbol: symbol.clone(),
                                    minted: 0,
                                });
                                let minted = class.minted.saturating_add(1);
                                ledger.set_nft_class(
                                    class_id,
                                    sov_state::NftClass { minted, ..class },
                                );
                                ExecutionStatus::Success
                            }
                        }
                    }
                }
            }
            Action::NftTransfer {
                collection,
                token_id,
                to,
            } => match ledger.nft_owner(collection, token_id) {
                None => ExecutionStatus::Failed {
                    reason: "no such nft".into(),
                },
                Some(owner) if owner != tx.signer => ExecutionStatus::Failed {
                    reason: "only the nft's owner may transfer it".into(),
                },
                Some(_) => {
                    ledger.transfer_nft(*collection, token_id, to.clone());
                    ExecutionStatus::Success
                }
            },
            Action::NftSetMeta {
                collection,
                token_id,
                metadata,
            } => match ledger.nft_owner(collection, token_id) {
                None => ExecutionStatus::Failed {
                    reason: "no such nft".into(),
                },
                Some(owner) if owner != tx.signer => ExecutionStatus::Failed {
                    reason: "only the nft's owner may set its metadata".into(),
                },
                Some(_) => {
                    ledger.set_nft_meta(*collection, token_id, metadata.clone());
                    ExecutionStatus::Success
                }
            },
            Action::SetMultisig { signers, threshold } => {
                // Opt into (or, when wrapped in MultisigExec, replace) M-of-N control.
                // Validate the policy: 1..=MAX signers, all distinct, 1 ≤ M ≤ N.
                let n = signers.len();
                let distinct = (0..n).all(|i| !signers[..i].contains(&signers[i]));
                if n == 0 || n > MAX_MULTISIG_SIGNERS {
                    ExecutionStatus::Failed {
                        reason: format!(
                            "multisig: signer count {n} out of range 1..={MAX_MULTISIG_SIGNERS}"
                        ),
                    }
                } else if !distinct {
                    ExecutionStatus::Failed {
                        reason: "multisig: signer keys must be distinct".into(),
                    }
                } else if *threshold == 0 || *threshold as usize > n {
                    ExecutionStatus::Failed {
                        reason: format!("multisig: threshold {threshold} out of range 1..={n}"),
                    }
                } else {
                    ledger.set_multisig(
                        tx.signer.clone(),
                        sov_state::Multisig {
                            signers: signers.clone(),
                            threshold: *threshold,
                        },
                    );
                    // SECURITY (H1): a pending proposal's approvals are stored as signer
                    // INDICES into the policy active when each was cast. Changing the
                    // policy here would silently remap those indices onto the NEW signer
                    // set (or a lowered threshold), so approvals given under the old
                    // policy would authorize a spend under the new one — signers who never
                    // approved. Invalidate every pending proposal for this account so an
                    // approval can never cross a policy change; members re-propose under
                    // the new policy.
                    ledger.remove_proposals_for(&tx.signer);
                    ExecutionStatus::Success
                }
            }
            // Unreachable: a MultisigExec was unwrapped to its inner action above; this
            // arm only satisfies exhaustiveness.
            Action::MultisigExec { .. } => ExecutionStatus::Failed {
                reason: "multisig: nested MultisigExec is not allowed".into(),
            },
            // ── On-chain multisig coordination ───────────────────────────────────
            // The member is `tx.signer` (their own key/nonce/fee); their signature on
            // this very transaction IS their approval. The vault is named in `account`.
            Action::ProposeMultisig { account, action } => {
                match ledger.multisig_of(account).cloned() {
                    None => ExecutionStatus::Failed {
                        reason: "multisig: account has no multisig policy".into(),
                    },
                    Some(policy) => {
                        let member = policy.signers.iter().position(|k| *k == tx.public_key);
                        let inner = action.as_ref();
                        match member {
                            None => ExecutionStatus::Failed {
                                reason: "multisig: signer is not a policy member".into(),
                            },
                            Some(_) if !is_proposable(inner) => ExecutionStatus::Failed {
                                reason: "multisig: only a Transfer can be proposed".into(),
                            },
                            Some(idx) => {
                                let action_bytes = borsh::to_vec(inner)
                                    .expect("Action serialization is infallible");
                                let key_bytes = borsh::to_vec(&tx.public_key)
                                    .expect("PublicKey serialization is infallible");
                                let id = proposal_id(account, &key_bytes, tx_nonce, &action_bytes);
                                let prop = sov_state::MultisigProposal {
                                    account: account.clone(),
                                    action: action_bytes,
                                    approvers: vec![idx as u16],
                                };
                                // Threshold already met (e.g. 1-of-N) → execute now,
                                // never stored; otherwise store it pending.
                                if (prop.approvers.len() as u16) >= policy.threshold {
                                    execute_proposal_action(ledger, account, inner)?
                                } else {
                                    ledger.set_proposal(id, prop);
                                    ExecutionStatus::Success
                                }
                            }
                        }
                    }
                }
            }
            Action::ApproveMultisig { account, proposal } => {
                match ledger.multisig_of(account).cloned() {
                    None => ExecutionStatus::Failed {
                        reason: "multisig: account has no multisig policy".into(),
                    },
                    Some(policy) => {
                        let member = policy.signers.iter().position(|k| *k == tx.public_key);
                        let existing = ledger.proposal(proposal).cloned();
                        match (member, existing) {
                            (None, _) => ExecutionStatus::Failed {
                                reason: "multisig: signer is not a policy member".into(),
                            },
                            (_, None) => ExecutionStatus::Failed {
                                reason: "multisig: no such pending proposal".into(),
                            },
                            (Some(idx), Some(prop)) if prop.account != *account => {
                                let _ = (idx, prop);
                                ExecutionStatus::Failed {
                                    reason: "multisig: proposal does not belong to this account"
                                        .into(),
                                }
                            }
                            (Some(idx), Some(mut prop)) => {
                                let idx = idx as u16;
                                if !prop.approvers.contains(&idx) {
                                    prop.approvers.push(idx);
                                }
                                if (prop.approvers.len() as u16) >= policy.threshold {
                                    // Enough approvals: execute AS the vault, then clear.
                                    match borsh::from_slice::<Action>(&prop.action) {
                                        Ok(inner) => {
                                            let status =
                                                execute_proposal_action(ledger, account, &inner)?;
                                            ledger.remove_proposal(proposal);
                                            status
                                        }
                                        Err(_) => ExecutionStatus::Failed {
                                            reason: "multisig: corrupt stored proposal".into(),
                                        },
                                    }
                                } else {
                                    ledger.set_proposal(*proposal, prop);
                                    ExecutionStatus::Success
                                }
                            }
                        }
                    }
                }
            }
            Action::CancelMultisig { account, proposal } => {
                let is_member = ledger
                    .multisig_of(account)
                    .map(|p| p.signers.contains(&tx.public_key))
                    .unwrap_or(false);
                let belongs = ledger
                    .proposal(proposal)
                    .map(|p| p.account == *account)
                    .unwrap_or(false);
                if !is_member {
                    ExecutionStatus::Failed {
                        reason: "multisig: signer is not a policy member".into(),
                    }
                } else if !belongs {
                    ExecutionStatus::Failed {
                        reason: "multisig: no such pending proposal".into(),
                    }
                } else {
                    ledger.remove_proposal(proposal);
                    ExecutionStatus::Success
                }
            }
            Action::VaultDeposit { amount } => {
                // Lock XUS from the signer's liquid balance into their vault as
                // collateral. Supply-neutral: the value moves out of the account
                // into the vault-collateral counter (still counted in total supply).
                if *amount == Balance::ZERO {
                    ExecutionStatus::Failed {
                        reason: "cannot deposit zero".into(),
                    }
                } else {
                    match signer.balance.checked_sub(*amount) {
                        None => ExecutionStatus::Failed {
                            reason: "insufficient balance".into(),
                        },
                        Some(remaining) => {
                            let mut vault = ledger.vault(&tx.signer);
                            match vault.collateral.checked_add(*amount) {
                                None => ExecutionStatus::Failed {
                                    reason: "vault collateral overflow".into(),
                                },
                                Some(collateral) => {
                                    vault.collateral = collateral;
                                    signer.balance = remaining;
                                    ledger.set_vault(&tx.signer, vault);
                                    ExecutionStatus::Success
                                }
                            }
                        }
                    }
                }
            }
            Action::VaultWithdraw { amount } => {
                // Release collateral back to the liquid balance, but only while the
                // vault stays at/above the minimum collateral ratio afterward.
                if *amount == Balance::ZERO {
                    ExecutionStatus::Failed {
                        reason: "cannot withdraw zero".into(),
                    }
                } else {
                    let mut vault = ledger.vault(&tx.signer);
                    match vault.collateral.checked_sub(*amount) {
                        None => ExecutionStatus::Failed {
                            reason: "vault holds less collateral than requested".into(),
                        },
                        Some(remaining_collateral) => {
                            let price = ledger.oracle_price();
                            if !sov_state::vault::is_healthy(
                                remaining_collateral,
                                vault.debt,
                                price,
                            ) {
                                ExecutionStatus::Failed {
                                    reason: "withdrawal would under-collateralize the vault".into(),
                                }
                            } else {
                                match signer.balance.checked_add(*amount) {
                                    None => ExecutionStatus::Failed {
                                        reason: "balance overflow".into(),
                                    },
                                    Some(balance) => {
                                        vault.collateral = remaining_collateral;
                                        signer.balance = balance;
                                        ledger.set_vault(&tx.signer, vault);
                                        ExecutionStatus::Success
                                    }
                                }
                            }
                        }
                    }
                }
            }
            Action::VaultMint { amount } => {
                // Mint xUSD against the vault's collateral, up to the minimum ratio
                // at the current oracle price. xUSD is a native asset, so this obeys
                // the per-asset conservation theorem automatically.
                if *amount == Balance::ZERO {
                    ExecutionStatus::Failed {
                        reason: "cannot mint zero".into(),
                    }
                } else {
                    let mut vault = ledger.vault(&tx.signer);
                    let price = ledger.oracle_price();
                    match vault.debt.checked_add(*amount) {
                        None => ExecutionStatus::Failed {
                            reason: "vault debt overflow".into(),
                        },
                        Some(new_debt) => {
                            if !sov_state::vault::is_healthy(vault.collateral, new_debt, price) {
                                ExecutionStatus::Failed {
                                    reason:
                                        "insufficient collateral: mint would breach the 150% ratio"
                                            .into(),
                                }
                            } else {
                                let asset = sov_state::vault::xusd_asset_id();
                                let issuer = AccountId::new(sov_state::vault::XUSD_ISSUER)
                                    .expect("reserved xUSD issuer id is valid");
                                let mut info = ledger.token(&asset).cloned().unwrap_or(TokenInfo {
                                    issuer,
                                    symbol: sov_state::vault::XUSD_SYMBOL.to_string(),
                                    issued: Balance::ZERO,
                                    burned: Balance::ZERO,
                                });
                                let bal = ledger.token_balance(&asset, &tx.signer);
                                match (info.issued.checked_add(*amount), bal.checked_add(*amount)) {
                                    (Some(issued), Some(credited)) => {
                                        info.issued = issued;
                                        vault.debt = new_debt;
                                        ledger.set_token(asset, info);
                                        ledger.set_token_balance(&asset, &tx.signer, credited);
                                        ledger.set_vault(&tx.signer, vault);
                                        ExecutionStatus::Success
                                    }
                                    _ => ExecutionStatus::Failed {
                                        reason: "xUSD supply overflow".into(),
                                    },
                                }
                            }
                        }
                    }
                }
            }
            Action::VaultBurn { amount } => {
                // Repay xUSD debt by burning the signer's xUSD, freeing the vault to
                // release collateral later. Burns real xUSD supply.
                if *amount == Balance::ZERO {
                    ExecutionStatus::Failed {
                        reason: "cannot burn zero".into(),
                    }
                } else {
                    let asset = sov_state::vault::xusd_asset_id();
                    let bal = ledger.token_balance(&asset, &tx.signer);
                    let mut vault = ledger.vault(&tx.signer);
                    match (bal.checked_sub(*amount), vault.debt.checked_sub(*amount)) {
                        (None, _) => ExecutionStatus::Failed {
                            reason: "insufficient xUSD balance to burn".into(),
                        },
                        (_, None) => ExecutionStatus::Failed {
                            reason: "repaying more than the vault's debt".into(),
                        },
                        (Some(remaining_bal), Some(new_debt)) => {
                            match ledger.token(&asset).cloned() {
                                None => ExecutionStatus::Failed {
                                    reason: "no xUSD outstanding".into(),
                                },
                                Some(mut info) => match info.burned.checked_add(*amount) {
                                    None => ExecutionStatus::Failed {
                                        reason: "xUSD burn overflow".into(),
                                    },
                                    Some(burned) => {
                                        info.burned = burned;
                                        vault.debt = new_debt;
                                        ledger.set_token(asset, info);
                                        ledger.set_token_balance(&asset, &tx.signer, remaining_bal);
                                        ledger.set_vault(&tx.signer, vault);
                                        ExecutionStatus::Success
                                    }
                                },
                            }
                        }
                    }
                }
            }
            Action::OracleUpdate { price } => {
                // Only the authorized price feed may publish; every other signer is
                // rejected. A zero price is nonsensical (would divide by zero).
                let oracle = AccountId::new(sov_state::vault::ORACLE_ACCOUNT)
                    .expect("oracle account id is valid");
                if tx.signer != oracle {
                    ExecutionStatus::Failed {
                        reason: "oracle: only the authorized price feed may publish".into(),
                    }
                } else if *price == 0 {
                    ExecutionStatus::Failed {
                        reason: "oracle: price must be positive".into(),
                    }
                } else {
                    ledger.set_oracle_price(*price);
                    ExecutionStatus::Success
                }
            }
        }
    };

    ledger.set_account(&tx.signer, signer);
    // Distribute the fee now that the signer's debit is committed: burn the base
    // fraction (deflationary) and split the rest between the block's miner and
    // proposer. Reads are fresh, so self-crediting and miner==proposer aliasing
    // are handled correctly.
    distribute_fee(ledger, ctx, fee_paid)?;
    Ok(Receipt {
        tx_id: stx.id(),
        status,
        gas_used,
        return_data,
        events,
    })
}

/// Validate and apply a contract's queued token-transfer commands: each moves
/// units of an existing asset from the **contract's own balance** to a named
/// recipient, gated by the asset's compliance policy exactly like a user
/// transfer (the contract is the sender; its velocity window accumulates
/// across the batch). Validation is all-or-nothing — every command is checked
/// against a scratch view (fresh ledger reads overlaid with in-batch updates,
/// so sequential and self-transfers settle exactly) and the ledger is only
/// written once the whole batch is sound. On any failure nothing is committed.
fn settle_contract_token_transfers(
    ledger: &mut Ledger,
    contract: &AccountId,
    cmds: &[sov_vm::TokenTransferCmd],
    height: u64,
) -> Result<(), String> {
    if cmds.is_empty() {
        return Ok(());
    }
    let mut scratch: std::collections::BTreeMap<(Hash, AccountId), u128> =
        std::collections::BTreeMap::new();
    // The contract's in-batch velocity windows, threaded per asset so a batch
    // cannot exceed a limit that each command alone would respect.
    let mut windows: std::collections::BTreeMap<Hash, SpendWindow> =
        std::collections::BTreeMap::new();
    let balance_of = |scratch: &std::collections::BTreeMap<(Hash, AccountId), u128>,
                      ledger: &Ledger,
                      asset: &Hash,
                      who: &AccountId| {
        scratch
            .get(&(*asset, who.clone()))
            .copied()
            .unwrap_or_else(|| ledger.token_balance(asset, who).grains())
    };
    for cmd in cmds {
        let asset = Hash::from_bytes(cmd.asset);
        if ledger.token(&asset).is_none() {
            return Err("contract token transfer names no such asset".into());
        }
        let to = AccountId::new(&cmd.to)
            .map_err(|_| String::from("contract token transfer names an invalid account"))?;
        // Compliance gate, identical to a user-initiated transfer, over the
        // batch-threaded window.
        if let Some(policy) = ledger.token_policy(&asset) {
            if !policy.transfer_control.permits(contract) {
                return Err(format!(
                    "compliance: account {contract} is blocked for this asset"
                ));
            }
            let window = windows
                .get(&asset)
                .copied()
                .unwrap_or_else(|| ledger.token_window(&asset, contract));
            let updated = policy
                .check_transfer(&to, Balance::from_grains(cmd.amount), height, &window)
                .map_err(|e| format!("compliance: {e}"))?;
            windows.insert(asset, updated);
        }
        let from_balance = balance_of(&scratch, ledger, &asset, contract);
        let remaining = from_balance
            .checked_sub(cmd.amount)
            .ok_or_else(|| String::from("contract token balance insufficient"))?;
        scratch.insert((asset, contract.clone()), remaining);
        // Read AFTER the debit landed in scratch, so a self-transfer nets to
        // exactly zero rather than double-counting.
        let to_balance = balance_of(&scratch, ledger, &asset, &to);
        let credited = to_balance
            .checked_add(cmd.amount)
            .ok_or_else(|| String::from("token balance overflow"))?;
        scratch.insert((asset, to), credited);
    }
    for ((asset, who), grains) in scratch {
        ledger.set_token_balance(&asset, &who, Balance::from_grains(grains));
    }
    for (asset, window) in windows {
        ledger.set_token_window(&asset, contract, window);
    }
    Ok(())
}

/// Pay `fee` to the block's miner. There is no tax and **nothing is burned** —
/// every grain of every fee goes to whoever found the block (pure Nakamoto). A
/// no-op when `fee` is zero.
fn distribute_fee(
    ledger: &mut Ledger,
    ctx: &BlockContext<'_>,
    fee: Balance,
) -> Result<(), ExecutionError> {
    credit(ledger, &ctx.miner, fee)
}

/// Credit `amount` to `id`'s liquid balance (a fresh read-modify-write).
fn credit(ledger: &mut Ledger, id: &AccountId, amount: Balance) -> Result<(), ExecutionError> {
    if amount == Balance::ZERO {
        return Ok(());
    }
    let mut account = ledger.account(id);
    account.balance = account
        .balance
        .checked_add(amount)
        .ok_or(ExecutionError::Overflow)?;
    ledger.set_account(id, account);
    Ok(())
}

/// The native-SOV transfer primitive, parameterized by the paying account, so it
/// serves both a normal `Transfer` (from = the tx signer) and an executed multisig
/// proposal (from = the vault). `from_acct` is the loaded, mutable account of `from`;
/// the caller commits it. Resolves a `.sov` recipient, checks the balance, and on
/// success debits `from_acct` and credits the recipient. Byte-identical to the
/// original inline `Transfer` arm.
fn do_transfer(
    ledger: &mut Ledger,
    from: &AccountId,
    from_acct: &mut sov_state::Account,
    to: &AccountId,
    amount: Balance,
) -> Result<ExecutionStatus, ExecutionError> {
    let dest = resolve_recipient(ledger, to);
    let to = &dest;
    match from_acct.balance.checked_sub(amount) {
        None => Ok(ExecutionStatus::Failed {
            reason: "insufficient balance".into(),
        }),
        Some(remaining) => {
            if to == from {
                // Self-transfer: funds stay put.
                Ok(ExecutionStatus::Success)
            } else {
                let mut recipient = ledger.account(to);
                match recipient.balance.checked_add(amount) {
                    None => Err(ExecutionError::Overflow),
                    Some(credited) => {
                        from_acct.balance = remaining;
                        recipient.balance = credited;
                        ledger.set_account(to, recipient);
                        Ok(ExecutionStatus::Success)
                    }
                }
            }
        }
    }
}

/// Whether `action` may be carried by an on-chain multisig proposal. v1 supports
/// native-SOV transfers (the core vault use — a treasury or shared account paying
/// out); arbitrary actions remain available via the legacy `MultisigExec` path.
fn is_proposable(action: &Action) -> bool {
    matches!(action, Action::Transfer { .. })
}

/// Deterministic id for a new proposal: domain-separated over the vault account, the
/// proposer's key + nonce (globally unique ⇒ no collision), and the encoded action.
/// Reproducible in replay (no dependency on the tx wrapper).
fn proposal_id(
    account: &AccountId,
    proposer_key: &[u8],
    proposer_nonce: u64,
    action_bytes: &[u8],
) -> Hash {
    let mut buf = Vec::new();
    buf.extend_from_slice(b"sov:msprop:v1");
    buf.push(0x00);
    buf.extend_from_slice(account.as_str().as_bytes());
    buf.push(0x00);
    buf.extend_from_slice(proposer_key);
    buf.extend_from_slice(&proposer_nonce.to_le_bytes());
    buf.extend_from_slice(action_bytes);
    Hash::digest(&buf)
}

/// Execute a pending proposal's stored action AS the vault `account` (load the vault,
/// run the value transfer, commit it). Only [`is_proposable`] actions reach here.
fn execute_proposal_action(
    ledger: &mut Ledger,
    account: &AccountId,
    action: &Action,
) -> Result<ExecutionStatus, ExecutionError> {
    match action {
        Action::Transfer { to, amount } => {
            let mut vault = ledger.account(account);
            let status = do_transfer(ledger, account, &mut vault, to, *amount)?;
            ledger.set_account(account, vault);
            Ok(status)
        }
        // Defensive: a non-proposable action should never have been stored.
        _ => Ok(ExecutionStatus::Failed {
            reason: "multisig: proposal carries an unsupported action".into(),
        }),
    }
}

/// One settleable leg of an intent swap: native SOV or an existing on-chain
/// asset. (Cross-chain swaps use the trustless HTLC path — there is no
/// committee-attested cross-chain pool.)
enum SettleLeg {
    /// Native SOV.
    Native,
    /// An existing on-chain asset.
    Token(Hash),
}

/// Classify an intent leg into something the ledger can actually settle, or
/// say exactly why it cannot.
fn settle_leg(ledger: &Ledger, asset: sov_intents::Asset) -> Result<SettleLeg, String> {
    match asset {
        sov_intents::Asset::Sov => Ok(SettleLeg::Native),
        sov_intents::Asset::Token(id) => {
            if ledger.token(&id).is_none() {
                Err("intent names a nonexistent asset".into())
            } else {
                Ok(SettleLeg::Token(id))
            }
        }
    }
}

/// Validate and atomically apply both legs of an intent settlement:
/// the owner gives `give_amount` of `give_asset` to the solver; the solver
/// gives `deliver_amount` of `want_asset` to the owner. Every check — leg
/// classification, compliance gates on both token legs, and funding on both
/// sides — runs **before** any mutation, so the swap is both-or-neither.
/// `signer` is the solver's in-flight account (its fee debit is not yet in
/// the ledger), so the solver's native funds are read and written THROUGH it,
/// never via a stale ledger read.
///
/// Outer `Err` = transaction-level arithmetic overflow on a native credit
/// (unreachable under the 21M cap, checked anyway). Inner `Err` = graceful
/// action failure with the specific reason.
#[allow(clippy::type_complexity)]
fn settle_intent_legs(
    ledger: &mut Ledger,
    signer: &mut sov_state::Account,
    solver: &AccountId,
    settlement: &sov_intents::Settlement,
    height: u64,
) -> Result<Result<(), String>, ExecutionError> {
    let intent = &settlement.intent.intent;
    let owner = &intent.owner;
    let give = Balance::from_grains(intent.give_amount);
    let deliver = Balance::from_grains(settlement.deliver_amount);

    // Classify both legs (External legs are refused with the honest reason).
    let give_leg = match settle_leg(ledger, intent.give_asset) {
        Ok(leg) => leg,
        Err(reason) => return Ok(Err(reason)),
    };
    let want_leg = match settle_leg(ledger, intent.want_asset) {
        Ok(leg) => leg,
        Err(reason) => return Ok(Err(reason)),
    };

    // Compliance gates on both token legs (each is an outgoing movement for
    // its sender), before anything moves.
    let owner_window = match &give_leg {
        SettleLeg::Token(asset) => {
            match check_token_outgoing(ledger, asset, owner, solver, give, height) {
                Ok(w) => w.map(|w| (*asset, w)),
                Err(reason) => return Ok(Err(reason)),
            }
        }
        SettleLeg::Native => None,
    };
    let solver_window = match &want_leg {
        SettleLeg::Token(asset) => {
            match check_token_outgoing(ledger, asset, solver, owner, deliver, height) {
                Ok(w) => w.map(|w| (*asset, w)),
                Err(reason) => return Ok(Err(reason)),
            }
        }
        SettleLeg::Native => None,
    };

    // Funding and post-state computation for all four balance writes, with
    // checked arithmetic — still no mutation.
    let mut owner_acct = ledger.account(owner);
    let owner_native_debited = match &give_leg {
        SettleLeg::Native => match owner_acct.balance.checked_sub(give) {
            None => return Ok(Err("owner cannot cover the given amount".into())),
            Some(b) => Some(b),
        },
        SettleLeg::Token(_) => None,
    };
    let owner_token_debited = match &give_leg {
        SettleLeg::Token(asset) => match ledger.token_balance(asset, owner).checked_sub(give) {
            None => return Ok(Err("owner cannot cover the given amount".into())),
            Some(b) => Some((*asset, b)),
        },
        SettleLeg::Native => None,
    };
    let solver_native_debited = match &want_leg {
        SettleLeg::Native => match signer.balance.checked_sub(deliver) {
            None => return Ok(Err("solver cannot cover the delivered amount".into())),
            Some(b) => Some(b),
        },
        SettleLeg::Token(_) => None,
    };
    let solver_token_debited = match &want_leg {
        SettleLeg::Token(asset) => match ledger.token_balance(asset, solver).checked_sub(deliver) {
            None => return Ok(Err("solver cannot cover the delivered amount".into())),
            Some(b) => Some((*asset, b)),
        },
        SettleLeg::Native => None,
    };
    // Credits. Native credit overflow is unreachable under the cap but
    // rejected rather than assumed; token credit overflow is reachable and
    // fails gracefully.
    let solver_native_credited = match &give_leg {
        SettleLeg::Native => Some(
            signer
                .balance
                .checked_add(give)
                .ok_or(ExecutionError::Overflow)?,
        ),
        SettleLeg::Token(_) => None,
    };
    let solver_token_credited = match &give_leg {
        SettleLeg::Token(asset) => match ledger.token_balance(asset, solver).checked_add(give) {
            None => return Ok(Err("token balance overflow".into())),
            Some(b) => Some((*asset, b)),
        },
        SettleLeg::Native => None,
    };
    let owner_native_credited = match &want_leg {
        SettleLeg::Native => Some(
            owner_acct
                .balance
                .checked_add(deliver)
                .ok_or(ExecutionError::Overflow)?,
        ),
        SettleLeg::Token(_) => None,
    };
    let owner_token_credited = match &want_leg {
        SettleLeg::Token(asset) => match ledger.token_balance(asset, owner).checked_add(deliver) {
            None => return Ok(Err("token balance overflow".into())),
            Some(b) => Some((*asset, b)),
        },
        SettleLeg::Native => None,
    };

    // Every check passed — apply all writes. The two legs touch disjoint
    // (asset, account) cells: give and want assets are distinct by the arm's
    // degenerate-swap gate, and owner ≠ solver by its self-fill gate.
    if let Some(b) = owner_native_debited {
        owner_acct.balance = b;
    }
    if let Some(b) = owner_native_credited {
        owner_acct.balance = b;
    }
    if let Some(b) = solver_native_debited {
        signer.balance = b;
    }
    if let Some(b) = solver_native_credited {
        signer.balance = b;
    }
    ledger.set_account(owner, owner_acct);
    if let Some((asset, b)) = owner_token_debited {
        ledger.set_token_balance(&asset, owner, b);
    }
    if let Some((asset, b)) = solver_token_credited {
        ledger.set_token_balance(&asset, solver, b);
    }
    if let Some((asset, b)) = solver_token_debited {
        ledger.set_token_balance(&asset, solver, b);
    }
    if let Some((asset, b)) = owner_token_credited {
        ledger.set_token_balance(&asset, owner, b);
    }
    if let Some((asset, w)) = owner_window {
        ledger.set_token_window(&asset, owner, w);
    }
    if let Some((asset, w)) = solver_window {
        ledger.set_token_window(&asset, solver, w);
    }
    Ok(Ok(()))
}

/// Whether `symbol` is a well-formed token symbol: 1–16 ASCII alphanumeric
/// bytes. Bounded and unambiguous so asset-id preimages stay canonical.
fn valid_token_symbol(symbol: &str) -> bool {
    (1..=16).contains(&symbol.len()) && symbol.bytes().all(|b| b.is_ascii_alphanumeric())
}

/// Maximum allow/deny-list entries a compliance policy may commit — bounds the
/// state one transaction can install (the entries are also priced per unit of
/// gas, but bounded explicitly rather than by fee economics alone).
const MAX_POLICY_ENTRIES: usize = 1024;

/// The one-time fee to register a name in the on-chain name registry, in grains,
/// charged on top of the transaction's gas fee. Deters name squatting. It is an
/// ordinary fee **earned by miners** (split miner/treasury/dev by
/// [`distribute_fee`], like every fee) — never burned, so the supply invariant is
/// untouched. 1 XUS (10^8 grains).
const NAME_REGISTRATION_FEE_GRAINS: u128 = 100_000_000;

/// Maximum signers in a multisig policy (N). Bounds approval-verification work per
/// `MultisigExec` and the policy's committed size. Generous for institutional
/// M-of-N (e.g. a reserve board) while keeping verification cost predictable.
const MAX_MULTISIG_SIGNERS: usize = 32;

/// Resolve a transfer recipient to the account that should actually be credited: a
/// **registered SNS name** resolves to its target account — an `*.sov` alias points at
/// the owner — so a transfer to a name reaches the owner's real (key-bound) account
/// instead of a bare, keyless, squattable name account. An **implicit** id, an
/// already-**existing** account, or a fresh account being created is used unchanged.
/// (This makes "send to alice.sov" land on alice safely, the SNS-handled-better fix.)
fn resolve_recipient(ledger: &Ledger, to: &AccountId) -> AccountId {
    if !to.is_implicit() {
        if let Some(target) = ledger.resolve_name(to.as_str()) {
            return target;
        }
    }
    to.clone()
}

/// Gate an **outgoing** movement of `asset` (a transfer or a burn) against the
/// asset's compliance policy. `counterparty` is the recipient for a transfer
/// and the sender itself for a burn. Returns the updated spend window to
/// persist alongside the movement — `None` when the asset has no policy.
/// Failure reasons name the specific control that blocked the movement.
fn check_token_outgoing(
    ledger: &Ledger,
    asset: &Hash,
    from: &AccountId,
    counterparty: &AccountId,
    amount: Balance,
    height: u64,
) -> Result<Option<SpendWindow>, String> {
    let Some(policy) = ledger.token_policy(asset) else {
        return Ok(None);
    };
    // The sender itself must be permitted (an asset-level deny list blocks an
    // account in both directions, like a reserve-asset address freeze).
    if !policy.transfer_control.permits(from) {
        return Err(format!(
            "compliance: account {from} is blocked for this asset"
        ));
    }
    // Freeze/pause, counterparty control, and spend velocity — the pure
    // decision function from sov-compliance, over the holder's rolling window.
    let window = ledger.token_window(asset, from);
    policy
        .check_transfer(counterparty, amount, height, &window)
        .map(Some)
        .map_err(|e| format!("compliance: {e}"))
}

/// SHA-256 of `data` — the HTLC hashlock primitive. Using SHA-256 (Bitcoin/Zcash
/// `OP_SHA256`) means the *same* preimage unlocks both sides of a cross-chain
/// atomic swap.
fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&hasher.finalize());
    bytes
}

/// Reasons applying a *block* of transactions fails: a block is invalid if it
/// contains any transaction that would be rejected.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BlockExecutionError {
    /// Transaction at `index` was rejected.
    #[error("transaction at index {index} rejected: {source}")]
    InvalidTransaction {
        /// Position of the offending transaction.
        index: usize,
        /// Why it was rejected.
        source: ExecutionError,
    },
    /// The block's coinbase mint failed (only reachable on arithmetic overflow
    /// of the miner's balance or the emission counter).
    #[error("coinbase failed: {source}")]
    Coinbase {
        /// Why the mint failed.
        source: ExecutionError,
    },
}

/// Apply the block's **coinbase** (Nakamoto consensus): mint the scheduled
/// proof-of-work reward to the block's miner (`ctx.miner` — the account named in
/// the header by whoever found the block's proof of work). The reward is the
/// emission schedule evaluated at cumulative *mined* supply, clamped to the
/// mining budget, so issuance halves on schedule and can never exceed its share
/// of the 21M cap. Returns the amount minted (`ZERO` once the budget is spent —
/// the chain then runs on fees alone, exactly like Bitcoin).
///
/// Runs identically in block production, import, and reorg replay, *before* the
/// block's transactions — the coinbase is part of the state transition the
/// header's `state_root` commits to, so a block that lies about its reward
/// cannot validate.
pub fn apply_coinbase(
    ledger: &mut Ledger,
    ctx: &BlockContext<'_>,
) -> Result<Balance, BlockExecutionError> {
    let reward = ctx.mining.reward_at(ctx.height, ledger.mined_emitted());
    if reward == Balance::ZERO {
        return Ok(Balance::ZERO);
    }
    let mint = |l: &mut Ledger| -> Result<(), ExecutionError> {
        // The ENTIRE coinbase goes to the miner — no tax, nothing burned (pure
        // Nakamoto issuance). `mined_emitted` advances by the full reward.
        credit(l, &ctx.miner, reward)?;
        l.add_mined_emitted(reward)
            .ok_or(ExecutionError::Overflow)?;
        Ok(())
    };
    mint(ledger).map_err(|source| BlockExecutionError::Coinbase { source })?;
    Ok(reward)
}

/// Apply an ordered list of transactions, returning one receipt each. Mutates
/// `ledger` in place; on error the ledger may be partially advanced, so callers
/// that need atomicity should apply against a clone and swap on success.
pub fn apply_transactions(
    ledger: &mut Ledger,
    transactions: &[SignedTransaction],
    ctx: &BlockContext<'_>,
) -> Result<Vec<Receipt>, BlockExecutionError> {
    let mut receipts = Vec::with_capacity(transactions.len());
    for (index, stx) in transactions.iter().enumerate() {
        let receipt = apply_transaction(ledger, stx, ctx)
            .map_err(|source| BlockExecutionError::InvalidTransaction { index, source })?;
        receipts.push(receipt);
    }
    Ok(receipts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sov_crypto::Keypair;
    use sov_mining::MiningPolicy;
    use sov_primitives::{AccountId, Balance};
    use sov_state::Account;
    use sov_types::Transaction;

    fn id(s: &str) -> AccountId {
        AccountId::new(s).unwrap()
    }

    /// A test context: empty parent hash and the easy test mining policy.
    fn policy() -> MiningPolicy {
        MiningPolicy::test()
    }
    fn miner_id() -> AccountId {
        id("val01.node.sov")
    }
    fn ctx(p: &MiningPolicy) -> BlockContext<'_> {
        BlockContext {
            height: 0,
            prev_hash: Hash::ZERO,
            mining: p,
            gas_price: Balance::ZERO,
            miner: miner_id(),
            pq: None,
        }
    }
    /// A context at a specific height (for staking/vesting tests).
    fn ctx_at(height: u64, p: &MiningPolicy) -> BlockContext<'_> {
        BlockContext {
            height,
            prev_hash: Hash::ZERO,
            mining: p,
            gas_price: Balance::ZERO,
            miner: miner_id(),
            pq: None,
        }
    }

    /// Build a signed transfer authorized by `seed`'s key.
    fn transfer(seed: [u8; 32], from: &str, to: &str, sov: u128, nonce: u64) -> SignedTransaction {
        let kp = Keypair::from_seed(seed);
        let tx = Transaction {
            signer: id(from),
            public_key: kp.public_key(),
            nonce,
            action: Action::Transfer {
                to: id(to),
                amount: Balance::from_sov(sov).unwrap(),
            },
        };
        SignedTransaction::sign(tx, &kp).unwrap()
    }

    /// A ledger where `usa.reserve.sov` is controlled by key seed `[1; 32]` and
    /// holds `sov` SOV.
    fn ledger_with_usa(sov: u128) -> Ledger {
        let mut ledger = Ledger::new();
        let key = Keypair::from_seed([1; 32]).public_key();
        ledger.set_account(
            &id("usa.reserve.sov"),
            Account::new(key, Balance::from_sov(sov).unwrap()),
        );
        ledger
    }

    #[test]
    fn successful_transfer_moves_funds_and_bumps_nonce() {
        let mut ledger = ledger_with_usa(100);
        let p = policy();
        let stx = transfer([1; 32], "usa.reserve.sov", "ecb.reserve.sov", 30, 0);
        let receipt = apply_transaction(&mut ledger, &stx, &ctx(&p)).unwrap();
        assert!(receipt.succeeded());
        assert_eq!(
            ledger.account(&id("usa.reserve.sov")).balance,
            Balance::from_sov(70).unwrap()
        );
        assert_eq!(
            ledger.account(&id("ecb.reserve.sov")).balance,
            Balance::from_sov(30).unwrap()
        );
        assert_eq!(ledger.account(&id("usa.reserve.sov")).nonce, 1);
    }

    #[test]
    fn shielded_action_shields_value_verifies_proof_and_rejects_replay() {
        use sov_shielded::{mint_to_shielded, ShieldedKey, ShieldedParams};

        let mut ledger = ledger_with_usa(100);
        let supply_before = ledger.total_supply().unwrap();

        // A real shielded bundle moving 50 SOV into the pool (value_balance =
        // -50 SOV). Submitted as a user action, the runtime treats vb<0 as a
        // shield: the signer's transparent balance funds the new shielded note.
        let params = ShieldedParams::build();
        let recipient = ShieldedKey::from_seed([9u8; 32]).unwrap().address();
        let fifty = Balance::from_sov(50).unwrap();
        let bundle =
            mint_to_shielded(&params, &recipient, u64::try_from(fifty.grains()).unwrap()).unwrap();
        assert_eq!(
            bundle.value_balance(),
            -i64::try_from(fifty.grains()).unwrap()
        );

        let kp = Keypair::from_seed([1; 32]);
        let shielded_tx = |nonce: u64, bytes: Vec<u8>| {
            SignedTransaction::sign(
                Transaction {
                    signer: id("usa.reserve.sov"),
                    public_key: kp.public_key(),
                    nonce,
                    action: Action::Shielded { bundle: bytes },
                },
                &kp,
            )
            .unwrap()
        };
        let p = policy();

        // 1. Shield succeeds: the proof verifies, the signer is debited 50 SOV,
        //    the pool grows by 50 SOV, and a note enters the tree.
        let r =
            apply_transaction(&mut ledger, &shielded_tx(0, bundle.to_bytes()), &ctx(&p)).unwrap();
        assert!(r.succeeded(), "valid shield must succeed");
        assert_eq!(
            ledger.account(&id("usa.reserve.sov")).balance,
            Balance::from_sov(50).unwrap()
        );
        assert_eq!(ledger.shielded_value(), fifty);
        assert_eq!(ledger.shielded().note_count(), 1);
        // Supply is conserved: value only moved transparent -> shielded.
        assert_eq!(ledger.total_supply().unwrap(), supply_before);

        // 2. Replaying the identical bundle is a double-spend (its nullifier is
        //    already recorded): the action fails and no value moves.
        let r2 =
            apply_transaction(&mut ledger, &shielded_tx(1, bundle.to_bytes()), &ctx(&p)).unwrap();
        assert!(!r2.succeeded(), "replaying a shielded bundle must fail");
        assert_eq!(
            ledger.account(&id("usa.reserve.sov")).balance,
            Balance::from_sov(50).unwrap()
        );
        assert_eq!(ledger.shielded_value(), fifty);

        // 3. A tampered bundle fails zero-knowledge verification.
        let mut bad = bundle.to_bytes();
        *bad.last_mut().unwrap() ^= 0xff;
        let r3 = apply_transaction(&mut ledger, &shielded_tx(2, bad), &ctx(&p)).unwrap();
        assert!(!r3.succeeded(), "a tampered shielded proof must fail");
    }

    fn signed(seed: [u8; 32], signer: &str, nonce: u64, action: Action) -> SignedTransaction {
        let kp = Keypair::from_seed(seed);
        SignedTransaction::sign(
            Transaction {
                signer: id(signer),
                public_key: kp.public_key(),
                nonce,
                action,
            },
            &kp,
        )
        .unwrap()
    }

    #[test]
    fn xusd_vault_deposit_mint_burn_withdraw_roundtrips_and_conserves_supply() {
        // The full DAI-style CDP loop at the honest $1 seed price: lock 150 XUS,
        // mint exactly 100 xUSD (the 150% ceiling), fail to mint one grain more or
        // withdraw while indebted, then repay and reclaim every XUS — with total
        // SOV supply conserved end-to-end and xUSD's own conservation intact.
        let mut ledger = ledger_with_usa(1000);
        let p = policy();
        let who = id("usa.reserve.sov");
        let xusd = sov_state::vault::xusd_asset_id();
        let supply_before = ledger.total_supply().unwrap();

        // Until the oracle publishes, XUS is priced at the honest $1 seed.
        assert_eq!(ledger.oracle_price(), sov_state::vault::SEED_XUS_USD_PRICE);

        // Deposit 150 XUS as collateral — pure movement, supply-neutral.
        let dep = signed(
            [1; 32],
            "usa.reserve.sov",
            0,
            Action::VaultDeposit {
                amount: Balance::from_sov(150).unwrap(),
            },
        );
        assert!(apply_transaction(&mut ledger, &dep, &ctx(&p))
            .unwrap()
            .succeeded());
        assert_eq!(
            ledger.vault(&who).collateral,
            Balance::from_sov(150).unwrap()
        );
        assert_eq!(ledger.total_supply().unwrap(), supply_before);

        // Mint exactly $100 xUSD (150 XUS × $1 ÷ 150%). One grain more must fail.
        let mint = signed(
            [1; 32],
            "usa.reserve.sov",
            1,
            Action::VaultMint {
                amount: Balance::from_sov(100).unwrap(),
            },
        );
        assert!(apply_transaction(&mut ledger, &mint, &ctx(&p))
            .unwrap()
            .succeeded());
        assert_eq!(
            ledger.token_balance(&xusd, &who),
            Balance::from_sov(100).unwrap()
        );
        let over = signed(
            [1; 32],
            "usa.reserve.sov",
            2,
            Action::VaultMint {
                amount: Balance::from_grains(1),
            },
        );
        assert!(!apply_transaction(&mut ledger, &over, &ctx(&p))
            .unwrap()
            .succeeded());

        // Withdrawing collateral while indebted must fail (would under-collateralize).
        let bad_wd = signed(
            [1; 32],
            "usa.reserve.sov",
            3,
            Action::VaultWithdraw {
                amount: Balance::from_sov(1).unwrap(),
            },
        );
        assert!(!apply_transaction(&mut ledger, &bad_wd, &ctx(&p))
            .unwrap()
            .succeeded());

        // Repay the full 100 xUSD; the asset's supply returns to zero.
        let burn = signed(
            [1; 32],
            "usa.reserve.sov",
            4,
            Action::VaultBurn {
                amount: Balance::from_sov(100).unwrap(),
            },
        );
        assert!(apply_transaction(&mut ledger, &burn, &ctx(&p))
            .unwrap()
            .succeeded());
        assert_eq!(ledger.token_balance(&xusd, &who), Balance::ZERO);
        assert_eq!(ledger.token(&xusd).unwrap().supply(), Some(Balance::ZERO));

        // Now the collateral is free — reclaim all 150 XUS.
        let wd = signed(
            [1; 32],
            "usa.reserve.sov",
            5,
            Action::VaultWithdraw {
                amount: Balance::from_sov(150).unwrap(),
            },
        );
        assert!(apply_transaction(&mut ledger, &wd, &ctx(&p))
            .unwrap()
            .succeeded());
        assert!(ledger.vault(&who).is_empty());
        assert_eq!(
            ledger.account(&who).balance,
            Balance::from_sov(1000).unwrap()
        );
        // Every XUS is accounted for: supply conserved across the whole loop.
        assert_eq!(ledger.total_supply().unwrap(), supply_before);
    }

    #[test]
    fn oracle_update_is_rejected_from_an_unauthorized_signer() {
        // Only the authorized feed may move the price; anyone else is refused and
        // the honest $1 seed stands — no minting against a wished-for price.
        let mut ledger = ledger_with_usa(10);
        let p = policy();
        let bad = signed(
            [1; 32],
            "usa.reserve.sov",
            0,
            Action::OracleUpdate {
                price: 5 * sov_state::vault::SCALE,
            },
        );
        assert!(!apply_transaction(&mut ledger, &bad, &ctx(&p))
            .unwrap()
            .succeeded());
        assert_eq!(ledger.oracle_price(), sov_state::vault::SEED_XUS_USD_PRICE);
    }

    #[test]
    fn htlc_atomic_swap_locks_then_claims_with_the_preimage() {
        // Alice (usa) escrows 50 SOV for Bob behind a SHA-256 hashlock; Bob claims
        // by revealing the preimage before the timeout. This is the SOV half of a
        // trustless cross-chain atomic swap — no custodian.
        let mut ledger = ledger_with_usa(100);
        let bob = Keypair::from_seed([2; 32]);
        ledger.set_account(
            &id("bob.sov"),
            Account::new(bob.public_key(), Balance::ZERO),
        );
        let p = policy();
        let supply_before = ledger.total_supply().unwrap();

        let secret = b"the-shared-atomic-swap-secret";
        let hashlock = sha256(secret);
        let lock = signed(
            [1; 32],
            "usa.reserve.sov",
            0,
            Action::HtlcLock {
                recipient: id("bob.sov"),
                amount: Balance::from_sov(50).unwrap(),
                hashlock,
                timeout_height: 100,
            },
        );
        let htlc_id = lock.id();
        assert!(apply_transaction(&mut ledger, &lock, &ctx_at(10, &p))
            .unwrap()
            .succeeded());
        assert_eq!(
            ledger.account(&id("usa.reserve.sov")).balance,
            Balance::from_sov(50).unwrap(),
            "locker is debited the escrow"
        );
        assert_eq!(ledger.htlc_locked(), Balance::from_sov(50).unwrap());
        assert_eq!(
            ledger.total_supply().unwrap(),
            supply_before,
            "locking is supply-neutral"
        );

        // A wrong preimage fails and moves nothing.
        let bad = signed(
            [2; 32],
            "bob.sov",
            0,
            Action::HtlcClaim {
                htlc_id,
                preimage: b"wrong".to_vec(),
            },
        );
        assert!(!apply_transaction(&mut ledger, &bad, &ctx_at(11, &p))
            .unwrap()
            .succeeded());
        assert_eq!(ledger.account(&id("bob.sov")).balance, Balance::ZERO);
        assert_eq!(ledger.htlc_locked(), Balance::from_sov(50).unwrap());

        // The correct preimage, before the timeout, pays Bob and settles the HTLC.
        let claim = signed(
            [2; 32],
            "bob.sov",
            1,
            Action::HtlcClaim {
                htlc_id,
                preimage: secret.to_vec(),
            },
        );
        assert!(apply_transaction(&mut ledger, &claim, &ctx_at(12, &p))
            .unwrap()
            .succeeded());
        assert_eq!(
            ledger.account(&id("bob.sov")).balance,
            Balance::from_sov(50).unwrap(),
            "recipient claims the escrow"
        );
        assert_eq!(ledger.htlc_locked(), Balance::ZERO);
        assert!(ledger.htlc(&htlc_id).is_none());
        assert_eq!(ledger.total_supply().unwrap(), supply_before);
    }

    #[test]
    fn htlc_refunds_to_the_locker_only_after_timeout() {
        let mut ledger = ledger_with_usa(100);
        let p = policy();
        let lock = signed(
            [1; 32],
            "usa.reserve.sov",
            0,
            Action::HtlcLock {
                recipient: id("bob.sov"),
                amount: Balance::from_sov(30).unwrap(),
                hashlock: sha256(b"secret"),
                timeout_height: 50,
            },
        );
        let htlc_id = lock.id();
        apply_transaction(&mut ledger, &lock, &ctx_at(10, &p)).unwrap();

        // Refund before the timeout is rejected.
        let early = signed(
            [1; 32],
            "usa.reserve.sov",
            1,
            Action::HtlcRefund { htlc_id },
        );
        assert!(!apply_transaction(&mut ledger, &early, &ctx_at(20, &p))
            .unwrap()
            .succeeded());
        assert_eq!(ledger.htlc_locked(), Balance::from_sov(30).unwrap());

        // At/after the timeout the locker reclaims the escrow.
        let refund = signed(
            [1; 32],
            "usa.reserve.sov",
            2,
            Action::HtlcRefund { htlc_id },
        );
        assert!(apply_transaction(&mut ledger, &refund, &ctx_at(50, &p))
            .unwrap()
            .succeeded());
        assert_eq!(
            ledger.account(&id("usa.reserve.sov")).balance,
            Balance::from_sov(100).unwrap(),
            "the full balance is restored to the locker"
        );
        assert_eq!(ledger.htlc_locked(), Balance::ZERO);
    }

    #[test]
    fn wrong_key_is_unauthorized() {
        let mut ledger = ledger_with_usa(100);
        let p = policy();
        let stx = transfer([9; 32], "usa.reserve.sov", "ecb.reserve.sov", 50, 0);
        assert_eq!(
            apply_transaction(&mut ledger, &stx, &ctx(&p)),
            Err(ExecutionError::Unauthorized {
                account: "usa.reserve.sov".into()
            })
        );
        assert_eq!(
            ledger.account(&id("usa.reserve.sov")).balance,
            Balance::from_sov(100).unwrap()
        );
    }

    #[test]
    fn insufficient_balance_fails_but_consumes_nonce() {
        let mut ledger = ledger_with_usa(10);
        let p = policy();
        let stx = transfer([1; 32], "usa.reserve.sov", "ecb.reserve.sov", 50, 0);
        let receipt = apply_transaction(&mut ledger, &stx, &ctx(&p)).unwrap();
        assert!(!receipt.succeeded());
        assert_eq!(
            ledger.account(&id("usa.reserve.sov")).balance,
            Balance::from_sov(10).unwrap()
        );
        assert_eq!(ledger.account(&id("usa.reserve.sov")).nonce, 1);
    }

    #[test]
    fn bad_nonce_is_rejected() {
        let mut ledger = ledger_with_usa(100);
        let p = policy();
        let stx = transfer([1; 32], "usa.reserve.sov", "ecb.reserve.sov", 1, 7);
        assert_eq!(
            apply_transaction(&mut ledger, &stx, &ctx(&p)),
            Err(ExecutionError::BadNonce {
                expected: 0,
                got: 7
            })
        );
    }

    #[test]
    fn tampered_signature_is_rejected() {
        let mut ledger = ledger_with_usa(100);
        let p = policy();
        let mut stx = transfer([1; 32], "usa.reserve.sov", "ecb.reserve.sov", 1, 0);
        stx.transaction.nonce = 1; // invalidates the signature
        assert_eq!(
            apply_transaction(&mut ledger, &stx, &ctx(&p)),
            Err(ExecutionError::InvalidSignature)
        );
    }

    #[test]
    fn total_supply_is_conserved_by_transfer() {
        let mut ledger = ledger_with_usa(100);
        let p = policy();
        let before = ledger.total_supply().unwrap();
        let stx = transfer([1; 32], "usa.reserve.sov", "ecb.reserve.sov", 40, 0);
        apply_transaction(&mut ledger, &stx, &ctx(&p)).unwrap();
        assert_eq!(ledger.total_supply().unwrap(), before);
    }

    #[test]
    fn apply_transactions_processes_in_order() {
        let mut ledger = ledger_with_usa(100);
        let p = policy();
        let txs = vec![
            transfer([1; 32], "usa.reserve.sov", "ecb.reserve.sov", 10, 0),
            transfer([1; 32], "usa.reserve.sov", "sgp.reserve.sov", 25, 1),
        ];
        let receipts = apply_transactions(&mut ledger, &txs, &ctx(&p)).unwrap();
        assert_eq!(receipts.len(), 2);
        assert!(receipts.iter().all(|r| r.succeeded()));
        assert_eq!(
            ledger.account(&id("usa.reserve.sov")).balance,
            Balance::from_sov(65).unwrap()
        );
        assert_eq!(
            ledger.total_supply().unwrap(),
            Balance::from_sov(100).unwrap()
        );
    }

    #[test]
    fn coinbase_mints_the_scheduled_reward_and_respects_the_budget() {
        // The coinbase is the sole issuance path: it mints the scheduled reward
        // to the block's miner, advances the emission counter, halves on
        // schedule, and stops dead at the budget — the 21M-cap discipline.
        let mut p = policy();
        p.base_reward = Balance::from_sov(50).unwrap();
        p.halving_interval_blocks = 2; // heights 1-2 pay 50; height 3 halves to 25
        p.mining_budget_grains = Balance::from_sov(125).unwrap().grains();
        let mut ledger = Ledger::new();
        let bctx = |height: u64| BlockContext {
            height,
            prev_hash: Hash::digest(b"head"),
            mining: &p,
            gas_price: Balance::ZERO,
            miner: id("miner.sov"),
            pq: None,
        };

        // Heights 1 & 2 mint 50 each (epoch 0); height 3 halves to 25
        // (Bitcoin's height-keyed rule) and exactly exhausts the 125-SOV budget.
        for (height, expected) in [(1u64, 50u128), (2, 50), (3, 25)] {
            let minted = apply_coinbase(&mut ledger, &bctx(height)).unwrap();
            assert_eq!(minted, Balance::from_sov(expected).unwrap());
        }
        assert_eq!(
            ledger.account(&id("miner.sov")).balance,
            Balance::from_sov(125).unwrap()
        );
        assert_eq!(ledger.mined_emitted(), Balance::from_sov(125).unwrap());
        assert_eq!(
            ledger.total_supply().unwrap(),
            Balance::from_sov(125).unwrap()
        );

        // Budget spent: every further coinbase mints exactly nothing — the
        // chain runs on fees alone, like post-subsidy Bitcoin.
        assert_eq!(
            apply_coinbase(&mut ledger, &bctx(4)).unwrap(),
            Balance::ZERO
        );
        assert_eq!(ledger.mined_emitted(), Balance::from_sov(125).unwrap());
    }

    #[test]
    fn keyless_account_claims_its_key_via_rotate_key() {
        // A fresh (keyless) account is claimed first-come-first-served with
        // RotateKey: the claiming signature proves possession of the claiming
        // key, the rotation proof binds the final key. Any other action from a
        // keyless account stays unauthorized.
        let mut ledger = Ledger::new();
        let p = policy();
        let claimer = Keypair::from_seed([7; 32]);
        let new_key_pair = Keypair::hybrid_from_seed([8; 32]);
        let new_key = new_key_pair.public_key();

        // A non-RotateKey action from the keyless account is rejected outright.
        let transfer = SignedTransaction::sign(
            Transaction {
                signer: id("fresh.sov"),
                public_key: claimer.public_key(),
                nonce: 0,
                action: Action::Transfer {
                    to: id("usa.reserve.sov"),
                    amount: Balance::ZERO,
                },
            },
            &claimer,
        )
        .unwrap();
        assert!(matches!(
            apply_transaction(&mut ledger, &transfer, &ctx(&p)),
            Err(ExecutionError::Unauthorized { .. })
        ));

        // RotateKey claims the name and binds the proven key.
        let proof = new_key_pair.sign(&sov_types::rotation_signing_bytes(
            &id("fresh.sov"),
            0,
            &new_key,
        ));
        let claim = SignedTransaction::sign(
            Transaction {
                signer: id("fresh.sov"),
                public_key: claimer.public_key(),
                nonce: 0,
                action: Action::RotateKey { new_key, proof },
            },
            &claimer,
        )
        .unwrap();
        let receipt = apply_transaction(&mut ledger, &claim, &ctx(&p)).unwrap();
        assert!(receipt.succeeded(), "claiming a fresh name must succeed");
        assert!(ledger.account(&id("fresh.sov")).is_controlled_by(&new_key));
    }

    // ---- Vesting ----

    fn action_tx(seed: [u8; 32], from: &str, action: Action, nonce: u64) -> SignedTransaction {
        let kp = Keypair::from_seed(seed);
        let tx = Transaction {
            signer: id(from),
            public_key: kp.public_key(),
            nonce,
            action,
        };
        SignedTransaction::sign(tx, &kp).unwrap()
    }

    #[test]
    fn deploy_then_call_contract_charges_gas_fee_to_caller() {
        // A trivial contract: exports memory and a `call` returning 7.
        let code = wat::parse_str(
            r#"(module (memory (export "memory") 1) (func (export "call") (result i32) (i32.const 7)))"#,
        )
        .unwrap();
        let p = policy();
        let mut ledger = Ledger::new();
        ledger.set_account(
            &id("dev.sov"),
            Account::new(
                Keypair::from_seed([1; 32]).public_key(),
                Balance::from_sov(10).unwrap(),
            ),
        );
        ledger.set_account(
            &id("usa.reserve.sov"),
            Account::new(
                Keypair::from_seed([2; 32]).public_key(),
                Balance::from_sov(10).unwrap(),
            ),
        );

        // Fees on: 1 grain per gas unit, collected by val01.
        let bctx = BlockContext {
            height: 1,
            prev_hash: Hash::ZERO,
            mining: &p,
            gas_price: Balance::from_grains(1),
            miner: id("miner.sov"),
            pq: None,
        };

        // Deploy from dev.sov.
        let deploy = {
            let kp = Keypair::from_seed([1; 32]);
            let tx = Transaction {
                signer: id("dev.sov"),
                public_key: kp.public_key(),
                nonce: 0,
                action: Action::Deploy { code: code.clone() },
            };
            SignedTransaction::sign(tx, &kp).unwrap()
        };
        assert!(apply_transaction(&mut ledger, &deploy, &bctx)
            .unwrap()
            .succeeded());
        assert!(ledger.account(&id("dev.sov")).is_contract());

        // Call from usa.reserve.sov.
        let call = {
            let kp = Keypair::from_seed([2; 32]);
            let tx = Transaction {
                signer: id("usa.reserve.sov"),
                public_key: kp.public_key(),
                nonce: 0,
                action: Action::Call {
                    contract: id("dev.sov"),
                    gas_limit: 1_000_000,
                    calldata: Vec::new(),
                },
            };
            SignedTransaction::sign(tx, &kp).unwrap()
        };
        let caller_before = ledger.account(&id("usa.reserve.sov")).balance.grains();
        let miner_before = ledger.account(&id("miner.sov")).balance.grains();
        let receipt = apply_transaction(&mut ledger, &call, &bctx).unwrap();
        assert!(receipt.succeeded());

        // The caller paid a positive gas fee, and the WHOLE fee goes to the miner —
        // no tax, nothing burned (pure Nakamoto).
        let fee = caller_before - ledger.account(&id("usa.reserve.sov")).balance.grains();
        assert!(fee > 0, "a gas fee should have been charged");
        let miner_delta = ledger.account(&id("miner.sov")).balance.grains() - miner_before;
        assert_eq!(
            miner_delta, fee,
            "the miner receives the entire fee (no tax, no burn)"
        );
    }

    #[test]
    fn extreme_gas_price_is_rejected_not_saturated() {
        // R-03: gas_used × gas_price uses checked arithmetic — an overflow rejects
        // the transaction instead of silently saturating into a consensus value.
        let p = policy();
        let bctx = BlockContext {
            height: 1,
            prev_hash: Hash::ZERO,
            mining: &p,
            gas_price: Balance::from_grains(u128::MAX),
            miner: miner_id(),
            pq: None,
        };
        let mut ledger = ledger_with_usa(1_000);
        let stx = transfer([1; 32], "usa.reserve.sov", "ecb.reserve.sov", 1, 0);
        assert!(matches!(
            apply_transaction(&mut ledger, &stx, &bctx),
            Err(ExecutionError::Overflow)
        ));
    }

    #[test]
    fn oversized_contract_code_is_rejected() {
        // BIP-110: a Deploy carrying more code than the policy permits is rejected,
        // keeping block space reserved for monetary use rather than data storage.
        let mut p = MiningPolicy::test();
        p.max_code_bytes = 16;
        let mut ledger = ledger_with_usa(10);
        let kp = Keypair::from_seed([1; 32]);
        let tx = Transaction {
            signer: id("usa.reserve.sov"),
            public_key: kp.public_key(),
            nonce: 0,
            action: Action::Deploy {
                code: vec![0u8; 100],
            },
        };
        let stx = SignedTransaction::sign(tx, &kp).unwrap();
        assert!(matches!(
            apply_transaction(&mut ledger, &stx, &ctx(&p)),
            Err(ExecutionError::DataTooLarge {
                limit: 16,
                got: 100
            })
        ));
    }

    #[test]
    fn calling_a_non_contract_fails() {
        let p = policy();
        let mut ledger = ledger_with_usa(10);
        let kp = Keypair::from_seed([1; 32]);
        let tx = Transaction {
            signer: id("usa.reserve.sov"),
            public_key: kp.public_key(),
            nonce: 0,
            action: Action::Call {
                contract: id("ecb.reserve.sov"),
                gas_limit: 1_000_000,
                calldata: Vec::new(),
            },
        };
        let stx = SignedTransaction::sign(tx, &kp).unwrap();
        let receipt = apply_transaction(&mut ledger, &stx, &ctx(&p)).unwrap();
        assert!(!receipt.succeeded()); // ecb.reserve.sov has no code
    }

    // ---- VM ABI v2: calldata, caller, return data, events, token bridge ----

    /// Deploy `wat_src` as a contract at `account` (controlled by key seed `seed`).
    fn deploy(ledger: &mut Ledger, seed: [u8; 32], account: &str, wat_src: &str, nonce: u64) {
        let code = wat::parse_str(wat_src).unwrap();
        let kp = Keypair::from_seed(seed);
        if !ledger.exists(&id(account)) {
            ledger.set_account(&id(account), Account::new(kp.public_key(), Balance::ZERO));
        }
        let stx = signed(seed, account, nonce, Action::Deploy { code });
        let p = policy();
        assert!(apply_transaction(ledger, &stx, &ctx(&p))
            .unwrap()
            .succeeded());
    }

    #[test]
    fn abi_v2_exposes_calldata_and_caller_and_records_return_data_and_events() {
        // The contract echoes its calldata as return data, and emits one event
        // whose topic is the calldata and whose payload is the authenticated
        // caller's account id. Everything lands in the committed receipt.
        let echo = r#"(module
            (import "env" "calldata" (func $cd (param i32 i32) (result i32)))
            (import "env" "caller" (func $cl (param i32 i32) (result i32)))
            (import "env" "set_return" (func $sr (param i32 i32)))
            (import "env" "emit" (func $em (param i32 i32 i32 i32)))
            (memory (export "memory") 1)
            (func (export "call") (result i32)
                (local $n i32) (local $c i32)
                (local.set $n (call $cd (i32.const 0) (i32.const 256)))
                (call $sr (i32.const 0) (local.get $n))
                (local.set $c (call $cl (i32.const 256) (i32.const 64)))
                (call $em (i32.const 0) (local.get $n) (i32.const 256) (local.get $c))
                (local.get $n)))"#;
        let mut ledger = ledger_with_usa(100);
        deploy(&mut ledger, [5; 32], "echo.sov", echo, 0);

        let p = policy();
        let calldata = b"sov-abi-v2".to_vec();
        let call = signed(
            [1; 32],
            "usa.reserve.sov",
            0,
            Action::Call {
                contract: id("echo.sov"),
                gas_limit: 1_000_000,
                calldata: calldata.clone(),
            },
        );
        let receipt = apply_transaction(&mut ledger, &call, &ctx(&p)).unwrap();
        assert!(receipt.succeeded());
        assert_eq!(receipt.return_data, calldata, "return data echoes calldata");
        assert_eq!(receipt.events.len(), 1);
        assert_eq!(receipt.events[0].topic, calldata);
        assert_eq!(
            receipt.events[0].data,
            b"usa.reserve.sov".to_vec(),
            "the event payload is the authenticated caller id"
        );
    }

    #[test]
    fn contract_token_transfer_moves_only_the_contracts_own_balance_and_conserves() {
        use sov_state::token_asset_id;
        use sov_verify::{check_ledger, check_transition};

        // A treasury contract: reads a 32-byte asset id from calldata and pays
        // out 10_000 grains (16 LE bytes in its data segment) to bob.sov from
        // ITS OWN token balance.
        let treasury = r#"(module
            (import "env" "calldata" (func $cd (param i32 i32) (result i32)))
            (import "env" "token_transfer" (func $tt (param i32 i32 i32 i32) (result i32)))
            (memory (export "memory") 1)
            (data (i32.const 64) "bob.sov")
            (data (i32.const 96) "\10\27\00\00\00\00\00\00\00\00\00\00\00\00\00\00")
            (func (export "call") (result i32)
                (drop (call $cd (i32.const 0) (i32.const 32)))
                (call $tt (i32.const 0) (i32.const 64) (i32.const 7) (i32.const 96))))"#;
        let mut ledger = ledger_with_usa(100);
        deploy(&mut ledger, [5; 32], "treasury.contract.sov", treasury, 0);

        // usa issues GOLD and funds the contract's token balance.
        let p = policy();
        let asset = token_asset_id(&id("usa.reserve.sov"), "GOLD");
        let issue = signed(
            [1; 32],
            "usa.reserve.sov",
            0,
            Action::TokenIssue {
                symbol: "GOLD".into(),
                amount: Balance::from_sov(1).unwrap(),
                to: id("treasury.contract.sov"),
            },
        );
        assert!(apply_transaction(&mut ledger, &issue, &ctx(&p))
            .unwrap()
            .succeeded());

        // Anyone calls the treasury; it pays bob from its own balance.
        let before = ledger.clone();
        let call = signed(
            [1; 32],
            "usa.reserve.sov",
            1,
            Action::Call {
                contract: id("treasury.contract.sov"),
                gas_limit: 1_000_000,
                calldata: asset.as_bytes().to_vec(),
            },
        );
        let receipt = apply_transaction(&mut ledger, &call, &ctx(&p)).unwrap();
        assert!(receipt.succeeded());
        assert_eq!(
            ledger.token_balance(&asset, &id("bob.sov")),
            Balance::from_grains(10_000)
        );
        assert_eq!(
            ledger.token_balance(&asset, &id("treasury.contract.sov")),
            Balance::from_grains(100_000_000 - 10_000)
        );
        // The caller's own token balance (zero) was never touched: the
        // contract spent only itself.
        assert_eq!(
            ledger.token_balance(&asset, &id("usa.reserve.sov")),
            Balance::ZERO
        );
        // Per-asset conservation and the native invariants hold across the call.
        check_transition(&before, &ledger).unwrap();
        check_ledger(&ledger, &p).unwrap();

        // A second treasury with NO balance: the same payout returns -1 (the
        // in-VM debit fails), the action still succeeds (the contract chose to
        // report it), and no units move.
        deploy(&mut ledger, [6; 32], "empty.contract.sov", treasury, 0);
        let call2 = signed(
            [1; 32],
            "usa.reserve.sov",
            2,
            Action::Call {
                contract: id("empty.contract.sov"),
                gas_limit: 1_000_000,
                calldata: asset.as_bytes().to_vec(),
            },
        );
        let r2 = apply_transaction(&mut ledger, &call2, &ctx(&p)).unwrap();
        assert!(r2.succeeded());
        assert_eq!(
            ledger.token_balance(&asset, &id("bob.sov")),
            Balance::from_grains(10_000),
            "an unfunded contract cannot move anyone's units"
        );
    }

    #[test]
    fn contract_token_transfer_to_invalid_account_fails_without_committing() {
        use sov_state::token_asset_id;

        // The recipient "BAD" is not a valid AccountId (uppercase): the VM
        // queues it, but runtime re-validation must fail the action — and the
        // contract's storage write from the same call must NOT commit.
        let bad_recipient = r#"(module
            (import "env" "calldata" (func $cd (param i32 i32) (result i32)))
            (import "env" "token_transfer" (func $tt (param i32 i32 i32 i32) (result i32)))
            (import "env" "storage_write" (func $sw (param i32 i32 i32 i32)))
            (memory (export "memory") 1)
            (data (i32.const 64) "BAD")
            (data (i32.const 96) "\01\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00")
            (data (i32.const 128) "marker")
            (func (export "call") (result i32)
                (call $sw (i32.const 128) (i32.const 6) (i32.const 128) (i32.const 6))
                (drop (call $cd (i32.const 0) (i32.const 32)))
                (drop (call $tt (i32.const 0) (i32.const 64) (i32.const 3) (i32.const 96)))
                (i32.const 0)))"#;
        let mut ledger = ledger_with_usa(100);
        deploy(&mut ledger, [5; 32], "bad.contract.sov", bad_recipient, 0);

        let p = policy();
        let asset = token_asset_id(&id("usa.reserve.sov"), "GOLD");
        let issue = signed(
            [1; 32],
            "usa.reserve.sov",
            0,
            Action::TokenIssue {
                symbol: "GOLD".into(),
                amount: Balance::from_sov(1).unwrap(),
                to: id("bad.contract.sov"),
            },
        );
        apply_transaction(&mut ledger, &issue, &ctx(&p)).unwrap();

        let call = signed(
            [1; 32],
            "usa.reserve.sov",
            1,
            Action::Call {
                contract: id("bad.contract.sov"),
                gas_limit: 1_000_000,
                calldata: asset.as_bytes().to_vec(),
            },
        );
        let receipt = apply_transaction(&mut ledger, &call, &ctx(&p)).unwrap();
        assert!(
            !receipt.succeeded(),
            "an invalid recipient must fail the action"
        );
        assert!(receipt.events.is_empty(), "a failed call records no events");
        assert_eq!(
            ledger.token_balance(&asset, &id("bad.contract.sov")),
            Balance::from_sov(1).unwrap(),
            "no units moved"
        );
        assert!(
            ledger
                .contract_value(&id("bad.contract.sov"), b"marker")
                .is_none(),
            "the failed call's storage write must not commit"
        );
    }

    #[test]
    fn oversized_calldata_is_rejected_by_bip110() {
        let mut p = MiningPolicy::test();
        p.max_code_bytes = 16;
        let mut ledger = ledger_with_usa(10);
        let stx = signed(
            [1; 32],
            "usa.reserve.sov",
            0,
            Action::Call {
                contract: id("echo.sov"),
                gas_limit: 1_000_000,
                calldata: vec![0u8; 100],
            },
        );
        assert!(matches!(
            apply_transaction(&mut ledger, &stx, &ctx(&p)),
            Err(ExecutionError::DataTooLarge {
                limit: 16,
                got: 100
            })
        ));
    }

    // ---- Native assets (tokens) ----

    #[test]
    fn token_issue_transfer_burn_lifecycle_conserves_the_asset() {
        use sov_state::token_asset_id;
        use sov_verify::{check_ledger, check_transition};

        let mut ledger = ledger_with_usa(100);
        let bob = Keypair::from_seed([2; 32]);
        ledger.set_account(
            &id("bob.sov"),
            Account::new(bob.public_key(), Balance::ZERO),
        );
        let p = policy();
        let asset = token_asset_id(&id("usa.reserve.sov"), "USD1");
        let sov_supply_before = ledger.total_supply().unwrap();

        // 1. Issue 1000 USD1 to the issuer itself. The asset is created, its
        //    issuer recorded, and the balance equals the issuance counter.
        let genesis = ledger.clone();
        let issue = signed(
            [1; 32],
            "usa.reserve.sov",
            0,
            Action::TokenIssue {
                symbol: "USD1".into(),
                amount: Balance::from_sov(1_000).unwrap(),
                to: id("usa.reserve.sov"),
            },
        );
        assert!(apply_transaction(&mut ledger, &issue, &ctx(&p))
            .unwrap()
            .succeeded());
        let info = ledger.token(&asset).unwrap().clone();
        assert_eq!(info.issuer, id("usa.reserve.sov"));
        assert_eq!(info.symbol, "USD1");
        assert_eq!(info.issued, Balance::from_sov(1_000).unwrap());
        assert_eq!(info.burned, Balance::ZERO);
        assert_eq!(
            ledger.token_balance(&asset, &id("usa.reserve.sov")),
            Balance::from_sov(1_000).unwrap()
        );
        // Token units are NOT SOV: total native supply is untouched.
        assert_eq!(ledger.total_supply().unwrap(), sov_supply_before);
        check_transition(&genesis, &ledger).unwrap();
        check_ledger(&ledger, &p).unwrap();

        // 2. Transfer 400 USD1 to bob — supply unchanged, balances move.
        let before_transfer = ledger.clone();
        let transfer = signed(
            [1; 32],
            "usa.reserve.sov",
            1,
            Action::TokenTransfer {
                asset,
                to: id("bob.sov"),
                amount: Balance::from_sov(400).unwrap(),
            },
        );
        assert!(apply_transaction(&mut ledger, &transfer, &ctx(&p))
            .unwrap()
            .succeeded());
        assert_eq!(
            ledger.token_balance(&asset, &id("usa.reserve.sov")),
            Balance::from_sov(600).unwrap()
        );
        assert_eq!(
            ledger.token_balance(&asset, &id("bob.sov")),
            Balance::from_sov(400).unwrap()
        );
        assert_eq!(
            ledger.token(&asset).unwrap().issued,
            Balance::from_sov(1_000).unwrap(),
            "a transfer never changes the issuance counter"
        );
        check_transition(&before_transfer, &ledger).unwrap();
        check_ledger(&ledger, &p).unwrap();

        // 3. Bob burns 150 USD1 — supply shrinks by exactly the burn.
        let before_burn = ledger.clone();
        let burn = signed(
            [2; 32],
            "bob.sov",
            0,
            Action::TokenBurn {
                asset,
                amount: Balance::from_sov(150).unwrap(),
            },
        );
        assert!(apply_transaction(&mut ledger, &burn, &ctx(&p))
            .unwrap()
            .succeeded());
        assert_eq!(
            ledger.token_balance(&asset, &id("bob.sov")),
            Balance::from_sov(250).unwrap()
        );
        let info = ledger.token(&asset).unwrap();
        assert_eq!(info.burned, Balance::from_sov(150).unwrap());
        assert_eq!(info.supply().unwrap(), Balance::from_sov(850).unwrap());
        check_transition(&before_burn, &ledger).unwrap();
        check_ledger(&ledger, &p).unwrap();

        // 4. A second issue mints more under the same asset id.
        let more = signed(
            [1; 32],
            "usa.reserve.sov",
            2,
            Action::TokenIssue {
                symbol: "USD1".into(),
                amount: Balance::from_sov(50).unwrap(),
                to: id("bob.sov"),
            },
        );
        assert!(apply_transaction(&mut ledger, &more, &ctx(&p))
            .unwrap()
            .succeeded());
        assert_eq!(
            ledger.token(&asset).unwrap().issued,
            Balance::from_sov(1_050).unwrap()
        );
        assert_eq!(
            ledger.token_balance(&asset, &id("bob.sov")),
            Balance::from_sov(300).unwrap()
        );
        check_ledger(&ledger, &p).unwrap();
        // Across the whole lifecycle, native SOV supply never moved.
        assert_eq!(ledger.total_supply().unwrap(), sov_supply_before);
    }

    #[test]
    fn token_asset_id_binds_issuance_to_the_issuer() {
        use sov_state::token_asset_id;

        // Two different accounts issuing the SAME symbol create two DIFFERENT
        // assets: the id derivation includes the issuer, so an attacker cannot
        // mint units of someone else's asset — authorization by hash binding.
        let mut ledger = ledger_with_usa(100);
        let mallory = Keypair::from_seed([3; 32]);
        ledger.set_account(
            &id("mallory.sov"),
            Account::new(mallory.public_key(), Balance::ZERO),
        );
        let p = policy();

        let usa_asset = token_asset_id(&id("usa.reserve.sov"), "USD1");
        let mallory_asset = token_asset_id(&id("mallory.sov"), "USD1");
        assert_ne!(usa_asset, mallory_asset);

        let issue = signed(
            [1; 32],
            "usa.reserve.sov",
            0,
            Action::TokenIssue {
                symbol: "USD1".into(),
                amount: Balance::from_sov(1_000).unwrap(),
                to: id("usa.reserve.sov"),
            },
        );
        apply_transaction(&mut ledger, &issue, &ctx(&p)).unwrap();

        // Mallory issues "USD1" too — it lands in HER namespace, not usa's.
        let forge = signed(
            [3; 32],
            "mallory.sov",
            0,
            Action::TokenIssue {
                symbol: "USD1".into(),
                amount: Balance::from_sov(1_000_000).unwrap(),
                to: id("mallory.sov"),
            },
        );
        assert!(apply_transaction(&mut ledger, &forge, &ctx(&p))
            .unwrap()
            .succeeded());
        assert_eq!(
            ledger.token(&usa_asset).unwrap().issued,
            Balance::from_sov(1_000).unwrap(),
            "usa's asset is untouched by mallory's issuance"
        );
        assert_eq!(
            ledger.token_balance(&usa_asset, &id("mallory.sov")),
            Balance::ZERO
        );
        assert_eq!(
            ledger.token(&mallory_asset).unwrap().issuer,
            id("mallory.sov")
        );
    }

    #[test]
    fn token_transfer_and_burn_enforce_balances_and_fail_gracefully() {
        use sov_state::token_asset_id;

        let mut ledger = ledger_with_usa(100);
        let bob = Keypair::from_seed([2; 32]);
        ledger.set_account(
            &id("bob.sov"),
            Account::new(bob.public_key(), Balance::ZERO),
        );
        let p = policy();
        let asset = token_asset_id(&id("usa.reserve.sov"), "GOLD");

        let issue = signed(
            [1; 32],
            "usa.reserve.sov",
            0,
            Action::TokenIssue {
                symbol: "GOLD".into(),
                amount: Balance::from_sov(10).unwrap(),
                to: id("bob.sov"),
            },
        );
        apply_transaction(&mut ledger, &issue, &ctx(&p)).unwrap();

        // Overspend fails (and consumes the nonce) without moving anything.
        let overspend = signed(
            [2; 32],
            "bob.sov",
            0,
            Action::TokenTransfer {
                asset,
                to: id("usa.reserve.sov"),
                amount: Balance::from_sov(11).unwrap(),
            },
        );
        let r = apply_transaction(&mut ledger, &overspend, &ctx(&p)).unwrap();
        assert!(!r.succeeded());
        assert_eq!(
            ledger.token_balance(&asset, &id("bob.sov")),
            Balance::from_sov(10).unwrap()
        );
        assert_eq!(ledger.account(&id("bob.sov")).nonce, 1);

        // Over-burn fails identically.
        let overburn = signed(
            [2; 32],
            "bob.sov",
            1,
            Action::TokenBurn {
                asset,
                amount: Balance::from_sov(11).unwrap(),
            },
        );
        assert!(!apply_transaction(&mut ledger, &overburn, &ctx(&p))
            .unwrap()
            .succeeded());
        assert_eq!(ledger.token(&asset).unwrap().burned, Balance::ZERO);

        // Transfer against a nonexistent asset fails.
        let ghost = signed(
            [2; 32],
            "bob.sov",
            2,
            Action::TokenTransfer {
                asset: Hash::digest(b"no-such-asset"),
                to: id("usa.reserve.sov"),
                amount: Balance::from_grains(1),
            },
        );
        assert!(!apply_transaction(&mut ledger, &ghost, &ctx(&p))
            .unwrap()
            .succeeded());

        // Self-transfer is a no-op success: units stay put, nonce advances.
        let selfsend = signed(
            [2; 32],
            "bob.sov",
            3,
            Action::TokenTransfer {
                asset,
                to: id("bob.sov"),
                amount: Balance::from_sov(5).unwrap(),
            },
        );
        assert!(apply_transaction(&mut ledger, &selfsend, &ctx(&p))
            .unwrap()
            .succeeded());
        assert_eq!(
            ledger.token_balance(&asset, &id("bob.sov")),
            Balance::from_sov(10).unwrap()
        );
        assert_eq!(ledger.account(&id("bob.sov")).nonce, 4);
    }

    #[test]
    fn token_issuance_overflow_fails_the_action_without_invalidating_the_block() {
        use sov_state::token_asset_id;

        // Unlike SOV (capped at 21M, overflow unreachable), a token's issuance
        // can genuinely reach u128::MAX. The overflow must be a graceful
        // Failed receipt — never an Err, which would invalidate a whole block.
        let mut ledger = ledger_with_usa(100);
        let p = policy();
        let asset = token_asset_id(&id("usa.reserve.sov"), "MAX");

        let issue_max = signed(
            [1; 32],
            "usa.reserve.sov",
            0,
            Action::TokenIssue {
                symbol: "MAX".into(),
                amount: Balance::from_grains(u128::MAX),
                to: id("usa.reserve.sov"),
            },
        );
        assert!(apply_transaction(&mut ledger, &issue_max, &ctx(&p))
            .unwrap()
            .succeeded());
        assert_eq!(
            ledger.token(&asset).unwrap().issued,
            Balance::from_grains(u128::MAX)
        );

        // One more unit would overflow the u128 counter: graceful failure,
        // nonce consumed, nothing mutated.
        let one_more = signed(
            [1; 32],
            "usa.reserve.sov",
            1,
            Action::TokenIssue {
                symbol: "MAX".into(),
                amount: Balance::from_grains(1),
                to: id("usa.reserve.sov"),
            },
        );
        let r = apply_transaction(&mut ledger, &one_more, &ctx(&p)).unwrap();
        assert!(!r.succeeded(), "issuance overflow must fail gracefully");
        assert_eq!(
            ledger.token(&asset).unwrap().issued,
            Balance::from_grains(u128::MAX)
        );
        assert_eq!(ledger.account(&id("usa.reserve.sov")).nonce, 2);
    }

    #[test]
    fn token_issue_validates_symbol_and_amount() {
        let mut ledger = ledger_with_usa(100);
        let p = policy();
        let bad = |nonce: u64, symbol: &str, grains: u128| {
            signed(
                [1; 32],
                "usa.reserve.sov",
                nonce,
                Action::TokenIssue {
                    symbol: symbol.into(),
                    amount: Balance::from_grains(grains),
                    to: id("usa.reserve.sov"),
                },
            )
        };
        // Empty symbol, oversized symbol, non-alphanumeric symbol, zero amount.
        for (nonce, stx) in [
            (0, bad(0, "", 1)),
            (1, bad(1, "ABCDEFGHIJKLMNOPQ", 1)), // 17 bytes
            (2, bad(2, "US D1", 1)),
            (3, bad(3, "USD1", 0)),
        ] {
            let r = apply_transaction(&mut ledger, &stx, &ctx(&p)).unwrap();
            assert!(!r.succeeded(), "invalid issue #{nonce} must fail");
        }
        assert_eq!(ledger.token_iter().count(), 0, "no asset was created");
    }

    #[test]
    fn token_actions_pay_their_fee_in_native_sov() {
        use sov_state::token_asset_id;

        let p = policy();
        let bctx = BlockContext {
            height: 1,
            prev_hash: Hash::ZERO,
            mining: &p,
            gas_price: Balance::from_grains(1),
            miner: id("miner.sov"),
            pq: None,
        };
        let mut ledger = ledger_with_usa(100);
        let sov_before = ledger.account(&id("usa.reserve.sov")).balance;
        let miner_before = ledger.account(&id("miner.sov")).balance.grains();

        let issue = signed(
            [1; 32],
            "usa.reserve.sov",
            0,
            Action::TokenIssue {
                symbol: "USD1".into(),
                amount: Balance::from_sov(1_000).unwrap(),
                to: id("usa.reserve.sov"),
            },
        );
        assert!(apply_transaction(&mut ledger, &issue, &bctx)
            .unwrap()
            .succeeded());

        // The fee left the signer's NATIVE balance (gas × price for a token op),
        // part was burned, and the token balance is exactly what was issued.
        let fee = sov_before.grains() - ledger.account(&id("usa.reserve.sov")).balance.grains();
        assert_eq!(
            fee,
            u128::from(crate::gas::INTRINSIC_GAS + crate::gas::BOOKKEEPING_GAS),
            "token issue pays the token-op gas in SOV"
        );
        assert!(
            ledger.account(&id("miner.sov")).balance.grains() > miner_before,
            "the fee is paid to the miner (nothing burned)"
        );
        let asset = token_asset_id(&id("usa.reserve.sov"), "USD1");
        assert_eq!(
            ledger.token_balance(&asset, &id("usa.reserve.sov")),
            Balance::from_sov(1_000).unwrap()
        );
    }

    // ---- Per-asset compliance (regulated issuance) ----

    use sov_compliance::{CompliancePolicy, SpendLimit, TransferControl};

    /// usa issues 1000 USD1 to itself and to bob; returns (ledger, asset).
    fn regulated_setup() -> (Ledger, Hash) {
        use sov_state::token_asset_id;
        let mut ledger = ledger_with_usa(1_000);
        let bob = Keypair::from_seed([2; 32]);
        ledger.set_account(
            &id("bob.sov"),
            Account::new(bob.public_key(), Balance::ZERO),
        );
        let p = policy();
        let asset = token_asset_id(&id("usa.reserve.sov"), "USD1");
        for (nonce, to) in [(0, "usa.reserve.sov"), (1, "bob.sov")] {
            let issue = signed(
                [1; 32],
                "usa.reserve.sov",
                nonce,
                Action::TokenIssue {
                    symbol: "USD1".into(),
                    amount: Balance::from_sov(1_000).unwrap(),
                    to: id(to),
                },
            );
            assert!(apply_transaction(&mut ledger, &issue, &ctx(&p))
                .unwrap()
                .succeeded());
        }
        (ledger, asset)
    }

    fn set_policy(
        ledger: &mut Ledger,
        asset: Hash,
        nonce: u64,
        policy_value: CompliancePolicy,
    ) -> Receipt {
        let p = policy();
        let stx = signed(
            [1; 32],
            "usa.reserve.sov",
            nonce,
            Action::TokenSetPolicy {
                asset,
                policy: policy_value,
            },
        );
        apply_transaction(ledger, &stx, &ctx(&p)).unwrap()
    }

    #[test]
    fn only_the_issuer_may_set_an_assets_policy() {
        let (mut ledger, asset) = regulated_setup();
        let p = policy();
        // bob (not the issuer) tries to pause usa's asset.
        let hijack = signed(
            [2; 32],
            "bob.sov",
            0,
            Action::TokenSetPolicy {
                asset,
                policy: CompliancePolicy {
                    frozen: true,
                    ..CompliancePolicy::default()
                },
            },
        );
        let r = apply_transaction(&mut ledger, &hijack, &ctx(&p)).unwrap();
        assert!(!r.succeeded(), "a non-issuer cannot regulate the asset");
        assert!(ledger.token_policy(&asset).is_none());

        // The issuer can.
        let r = set_policy(
            &mut ledger,
            asset,
            2,
            CompliancePolicy {
                frozen: true,
                ..CompliancePolicy::default()
            },
        );
        assert!(r.succeeded());
        assert!(ledger.token_policy(&asset).unwrap().frozen);
    }

    #[test]
    fn paused_asset_blocks_issue_transfer_and_burn_until_unpaused() {
        use sov_verify::check_ledger;
        let (mut ledger, asset) = regulated_setup();
        let p = policy();
        assert!(set_policy(
            &mut ledger,
            asset,
            2,
            CompliancePolicy {
                frozen: true,
                ..CompliancePolicy::default()
            },
        )
        .succeeded());

        // Mint, transfer, and burn are all blocked while paused.
        let mint = signed(
            [1; 32],
            "usa.reserve.sov",
            3,
            Action::TokenIssue {
                symbol: "USD1".into(),
                amount: Balance::from_sov(1).unwrap(),
                to: id("usa.reserve.sov"),
            },
        );
        assert!(!apply_transaction(&mut ledger, &mint, &ctx(&p))
            .unwrap()
            .succeeded());
        let transfer = signed(
            [2; 32],
            "bob.sov",
            0,
            Action::TokenTransfer {
                asset,
                to: id("usa.reserve.sov"),
                amount: Balance::from_sov(1).unwrap(),
            },
        );
        assert!(!apply_transaction(&mut ledger, &transfer, &ctx(&p))
            .unwrap()
            .succeeded());
        let burn = signed(
            [2; 32],
            "bob.sov",
            1,
            Action::TokenBurn {
                asset,
                amount: Balance::from_sov(1).unwrap(),
            },
        );
        assert!(!apply_transaction(&mut ledger, &burn, &ctx(&p))
            .unwrap()
            .succeeded());
        assert_eq!(
            ledger.token_balance(&asset, &id("bob.sov")),
            Balance::from_sov(1_000).unwrap(),
            "nothing moved while paused"
        );

        // Unpause: movement resumes. The issuer is never locked out of the
        // policy action itself.
        assert!(set_policy(&mut ledger, asset, 4, CompliancePolicy::unrestricted()).succeeded());
        let transfer = signed(
            [2; 32],
            "bob.sov",
            2,
            Action::TokenTransfer {
                asset,
                to: id("usa.reserve.sov"),
                amount: Balance::from_sov(1).unwrap(),
            },
        );
        assert!(apply_transaction(&mut ledger, &transfer, &ctx(&p))
            .unwrap()
            .succeeded());
        check_ledger(&ledger, &p).unwrap();
    }

    #[test]
    fn deny_listed_account_is_blocked_in_both_directions() {
        let (mut ledger, asset) = regulated_setup();
        let p = policy();
        assert!(set_policy(
            &mut ledger,
            asset,
            2,
            CompliancePolicy {
                transfer_control: TransferControl::DenyList([id("bob.sov")].into_iter().collect()),
                ..CompliancePolicy::default()
            },
        )
        .succeeded());

        // bob cannot send (sender block)...
        let send = signed(
            [2; 32],
            "bob.sov",
            0,
            Action::TokenTransfer {
                asset,
                to: id("usa.reserve.sov"),
                amount: Balance::from_sov(1).unwrap(),
            },
        );
        assert!(!apply_transaction(&mut ledger, &send, &ctx(&p))
            .unwrap()
            .succeeded());
        // ...cannot burn (his funds are frozen at the asset level)...
        let burn = signed(
            [2; 32],
            "bob.sov",
            1,
            Action::TokenBurn {
                asset,
                amount: Balance::from_sov(1).unwrap(),
            },
        );
        assert!(!apply_transaction(&mut ledger, &burn, &ctx(&p))
            .unwrap()
            .succeeded());
        // ...and cannot receive (recipient block), nor be minted to.
        let to_bob = signed(
            [1; 32],
            "usa.reserve.sov",
            3,
            Action::TokenTransfer {
                asset,
                to: id("bob.sov"),
                amount: Balance::from_sov(1).unwrap(),
            },
        );
        assert!(!apply_transaction(&mut ledger, &to_bob, &ctx(&p))
            .unwrap()
            .succeeded());
        let mint_to_bob = signed(
            [1; 32],
            "usa.reserve.sov",
            4,
            Action::TokenIssue {
                symbol: "USD1".into(),
                amount: Balance::from_sov(1).unwrap(),
                to: id("bob.sov"),
            },
        );
        assert!(!apply_transaction(&mut ledger, &mint_to_bob, &ctx(&p))
            .unwrap()
            .succeeded());
        // Unlisted parties move freely.
        let free = signed(
            [1; 32],
            "usa.reserve.sov",
            5,
            Action::TokenTransfer {
                asset,
                to: id("carol.sov"),
                amount: Balance::from_sov(1).unwrap(),
            },
        );
        assert!(apply_transaction(&mut ledger, &free, &ctx(&p))
            .unwrap()
            .succeeded());
    }

    #[test]
    fn spend_velocity_limit_caps_a_holder_per_window_and_rolls_over() {
        let (mut ledger, asset) = regulated_setup();
        let p = policy();
        assert!(set_policy(
            &mut ledger,
            asset,
            2,
            CompliancePolicy {
                spend_limit: Some(SpendLimit {
                    max_per_window: Balance::from_sov(100).unwrap(),
                    window_blocks: 10,
                }),
                ..CompliancePolicy::default()
            },
        )
        .succeeded());

        let send = |nonce: u64, sov: u128| {
            signed(
                [2; 32],
                "bob.sov",
                nonce,
                Action::TokenTransfer {
                    asset,
                    to: id("usa.reserve.sov"),
                    amount: Balance::from_sov(sov).unwrap(),
                },
            )
        };
        // 60 + 40 at heights 1 and 5 fill the window exactly.
        assert!(apply_transaction(&mut ledger, &send(0, 60), &ctx_at(1, &p))
            .unwrap()
            .succeeded());
        assert!(apply_transaction(&mut ledger, &send(1, 40), &ctx_at(5, &p))
            .unwrap()
            .succeeded());
        // One more SOV inside the same window is blocked.
        assert!(!apply_transaction(&mut ledger, &send(2, 1), &ctx_at(6, &p))
            .unwrap()
            .succeeded());
        // At height 11 the window has elapsed: spending resumes.
        assert!(
            apply_transaction(&mut ledger, &send(3, 80), &ctx_at(11, &p))
                .unwrap()
                .succeeded()
        );
        assert_eq!(
            ledger.token_window(&asset, &id("bob.sov")).spent,
            Balance::from_sov(80).unwrap()
        );
    }

    #[test]
    fn contract_token_transfers_obey_the_assets_compliance_policy() {
        use sov_state::token_asset_id;

        // The p17-i1 treasury contract pays bob.sov 10_000 grains of the asset
        // named in calldata. With bob deny-listed, the contract's payout must
        // fail the whole action — the bridge is policy-gated like any transfer.
        let treasury = r#"(module
            (import "env" "calldata" (func $cd (param i32 i32) (result i32)))
            (import "env" "token_transfer" (func $tt (param i32 i32 i32 i32) (result i32)))
            (memory (export "memory") 1)
            (data (i32.const 64) "bob.sov")
            (data (i32.const 96) "\10\27\00\00\00\00\00\00\00\00\00\00\00\00\00\00")
            (func (export "call") (result i32)
                (drop (call $cd (i32.const 0) (i32.const 32)))
                (call $tt (i32.const 0) (i32.const 64) (i32.const 7) (i32.const 96))))"#;
        let mut ledger = ledger_with_usa(1_000);
        deploy(&mut ledger, [5; 32], "treasury.contract.sov", treasury, 0);
        let p = policy();
        let asset = token_asset_id(&id("usa.reserve.sov"), "USD1");
        let issue = signed(
            [1; 32],
            "usa.reserve.sov",
            0,
            Action::TokenIssue {
                symbol: "USD1".into(),
                amount: Balance::from_sov(1).unwrap(),
                to: id("treasury.contract.sov"),
            },
        );
        assert!(apply_transaction(&mut ledger, &issue, &ctx(&p))
            .unwrap()
            .succeeded());
        assert!(set_policy(
            &mut ledger,
            asset,
            1,
            CompliancePolicy {
                transfer_control: TransferControl::DenyList([id("bob.sov")].into_iter().collect()),
                ..CompliancePolicy::default()
            },
        )
        .succeeded());

        let call = signed(
            [1; 32],
            "usa.reserve.sov",
            2,
            Action::Call {
                contract: id("treasury.contract.sov"),
                gas_limit: 1_000_000,
                calldata: asset.as_bytes().to_vec(),
            },
        );
        let receipt = apply_transaction(&mut ledger, &call, &ctx(&p)).unwrap();
        assert!(
            !receipt.succeeded(),
            "a contract payout to a deny-listed account must fail"
        );
        assert_eq!(ledger.token_balance(&asset, &id("bob.sov")), Balance::ZERO);

        // Lift the policy: the identical call now pays out.
        assert!(set_policy(&mut ledger, asset, 3, CompliancePolicy::unrestricted()).succeeded());
        let call2 = signed(
            [1; 32],
            "usa.reserve.sov",
            4,
            Action::Call {
                contract: id("treasury.contract.sov"),
                gas_limit: 1_000_000,
                calldata: asset.as_bytes().to_vec(),
            },
        );
        assert!(apply_transaction(&mut ledger, &call2, &ctx(&p))
            .unwrap()
            .succeeded());
        assert_eq!(
            ledger.token_balance(&asset, &id("bob.sov")),
            Balance::from_grains(10_000)
        );
    }

    #[test]
    fn compliance_never_touches_native_sov() {
        // Even with usa's asset fully frozen and usa itself deny-listed on it,
        // NATIVE SOV transfers are untouched — compliance is per-asset and
        // issuer-opt-in; the monetary base stays permissionless.
        let (mut ledger, asset) = regulated_setup();
        let p = policy();
        assert!(set_policy(
            &mut ledger,
            asset,
            2,
            CompliancePolicy {
                frozen: true,
                transfer_control: TransferControl::DenyList(
                    [id("usa.reserve.sov"), id("bob.sov")].into_iter().collect()
                ),
                ..CompliancePolicy::default()
            },
        )
        .succeeded());
        let native = transfer([1; 32], "usa.reserve.sov", "bob.sov", 50, 3);
        assert!(apply_transaction(&mut ledger, &native, &ctx(&p))
            .unwrap()
            .succeeded());
        assert_eq!(
            ledger.account(&id("bob.sov")).balance,
            Balance::from_sov(50).unwrap()
        );
    }

    #[test]
    fn oversized_policy_is_rejected_and_replacement_resets_windows() {
        let (mut ledger, asset) = regulated_setup();
        let p = policy();
        // 1025 deny-list entries exceed the bound.
        let big: std::collections::BTreeSet<AccountId> =
            (0..1025).map(|i| id(&format!("acct{i}.sov"))).collect();
        let r = set_policy(
            &mut ledger,
            asset,
            2,
            CompliancePolicy {
                transfer_control: TransferControl::DenyList(big),
                ..CompliancePolicy::default()
            },
        );
        assert!(!r.succeeded(), "an over-bound policy must fail");
        assert!(ledger.token_policy(&asset).is_none());

        // Install a velocity limit, spend under it, then replace the policy:
        // the window accounting must reset.
        assert!(set_policy(
            &mut ledger,
            asset,
            3,
            CompliancePolicy {
                spend_limit: Some(SpendLimit {
                    max_per_window: Balance::from_sov(100).unwrap(),
                    window_blocks: 10,
                }),
                ..CompliancePolicy::default()
            },
        )
        .succeeded());
        let send = signed(
            [2; 32],
            "bob.sov",
            0,
            Action::TokenTransfer {
                asset,
                to: id("usa.reserve.sov"),
                amount: Balance::from_sov(60).unwrap(),
            },
        );
        assert!(apply_transaction(&mut ledger, &send, &ctx_at(1, &p))
            .unwrap()
            .succeeded());
        assert_eq!(
            ledger.token_window(&asset, &id("bob.sov")).spent,
            Balance::from_sov(60).unwrap()
        );
        assert!(set_policy(
            &mut ledger,
            asset,
            4,
            CompliancePolicy {
                spend_limit: Some(SpendLimit {
                    max_per_window: Balance::from_sov(100).unwrap(),
                    window_blocks: 10,
                }),
                ..CompliancePolicy::default()
            },
        )
        .succeeded());
        assert_eq!(
            ledger.token_window(&asset, &id("bob.sov")),
            sov_compliance::SpendWindow::default(),
            "replacing a policy resets velocity accounting"
        );
    }

    // ---- Intent settlement: the on-chain liquidity rail ----

    use sov_intents::{Asset as IntentAsset, Intent, Settlement, SignedIntent};

    /// usa (seed [1;32]) holds 1000 SOV and 1000 USD1; bob (seed [2;32]) holds
    /// 1000 SOV. Returns (ledger, USD1 asset id).
    fn liquidity_setup() -> (Ledger, Hash) {
        use sov_state::token_asset_id;
        let mut ledger = ledger_with_usa(1_000);
        let bob = Keypair::from_seed([2; 32]);
        ledger.set_account(
            &id("bob.sov"),
            Account::new(bob.public_key(), Balance::from_sov(1_000).unwrap()),
        );
        let p = policy();
        let asset = token_asset_id(&id("usa.reserve.sov"), "USD1");
        let issue = signed(
            [1; 32],
            "usa.reserve.sov",
            0,
            Action::TokenIssue {
                symbol: "USD1".into(),
                amount: Balance::from_sov(1_000).unwrap(),
                to: id("usa.reserve.sov"),
            },
        );
        assert!(apply_transaction(&mut ledger, &issue, &ctx(&p))
            .unwrap()
            .succeeded());
        (ledger, asset)
    }

    /// usa's REAL signed intent: give 100 USD1, want ≥ 90 SOV, until height 100.
    fn usa_intent(asset: Hash, nonce: u64) -> SignedIntent {
        let kp = Keypair::from_seed([1; 32]);
        Intent {
            owner: id("usa.reserve.sov"),
            public_key: kp.public_key(),
            nonce,
            give_asset: IntentAsset::Token(asset),
            give_amount: Balance::from_sov(100).unwrap().grains(),
            want_asset: IntentAsset::Sov,
            min_receive: Balance::from_sov(90).unwrap().grains(),
            expiry_height: 100,
        }
        .sign(&kp)
        .unwrap()
    }

    fn fill(intent: SignedIntent, deliver_sov: u128, solver_nonce: u64) -> SignedTransaction {
        signed(
            [2; 32],
            "bob.sov",
            solver_nonce,
            Action::IntentSettle {
                settlement: Settlement {
                    intent,
                    solver: id("bob.sov"),
                    deliver_amount: Balance::from_sov(deliver_sov).unwrap().grains(),
                },
            },
        )
    }

    #[test]
    fn intent_settlement_swaps_token_for_sov_atomically_and_conserves() {
        use sov_verify::{check_ledger, check_transition};
        let (mut ledger, asset) = liquidity_setup();
        let p = policy();
        let before = ledger.clone();
        let native_supply_before = ledger.total_supply().unwrap();

        // bob fills usa's intent, delivering 95 SOV (above the 90 floor —
        // solver competition delivers more, never less).
        let r = apply_transaction(
            &mut ledger,
            &fill(usa_intent(asset, 0), 95, 0),
            &ctx_at(10, &p),
        )
        .unwrap();
        assert!(
            r.succeeded(),
            "a valid settlement must succeed: {:?}",
            r.status
        );

        // Both legs landed: usa gave 100 USD1, received 95 SOV; bob mirror.
        assert_eq!(
            ledger.token_balance(&asset, &id("usa.reserve.sov")),
            Balance::from_sov(900).unwrap()
        );
        assert_eq!(
            ledger.token_balance(&asset, &id("bob.sov")),
            Balance::from_sov(100).unwrap()
        );
        assert_eq!(
            ledger.account(&id("usa.reserve.sov")).balance,
            Balance::from_sov(1_095).unwrap()
        );
        assert_eq!(
            ledger.account(&id("bob.sov")).balance,
            Balance::from_sov(905).unwrap()
        );
        // Conservation: native supply unchanged; per-asset theorem holds.
        assert_eq!(ledger.total_supply().unwrap(), native_supply_before);
        check_transition(&before, &ledger).unwrap();
        check_ledger(&ledger, &p).unwrap();
    }

    #[test]
    fn intent_cannot_be_replayed_or_filled_below_minimum_or_after_expiry() {
        let (mut ledger, asset) = liquidity_setup();
        let p = policy();

        // Below the slippage floor: rejected, nothing moves.
        let r = apply_transaction(
            &mut ledger,
            &fill(usa_intent(asset, 0), 89, 0),
            &ctx_at(10, &p),
        )
        .unwrap();
        assert!(!r.succeeded());
        assert_eq!(ledger.token_balance(&asset, &id("bob.sov")), Balance::ZERO);

        // Valid fill consumes the intent...
        assert!(apply_transaction(
            &mut ledger,
            &fill(usa_intent(asset, 0), 95, 1),
            &ctx_at(10, &p)
        )
        .unwrap()
        .succeeded());
        // ...so the IDENTICAL intent cannot settle twice (replay exclusion),
        // even with a different delivery.
        let replay = apply_transaction(
            &mut ledger,
            &fill(usa_intent(asset, 0), 99, 2),
            &ctx_at(11, &p),
        )
        .unwrap();
        assert!(
            !replay.succeeded(),
            "a consumed intent must never settle again"
        );
        assert_eq!(
            ledger.token_balance(&asset, &id("bob.sov")),
            Balance::from_sov(100).unwrap(),
            "exactly one fill ever lands"
        );

        // A FRESH intent (new owner nonce) after its expiry height: rejected.
        let late = apply_transaction(
            &mut ledger,
            &fill(usa_intent(asset, 1), 95, 3),
            &ctx_at(101, &p),
        )
        .unwrap();
        assert!(!late.succeeded(), "an expired intent must not settle");
    }

    #[test]
    fn forged_or_tampered_intents_are_rejected() {
        let (mut ledger, asset) = liquidity_setup();
        let p = policy();

        // Forgery: mallory signs an intent CLAIMING usa as owner with her own
        // key. The signature verifies against her key — but her key is not
        // usa's registered on-chain key, so the settlement dies.
        let mallory = Keypair::from_seed([9; 32]);
        let forged = Intent {
            owner: id("usa.reserve.sov"),
            public_key: mallory.public_key(),
            nonce: 0,
            give_asset: IntentAsset::Token(asset),
            give_amount: Balance::from_sov(1_000).unwrap().grains(),
            want_asset: IntentAsset::Sov,
            min_receive: 1,
            expiry_height: 100,
        }
        .sign(&mallory)
        .unwrap();
        let r = apply_transaction(&mut ledger, &fill(forged, 1, 0), &ctx_at(10, &p)).unwrap();
        assert!(!r.succeeded(), "a forged-owner intent must be rejected");
        assert_eq!(
            ledger.token_balance(&asset, &id("usa.reserve.sov")),
            Balance::from_sov(1_000).unwrap(),
            "the victim's funds are untouched"
        );

        // Tampering: take usa's real signed intent and sweeten the terms.
        let mut tampered = usa_intent(asset, 0);
        tampered.intent.give_amount = Balance::from_sov(1_000).unwrap().grains();
        let r = apply_transaction(&mut ledger, &fill(tampered, 95, 1), &ctx_at(10, &p)).unwrap();
        assert!(
            !r.succeeded(),
            "a tampered intent must fail signature verification"
        );
    }

    #[test]
    fn cancel_consumes_the_intent_and_only_the_owner_may_cancel() {
        let (mut ledger, asset) = liquidity_setup();
        let p = policy();
        let signed_intent = usa_intent(asset, 0);

        // bob cannot cancel usa's intent.
        let foreign_cancel = signed(
            [2; 32],
            "bob.sov",
            0,
            Action::IntentCancel {
                intent: signed_intent.intent.clone(),
            },
        );
        assert!(
            !apply_transaction(&mut ledger, &foreign_cancel, &ctx_at(5, &p))
                .unwrap()
                .succeeded()
        );

        // usa cancels; the intent is consumed and can never settle.
        let cancel = signed(
            [1; 32],
            "usa.reserve.sov",
            1,
            Action::IntentCancel {
                intent: signed_intent.intent.clone(),
            },
        );
        assert!(apply_transaction(&mut ledger, &cancel, &ctx_at(5, &p))
            .unwrap()
            .succeeded());
        let r =
            apply_transaction(&mut ledger, &fill(signed_intent, 95, 1), &ctx_at(10, &p)).unwrap();
        assert!(!r.succeeded(), "a cancelled intent must never settle");
        assert_eq!(ledger.token_balance(&asset, &id("bob.sov")), Balance::ZERO);
    }

    #[test]
    fn underfunded_settlement_moves_nothing_on_either_side() {
        let (mut ledger, asset) = liquidity_setup();
        let p = policy();

        // Drain bob's SOV below the delivery he promises: the solver leg
        // cannot fund, and the owner leg must not half-apply.
        let drain = transfer([2; 32], "bob.sov", "carol.sov", 950, 0);
        assert!(apply_transaction(&mut ledger, &drain, &ctx(&p))
            .unwrap()
            .succeeded());
        let before_owner_token = ledger.token_balance(&asset, &id("usa.reserve.sov"));
        let before_owner_native = ledger.account(&id("usa.reserve.sov")).balance;

        let r = apply_transaction(
            &mut ledger,
            &fill(usa_intent(asset, 0), 95, 1),
            &ctx_at(10, &p),
        )
        .unwrap();
        assert!(!r.succeeded(), "an underfunded solver cannot settle");
        assert_eq!(
            ledger.token_balance(&asset, &id("usa.reserve.sov")),
            before_owner_token,
            "the owner's give leg must not half-apply"
        );
        assert_eq!(
            ledger.account(&id("usa.reserve.sov")).balance,
            before_owner_native
        );
    }

    #[test]
    fn settlement_respects_the_assets_compliance_policy() {
        let (mut ledger, asset) = liquidity_setup();
        let p = policy();
        // The issuer deny-lists bob on USD1: usa's give leg (usa -> bob of
        // USD1) is blocked at the compliance gate, so the settlement fails.
        assert!(set_policy(
            &mut ledger,
            asset,
            1,
            CompliancePolicy {
                transfer_control: TransferControl::DenyList([id("bob.sov")].into_iter().collect()),
                ..CompliancePolicy::default()
            },
        )
        .succeeded());
        let r = apply_transaction(
            &mut ledger,
            &fill(usa_intent(asset, 0), 95, 0),
            &ctx_at(10, &p),
        )
        .unwrap();
        assert!(
            !r.succeeded(),
            "a settlement whose token leg violates compliance must fail"
        );
        assert_eq!(ledger.token_balance(&asset, &id("bob.sov")), Balance::ZERO);
        assert_eq!(
            ledger.account(&id("bob.sov")).balance,
            Balance::from_sov(1_000).unwrap(),
            "the solver's SOV leg must not half-apply"
        );
    }

    #[test]
    fn token_for_token_settlement_conserves_both_assets() {
        use sov_state::token_asset_id;
        use sov_verify::{check_ledger, check_transition};
        let (mut ledger, usd1) = liquidity_setup();
        let p = policy();
        // bob issues his own asset GOLD and offers it for usa's USD1.
        let gold = token_asset_id(&id("bob.sov"), "GOLD");
        let issue = signed(
            [2; 32],
            "bob.sov",
            0,
            Action::TokenIssue {
                symbol: "GOLD".into(),
                amount: Balance::from_sov(500).unwrap(),
                to: id("bob.sov"),
            },
        );
        assert!(apply_transaction(&mut ledger, &issue, &ctx(&p))
            .unwrap()
            .succeeded());

        let kp = Keypair::from_seed([1; 32]);
        let intent = Intent {
            owner: id("usa.reserve.sov"),
            public_key: kp.public_key(),
            nonce: 7,
            give_asset: IntentAsset::Token(usd1),
            give_amount: Balance::from_sov(200).unwrap().grains(),
            want_asset: IntentAsset::Token(gold),
            min_receive: Balance::from_sov(50).unwrap().grains(),
            expiry_height: 100,
        }
        .sign(&kp)
        .unwrap();
        let before = ledger.clone();
        let stx = signed(
            [2; 32],
            "bob.sov",
            1,
            Action::IntentSettle {
                settlement: Settlement {
                    intent,
                    solver: id("bob.sov"),
                    deliver_amount: Balance::from_sov(60).unwrap().grains(),
                },
            },
        );
        assert!(apply_transaction(&mut ledger, &stx, &ctx_at(10, &p))
            .unwrap()
            .succeeded());
        assert_eq!(
            ledger.token_balance(&usd1, &id("bob.sov")),
            Balance::from_sov(200).unwrap()
        );
        assert_eq!(
            ledger.token_balance(&gold, &id("usa.reserve.sov")),
            Balance::from_sov(60).unwrap()
        );
        check_transition(&before, &ledger).unwrap();
        check_ledger(&ledger, &p).unwrap();
    }

    // ---- Key rotation (cryptographic agility) ----

    #[test]
    fn rotate_key_replaces_the_controlling_key_and_kills_the_old_one() {
        use sov_types::rotation_signing_bytes;
        let mut ledger = ledger_with_usa(100);
        let p = policy();
        let new_kp = Keypair::from_seed([42; 32]);
        let new_key = new_kp.public_key();

        // Rotation: signed by the CURRENT key, possession proven by the NEW key.
        let proof = new_kp.sign(&rotation_signing_bytes(&id("usa.reserve.sov"), 0, &new_key));
        let rotate = signed(
            [1; 32],
            "usa.reserve.sov",
            0,
            Action::RotateKey { new_key, proof },
        );
        assert!(apply_transaction(&mut ledger, &rotate, &ctx(&p))
            .unwrap()
            .succeeded());
        assert_eq!(ledger.account(&id("usa.reserve.sov")).key, Some(new_key));
        assert_eq!(
            ledger.account(&id("usa.reserve.sov")).balance,
            Balance::from_sov(100).unwrap(),
            "rotation moves no funds"
        );

        // The OLD key is dead: a transfer signed with it is unauthorized.
        let stale = transfer([1; 32], "usa.reserve.sov", "ecb.reserve.sov", 10, 1);
        assert_eq!(
            apply_transaction(&mut ledger, &stale, &ctx(&p)),
            Err(ExecutionError::Unauthorized {
                account: "usa.reserve.sov".into()
            })
        );

        // The NEW key controls the account.
        let fresh = transfer([42; 32], "usa.reserve.sov", "ecb.reserve.sov", 10, 1);
        assert!(apply_transaction(&mut ledger, &fresh, &ctx(&p))
            .unwrap()
            .succeeded());
    }

    #[test]
    fn rotation_requires_a_possession_proof_from_the_new_key() {
        use sov_types::rotation_signing_bytes;
        let mut ledger = ledger_with_usa(100);
        let p = policy();
        let old_kp = Keypair::from_seed([1; 32]);
        let new_key = Keypair::from_seed([42; 32]).public_key();

        // Proof signed by the OLD key (owner does not hold the new key): fails.
        let bad_proof = old_kp.sign(&rotation_signing_bytes(&id("usa.reserve.sov"), 0, &new_key));
        let rotate = signed(
            [1; 32],
            "usa.reserve.sov",
            0,
            Action::RotateKey {
                new_key,
                proof: bad_proof,
            },
        );
        let r = apply_transaction(&mut ledger, &rotate, &ctx(&p)).unwrap();
        assert!(!r.succeeded(), "an unpossessed key must never be installed");
        assert_eq!(
            ledger.account(&id("usa.reserve.sov")).key,
            Some(old_kp.public_key()),
            "the controlling key is unchanged"
        );
    }

    #[test]
    fn rotation_proofs_are_bound_to_account_and_nonce() {
        use sov_types::rotation_signing_bytes;
        let mut ledger = ledger_with_usa(100);
        let bob = Keypair::from_seed([2; 32]);
        ledger.set_account(
            &id("bob.sov"),
            Account::new(bob.public_key(), Balance::ZERO),
        );
        let p = policy();
        let new_kp = Keypair::from_seed([42; 32]);
        let new_key = new_kp.public_key();

        // A proof minted for usa's rotation (nonce 0) cannot rotate bob's
        // account: the signed message names the account.
        let usa_proof = new_kp.sign(&rotation_signing_bytes(&id("usa.reserve.sov"), 0, &new_key));
        let cross = signed(
            [2; 32],
            "bob.sov",
            0,
            Action::RotateKey {
                new_key,
                proof: usa_proof,
            },
        );
        assert!(!apply_transaction(&mut ledger, &cross, &ctx(&p))
            .unwrap()
            .succeeded());
        assert_eq!(ledger.account(&id("bob.sov")).key, Some(bob.public_key()));

        // Nor can usa's own nonce-0 proof be used at a later nonce: the nonce
        // is in the signed message, so each proof is single-use.
        let burn_nonce = transfer([1; 32], "usa.reserve.sov", "ecb.reserve.sov", 1, 0);
        apply_transaction(&mut ledger, &burn_nonce, &ctx(&p)).unwrap();
        let usa_proof = new_kp.sign(&rotation_signing_bytes(&id("usa.reserve.sov"), 0, &new_key));
        let stale = signed(
            [1; 32],
            "usa.reserve.sov",
            1,
            Action::RotateKey {
                new_key,
                proof: usa_proof,
            },
        );
        assert!(!apply_transaction(&mut ledger, &stale, &ctx(&p))
            .unwrap()
            .succeeded());
    }

    #[test]
    fn an_implicit_account_can_be_claimed_only_by_its_own_key() {
        use sov_types::rotation_signing_bytes;
        let p = policy();

        // A miner's key, and the IMPLICIT account its coinbase pays. The account
        // is keyless but funded — exactly the post-mining, pre-activation state
        // a squatter tried to inherit.
        let miner = Keypair::from_seed([42; 32]);
        let mined = miner.public_key().implicit_account_id();
        assert!(mined.is_implicit());
        let mut ledger = Ledger::new();
        ledger.set_account(
            &mined,
            Account::with_balance(Balance::from_sov(100).unwrap()),
        );

        // ATTACKER: a different key tries to claim the funded implicit account.
        // It must sign with its OWN key (it cannot forge the miner's), so the
        // claim is rejected — the id is not this key's hash.
        let thief = Keypair::from_seed([7; 32]);
        let thief_key = thief.public_key();
        let thief_proof = thief.sign(&rotation_signing_bytes(&mined, 0, &thief_key));
        let steal = SignedTransaction::sign(
            Transaction {
                signer: mined.clone(),
                public_key: thief_key,
                nonce: 0,
                action: Action::RotateKey {
                    new_key: thief_key,
                    proof: thief_proof,
                },
            },
            &thief,
        )
        .unwrap();
        assert_eq!(
            apply_transaction(&mut ledger, &steal, &ctx(&p)),
            Err(ExecutionError::Unauthorized {
                account: mined.to_string()
            }),
            "a stranger's key must never claim an implicit account"
        );
        assert!(
            ledger.account(&mined).key.is_none(),
            "the implicit account is still unclaimed after the theft attempt"
        );

        // RIGHTFUL OWNER: the miner — whose key hashes to the id — claims it.
        let miner_key = miner.public_key();
        let proof = miner.sign(&rotation_signing_bytes(&mined, 0, &miner_key));
        let claim = SignedTransaction::sign(
            Transaction {
                signer: mined.clone(),
                public_key: miner_key,
                nonce: 0,
                action: Action::RotateKey {
                    new_key: miner_key,
                    proof,
                },
            },
            &miner,
        )
        .unwrap();
        assert!(apply_transaction(&mut ledger, &claim, &ctx(&p))
            .unwrap()
            .succeeded());
        assert_eq!(ledger.account(&mined).key, Some(miner_key));

        // …and only now can the mined funds move.
        let spend = transfer([42; 32], mined.as_str(), "ecb.reserve.sov", 10, 1);
        assert!(apply_transaction(&mut ledger, &spend, &ctx(&p))
            .unwrap()
            .succeeded());
    }

    #[test]
    fn an_implicit_account_spends_directly_with_its_key_no_activation() {
        let p = policy();

        // A funded, KEYLESS implicit account (a freshly-mined coinbase id).
        let miner = Keypair::from_seed([42; 32]);
        let mined = miner.public_key().implicit_account_id();
        let mut ledger = Ledger::new();
        ledger.set_account(
            &mined,
            Account::with_balance(Balance::from_sov(100).unwrap()),
        );
        assert!(ledger.account(&mined).key.is_none(), "starts keyless");

        // A STRANGER cannot spend it directly (their key's hash isn't the id).
        let thief_spend = transfer([7; 32], mined.as_str(), "ecb.reserve.sov", 10, 0);
        assert_eq!(
            apply_transaction(&mut ledger, &thief_spend, &ctx(&p)),
            Err(ExecutionError::Unauthorized {
                account: mined.to_string()
            }),
        );

        // The OWNER spends DIRECTLY — no RotateKey/activation first. The key whose
        // hash IS the id self-certifies; it binds on first use.
        let spend = transfer([42; 32], mined.as_str(), "ecb.reserve.sov", 40, 0);
        assert!(apply_transaction(&mut ledger, &spend, &ctx(&p))
            .unwrap()
            .succeeded());
        assert_eq!(
            ledger.account(&mined).balance,
            Balance::from_sov(60).unwrap(),
            "funds moved without any activation step"
        );
        assert_eq!(
            ledger.account(&mined).key,
            Some(miner.public_key()),
            "the key bound itself on first use"
        );
    }

    // ---- Shielded-pool drain limiter (p18-i4) ----

    #[test]
    fn deshield_rate_limit_caps_pool_outflow_per_window() {
        use sov_shielded::{
            mint_to_shielded, recover_outputs, unshield, witness_latest, ShieldedKey,
            ShieldedParams,
        };
        use sov_verify::{check_ledger, check_transition};

        // Policy with the drain limiter ON: 100-block windows. Two variants:
        // a 30-SOV cap (under the de-shield) and a 60-SOV cap (over it).
        let mut tight = MiningPolicy::test();
        tight.deshield_window_blocks = 100;
        tight.deshield_limit_grains = Balance::from_sov(30).unwrap().grains();
        let mut roomy = tight.clone();
        roomy.deshield_limit_grains = Balance::from_sov(60).unwrap().grains();

        let mut ledger = ledger_with_usa(100);
        let params = ShieldedParams::build();
        let alice = ShieldedKey::from_seed([9u8; 32]).unwrap();
        let fifty = Balance::from_sov(50).unwrap();
        let kp = Keypair::from_seed([1; 32]);
        let shielded_tx = |nonce: u64, bytes: Vec<u8>| {
            SignedTransaction::sign(
                Transaction {
                    signer: id("usa.reserve.sov"),
                    public_key: kp.public_key(),
                    nonce,
                    action: Action::Shielded { bundle: bytes },
                },
                &kp,
            )
            .unwrap()
        };

        // 1. Shield 50 SOV (REAL proof). The limiter only meters OUTFLOW, so
        //    a shield is unaffected even under the tight policy.
        let mint = mint_to_shielded(&params, &alice.address(), 50 * 100_000_000).unwrap();
        let r = apply_transaction(
            &mut ledger,
            &shielded_tx(0, mint.to_bytes()),
            &ctx_at(10, &tight),
        )
        .unwrap();
        assert!(r.succeeded(), "shielding is never rate-limited");
        assert_eq!(ledger.shielded_value(), fifty);

        // 2. Build the REAL de-shield: spend Alice's note with no output
        //    (value balance +50 SOV), witnessed against the pool's own tree.
        let note = recover_outputs(&alice, &mint).remove(0);
        let (path, tree_anchor) = witness_latest(&mint.note_commitment_bytes()).unwrap();
        let out = unshield(&params, &alice, &note, path, tree_anchor).unwrap();
        assert_eq!(
            out.value_balance(),
            i64::try_from(fifty.grains()).unwrap(),
            "an unshield's value balance is the de-shielded amount"
        );

        // 3. Under the 30-SOV cap, the 50-SOV de-shield FAILS — and nothing
        //    moves: pool intact, nullifier unconsumed, window untouched.
        let r = apply_transaction(
            &mut ledger,
            &shielded_tx(1, out.to_bytes()),
            &ctx_at(20, &tight),
        )
        .unwrap();
        assert!(!r.succeeded(), "a de-shield over the window cap must fail");
        assert_eq!(ledger.shielded_value(), fifty, "pool is untouched");
        assert_eq!(ledger.deshield_window(), (0, Balance::ZERO));

        // 4. Under the 60-SOV cap, the SAME bundle settles: pool drains,
        //    signer credited, and the window records the outflow.
        let before = ledger.clone();
        let r = apply_transaction(
            &mut ledger,
            &shielded_tx(2, out.to_bytes()),
            &ctx_at(20, &roomy),
        )
        .unwrap();
        assert!(r.succeeded(), "an in-cap de-shield settles: {:?}", r.status);
        assert_eq!(ledger.shielded_value(), Balance::ZERO);
        assert_eq!(
            ledger.account(&id("usa.reserve.sov")).balance,
            Balance::from_sov(100).unwrap(),
            "50 shielded out, 50 de-shielded back"
        );
        // The first window is anchored at genesis (start 0, [0,100)), same
        // semantics as the compliance SpendWindow; the outflow is recorded.
        assert_eq!(ledger.deshield_window(), (0, fifty));
        // Conservation holds through the metered de-shield.
        check_transition(&before, &ledger).unwrap();
        check_ledger(&ledger, &roomy).unwrap();
    }

    // ---- Post-quantum sunset policy (the Q-day runbook) ----

    use sov_mining::PqSchedule;

    /// A context at `height` with the PQ schedule: rotation window opens at
    /// 100, sunset at 200, threshold 50 SOV.
    fn pq_ctx(height: u64, p: &MiningPolicy) -> BlockContext<'_> {
        BlockContext {
            height,
            prev_hash: Hash::ZERO,
            mining: p,
            gas_price: Balance::ZERO,
            miner: miner_id(),
            pq: Some(PqSchedule {
                rotation_only_height: 100,
                sunset_height: 200,
                threshold_grains: Balance::from_sov(50).unwrap().grains(),
            }),
        }
    }

    #[test]
    fn pq_window_forces_rich_legacy_accounts_to_rotate_and_only_to_hybrid() {
        use sov_types::rotation_signing_bytes;
        let p = policy();
        // usa holds 100 SOV (over the 50 threshold) on a V1 key.
        let mut ledger = ledger_with_usa(100);

        // Before the window (height 99): a V1 transfer is fine.
        let t = transfer([1; 32], "usa.reserve.sov", "ecb.reserve.sov", 1, 0);
        assert!(apply_transaction(&mut ledger, &t, &pq_ctx(99, &p))
            .unwrap()
            .succeeded());

        // Inside the window (height 100): the same transfer is REJECTED.
        let t = transfer([1; 32], "usa.reserve.sov", "ecb.reserve.sov", 1, 1);
        assert!(matches!(
            apply_transaction(&mut ledger, &t, &pq_ctx(100, &p)),
            Err(ExecutionError::PqRotationRequired { .. })
        ));

        // A V1 -> V1 rotation does not evade the sunset: rejected.
        let evade_kp = Keypair::from_seed([50; 32]);
        let evade_key = evade_kp.public_key();
        let evade_proof = evade_kp.sign(&rotation_signing_bytes(
            &id("usa.reserve.sov"),
            1,
            &evade_key,
        ));
        let evade = signed(
            [1; 32],
            "usa.reserve.sov",
            1,
            Action::RotateKey {
                new_key: evade_key,
                proof: evade_proof,
            },
        );
        assert!(matches!(
            apply_transaction(&mut ledger, &evade, &pq_ctx(100, &p)),
            Err(ExecutionError::PqRotationRequired { .. })
        ));

        // The rotation to a HYBRID key is the one admissible action.
        let hybrid = Keypair::hybrid_from_seed([51; 32]);
        let new_key = hybrid.public_key();
        let proof = hybrid.sign(&rotation_signing_bytes(&id("usa.reserve.sov"), 1, &new_key));
        let rotate = signed(
            [1; 32],
            "usa.reserve.sov",
            1,
            Action::RotateKey { new_key, proof },
        );
        assert!(apply_transaction(&mut ledger, &rotate, &pq_ctx(100, &p))
            .unwrap()
            .succeeded());

        // Migrated: the hybrid account transacts freely inside the window.
        let tx = Transaction {
            signer: id("usa.reserve.sov"),
            public_key: new_key,
            nonce: 2,
            action: Action::Transfer {
                to: id("ecb.reserve.sov"),
                amount: Balance::from_sov(1).unwrap(),
            },
        };
        let stx = SignedTransaction::sign(tx, &hybrid).unwrap();
        assert!(apply_transaction(&mut ledger, &stx, &pq_ctx(150, &p))
            .unwrap()
            .succeeded());
    }

    #[test]
    fn pq_window_spares_small_legacy_accounts_until_the_sunset() {
        let p = policy();
        // bob holds 10 SOV (under the 50 threshold) on a V1 key.
        let mut ledger = Ledger::new();
        let bob = Keypair::from_seed([2; 32]);
        ledger.set_account(
            &id("bob.sov"),
            Account::new(bob.public_key(), Balance::from_sov(10).unwrap()),
        );

        // Inside the window: small accounts still transact on V1.
        let t = transfer([2; 32], "bob.sov", "carol.sov", 1, 0);
        assert!(apply_transaction(&mut ledger, &t, &pq_ctx(150, &p))
            .unwrap()
            .succeeded());

        // At the sunset (height 200): ALL V1 signatures are rejected — even
        // the rotation itself (a V1 signature no longer proves ownership).
        let t = transfer([2; 32], "bob.sov", "carol.sov", 1, 1);
        assert!(matches!(
            apply_transaction(&mut ledger, &t, &pq_ctx(200, &p)),
            Err(ExecutionError::PqSunset { .. })
        ));
        let hybrid = Keypair::hybrid_from_seed([52; 32]);
        let new_key = hybrid.public_key();
        let proof = hybrid.sign(&sov_types::rotation_signing_bytes(
            &id("bob.sov"),
            1,
            &new_key,
        ));
        let late_rotate = signed([2; 32], "bob.sov", 1, Action::RotateKey { new_key, proof });
        assert!(matches!(
            apply_transaction(&mut ledger, &late_rotate, &pq_ctx(200, &p)),
            Err(ExecutionError::PqSunset { .. })
        ));
        // The funds are frozen, not stolen: balance intact.
        assert_eq!(
            ledger.account(&id("bob.sov")).balance,
            Balance::from_sov(9).unwrap()
        );
    }

    #[test]
    fn pq_sunset_never_touches_hybrid_accounts() {
        let p = policy();
        let hybrid = Keypair::hybrid_from_seed([53; 32]);
        let mut ledger = Ledger::new();
        ledger.set_account(
            &id("pq.reserve.sov"),
            Account::new(hybrid.public_key(), Balance::from_sov(1_000).unwrap()),
        );
        // Far past the sunset, far above the threshold: hybrid transacts freely.
        let tx = Transaction {
            signer: id("pq.reserve.sov"),
            public_key: hybrid.public_key(),
            nonce: 0,
            action: Action::Transfer {
                to: id("ecb.reserve.sov"),
                amount: Balance::from_sov(100).unwrap(),
            },
        };
        let stx = SignedTransaction::sign(tx, &hybrid).unwrap();
        assert!(apply_transaction(&mut ledger, &stx, &pq_ctx(10_000, &p))
            .unwrap()
            .succeeded());
    }

    // ---- Hybrid post-quantum keys (Ed25519 + ML-DSA-65) ----

    #[test]
    fn account_migrates_to_a_hybrid_pq_key_and_transacts_under_it() {
        use sov_types::rotation_signing_bytes;
        // The full Phase 18 migration flow on a real ledger: a V1 (Ed25519)
        // account rotates to a hybrid Ed25519+ML-DSA-65 key — possession
        // proven by a REAL hybrid signature — then transacts under it. The
        // old V1 key is dead; quantum-breaking Ed25519 alone no longer
        // suffices to spend from this account.
        let mut ledger = ledger_with_usa(100);
        let p = policy();
        let hybrid = Keypair::hybrid_from_seed([77; 32]);
        let new_key = hybrid.public_key();
        assert_eq!(new_key.scheme(), "hybrid65");

        let proof = hybrid.sign(&rotation_signing_bytes(&id("usa.reserve.sov"), 0, &new_key));
        let rotate = signed(
            [1; 32],
            "usa.reserve.sov",
            0,
            Action::RotateKey { new_key, proof },
        );
        assert!(apply_transaction(&mut ledger, &rotate, &ctx(&p))
            .unwrap()
            .succeeded());
        assert_eq!(ledger.account(&id("usa.reserve.sov")).key, Some(new_key));

        // The old Ed25519 key no longer controls the account.
        let stale = transfer([1; 32], "usa.reserve.sov", "ecb.reserve.sov", 10, 1);
        assert!(matches!(
            apply_transaction(&mut ledger, &stale, &ctx(&p)),
            Err(ExecutionError::Unauthorized { .. })
        ));

        // A transfer signed by the HYBRID keypair (both component signatures
        // verified by consensus) moves funds.
        let tx = Transaction {
            signer: id("usa.reserve.sov"),
            public_key: new_key,
            nonce: 1,
            action: Action::Transfer {
                to: id("ecb.reserve.sov"),
                amount: Balance::from_sov(10).unwrap(),
            },
        };
        let stx = SignedTransaction::sign(tx, &hybrid).unwrap();
        assert!(stx.verify_signature());
        assert!(apply_transaction(&mut ledger, &stx, &ctx(&p))
            .unwrap()
            .succeeded());
        assert_eq!(
            ledger.account(&id("ecb.reserve.sov")).balance,
            Balance::from_sov(10).unwrap()
        );

        // Tampering with either signed byte (including the scheme byte inside
        // the signing payload) invalidates the hybrid signature.
        let mut tampered = stx.clone();
        tampered.transaction.nonce = 99;
        assert!(!tampered.verify_signature());
    }

    #[test]
    fn hybrid_envelopes_pay_the_per_byte_surcharge_v1_fees_unchanged() {
        use crate::gas::{envelope_gas, CALLDATA_GAS_PER_BYTE, INTRINSIC_GAS, ML_DSA_VERIFY_GAS};
        use sov_crypto::{ML_DSA_65_PK_LEN, ML_DSA_65_SIG_LEN};

        let p = policy();
        let bctx = BlockContext {
            height: 1,
            prev_hash: Hash::ZERO,
            mining: &p,
            gas_price: Balance::from_grains(1),
            miner: miner_id(),
            pq: None,
        };

        // A V1 transfer pays exactly the intrinsic gas — no envelope charge.
        let mut ledger = ledger_with_usa(100);
        let before = ledger.account(&id("usa.reserve.sov")).balance.grains();
        let v1 = transfer([1; 32], "usa.reserve.sov", "ecb.reserve.sov", 1, 0);
        let r = apply_transaction(&mut ledger, &v1, &bctx).unwrap();
        assert!(r.succeeded());
        let v1_fee = before
            - ledger.account(&id("usa.reserve.sov")).balance.grains()
            - Balance::from_sov(1).unwrap().grains();
        assert_eq!(v1_fee, u128::from(INTRINSIC_GAS), "V1 fees are unchanged");

        // The same transfer under a hybrid key pays the documented surcharge.
        let hybrid = Keypair::hybrid_from_seed([78; 32]);
        let mut ledger2 = Ledger::new();
        ledger2.set_account(
            &id("usa.reserve.sov"),
            Account::new(hybrid.public_key(), Balance::from_sov(100).unwrap()),
        );
        let tx = Transaction {
            signer: id("usa.reserve.sov"),
            public_key: hybrid.public_key(),
            nonce: 0,
            action: Action::Transfer {
                to: id("ecb.reserve.sov"),
                amount: Balance::from_sov(1).unwrap(),
            },
        };
        let stx = SignedTransaction::sign(tx, &hybrid).unwrap();
        let before2 = ledger2.account(&id("usa.reserve.sov")).balance.grains();
        let r2 = apply_transaction(&mut ledger2, &stx, &bctx).unwrap();
        assert!(r2.succeeded());
        let hybrid_fee = before2
            - ledger2.account(&id("usa.reserve.sov")).balance.grains()
            - Balance::from_sov(1).unwrap().grains();
        let expected_surcharge = (ML_DSA_65_PK_LEN + ML_DSA_65_SIG_LEN) as u128
            * u128::from(CALLDATA_GAS_PER_BYTE)
            + u128::from(ML_DSA_VERIFY_GAS);
        assert_eq!(hybrid_fee, u128::from(INTRINSIC_GAS) + expected_surcharge);
        assert_eq!(
            envelope_gas(&hybrid.public_key()) as u128,
            expected_surcharge
        );
    }

    #[test]
    fn claim_vesting_releases_locked_funds_after_unlock() {
        let mut ledger = Ledger::new();
        let p = policy();
        // A vesting account: keyed, 0 liquid, 500 locked until height 100.
        let key = Keypair::from_seed([1; 32]).public_key();
        ledger.set_account(
            &id("foundation.sov"),
            Account {
                balance: Balance::ZERO,
                locked: Balance::from_sov(500).unwrap(),
                unlock_height: 100,
                key: Some(key),
                ..Account::default()
            },
        );

        // Before unlock: claim fails, nothing moves.
        let early = action_tx([1; 32], "foundation.sov", Action::ClaimVesting, 0);
        assert!(!apply_transaction(&mut ledger, &early, &ctx_at(99, &p))
            .unwrap()
            .succeeded());
        assert_eq!(ledger.account(&id("foundation.sov")).balance, Balance::ZERO);

        // At/after unlock: locked funds move to the liquid balance.
        let ok = action_tx([1; 32], "foundation.sov", Action::ClaimVesting, 1);
        assert!(apply_transaction(&mut ledger, &ok, &ctx_at(100, &p))
            .unwrap()
            .succeeded());
        let acct = ledger.account(&id("foundation.sov"));
        assert_eq!(acct.balance, Balance::from_sov(500).unwrap());
        assert_eq!(acct.locked, Balance::ZERO);
    }

    #[test]
    fn register_name_aliases_the_signer_account_and_pays_the_fee_to_miners() {
        // usa.reserve.sov registers "treasury.sov": it must RESOLVE to usa (the
        // signer's own account — funds never move into the name), cost the
        // one-time fee, and that fee must be EARNED (distributed to the miner),
        // never burned, so SOV supply is conserved.
        let mut ledger = ledger_with_usa(100);
        let p = policy();
        let before = ledger.clone();
        let reg = signed(
            [1; 32],
            "usa.reserve.sov",
            0,
            Action::RegisterName {
                name: "treasury.sov".into(),
            },
        );
        assert!(apply_transaction(&mut ledger, &reg, &ctx(&p))
            .unwrap()
            .succeeded());

        // ENS/SNS resolution: the alias points at the registrant's account.
        assert_eq!(
            ledger.resolve_name("treasury.sov"),
            Some(id("usa.reserve.sov"))
        );
        assert_eq!(
            ledger.names_owned_by(&id("usa.reserve.sov")),
            vec!["treasury.sov".to_string()]
        );
        assert_eq!(
            ledger.name_record("treasury.sov").unwrap().owner,
            id("usa.reserve.sov")
        );

        // The registrant paid exactly the 1-XUS fee...
        let fee = Balance::from_grains(NAME_REGISTRATION_FEE_GRAINS);
        assert_eq!(
            ledger.account(&id("usa.reserve.sov")).balance,
            Balance::from_sov(100).unwrap().checked_sub(fee).unwrap()
        );
        // ...and it was EARNED by the miner (not burned). Supply is conserved
        // across the transition (Δmined == 0, value only moved).
        assert!(ledger.account(&miner_id()).balance > Balance::ZERO);
        use sov_verify::check_transition;
        check_transition(&before, &ledger).expect("fee earned, not burned — value conserved");
    }

    #[test]
    fn transfer_to_an_sns_name_resolves_to_the_owner_not_a_squattable_name() {
        // The SNS-handled-better fix: a transfer to a registered `.sov` name credits the
        // name's OWNER (its resolved account), and NEVER creates a bare keyless `shop.sov`
        // account that a stranger could claim first-come. Native + token transfers both.
        let mut ledger = ledger_with_usa(1_000);
        let p = policy();

        // usa registers "shop.sov" → it resolves to usa.
        let reg = signed(
            [1; 32],
            "usa.reserve.sov",
            0,
            Action::RegisterName {
                name: "shop.sov".into(),
            },
        );
        assert!(apply_transaction(&mut ledger, &reg, &ctx(&p))
            .unwrap()
            .succeeded());
        assert_eq!(ledger.resolve_name("shop.sov"), Some(id("usa.reserve.sov")));

        // Fund a separate implicit sender B, then B sends 50 to the NAME "shop.sov".
        let b_id = Keypair::from_seed([2; 32])
            .public_key()
            .implicit_account_id();
        let fund = transfer([1; 32], "usa.reserve.sov", b_id.as_str(), 200, 1);
        assert!(apply_transaction(&mut ledger, &fund, &ctx(&p))
            .unwrap()
            .succeeded());
        let usa_before = ledger.account(&id("usa.reserve.sov")).balance;

        let pay = transfer([2; 32], b_id.as_str(), "shop.sov", 50, 0);
        assert!(apply_transaction(&mut ledger, &pay, &ctx(&p))
            .unwrap()
            .succeeded());

        // The 50 landed on usa (the resolved owner)…
        assert_eq!(
            ledger.account(&id("usa.reserve.sov")).balance,
            usa_before
                .checked_add(Balance::from_sov(50).unwrap())
                .unwrap()
        );
        // …and NO literal "shop.sov" account was ever created — the squat footgun is closed.
        assert!(!ledger.exists(&id("shop.sov")));
        assert_eq!(ledger.account(&id("shop.sov")).balance, Balance::ZERO);
    }

    #[test]
    fn register_name_rejects_bad_shape_shadows_and_duplicates() {
        let mut ledger = ledger_with_usa(100);
        let p = policy();

        // Not a *.sov name → rejected (and the name does not resolve).
        let bad = signed(
            [1; 32],
            "usa.reserve.sov",
            0,
            Action::RegisterName {
                name: "treasury".into(),
            },
        );
        assert!(!apply_transaction(&mut ledger, &bad, &ctx(&p))
            .unwrap()
            .succeeded());
        assert_eq!(ledger.resolve_name("treasury"), None);

        // Shadowing an existing keyed account (usa itself) is refused.
        let shadow = signed(
            [1; 32],
            "usa.reserve.sov",
            1,
            Action::RegisterName {
                name: "usa.reserve.sov".into(),
            },
        );
        assert!(!apply_transaction(&mut ledger, &shadow, &ctx(&p))
            .unwrap()
            .succeeded());

        // A fresh name registers; a second claim (even by another account) fails.
        let ok = signed(
            [1; 32],
            "usa.reserve.sov",
            2,
            Action::RegisterName {
                name: "treasury.sov".into(),
            },
        );
        assert!(apply_transaction(&mut ledger, &ok, &ctx(&p))
            .unwrap()
            .succeeded());
        let bob = Keypair::from_seed([2; 32]).public_key();
        ledger.set_account(
            &id("bob.sov"),
            Account::new(bob, Balance::from_sov(100).unwrap()),
        );
        let dup = signed(
            [2; 32],
            "bob.sov",
            0,
            Action::RegisterName {
                name: "treasury.sov".into(),
            },
        );
        assert!(!apply_transaction(&mut ledger, &dup, &ctx(&p))
            .unwrap()
            .succeeded());
        // Still resolves to the original owner.
        assert_eq!(
            ledger.resolve_name("treasury.sov"),
            Some(id("usa.reserve.sov"))
        );
    }

    #[test]
    fn transfer_name_moves_ownership_only_for_the_current_owner() {
        let mut ledger = ledger_with_usa(100);
        let p = policy();
        let bobk = Keypair::from_seed([2; 32]).public_key();
        ledger.set_account(
            &id("bob.sov"),
            Account::new(bobk, Balance::from_sov(100).unwrap()),
        );

        let reg = signed(
            [1; 32],
            "usa.reserve.sov",
            0,
            Action::RegisterName {
                name: "treasury.sov".into(),
            },
        );
        assert!(apply_transaction(&mut ledger, &reg, &ctx(&p))
            .unwrap()
            .succeeded());

        // A non-owner cannot transfer the name.
        let steal = signed(
            [2; 32],
            "bob.sov",
            0,
            Action::TransferName {
                name: "treasury.sov".into(),
                to: id("bob.sov"),
            },
        );
        assert!(!apply_transaction(&mut ledger, &steal, &ctx(&p))
            .unwrap()
            .succeeded());
        assert_eq!(
            ledger.resolve_name("treasury.sov"),
            Some(id("usa.reserve.sov"))
        );

        // The owner hands it to bob; it now resolves to and is owned by bob.
        let give = signed(
            [1; 32],
            "usa.reserve.sov",
            1,
            Action::TransferName {
                name: "treasury.sov".into(),
                to: id("bob.sov"),
            },
        );
        assert!(apply_transaction(&mut ledger, &give, &ctx(&p))
            .unwrap()
            .succeeded());
        assert_eq!(ledger.resolve_name("treasury.sov"), Some(id("bob.sov")));
        assert_eq!(
            ledger.names_owned_by(&id("bob.sov")),
            vec!["treasury.sov".to_string()]
        );
        assert!(ledger.names_owned_by(&id("usa.reserve.sov")).is_empty());
    }

    #[test]
    fn register_name_requires_funds_for_the_fee() {
        let mut ledger = Ledger::new();
        let key = Keypair::from_seed([5; 32]).public_key();
        // Less than the 1-XUS registration fee.
        ledger.set_account(&id("poor.sov"), Account::new(key, Balance::from_grains(1)));
        let p = policy();
        let reg = signed(
            [5; 32],
            "poor.sov",
            0,
            Action::RegisterName {
                name: "broke.sov".into(),
            },
        );
        assert!(!apply_transaction(&mut ledger, &reg, &ctx(&p))
            .unwrap()
            .succeeded());
        assert_eq!(ledger.resolve_name("broke.sov"), None);
    }

    #[test]
    fn nft_mint_is_issuer_bound_unique_and_transferable() {
        let mut ledger = ledger_with_usa(100);
        let p = policy();
        let class = sov_state::nft_class_id(&id("usa.reserve.sov"), "art");

        // usa mints item "1" in collection "art" to itself.
        let mint = signed(
            [1; 32],
            "usa.reserve.sov",
            0,
            Action::NftMint {
                symbol: "art".into(),
                token_id: b"1".to_vec(),
                to: id("usa.reserve.sov"),
                metadata: b"ipfs://x".to_vec(),
            },
        );
        assert!(apply_transaction(&mut ledger, &mint, &ctx(&p))
            .unwrap()
            .succeeded());
        assert_eq!(ledger.nft_owner(&class, b"1"), Some(id("usa.reserve.sov")));
        assert_eq!(ledger.nft_class(&class).unwrap().minted, 1);

        // Non-fungible: minting the same item id again is rejected.
        let dup = signed(
            [1; 32],
            "usa.reserve.sov",
            1,
            Action::NftMint {
                symbol: "art".into(),
                token_id: b"1".to_vec(),
                to: id("usa.reserve.sov"),
                metadata: vec![],
            },
        );
        assert!(!apply_transaction(&mut ledger, &dup, &ctx(&p))
            .unwrap()
            .succeeded());

        // Only the owner may transfer; a non-owner is refused, the owner succeeds.
        let bobk = Keypair::from_seed([2; 32]).public_key();
        ledger.set_account(
            &id("bob.sov"),
            Account::new(bobk, Balance::from_sov(10).unwrap()),
        );
        let steal = signed(
            [2; 32],
            "bob.sov",
            0,
            Action::NftTransfer {
                collection: class,
                token_id: b"1".to_vec(),
                to: id("bob.sov"),
            },
        );
        assert!(!apply_transaction(&mut ledger, &steal, &ctx(&p))
            .unwrap()
            .succeeded());
        let give = signed(
            [1; 32],
            "usa.reserve.sov",
            2,
            Action::NftTransfer {
                collection: class,
                token_id: b"1".to_vec(),
                to: id("bob.sov"),
            },
        );
        assert!(apply_transaction(&mut ledger, &give, &ctx(&p))
            .unwrap()
            .succeeded());
        assert_eq!(ledger.nft_owner(&class, b"1"), Some(id("bob.sov")));

        // The new owner (bob) sets metadata — the resolver/records hook.
        let meta = signed(
            [2; 32],
            "bob.sov",
            1,
            Action::NftSetMeta {
                collection: class,
                token_id: b"1".to_vec(),
                metadata: b"new".to_vec(),
            },
        );
        assert!(apply_transaction(&mut ledger, &meta, &ctx(&p))
            .unwrap()
            .succeeded());
        assert_eq!(ledger.nft(&class, b"1").unwrap().metadata, b"new".to_vec());
    }

    #[test]
    fn sns_names_are_nfts_in_the_reserved_collection() {
        // A registered SNS name IS an NFT in the reserved SNS collection — the two
        // views agree, proving names are non-fungible tokens.
        let mut ledger = ledger_with_usa(100);
        let p = policy();
        let reg = signed(
            [1; 32],
            "usa.reserve.sov",
            0,
            Action::RegisterName {
                name: "bank.sov".into(),
            },
        );
        assert!(apply_transaction(&mut ledger, &reg, &ctx(&p))
            .unwrap()
            .succeeded());
        // Resolves via the SNS façade...
        assert_eq!(ledger.resolve_name("bank.sov"), Some(id("usa.reserve.sov")));
        // ...and is the same item via the generic NFT view.
        assert_eq!(
            ledger.nft_owner(&sov_state::sns_class(), b"bank.sov"),
            Some(id("usa.reserve.sov"))
        );
    }

    /// Build a `MultisigExec` for `inner` on `account` at `nonce`, relayed by
    /// `submitter_seed` (a policy member) and approved by `approvers` (each an
    /// `(index, seed)` signing the canonical message).
    fn multisig_exec(
        submitter_seed: [u8; 32],
        account: &str,
        nonce: u64,
        inner: Action,
        approvers: &[(u16, [u8; 32])],
    ) -> SignedTransaction {
        let msg = sov_types::multisig_signing_bytes(&id(account), nonce, &inner);
        let approvals = approvers
            .iter()
            .map(|(idx, seed)| sov_types::MultisigApproval {
                signer: *idx,
                signature: Keypair::from_seed(*seed).sign(&msg),
            })
            .collect();
        signed(
            submitter_seed,
            account,
            nonce,
            Action::MultisigExec {
                action: Box::new(inner),
                approvals,
            },
        )
    }

    #[test]
    fn multisig_enforces_threshold_and_disables_single_key() {
        let mut ledger = ledger_with_usa(100); // usa.reserve.sov keyed by [1;32]
        let p = policy();
        let signers = vec![
            Keypair::from_seed([1; 32]).public_key(),
            Keypair::from_seed([2; 32]).public_key(),
            Keypair::from_seed([3; 32]).public_key(),
        ];
        // The current key (A) opts the account into 2-of-3 multisig.
        let set = signed(
            [1; 32],
            "usa.reserve.sov",
            0,
            Action::SetMultisig {
                signers,
                threshold: 2,
            },
        );
        assert!(apply_transaction(&mut ledger, &set, &ctx(&p))
            .unwrap()
            .succeeded());
        assert!(ledger.multisig_of(&id("usa.reserve.sov")).is_some());

        // A single-key spend by A is now REJECTED at authorization (disabled).
        let direct = transfer([1; 32], "usa.reserve.sov", "ecb.reserve.sov", 10, 1);
        assert!(matches!(
            apply_transaction(&mut ledger, &direct, &ctx(&p)),
            Err(ExecutionError::Unauthorized { .. })
        ));

        let inner = Action::Transfer {
            to: id("ecb.reserve.sov"),
            amount: Balance::from_sov(10).unwrap(),
        };
        // ONE approval is below the threshold of 2 → fails (nonce still consumed).
        let one = multisig_exec(
            [1; 32],
            "usa.reserve.sov",
            1,
            inner.clone(),
            &[(0, [1; 32])],
        );
        assert!(!apply_transaction(&mut ledger, &one, &ctx(&p))
            .unwrap()
            .succeeded());
        assert_eq!(
            ledger.account(&id("ecb.reserve.sov")).balance,
            Balance::ZERO
        );

        // TWO distinct valid approvals (A + B) execute the inner transfer.
        let two = multisig_exec(
            [1; 32],
            "usa.reserve.sov",
            2,
            inner,
            &[(0, [1; 32]), (1, [2; 32])],
        );
        assert!(apply_transaction(&mut ledger, &two, &ctx(&p))
            .unwrap()
            .succeeded());
        assert_eq!(
            ledger.account(&id("ecb.reserve.sov")).balance,
            Balance::from_sov(10).unwrap()
        );
    }

    #[test]
    fn multisig_rejects_duplicate_and_misbound_approvals() {
        let mut ledger = ledger_with_usa(100);
        let p = policy();
        let signers = vec![
            Keypair::from_seed([1; 32]).public_key(),
            Keypair::from_seed([2; 32]).public_key(),
            Keypair::from_seed([3; 32]).public_key(),
        ];
        let set = signed(
            [1; 32],
            "usa.reserve.sov",
            0,
            Action::SetMultisig {
                signers,
                threshold: 2,
            },
        );
        apply_transaction(&mut ledger, &set, &ctx(&p)).unwrap();

        let inner = Action::Transfer {
            to: id("ecb.reserve.sov"),
            amount: Balance::from_sov(10).unwrap(),
        };

        // The SAME signer twice counts once → still below threshold → fails.
        let dup = multisig_exec(
            [1; 32],
            "usa.reserve.sov",
            1,
            inner.clone(),
            &[(0, [1; 32]), (0, [1; 32])],
        );
        assert!(!apply_transaction(&mut ledger, &dup, &ctx(&p))
            .unwrap()
            .succeeded());

        // Approvals BOUND TO A DIFFERENT action don't authorize this one: sign over
        // a decoy transfer, then submit the real one with those approvals. (The
        // `dup` attempt above consumed nonce 1, so this is nonce 2.)
        let decoy = Action::Transfer {
            to: id("attacker.sov"),
            amount: Balance::from_sov(99).unwrap(),
        };
        let msg_decoy = sov_types::multisig_signing_bytes(&id("usa.reserve.sov"), 2, &decoy);
        let approvals = vec![
            sov_types::MultisigApproval {
                signer: 0,
                signature: Keypair::from_seed([1; 32]).sign(&msg_decoy),
            },
            sov_types::MultisigApproval {
                signer: 1,
                signature: Keypair::from_seed([2; 32]).sign(&msg_decoy),
            },
        ];
        let misbound = signed(
            [1; 32],
            "usa.reserve.sov",
            2,
            Action::MultisigExec {
                action: Box::new(inner),
                approvals,
            },
        );
        assert!(!apply_transaction(&mut ledger, &misbound, &ctx(&p))
            .unwrap()
            .succeeded());
        // Neither attempt moved any funds.
        assert_eq!(
            ledger.account(&id("ecb.reserve.sov")).balance,
            Balance::ZERO
        );
        assert_eq!(ledger.account(&id("attacker.sov")).balance, Balance::ZERO);
    }

    /// The implicit account string a key controls.
    fn implicit(seed: [u8; 32]) -> String {
        Keypair::from_seed(seed)
            .public_key()
            .implicit_account_id()
            .to_string()
    }

    #[test]
    fn onchain_proposal_executes_at_threshold() {
        // 2-of-3 vault funded with 100. A member proposes a 10-SOV spend from their
        // OWN account; a second member approves from theirs; the chain executes it AS
        // the vault. No detached approvals — each member just signs one transaction.
        let mut ledger = ledger_with_usa(100);
        let p = policy();
        let signers = vec![
            Keypair::from_seed([1; 32]).public_key(),
            Keypair::from_seed([2; 32]).public_key(),
            Keypair::from_seed([3; 32]).public_key(),
        ];
        let set = signed(
            [1; 32],
            "usa.reserve.sov",
            0,
            Action::SetMultisig {
                signers,
                threshold: 2,
            },
        );
        assert!(apply_transaction(&mut ledger, &set, &ctx(&p))
            .unwrap()
            .succeeded());

        let inner = Action::Transfer {
            to: id("ecb.reserve.sov"),
            amount: Balance::from_sov(10).unwrap(),
        };
        // Member A (key 1) proposes from their own implicit account — 1 of 2; unspent.
        let propose = signed(
            [1; 32],
            &implicit([1; 32]),
            0,
            Action::ProposeMultisig {
                account: id("usa.reserve.sov"),
                action: Box::new(inner.clone()),
            },
        );
        assert!(apply_transaction(&mut ledger, &propose, &ctx(&p))
            .unwrap()
            .succeeded());
        assert_eq!(
            ledger.account(&id("usa.reserve.sov")).balance,
            Balance::from_sov(100).unwrap(),
            "nothing spent at 1 of 2"
        );
        let pending = ledger.proposals_for(&id("usa.reserve.sov"));
        assert_eq!(pending.len(), 1, "one pending proposal");
        let prop_id = pending[0].0;

        // A non-member cannot approve.
        let bad = signed(
            [9; 32],
            &implicit([9; 32]),
            0,
            Action::ApproveMultisig {
                account: id("usa.reserve.sov"),
                proposal: prop_id,
            },
        );
        assert!(
            !apply_transaction(&mut ledger, &bad, &ctx(&p))
                .unwrap()
                .succeeded(),
            "a non-member's approval is rejected"
        );

        // Member B approves → threshold met → the chain executes AS the vault.
        let approve = signed(
            [2; 32],
            &implicit([2; 32]),
            0,
            Action::ApproveMultisig {
                account: id("usa.reserve.sov"),
                proposal: prop_id,
            },
        );
        assert!(apply_transaction(&mut ledger, &approve, &ctx(&p))
            .unwrap()
            .succeeded());
        assert_eq!(
            ledger.account(&id("usa.reserve.sov")).balance,
            Balance::from_sov(90).unwrap(),
            "vault debited 10"
        );
        assert_eq!(
            ledger.account(&id("ecb.reserve.sov")).balance,
            Balance::from_sov(10).unwrap(),
            "recipient credited 10"
        );
        assert!(
            ledger.proposals_for(&id("usa.reserve.sov")).is_empty(),
            "proposal cleared after execution"
        );
    }

    #[test]
    fn policy_change_invalidates_pending_proposals_so_stale_approvers_cannot_spend() {
        // H1 regression. A pending proposal's approvals are stored as signer INDICES into
        // the policy active when each was cast. If a policy change left them in place, the
        // indices would remap onto the NEW signer set / threshold — so approvals given
        // under the old policy would authorize a spend under the new one (signers who
        // never approved, or a lowered threshold). A policy change MUST invalidate every
        // pending proposal.
        let mut ledger = ledger_with_usa(100);
        let p = policy();

        // Vault opts into 3-of-3 [A, B, C].
        let old_signers = vec![
            Keypair::from_seed([1; 32]).public_key(), // A (idx 0)
            Keypair::from_seed([2; 32]).public_key(), // B (idx 1)
            Keypair::from_seed([3; 32]).public_key(), // C (idx 2)
        ];
        let set = signed(
            [1; 32],
            "usa.reserve.sov",
            0,
            Action::SetMultisig {
                signers: old_signers,
                threshold: 3,
            },
        );
        assert!(apply_transaction(&mut ledger, &set, &ctx(&p))
            .unwrap()
            .succeeded());

        // A proposes a 10-SOV spend; B approves → 2 of 3, PENDING (not executed).
        let inner = Action::Transfer {
            to: id("ecb.reserve.sov"),
            amount: Balance::from_sov(10).unwrap(),
        };
        let propose = signed(
            [1; 32],
            &implicit([1; 32]),
            0,
            Action::ProposeMultisig {
                account: id("usa.reserve.sov"),
                action: Box::new(inner),
            },
        );
        assert!(apply_transaction(&mut ledger, &propose, &ctx(&p))
            .unwrap()
            .succeeded());
        let prop_id = ledger.proposals_for(&id("usa.reserve.sov"))[0].0;
        let approve_b = signed(
            [2; 32],
            &implicit([2; 32]),
            0,
            Action::ApproveMultisig {
                account: id("usa.reserve.sov"),
                proposal: prop_id,
            },
        );
        assert!(apply_transaction(&mut ledger, &approve_b, &ctx(&p))
            .unwrap()
            .succeeded());
        assert_eq!(
            ledger.proposals_for(&id("usa.reserve.sov")).len(),
            1,
            "pending at 2 of 3"
        );

        // The members legitimately ROTATE to a NEW 2-of-2 set [A, D] (vault nonce 1),
        // approved by the current 3-of-3. Threshold DROPS to 2 and D is a brand-new
        // signer who NEVER approved the spend — exactly the conditions the old bug
        // would have let the stale 2-approver proposal execute under.
        let new_signers = vec![
            Keypair::from_seed([1; 32]).public_key(), // A (idx 0)
            Keypair::from_seed([4; 32]).public_key(), // D (idx 1) — never approved
        ];
        let rotate = multisig_exec(
            [1; 32],
            "usa.reserve.sov",
            1,
            Action::SetMultisig {
                signers: new_signers,
                threshold: 2,
            },
            &[(0, [1; 32]), (1, [2; 32]), (2, [3; 32])],
        );
        assert!(apply_transaction(&mut ledger, &rotate, &ctx(&p))
            .unwrap()
            .succeeded());
        assert_eq!(
            ledger
                .multisig_of(&id("usa.reserve.sov"))
                .unwrap()
                .threshold,
            2,
            "policy rotated"
        );

        // THE FIX: the in-flight proposal is gone — old-policy approvals can't carry over.
        assert!(
            ledger.proposals_for(&id("usa.reserve.sov")).is_empty(),
            "policy change invalidated the pending proposal"
        );

        // The new signer D cannot execute the stale proposal — it no longer exists.
        let attack = signed(
            [4; 32],
            &implicit([4; 32]),
            0,
            Action::ApproveMultisig {
                account: id("usa.reserve.sov"),
                proposal: prop_id,
            },
        );
        assert!(
            !apply_transaction(&mut ledger, &attack, &ctx(&p))
                .unwrap()
                .succeeded(),
            "a stale proposal cannot be approved after a policy change"
        );
        assert_eq!(
            ledger.account(&id("usa.reserve.sov")).balance,
            Balance::from_sov(100).unwrap(),
            "vault never debited — the stale-approver spend was blocked"
        );
    }

    #[test]
    fn onchain_proposal_can_be_cancelled_by_a_member() {
        let mut ledger = ledger_with_usa(100);
        let p = policy();
        let signers = vec![
            Keypair::from_seed([1; 32]).public_key(),
            Keypair::from_seed([2; 32]).public_key(),
            Keypair::from_seed([3; 32]).public_key(),
        ];
        let set = signed(
            [1; 32],
            "usa.reserve.sov",
            0,
            Action::SetMultisig {
                signers,
                threshold: 2,
            },
        );
        apply_transaction(&mut ledger, &set, &ctx(&p)).unwrap();
        let propose = signed(
            [1; 32],
            &implicit([1; 32]),
            0,
            Action::ProposeMultisig {
                account: id("usa.reserve.sov"),
                action: Box::new(Action::Transfer {
                    to: id("ecb.reserve.sov"),
                    amount: Balance::from_sov(10).unwrap(),
                }),
            },
        );
        apply_transaction(&mut ledger, &propose, &ctx(&p)).unwrap();
        let prop_id = ledger.proposals_for(&id("usa.reserve.sov"))[0].0;

        // Member B cancels it — gone, nothing spent.
        let cancel = signed(
            [2; 32],
            &implicit([2; 32]),
            0,
            Action::CancelMultisig {
                account: id("usa.reserve.sov"),
                proposal: prop_id,
            },
        );
        assert!(apply_transaction(&mut ledger, &cancel, &ctx(&p))
            .unwrap()
            .succeeded());
        assert!(ledger.proposals_for(&id("usa.reserve.sov")).is_empty());
        assert_eq!(
            ledger.account(&id("usa.reserve.sov")).balance,
            Balance::from_sov(100).unwrap()
        );
    }
}
