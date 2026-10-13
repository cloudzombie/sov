//! Wallet-level spend construction for pool v2 — the layer between a note
//! store and [`crate::prover`].
//!
//! [`crate::prover::prove_bundle`] takes exact spends and outputs
//! and produces a proof. It does not choose which notes to spend, compute
//! change, encrypt to a recipient, or authorize the carrier. Without that layer
//! the pool is readable but unusable: a wallet can show a balance and never
//! move it.
//!
//! Everything here is CLIENT-side. It builds a bundle a node will verify; it
//! decides nothing about validity. A bundle this module produces is accepted or
//! rejected purely on the consensus rules, so a bug here costs the sender a
//! rejected transaction, never the network its integrity.
//!
//! ## What is deliberately conservative
//!
//! * **Value is conserved exactly**, and the balance is checked here before any
//!   proving work. The circuit enforces conservation regardless; failing early
//!   turns a 25-second proof that will certainly be rejected into an immediate
//!   error with real numbers in it.
//! * **Change always returns to the sender's own address.** A spend that
//!   consumed more than it paid and produced no change would burn the
//!   remainder, silently and irreversibly.
//! * **Notes are selected largest-first**, which minimises the number consumed
//!   and therefore the number of nullifiers published. Each nullifier is a
//!   public linkability signal, so spending four small notes where one large
//!   note would do leaks more than it needs to.
//! * **Every value is bounded** by [`MAX_NOTE_VALUE`] before it reaches the
//!   circuit, so the no-wrap argument in [`crate::note`] holds by construction
//!   rather than by hope.

use crate::air::NUM_SLOTS;
use crate::auth::AuthKeypair;
use crate::bundle::{bundle_digest, SpendBundle};
use crate::carrier::{sign_in_carrier, CarrierContext};
use crate::encrypt::{encrypt_note, NoteCiphertext};
use crate::hd::{PqAddress, PqShieldedKey};
use crate::note::{derive_rho, Note, MAX_NOTE_VALUE};
use crate::prover::{prove_bundle, BundleSpend, SpendProofError};
use crate::scan::PqNoteStore;
use crate::tree::MerklePath;
use zeroize::Zeroizing;

/// Why a spend could not be built.
///
/// Every variant carries the numbers an operator needs to act, rather than a
/// bare "failed" — a wallet that cannot say how much it was short is a wallet
/// its owner cannot use.
#[derive(Debug, thiserror::Error)]
pub enum SpendBuildError {
    /// Operating-system entropy is unavailable; no deterministic fallback is used.
    #[error("cannot obtain secure randomness for a new shielded note")]
    Randomness,
    /// The wallet does not hold enough unspent value.
    #[error("insufficient shielded balance: have {have} grains, need {need} grains")]
    Insufficient {
        /// Total unspent value the wallet holds.
        have: u64,
        /// What the spend required (amount + fee).
        need: u64,
    },
    /// Covering the amount would take more input notes than the fixed 4-in
    /// bundle shape allows.
    #[error(
        "spend needs more than {NUM_SLOTS} input notes ({needed} required); \
         consolidate first by sending to yourself"
    )]
    TooManyInputs {
        /// How many notes largest-first selection required.
        needed: usize,
    },
    /// A value exceeded the range the circuit proves.
    #[error("value {value} exceeds MAX_NOTE_VALUE {MAX_NOTE_VALUE}")]
    ValueOutOfRange {
        /// The offending value, in grains.
        value: u64,
    },
    /// A selected note has no Merkle witness in the store — the store is
    /// behind the chain, or was not rescanned after a reorg.
    #[error("no membership witness for the note at position {position}; rescan the pool")]
    MissingWitness {
        /// The note's tree position.
        position: u64,
    },
    /// Source stores were not scanned through the same block and pool tree.
    #[error("pool-v2 source {source_index} is on a different scan height, block, or tree; rescan all keys together")]
    SourceScanMismatch {
        /// Index in the caller's source list.
        source_index: usize,
    },
    /// One tree position appeared in multiple source stores. Counting it twice
    /// would inflate the displayed spendable amount and duplicate a nullifier.
    #[error("pool-v2 note position {position} appears in more than one source")]
    DuplicatePosition {
        /// The duplicated global tree position.
        position: u64,
    },
    /// A store/key pair did not reconstruct the commitment in its witness.
    #[error("pool-v2 source key does not own the commitment at position {position}")]
    SourceKeyMismatch {
        /// The position whose ownership key does not match its tree leaf.
        position: u64,
    },
    /// Summing all source balances overflowed the amount representation.
    #[error("pool-v2 source balance exceeds the supported amount range")]
    BalanceOverflow,
    /// Note encryption to the recipient failed (a malformed ML-KEM key).
    #[error("cannot encrypt to recipient: {0}")]
    Encrypt(String),
    /// The carrier authorization signature failed.
    #[error("cannot authorize bundle: {0}")]
    Auth(String),
    /// Proving failed.
    #[error(transparent)]
    Prove(#[from] SpendProofError),
}

/// A built, authorized bundle plus the notes it consumed.
///
/// The consumed positions are returned so a wallet can mark them locally
/// without rescanning — but they are only truly spent once the transaction is
/// mined, so a caller must not treat this as confirmation.
#[derive(Debug, Clone)]
pub struct BuiltSpend {
    /// The bundle, ready to encode into `Action::ShieldedV2`.
    pub bundle: SpendBundle,
    /// Tree positions of the notes this spend consumes.
    pub spent_positions: Vec<u64>,
    /// Value returned to the sender as change (0 when the spend was exact).
    pub change_grains: u64,
}

/// Select unspent notes largest-first until `need` is covered.
///
/// Largest-first minimises the number of notes consumed, and therefore the
/// number of nullifiers published — each one is a public linkability signal.
fn select(
    store: &PqNoteStore,
    key: &PqShieldedKey,
    need: u64,
) -> Result<(Vec<(Note, u64)>, u64), SpendBuildError> {
    let mut owned = store.unspent(key);
    owned.sort_unstable_by_key(|(n, _)| std::cmp::Reverse(n.value_grains));
    let have: u64 = owned.iter().map(|(n, _)| n.value_grains).sum();
    if have < need {
        return Err(SpendBuildError::Insufficient { have, need });
    }
    let mut picked = Vec::new();
    let mut total = 0u64;
    for (note, pos) in owned {
        if total >= need {
            break;
        }
        total = total.saturating_add(note.value_grains);
        picked.push((note, pos));
    }
    if picked.len() > NUM_SLOTS {
        return Err(SpendBuildError::TooManyInputs {
            needed: picked.len(),
        });
    }
    Ok((picked, total))
}

/// Build and authorize a pool-v2 spend.
///
/// * `to` — the recipient. `None` means a DE-SHIELD: the value leaves the pool
///   to the transparent leg instead of becoming a note.
/// * `amount_grains` — what the recipient receives (or what leaves the pool).
/// * `fee_grains` — the transparent fee.
///
/// Change always returns to `key`'s own address; a spend that produced none
/// would burn the remainder.
pub fn build_spend(
    key: &PqShieldedKey,
    store: &PqNoteStore,
    to: Option<&PqAddress>,
    amount_grains: u64,
    fee_grains: u64,
) -> Result<BuiltSpend, SpendBuildError> {
    build_spend_inner(
        key,
        store,
        to,
        amount_grains,
        fee_grains,
        &key.address(),
        None,
    )
}

/// Build a context-bound hiding spend of historical or new notes. The carrier
/// nonce must be chosen before proving. Change has an explicit destination so
/// migration can pay a fresh suite-2 key instead of an exposed legacy NSK.
#[cfg(feature = "zk-suite2")]
#[allow(clippy::too_many_arguments)]
pub fn build_spend_suite2(
    key: &PqShieldedKey,
    store: &PqNoteStore,
    to: Option<&PqAddress>,
    amount_grains: u64,
    fee_grains: u64,
    change_to: &PqAddress,
    carrier: &CarrierContext<'_>,
) -> Result<BuiltSpend, SpendBuildError> {
    build_spend_inner(
        key,
        store,
        to,
        amount_grains,
        fee_grains,
        change_to,
        Some(carrier),
    )
}

#[cfg(feature = "zk-suite2")]
struct MixedNote<'a> {
    key: &'a PqShieldedKey,
    store: &'a PqNoteStore,
    note: Note,
    position: u64,
}

/// Select across keys without counting the same global note position twice.
#[cfg(feature = "zk-suite2")]
fn select_mixed<'a>(
    sources: &[(&'a PqShieldedKey, &'a PqNoteStore)],
    need: u64,
) -> Result<(Vec<MixedNote<'a>>, u64), SpendBuildError> {
    let Some((_, first)) = sources.first() else {
        return Err(SpendBuildError::Insufficient { have: 0, need });
    };
    let mut positions = std::collections::BTreeSet::new();
    let mut owned = Vec::new();
    let mut have = 0u64;
    for (source, (key, store)) in sources.iter().enumerate() {
        if store.root() != first.root()
            || store.scanned_height() != first.scanned_height()
            || store.tip_checkpoint() != first.tip_checkpoint()
            || store.commitment_count() != first.commitment_count()
        {
            return Err(SpendBuildError::SourceScanMismatch {
                source_index: source,
            });
        }
        for (note, position) in store.unspent(key) {
            if !positions.insert(position) {
                return Err(SpendBuildError::DuplicatePosition { position });
            }
            have = have
                .checked_add(note.value_grains)
                .ok_or(SpendBuildError::BalanceOverflow)?;
            owned.push(MixedNote {
                key,
                store,
                note,
                position,
            });
        }
    }
    if have < need {
        return Err(SpendBuildError::Insufficient { have, need });
    }
    owned.sort_unstable_by(|a, b| {
        b.note
            .value_grains
            .cmp(&a.note.value_grains)
            .then_with(|| a.position.cmp(&b.position))
    });
    let mut picked = Vec::new();
    let mut total = 0u64;
    for input in owned {
        if total >= need {
            break;
        }
        total = total
            .checked_add(input.note.value_grains)
            .ok_or(SpendBuildError::BalanceOverflow)?;
        picked.push(input);
    }
    if picked.len() > NUM_SLOTS {
        return Err(SpendBuildError::TooManyInputs {
            needed: picked.len(),
        });
    }
    Ok((picked, total))
}

/// Spend historical and fresh pool-v2 notes together through hiding suite 2.
///
/// Each input proves its own source key's spending-seed preimage. `auth_key`
/// authorizes the already chosen carrier, independently of input ownership;
/// change can therefore move to a fresh suite-2 address. All source stores must
/// represent the same scanned block, root and global commitment positions.
/// Amount and fee are exact: this never produces a partial payment when four
/// inputs cannot cover the request. Runtime policy currently requires fee zero;
/// a withdrawal amount is the gross transparent-out leg before carrier fees.
#[cfg(feature = "zk-suite2")]
#[allow(clippy::too_many_arguments)]
pub fn build_spend_suite2_mixed(
    sources: &[(&PqShieldedKey, &PqNoteStore)],
    auth_key: &PqShieldedKey,
    to: Option<&PqAddress>,
    amount_grains: u64,
    fee_grains: u64,
    change_to: &PqAddress,
    carrier: &CarrierContext<'_>,
) -> Result<BuiltSpend, SpendBuildError> {
    for value in [amount_grains, fee_grains] {
        if value > MAX_NOTE_VALUE {
            return Err(SpendBuildError::ValueOutOfRange { value });
        }
    }
    let need = amount_grains
        .checked_add(fee_grains)
        .ok_or(SpendBuildError::BalanceOverflow)?;
    let (picked, input_total) = select_mixed(sources, need)?;
    let change = input_total
        .checked_sub(need)
        .ok_or(SpendBuildError::Insufficient {
            have: input_total,
            need,
        })?;
    if change > MAX_NOTE_VALUE {
        return Err(SpendBuildError::ValueOutOfRange { value: change });
    }

    let mut spends = Vec::with_capacity(picked.len());
    let mut spent_positions = Vec::with_capacity(picked.len());
    for input in picked {
        let (path, anchor) =
            input
                .store
                .witness(input.position)
                .ok_or(SpendBuildError::MissingWitness {
                    position: input.position,
                })?;
        if anchor != input.store.root() || path.compute_root(input.note.commitment()) != anchor {
            return Err(SpendBuildError::SourceKeyMismatch {
                position: input.position,
            });
        }
        spends.push(crate::zk_suite2::Suite2Spend::new(
            BundleSpend {
                key: input.key.spend_key().clone(),
                note: input.note,
                path,
            },
            input.key.spending_seed_preimage(),
        )?);
        spent_positions.push(input.position);
    }

    let mut outputs = Vec::new();
    let mut recipients = Vec::new();
    if let Some(to) = to {
        outputs.push(
            Note::new(amount_grains, to.owner_tag(), fresh_rho()?).ok_or(
                SpendBuildError::ValueOutOfRange {
                    value: amount_grains,
                },
            )?,
        );
        recipients.push(to.clone());
    }
    if change > 0 {
        outputs.push(
            Note::new(change, change_to.owner_tag(), fresh_rho()?)
                .ok_or(SpendBuildError::ValueOutOfRange { value: change })?,
        );
        recipients.push(change_to.clone());
    }
    let transparent_out = if to.is_none() { amount_grains } else { 0 };
    let (proof, publics) = prove_suite2_selected(
        auth_key,
        &spends,
        &outputs,
        0,
        transparent_out,
        fee_grains,
        carrier,
    )?;
    let bundle = finish_selected(
        auth_key,
        publics,
        proof,
        &outputs,
        &recipients,
        Some(carrier),
    )?;
    Ok(BuiltSpend {
        bundle,
        spent_positions,
        change_grains: change,
    })
}

#[allow(clippy::too_many_arguments)]
fn build_spend_inner(
    key: &PqShieldedKey,
    store: &PqNoteStore,
    to: Option<&PqAddress>,
    amount_grains: u64,
    fee_grains: u64,
    change_to: &PqAddress,
    carrier: Option<&CarrierContext<'_>>,
) -> Result<BuiltSpend, SpendBuildError> {
    for v in [amount_grains, fee_grains] {
        if v > MAX_NOTE_VALUE {
            return Err(SpendBuildError::ValueOutOfRange { value: v });
        }
    }
    let need = amount_grains
        .checked_add(fee_grains)
        .ok_or(SpendBuildError::ValueOutOfRange {
            value: MAX_NOTE_VALUE,
        })?;

    let (picked, input_total) = select(store, key, need)?;
    // `select` guarantees this, but the subtraction is the one place a mistake
    // would silently mint, so it is checked rather than assumed.
    let change = input_total
        .checked_sub(need)
        .ok_or(SpendBuildError::Insufficient {
            have: input_total,
            need,
        })?;
    if change > MAX_NOTE_VALUE {
        return Err(SpendBuildError::ValueOutOfRange { value: change });
    }

    // Witnesses. A missing one means the store is behind the chain; proving
    // against a stale anchor would waste ~25 s and be rejected.
    let mut spends = Vec::with_capacity(picked.len());
    let mut spent_positions = Vec::with_capacity(picked.len());
    for (note, position) in &picked {
        let (path, _anchor): (MerklePath, _) =
            store
                .witness(*position)
                .ok_or(SpendBuildError::MissingWitness {
                    position: *position,
                })?;
        spends.push(BundleSpend {
            key: key.spend_key().clone(),
            note: *note,
            path,
        });
        spent_positions.push(*position);
    }

    // Fresh entropy for every output, including retries and different chains.
    // Positions protect nullifier uniqueness, but a repeated rho still makes
    // equal-value payments to the same recipient publicly linkable.
    let mut outputs: Vec<Note> = Vec::new();
    let mut recipients: Vec<PqAddress> = Vec::new();

    if let Some(dest) = to {
        let note = Note::new(amount_grains, dest.owner_tag(), fresh_rho()?).ok_or(
            SpendBuildError::ValueOutOfRange {
                value: amount_grains,
            },
        )?;
        outputs.push(note);
        recipients.push(dest.clone());
    }
    if change > 0 {
        let own = change_to.clone();
        let note = Note::new(change, own.owner_tag(), fresh_rho()?)
            .ok_or(SpendBuildError::ValueOutOfRange { value: change })?;
        outputs.push(note);
        recipients.push(own);
    }

    // The transparent legs. A de-shield moves `amount_grains` out of the pool;
    // a shielded transfer moves nothing out. `transparent_in` is zero here —
    // shielding INTO the pool is `build_shield`.
    let transparent_out = if to.is_none() { amount_grains } else { 0 };

    let (proof_bytes, public_inputs) = prove_selected(
        key,
        &spends,
        &outputs,
        0,
        transparent_out,
        fee_grains,
        carrier,
    )?;

    finish_selected(
        key,
        public_inputs,
        proof_bytes,
        &outputs,
        &recipients,
        carrier,
    )
    .map(|bundle| BuiltSpend {
        bundle,
        spent_positions,
        change_grains: change,
    })
}

/// Shield into the hiding suite with the actual carrier fixed before proving.
/// This API does not establish that a legacy recipient key remains secret.
#[cfg(feature = "zk-suite2")]
pub fn build_shield_suite2(
    key: &PqShieldedKey,
    to: &PqAddress,
    amount_grains: u64,
    fee_grains: u64,
    carrier: &CarrierContext<'_>,
) -> Result<SpendBundle, SpendBuildError> {
    for value in [amount_grains, fee_grains] {
        if value > MAX_NOTE_VALUE {
            return Err(SpendBuildError::ValueOutOfRange { value });
        }
    }
    let total = amount_grains
        .checked_add(fee_grains)
        .filter(|total| *total <= MAX_NOTE_VALUE)
        .ok_or(SpendBuildError::ValueOutOfRange {
            value: MAX_NOTE_VALUE,
        })?;
    let note = Note::new(amount_grains, to.owner_tag(), fresh_rho()?).ok_or(
        SpendBuildError::ValueOutOfRange {
            value: amount_grains,
        },
    )?;
    let (proof, publics) = prove_selected(key, &[], &[note], total, 0, fee_grains, Some(carrier))?;
    finish_selected(
        key,
        publics,
        proof,
        &[note],
        std::slice::from_ref(to),
        Some(carrier),
    )
}

#[allow(clippy::too_many_arguments)]
fn prove_selected(
    key: &PqShieldedKey,
    spends: &[BundleSpend],
    outputs: &[Note],
    transparent_in: u64,
    transparent_out: u64,
    fee: u64,
    carrier: Option<&CarrierContext<'_>>,
) -> Result<(Vec<u8>, crate::BundlePublicInputs), SpendProofError> {
    #[cfg(feature = "zk-suite2")]
    if let Some(carrier) = carrier {
        let witnesses: Vec<_> = spends
            .iter()
            .cloned()
            .map(|spend| crate::zk_suite2::Suite2Spend::new(spend, key.spending_seed_preimage()))
            .collect::<Result<_, _>>()?;
        return prove_suite2_selected(
            key,
            &witnesses,
            outputs,
            transparent_in,
            transparent_out,
            fee,
            carrier,
        );
    }
    let _ = (key, carrier);
    prove_bundle(spends, outputs, transparent_in, transparent_out, fee)
}

#[cfg(feature = "zk-suite2")]
#[allow(clippy::too_many_arguments)]
fn prove_suite2_selected(
    key: &PqShieldedKey,
    spends: &[crate::zk_suite2::Suite2Spend],
    outputs: &[Note],
    transparent_in: u64,
    transparent_out: u64,
    fee: u64,
    carrier: &CarrierContext<'_>,
) -> Result<(Vec<u8>, crate::BundlePublicInputs), SpendProofError> {
    let auth_pk = key.auth_key().public_bytes();
    crate::zk_suite2::prove_bundle(
        spends,
        outputs,
        transparent_in,
        transparent_out,
        fee,
        &crate::zk_suite2::Suite2Context {
            chain_id: carrier.chain_id,
            genesis: carrier.genesis,
            signer: carrier.signer,
            nonce: carrier.nonce,
            auth_pk: &auth_pk,
        },
    )
}

fn finish_selected(
    key: &PqShieldedKey,
    public_inputs: crate::BundlePublicInputs,
    proof: Vec<u8>,
    outputs: &[Note],
    recipients: &[PqAddress],
    carrier: Option<&CarrierContext<'_>>,
) -> Result<SpendBundle, SpendBuildError> {
    let mut bundle = finish(key, public_inputs, proof, outputs, recipients)?;
    if let Some(carrier) = carrier {
        let (auth_pk, auth_sig) = sign_in_carrier(
            key.auth_key(),
            &bundle.public_inputs,
            &bundle.output_ciphertexts,
            carrier,
        )
        .map_err(|e| SpendBuildError::Auth(e.to_string()))?;
        bundle.auth_pk = auth_pk;
        bundle.auth_sig = auth_sig;
    }
    Ok(bundle)
}

/// Build a SHIELD: move `amount_grains` from the transparent ledger into pool
/// v2 as a note owned by `to`.
///
/// No input notes, so no witnesses and no change — the value enters through the
/// transparent leg.
pub fn build_shield(
    key: &PqShieldedKey,
    to: &PqAddress,
    amount_grains: u64,
    fee_grains: u64,
) -> Result<SpendBundle, SpendBuildError> {
    for v in [amount_grains, fee_grains] {
        if v > MAX_NOTE_VALUE {
            return Err(SpendBuildError::ValueOutOfRange { value: v });
        }
    }
    let transparent_in =
        amount_grains
            .checked_add(fee_grains)
            .ok_or(SpendBuildError::ValueOutOfRange {
                value: MAX_NOTE_VALUE,
            })?;
    if transparent_in > MAX_NOTE_VALUE {
        return Err(SpendBuildError::ValueOutOfRange {
            value: transparent_in,
        });
    }

    let note = Note::new(amount_grains, to.owner_tag(), fresh_rho()?).ok_or(
        SpendBuildError::ValueOutOfRange {
            value: amount_grains,
        },
    )?;
    let outputs = vec![note];
    let (proof_bytes, public_inputs) = prove_bundle(&[], &outputs, transparent_in, 0, fee_grains)?;
    finish(
        key,
        public_inputs,
        proof_bytes,
        &outputs,
        std::slice::from_ref(to),
    )
}

/// Generate independent note randomness. The ciphertext preserves this rho,
/// so phrase restoration recovers it by rescanning rather than guessing an index.
fn fresh_rho() -> Result<crate::hash::PqDigest, SpendBuildError> {
    let mut entropy = Zeroizing::new([0u8; 32]);
    getrandom::getrandom(entropy.as_mut()).map_err(|_| SpendBuildError::Randomness)?;
    Ok(derive_rho(&entropy, 0))
}

/// Encrypt each real output to its recipient and authorize the bundle.
///
/// The authorization signs [`bundle_digest`], which covers the public inputs,
/// every output ciphertext, and the authorizing key itself — so none of them
/// can be reshaped around the signature.
fn finish(
    key: &PqShieldedKey,
    public_inputs: crate::air::BundlePublicInputs,
    proof_bytes: Vec<u8>,
    outputs: &[Note],
    recipients: &[PqAddress],
) -> Result<SpendBundle, SpendBuildError> {
    debug_assert_eq!(outputs.len(), recipients.len());
    let mut output_ciphertexts: [Option<NoteCiphertext>; NUM_SLOTS] = Default::default();
    for (i, (note, dest)) in outputs.iter().zip(recipients).enumerate() {
        output_ciphertexts[i] = Some(
            encrypt_note(dest.kem_ek(), note)
                .map_err(|e| SpendBuildError::Encrypt(e.to_string()))?,
        );
    }

    let auth: &AuthKeypair = key.auth_key();
    let auth_pk = auth.public_bytes();
    let digest = bundle_digest(&public_inputs, &output_ciphertexts, &auth_pk);
    let auth_sig = auth
        .sign(&digest)
        .map_err(|e| SpendBuildError::Auth(e.to_string()))?;

    Ok(SpendBundle {
        public_inputs,
        proof_bytes,
        output_ciphertexts,
        auth_pk,
        auth_sig,
    })
}

/// Bind a built bundle to the transaction that will carry it.
///
/// [`build_shield`] and [`build_spend`] sign the bundle digest, which proves
/// the bundle's own integrity but says nothing about WHICH transaction may
/// carry it. Consensus ([`crate::carrier::verify_carrier_auth`]) requires the
/// stronger statement: a signature over `carrier_sighash(digest, {signer,
/// nonce})`. Without this step a bundle is inadmissible — and, worse, a bundle
/// bound to nothing could be lifted onto someone else's transaction.
///
/// It is separate from building because the nonce is only known at submit
/// time, after the ~25 s proving work is already done. Call it last, with the
/// exact `{chain_id, genesis, signer, nonce}` the carrier transaction will use.
/// This historical API does not bind that context into the old STARK itself:
/// copying a valid proof and reauthorizing it with another key remains possible.
/// New hiding-suite builders require the actual carrier before proving instead.
///
/// `chain_id`/`genesis` are THIS network's identity (PQV2-06): they are folded
/// into the authorized message so the bundle cannot be replayed onto another
/// SOV network, independently of the `tx-domain` fork's activation state. Sign
/// with the domain the connected node reports for its chain (always available,
/// not the activation-gated signing domain).
pub fn authorize_for_carrier(
    bundle: &mut SpendBundle,
    key: &PqShieldedKey,
    chain_id: &str,
    genesis: &[u8; 32],
    signer: &str,
    nonce: u64,
) -> Result<(), SpendBuildError> {
    let (auth_pk, auth_sig) = sign_in_carrier(
        key.auth_key(),
        &bundle.public_inputs,
        &bundle.output_ciphertexts,
        &CarrierContext {
            chain_id: chain_id.as_bytes(),
            genesis,
            signer: signer.as_bytes(),
            nonce,
        },
    )
    .map_err(|e| SpendBuildError::Auth(e.to_string()))?;
    bundle.auth_pk = auth_pk;
    bundle.auth_sig = auth_sig;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::carrier::verify_carrier_auth;

    /// A built bundle is NOT admissible until it is carrier-bound, and once
    /// bound it is bound to exactly ONE {signer, nonce}.
    ///
    /// This is a regression test for a real defect: `build_shield` signed the
    /// bundle digest, but consensus requires a signature over
    /// `carrier_sighash(digest, {signer, nonce})`. Every wallet-built v2
    /// bundle was therefore rejected with `CarrierAuth`, and the whole pool-v2
    /// transaction path was non-functional end to end. It was invisible
    /// because the CLI's dormancy guard refuses before a bundle is ever built.
    #[test]
    fn a_bundle_must_be_carrier_bound_and_binds_to_exactly_one_carrier() {
        let k = PqShieldedKey::from_leaf_seed(&[7u8; 32]);
        const GEN: &[u8; 32] = &[0xAA; 32];
        let ctx = |signer: &'static str, nonce: u64| CarrierContext {
            chain_id: b"sov-mainnet",
            genesis: GEN,
            signer: signer.as_bytes(),
            nonce,
        };
        let mut b = build_shield(&k, &k.address(), 100_000_000, 0).expect("build");

        assert!(
            !verify_carrier_auth(&b, &ctx("usa.reserve.sov", 0)),
            "an UNBOUND bundle must not satisfy consensus carrier auth"
        );

        authorize_for_carrier(&mut b, &k, "sov-mainnet", GEN, "usa.reserve.sov", 0)
            .expect("authorize");
        assert!(
            verify_carrier_auth(&b, &ctx("usa.reserve.sov", 0)),
            "after binding, its own carrier must verify"
        );
        assert!(
            !verify_carrier_auth(&b, &ctx("usa.reserve.sov", 1)),
            "a different NONCE must not verify — else the bundle replays"
        );
        assert!(
            !verify_carrier_auth(&b, &ctx("miner.sov", 0)),
            "a different SIGNER must not verify — else the bundle is stealable"
        );
        // A different NETWORK (chain id) must not verify — else the bundle
        // replays cross-network (PQV2-06).
        assert!(
            !verify_carrier_auth(
                &b,
                &CarrierContext {
                    chain_id: b"sov-testnet-1",
                    genesis: GEN,
                    signer: b"usa.reserve.sov",
                    nonce: 0,
                }
            ),
            "a different CHAIN ID must not verify — else the bundle replays cross-network"
        );
    }

    use crate::prover::verify_spend;
    use crate::wire::encode_bundle;

    use crate::air::BundlePublicInputs;
    use crate::auth::{AUTH_PK_LEN, AUTH_SIG_LEN};
    use crate::hash::PqDigest;

    fn key(seed: u8) -> PqShieldedKey {
        PqShieldedKey::from_leaf_seed(&[seed; 32])
    }

    /// Fund a store the REAL way — by ingesting a block carrying output
    /// ciphertexts, exactly as a scan does. Poking notes straight into the
    /// store would test a shape the chain never produces, and would skip the
    /// trial-decapsulation that assigns tree positions.
    fn funded(k: &PqShieldedKey, values: &[u64]) -> PqNoteStore {
        let mut store = PqNoteStore::new(0);
        // Chunked across blocks: a bundle carries at most NUM_SLOTS outputs, so
        // holding more than four notes takes more than one block — exactly as
        // on a real chain.
        for (block, chunk) in values.chunks(NUM_SLOTS).enumerate() {
            fund_one_block(&mut store, k, chunk, (block + 1) as u64);
        }
        store
    }

    /// Ingest one block carrying up to `NUM_SLOTS` outputs to `k`.
    fn fund_one_block(store: &mut PqNoteStore, k: &PqShieldedKey, values: &[u64], height: u64) {
        assert!(values.len() <= NUM_SLOTS);
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
        let mut cts: [Option<NoteCiphertext>; NUM_SLOTS] = Default::default();
        let addr = k.address();
        for (slot, v) in values.iter().enumerate() {
            // rho must be unique per note across the whole chain, exactly as a
            // real sending wallet allocates it — a repeat would repeat a
            // nullifier and make the second spend unminable.
            let rho_index = height * NUM_SLOTS as u64 + slot as u64;
            let note = Note::new(*v, addr.owner_tag(), k.rho(rho_index)).expect("note");
            pi.output_commitments[slot] = note.commitment();
            pi.output_dummy[slot] = false;
            cts[slot] = Some(encrypt_note(addr.kem_ek(), &note).expect("encrypt"));
        }
        let bundle = SpendBundle {
            public_inputs: pi,
            proof_bytes: Vec::new(),
            output_ciphertexts: cts,
            auth_pk: [0u8; AUTH_PK_LEN],
            auth_sig: [0u8; AUTH_SIG_LEN],
        };
        store.ingest_block(k, height, [0u8; 32], &[&bundle]);
    }

    /// A shield builds, proves, verifies, and encodes — the full path a wallet
    /// takes to put value into the pool.
    #[test]
    fn a_shield_round_trips_through_verification() {
        let k = key(1);
        let bundle = build_shield(&k, &k.address(), 5_000, 100).expect("shield builds");
        verify_spend(&bundle.proof_bytes, &bundle.public_inputs).expect("the node would accept it");
        // Conservation, читаемо: in == out + fee.
        assert_eq!(bundle.public_inputs.transparent_in, 5_100);
        assert_eq!(bundle.public_inputs.transparent_out, 0);
        assert_eq!(bundle.public_inputs.fee_grains, 100);
        assert!(
            !encode_bundle(&bundle).is_empty(),
            "it encodes for the wire"
        );
    }

    #[test]
    fn repeated_equal_shields_use_fresh_rho_and_restore_from_ciphertexts() {
        let sender = key(41);
        let recipient = key(42);
        let first = build_shield(&sender, &recipient.address(), 5_000, 0).expect("first shield");
        let second = build_shield(&sender, &recipient.address(), 5_000, 0).expect("second shield");
        let decrypt = |bundle: &SpendBundle| {
            recipient
                .encryption_key()
                .decrypt(bundle.output_ciphertexts[0].as_ref().expect("ciphertext"))
                .expect("restore note")
        };
        let first_note = decrypt(&first);
        let second_note = decrypt(&second);
        assert_ne!(first_note.rho, second_note.rho);
        assert_ne!(first_note.commitment(), second_note.commitment());
        assert_eq!(first_note.value_grains, 5_000);
        assert_eq!(second_note.value_grains, 5_000);
        // A restored phrase derives the same decapsulation key; randomness
        // comes from the ciphertext, rather than an implicit local counter.
        let restored = key(42);
        assert_eq!(
            restored
                .encryption_key()
                .decrypt(first.output_ciphertexts[0].as_ref().expect("ciphertext"))
                .expect("restored"),
            first_note
        );
    }

    /// A spend with no recipient is a DE-SHIELD: value leaves via the
    /// transparent leg, and any remainder returns as change rather than burning.
    #[test]
    fn a_deshield_returns_change_and_never_burns_the_remainder() {
        let k = key(2);
        let store = funded(&k, &[10_000]);

        let built = build_spend(&k, &store, None, 4_000, 100).expect("deshield builds");
        assert_eq!(built.bundle.public_inputs.transparent_out, 4_000);
        assert_eq!(
            built.change_grains, 5_900,
            "10,000 - 4,000 - 100 must come back as change, not vanish"
        );
        verify_spend(&built.bundle.proof_bytes, &built.bundle.public_inputs)
            .expect("the node would accept it");
    }

    /// Spending more than the wallet holds fails BEFORE proving, and says by
    /// how much.
    #[test]
    fn an_overspend_fails_early_with_real_numbers() {
        let k = key(3);
        let store = funded(&k, &[1_000]);

        match build_spend(&k, &store, None, 5_000, 10) {
            Err(SpendBuildError::Insufficient { have, need }) => {
                assert_eq!(have, 1_000);
                assert_eq!(need, 5_010, "the shortfall is stated exactly");
            }
            other => panic!("expected Insufficient, got {other:?}"),
        }
    }

    /// The fixed 4-in shape is enforced with an actionable error rather than a
    /// proving failure the operator cannot interpret.
    #[test]
    fn needing_more_than_four_inputs_says_so() {
        let k = key(4);
        // Eight notes of 100: the wallet HOLDS 800, so this is not a shortfall
        // — covering 550 simply needs six inputs, and the bundle shape allows
        // four. The error must say that, not "insufficient".
        let store = funded(&k, &[100, 100, 100, 100, 100, 100, 100, 100]);
        match build_spend(&k, &store, None, 550, 0) {
            Err(SpendBuildError::TooManyInputs { needed }) => {
                assert!(needed > NUM_SLOTS, "it reports how many were required");
            }
            other => panic!("expected TooManyInputs, got {other:?}"),
        }
    }

    /// Largest-first selection consumes as few notes as possible, so as few
    /// nullifiers as possible become public.
    #[test]
    fn selection_is_largest_first_to_minimise_published_nullifiers() {
        let k = key(5);
        let store = funded(&k, &[100, 9_000, 200, 50]);
        let built = build_spend(&k, &store, None, 8_000, 0).expect("builds");
        assert_eq!(
            built.spent_positions.len(),
            1,
            "the single 9,000 note covers it; spending four small ones would \
             publish four nullifiers instead of one"
        );
    }

    #[cfg(feature = "zk-suite2")]
    mod mixed_suite2 {
        use super::*;

        const GENESIS: &[u8; 32] = &[0x71; 32];

        fn carrier(nonce: u64) -> CarrierContext<'static> {
            CarrierContext {
                chain_id: b"sov-mixed-wallet-test",
                genesis: GENESIS,
                signer: b"mixed.sender.sov",
                nonce,
            }
        }

        fn verify_suite2(bundle: &SpendBundle, context: &CarrierContext<'_>) {
            crate::zk_suite2::verify_spend(
                &bundle.proof_bytes,
                &bundle.public_inputs,
                &crate::zk_suite2::Suite2Context {
                    chain_id: context.chain_id,
                    genesis: context.genesis,
                    signer: context.signer,
                    nonce: context.nonce,
                    auth_pk: &bundle.auth_pk,
                },
            )
            .expect("suite-2 proof verifies under actual carrier");
            assert!(verify_carrier_auth(bundle, context));
        }

        // Fast source-selection fixtures still scan real encrypted commitments:
        // the stores share the complete global tree, but decrypt different keys.
        fn views(old: &PqShieldedKey, fresh: &PqShieldedKey) -> (PqNoteStore, PqNoteStore) {
            let notes = [
                Note::new(6_000, old.owner_tag(), old.rho(101)).unwrap(),
                Note::new(4_000, fresh.owner_tag(), fresh.rho(102)).unwrap(),
            ];
            let bundle = finish(
                fresh,
                BundlePublicInputs {
                    anchors: [PqDigest::ZERO; NUM_SLOTS],
                    nullifiers: [PqDigest::ZERO; NUM_SLOTS],
                    input_dummy: [true; NUM_SLOTS],
                    output_commitments: [
                        notes[0].commitment(),
                        notes[1].commitment(),
                        PqDigest::ZERO,
                        PqDigest::ZERO,
                    ],
                    output_dummy: [false, false, true, true],
                    transparent_in: 10_000,
                    transparent_out: 0,
                    fee_grains: 0,
                },
                Vec::new(),
                &notes,
                &[old.address(), fresh.address()],
            )
            .unwrap();
            let mut old_store = PqNoteStore::new(0);
            let mut fresh_store = PqNoteStore::new(0);
            old_store.ingest_block(old, 1, [1; 32], &[&bundle]);
            fresh_store.ingest_block(fresh, 1, [1; 32], &[&bundle]);
            (old_store, fresh_store)
        }

        #[test]
        fn mixed_sources_require_the_same_height_root_and_tip() {
            let old = key(71);
            let fresh = PqShieldedKey::from_leaf_seed_suite2(&[71; 32]);
            let (mut old_store, mut fresh_store) = views(&old, &fresh);
            fresh_store.ingest_block(&fresh, 2, [2; 32], &[]);
            let sources = [(&old, &old_store), (&fresh, &fresh_store)];
            assert!(matches!(
                build_spend_suite2_mixed(
                    &sources,
                    &fresh,
                    None,
                    8_000,
                    0,
                    &fresh.address(),
                    &carrier(2),
                ),
                Err(SpendBuildError::SourceScanMismatch { source_index: 1 })
            ));
            // No pool activity: equal height and root can still be different
            // branches. The tip hash is an independent required equality.
            old_store.ingest_block(&old, 2, [3; 32], &[]);
            assert_eq!(old_store.root(), fresh_store.root());
            assert_eq!(old_store.scanned_height(), fresh_store.scanned_height());
            assert!(matches!(
                select_mixed(&[(&old, &old_store), (&fresh, &fresh_store)], 8_000),
                Err(SpendBuildError::SourceScanMismatch { source_index: 1 })
            ));
            // Same height and block hash, but inconsistent pool commitment data.
            let mut different_root = funded(&fresh, &[4_000, 6_000]);
            different_root.ingest_block(&fresh, 2, [3; 32], &[]);
            assert_eq!(old_store.tip_checkpoint(), different_root.tip_checkpoint());
            assert_eq!(
                old_store.commitment_count(),
                different_root.commitment_count()
            );
            assert_ne!(old_store.root(), different_root.root());
            assert!(matches!(
                select_mixed(&[(&old, &old_store), (&fresh, &different_root)], 8_000),
                Err(SpendBuildError::SourceScanMismatch { .. })
            ));
        }

        #[test]
        fn mixed_sources_reject_duplicate_positions_and_wrong_keys_before_proving() {
            let old = key(73);
            let fresh = PqShieldedKey::from_leaf_seed_suite2(&[73; 32]);
            let (old_store, fresh_store) = views(&old, &fresh);
            assert!(matches!(
                select_mixed(&[(&old, &old_store), (&old, &old_store)], 8_000),
                Err(SpendBuildError::DuplicatePosition { position: 0 })
            ));
            assert!(matches!(
                build_spend_suite2_mixed(
                    &[(&fresh, &old_store)],
                    &fresh,
                    None,
                    5_000,
                    0,
                    &fresh.address(),
                    &carrier(2),
                ),
                Err(SpendBuildError::SourceKeyMismatch { position: 0 })
            ));
            match select_mixed(&[(&old, &old_store), (&fresh, &fresh_store)], 10_001) {
                Err(SpendBuildError::Insufficient { have, need }) => {
                    assert_eq!((have, need), (10_000, 10_001));
                }
                _ => panic!("mixed balance must report the exact shortfall"),
            }
            let many = funded(&old, &[100; 8]);
            assert!(matches!(
                select_mixed(&[(&old, &many)], 550),
                Err(SpendBuildError::TooManyInputs { needed: 6 })
            ));
            let overflowing = funded(&old, &[MAX_NOTE_VALUE; 9]);
            assert!(matches!(
                select_mixed(&[(&old, &overflowing)], 1),
                Err(SpendBuildError::BalanceOverflow)
            ));
        }

        #[test]
        fn mixed_suite2_real_proof_spends_old_and_fresh_notes_in_one_global_tree() {
            let old = key(75);
            let fresh = PqShieldedKey::from_leaf_seed_suite2(&[75; 32]);
            let recipient = PqShieldedKey::from_leaf_seed_suite2(&[76; 32]);
            let legacy = build_shield(&old, &old.address(), 6_000, 0).unwrap();
            verify_spend(&legacy.proof_bytes, &legacy.public_inputs).unwrap();
            let fresh_deposit =
                build_shield_suite2(&fresh, &fresh.address(), 4_000, 0, &carrier(1)).unwrap();
            verify_suite2(&fresh_deposit, &carrier(1));

            let mut old_store = PqNoteStore::new(0);
            let mut fresh_store = PqNoteStore::new(0);
            let mut recipient_store = PqNoteStore::new(0);
            let mut state = crate::ShieldedV2State::new();
            for (height, bundle) in [(1, &legacy), (2, &fresh_deposit)] {
                old_store.ingest_block(&old, height, [height as u8; 32], &[bundle]);
                fresh_store.ingest_block(&fresh, height, [height as u8; 32], &[bundle]);
                recipient_store.ingest_block(&recipient, height, [height as u8; 32], &[bundle]);
                state
                    .apply(&[], &[bundle.public_inputs.output_commitments[0]])
                    .unwrap();
            }
            assert_eq!(old_store.root(), fresh_store.root());
            assert_eq!(old_store.root(), state.root());
            assert_eq!(old_store.balance(), 6_000);
            assert_eq!(fresh_store.balance(), 4_000);
            let old_note = old_store.unspent(&old)[0].0;
            let fresh_note = fresh_store.unspent(&fresh)[0].0;
            let expected_nullifiers = [
                old.spend_key().nullifier(old_note.rho, 0),
                fresh.spend_key().nullifier(fresh_note.rho, 1),
            ];
            // Restore the phrase-derived keys and persisted scans before
            // spending. Saved NSKs alone cannot satisfy suite-2 ownership.
            let restored_old = key(75);
            let restored_fresh = PqShieldedKey::from_leaf_seed_suite2(&[75; 32]);
            let mut old_store = PqNoteStore::from_bytes(&old_store.to_bytes()).unwrap();
            let mut fresh_store = PqNoteStore::from_bytes(&fresh_store.to_bytes()).unwrap();

            let built = build_spend_suite2_mixed(
                &[(&restored_old, &old_store), (&restored_fresh, &fresh_store)],
                &restored_fresh,
                Some(&recipient.address()),
                9_000,
                0,
                &fresh.address(),
                &carrier(2),
            )
            .expect("neither source alone covers the exact payment; together they do");
            verify_suite2(&built.bundle, &carrier(2));
            assert_eq!(built.spent_positions, vec![0, 1]);
            assert_eq!(built.change_grains, 1_000);
            assert_eq!(built.bundle.auth_pk, fresh.auth_key().public_bytes());
            let pi = &built.bundle.public_inputs;
            assert_eq!(&pi.nullifiers[..2], &expected_nullifiers);
            assert_eq!(&pi.anchors[..2], &[state.root(); 2]);
            assert_eq!(
                (pi.transparent_in, pi.transparent_out, pi.fee_grains),
                (0, 0, 0)
            );
            let payment = recipient
                .encryption_key()
                .decrypt(built.bundle.output_ciphertexts[0].as_ref().unwrap())
                .unwrap();
            let change = fresh
                .encryption_key()
                .decrypt(built.bundle.output_ciphertexts[1].as_ref().unwrap())
                .unwrap();
            assert_eq!(payment.value_grains, 9_000);
            assert_eq!(payment.commitment(), pi.output_commitments[0]);
            assert_eq!(change.value_grains, 1_000);
            assert_eq!(change.owner_tag, fresh.owner_tag());
            assert_eq!(change.commitment(), pi.output_commitments[1]);

            let wire = crate::wire::encode_bundle_for_suite(2, &built.bundle).unwrap();
            let decoded = crate::wire::decode_bundle_for_suite(2, &wire).unwrap();
            verify_suite2(&decoded, &carrier(2));
            state
                .apply(&pi.nullifiers[..2], &pi.output_commitments[..2])
                .unwrap();
            for (key, store) in [
                (&old, &mut old_store),
                (&fresh, &mut fresh_store),
                (&recipient, &mut recipient_store),
            ] {
                store.ingest_block(key, 3, [3; 32], &[&decoded]);
                assert_eq!(store.root(), state.root());
            }
            assert_eq!(old_store.balance(), 0);
            assert_eq!(fresh_store.balance(), 1_000);
            assert_eq!(recipient_store.balance(), 9_000);
            let reloaded_fresh = PqNoteStore::from_bytes(&fresh_store.to_bytes()).unwrap();
            assert_eq!(reloaded_fresh.balance(), 1_000);
            assert_eq!(reloaded_fresh.root(), state.root());
            assert_eq!(reloaded_fresh.unspent(&restored_fresh).len(), 1);
            assert_eq!(state.nullifier_count(), 2);
            assert_eq!(state.note_count(), 4);
            assert_eq!(
                old_store.balance() + fresh_store.balance() + recipient_store.balance(),
                legacy.public_inputs.transparent_in + fresh_deposit.public_inputs.transparent_in,
                "funding and private transfer conserve the entire pool supply"
            );
            let before = state.commitment();
            assert!(state.apply(&pi.nullifiers[..2], &[]).is_err());
            assert_eq!(
                state.commitment(),
                before,
                "replay rejection does not mutate state"
            );
        }
    }
}
