//! Shielded transfers: spending a received note and creating a new shielded
//! output, fully hidden, with a real Halo2 proof.

use orchard::builder::{Builder, BundleType};
use orchard::keys::{Scope, SpendAuthorizingKey};
use orchard::tree::{Anchor, MerklePath};
use orchard::value::NoteValue;
use rand::rngs::OsRng;

use crate::keys::{ShieldedAddress, ShieldedKey};
use crate::pool::{ShieldedBundle, ShieldedParams};
use crate::wallet::ReceivedNote;
use crate::ShieldedError;

/// Build a fully-shielded transfer: spend `note` (owned by `spender`, proven to
/// be in the note-commitment tree at `anchor` via `merkle_path`) and pay its
/// **entire value** to `recipient` as a new shielded note.
///
/// Sender, recipient, and amount are all hidden; the bundle's value balance is
/// zero, so value stays inside the shielded pool. The returned bundle carries a
/// genuine Halo2 proof and a spend-authorizing signature, and is ready to
/// verify and apply. (Partial spends with change back to the sender are a
/// straightforward extension — add a second output for the change.)
pub fn shielded_transfer(
    params: &ShieldedParams,
    spender: &ShieldedKey,
    note: &ReceivedNote,
    merkle_path: MerklePath,
    anchor: Anchor,
    recipient: &ShieldedAddress,
) -> Result<ShieldedBundle, ShieldedError> {
    let mut rng = OsRng;
    let fvk = spender.fvk();
    let ovk = fvk.to_ovk(Scope::External);

    let mut builder = Builder::new(BundleType::DEFAULT, anchor);
    builder
        .add_spend(fvk, note.note(), merkle_path)
        .map_err(|e| ShieldedError::Build(e.to_string()))?;
    builder
        .add_output(Some(ovk), recipient.0, note.note_value(), [0u8; 512])
        .map_err(|e| ShieldedError::Build(e.to_string()))?;

    let unauthorized = builder
        .build::<i64>(&mut rng)
        .map_err(|e| ShieldedError::Build(e.to_string()))?
        .ok_or(ShieldedError::EmptyBundle)?
        .0;

    // Prove, then sign: the real spend is authorized by the spender's key; any
    // dummy padding spends are signed automatically by the builder.
    let ask = SpendAuthorizingKey::from(spender.spending_key());
    let bundle = unauthorized
        .create_proof(params.proving_key(), &mut rng)
        .map_err(|e| ShieldedError::Prove(e.to_string()))?
        .apply_signatures(rng, [0u8; 32], &[ask])
        .map_err(|e| ShieldedError::Build(e.to_string()))?;

    Ok(ShieldedBundle::from_authorized(bundle))
}

/// Build a **partial** shielded transfer: spend `note`, pay `amount` to
/// `recipient`, and return the remaining `note.value() - amount` to the spender
/// as a private change note. Both outputs are shielded and the value balance is
/// zero, so value stays in the pool. Errors if `amount` exceeds the note value.
///
/// This is the general spend; a full-value transfer is the special case
/// `amount == note.value()` (which [`shielded_transfer`] does in a single output).
pub fn shielded_transfer_with_change(
    params: &ShieldedParams,
    spender: &ShieldedKey,
    note: &ReceivedNote,
    merkle_path: MerklePath,
    anchor: Anchor,
    recipient: &ShieldedAddress,
    amount: u64,
) -> Result<ShieldedBundle, ShieldedError> {
    let total = note.value();
    let change = total
        .checked_sub(amount)
        .ok_or_else(|| ShieldedError::Build("amount exceeds note value".to_string()))?;

    let mut rng = OsRng;
    let fvk = spender.fvk();
    let ovk = fvk.to_ovk(Scope::External);
    let change_addr = spender.address();

    let mut builder = Builder::new(BundleType::DEFAULT, anchor);
    builder
        .add_spend(fvk, note.note(), merkle_path)
        .map_err(|e| ShieldedError::Build(e.to_string()))?;
    builder
        .add_output(
            Some(ovk.clone()),
            recipient.0,
            NoteValue::from_raw(amount),
            [0u8; 512],
        )
        .map_err(|e| ShieldedError::Build(e.to_string()))?;
    // The change note pays the spender back, privately.
    builder
        .add_output(
            Some(ovk),
            change_addr.0,
            NoteValue::from_raw(change),
            [0u8; 512],
        )
        .map_err(|e| ShieldedError::Build(e.to_string()))?;

    let unauthorized = builder
        .build::<i64>(&mut rng)
        .map_err(|e| ShieldedError::Build(e.to_string()))?
        .ok_or(ShieldedError::EmptyBundle)?
        .0;

    let ask = SpendAuthorizingKey::from(spender.spending_key());
    let bundle = unauthorized
        .create_proof(params.proving_key(), &mut rng)
        .map_err(|e| ShieldedError::Prove(e.to_string()))?
        .apply_signatures(rng, [0u8; 32], &[ask])
        .map_err(|e| ShieldedError::Build(e.to_string()))?;

    Ok(ShieldedBundle::from_authorized(bundle))
}

/// Build a **de-shield**: spend `note` with *no* shielded output, so the
/// bundle's value balance is `+note.value()` — value leaves the pool and the
/// runtime credits it to the submitting account's transparent balance. The
/// returned bundle carries a genuine Halo2 proof and the spender's
/// authorizing signature. (The runtime additionally enforces the pool-balance
/// turnstile and the per-window de-shield rate limit on this path.)
pub fn unshield(
    params: &ShieldedParams,
    spender: &ShieldedKey,
    note: &ReceivedNote,
    merkle_path: MerklePath,
    anchor: Anchor,
) -> Result<ShieldedBundle, ShieldedError> {
    let mut rng = OsRng;
    let fvk = spender.fvk();

    let mut builder = Builder::new(BundleType::DEFAULT, anchor);
    builder
        .add_spend(fvk, note.note(), merkle_path)
        .map_err(|e| ShieldedError::Build(e.to_string()))?;
    // No output: the builder pads with dummy zero-value actions, leaving the
    // bundle's net value balance at +note.value() — the de-shielded amount.

    let unauthorized = builder
        .build::<i64>(&mut rng)
        .map_err(|e| ShieldedError::Build(e.to_string()))?
        .ok_or(ShieldedError::EmptyBundle)?
        .0;

    let ask = SpendAuthorizingKey::from(spender.spending_key());
    let bundle = unauthorized
        .create_proof(params.proving_key(), &mut rng)
        .map_err(|e| ShieldedError::Prove(e.to_string()))?
        .apply_signatures(rng, [0u8; 32], &[ask])
        .map_err(|e| ShieldedError::Build(e.to_string()))?;

    Ok(ShieldedBundle::from_authorized(bundle))
}

/// Build a **partial de-shield**: spend `note`, move `amount` out of the pool to
/// the submitting account's transparent balance, and return the remaining
/// `note.value() - amount` to the spender as a private change note. The bundle's
/// value balance is exactly `+amount`, so only `amount` leaves the pool. Errors if
/// `amount` exceeds the note value.
///
/// This is what lets a wallet de-shield a **variable** amount from a note instead
/// of the whole note at once; `amount == note.value()` is the special case with no
/// change, identical to [`unshield`]. (The runtime still enforces the pool-balance
/// turnstile and the per-window de-shield rate limit on the resulting bundle.)
pub fn unshield_amount(
    params: &ShieldedParams,
    spender: &ShieldedKey,
    note: &ReceivedNote,
    merkle_path: MerklePath,
    anchor: Anchor,
    amount: u64,
) -> Result<ShieldedBundle, ShieldedError> {
    let change = note
        .value()
        .checked_sub(amount)
        .ok_or_else(|| ShieldedError::Build("amount exceeds note value".to_string()))?;

    let mut rng = OsRng;
    let fvk = spender.fvk();

    let mut builder = Builder::new(BundleType::DEFAULT, anchor);
    builder
        .add_spend(fvk.clone(), note.note(), merkle_path)
        .map_err(|e| ShieldedError::Build(e.to_string()))?;
    // A change note back to the spender for the un-de-shielded remainder; the
    // value NOT returned (`amount`) becomes the bundle's positive value balance —
    // the de-shielded amount. When `change == 0` there is no output, so the whole
    // note de-shields (exactly like `unshield`).
    if change > 0 {
        let ovk = fvk.to_ovk(Scope::External);
        let change_addr = spender.address();
        builder
            .add_output(
                Some(ovk),
                change_addr.0,
                NoteValue::from_raw(change),
                [0u8; 512],
            )
            .map_err(|e| ShieldedError::Build(e.to_string()))?;
    }

    let unauthorized = builder
        .build::<i64>(&mut rng)
        .map_err(|e| ShieldedError::Build(e.to_string()))?
        .ok_or(ShieldedError::EmptyBundle)?
        .0;

    let ask = SpendAuthorizingKey::from(spender.spending_key());
    let bundle = unauthorized
        .create_proof(params.proving_key(), &mut rng)
        .map_err(|e| ShieldedError::Prove(e.to_string()))?
        .apply_signatures(rng, [0u8; 32], &[ask])
        .map_err(|e| ShieldedError::Build(e.to_string()))?;

    Ok(ShieldedBundle::from_authorized(bundle))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pool::mint_to_shielded;
    use crate::state::ShieldedState;
    use crate::wallet::{recover_outputs, witness_latest, NoteWitnessTree};

    #[test]
    fn shielded_transfer_spends_a_received_note_and_verifies() {
        let params = ShieldedParams::build();
        let alice = ShieldedKey::from_seed([1u8; 32]).unwrap();
        let bob = ShieldedKey::from_seed([2u8; 32]).unwrap();

        // 1. Mint 50 into a shielded note for Alice.
        let mint = mint_to_shielded(&params, &alice.address(), 50).unwrap();

        // 2. Alice scans the mint and recovers her spendable note; Bob cannot.
        let received = recover_outputs(&alice, &mint);
        assert_eq!(received.len(), 1, "Alice recovers exactly her minted note");
        assert_eq!(received[0].value(), 50);
        assert!(
            recover_outputs(&bob, &mint).is_empty(),
            "Bob cannot decrypt Alice's note"
        );

        // 3. Witness Alice's note (the only commitment in the tree so far).
        let (path, anchor) = witness_latest(&mint.note_commitment_bytes()).expect("witness");

        // 4. Alice transfers the full value to Bob, fully shielded.
        let transfer =
            shielded_transfer(&params, &alice, &received[0], path, anchor, &bob.address()).unwrap();
        assert!(transfer.verify(&params), "real transfer proof must verify");
        assert_eq!(
            transfer.value_balance(),
            0,
            "a pure transfer keeps value inside the shielded pool"
        );

        // 5. Bob can now recover the transferred note.
        assert_eq!(
            recover_outputs(&bob, &transfer).len(),
            1,
            "Bob receives the shielded output"
        );

        // 6. The spend integrates with consensus state, and a replay is rejected
        //    as a double-spend (the nullifier is already present).
        let mut state = ShieldedState::new();
        state.apply_bundle(&transfer).unwrap();
        assert_eq!(
            state.apply_bundle(&transfer),
            Err(ShieldedError::DoubleSpend),
            "replaying the same spend is a double-spend"
        );
    }

    /// A valid, distinct note commitment that is not the empty-leaf sentinel.
    fn unrelated_cmx(n: u8) -> [u8; 32] {
        let mut b = [0u8; 32];
        b[0] = 1;
        b[1] = n;
        b
    }

    #[test]
    fn partial_spend_of_a_witnessed_old_note_pays_recipient_and_change() {
        let params = ShieldedParams::build();
        let alice = ShieldedKey::from_seed([1u8; 32]).unwrap();
        let bob = ShieldedKey::from_seed([2u8; 32]).unwrap();

        // Mint a 50-unit note to Alice and recover it.
        let mint = mint_to_shielded(&params, &alice.address(), 50).unwrap();
        let received = recover_outputs(&alice, &mint);
        assert_eq!(received.len(), 1);
        assert_eq!(received[0].value(), 50);

        // Build a witnessing tree: Alice's note is appended and MARKED, then two
        // more (unowned) notes arrive — so Alice's note is no longer the tip and
        // a tip-only `witness_latest` could not witness it.
        let mut tree = NoteWitnessTree::new();
        let alice_cmx = mint.note_commitment_bytes()[0];
        tree.append(&alice_cmx).unwrap();
        let pos = tree.mark().unwrap();
        assert_eq!(pos, 0);
        tree.append(&unrelated_cmx(7)).unwrap();
        tree.append(&unrelated_cmx(9)).unwrap();

        // Witness Alice's OLD note (position 0) against the current 3-leaf root.
        let (path, anchor) = tree
            .witness(pos)
            .expect("an old marked note is witnessable");

        // Partial spend: 30 to Bob, 20 change back to Alice — fully shielded.
        let transfer = shielded_transfer_with_change(
            &params,
            &alice,
            &received[0],
            path,
            anchor,
            &bob.address(),
            30,
        )
        .unwrap();
        assert!(transfer.verify(&params), "partial-spend proof must verify");
        assert_eq!(transfer.value_balance(), 0, "value stays in the pool");

        // Bob receives 30; Alice receives the 20 change.
        let bobs = recover_outputs(&bob, &transfer);
        assert_eq!(bobs.len(), 1);
        assert_eq!(bobs[0].value(), 30);
        let alices = recover_outputs(&alice, &transfer);
        assert_eq!(alices.len(), 1);
        assert_eq!(alices[0].value(), 20);

        // Over-spending a note is rejected.
        let (path2, anchor2) = tree.witness(pos).unwrap();
        assert!(shielded_transfer_with_change(
            &params,
            &alice,
            &received[0],
            path2,
            anchor2,
            &bob.address(),
            51,
        )
        .is_err());
    }

    #[test]
    fn partial_deshield_moves_a_variable_amount_out_and_keeps_change_shielded() {
        let params = ShieldedParams::build();
        let alice = ShieldedKey::from_seed([3u8; 32]).unwrap();

        // Mint a 50-unit note to Alice and recover it.
        let mint = mint_to_shielded(&params, &alice.address(), 50).unwrap();
        let received = recover_outputs(&alice, &mint);
        assert_eq!(received[0].value(), 50);

        let mut tree = NoteWitnessTree::new();
        tree.append(&mint.note_commitment_bytes()[0]).unwrap();
        let pos = tree.mark().unwrap();
        let (path, anchor) = tree.witness(pos).unwrap();

        // De-shield a VARIABLE amount (30 of 50): value balance is +30 (only 30
        // leaves the pool), and Alice keeps a 20 shielded change note.
        let bundle = unshield_amount(&params, &alice, &received[0], path, anchor, 30).unwrap();
        assert!(bundle.verify(&params), "partial de-shield proof must verify");
        assert_eq!(bundle.value_balance(), 30, "exactly the de-shielded amount leaves");
        let change = recover_outputs(&alice, &bundle);
        assert_eq!(change.len(), 1, "the remainder stays shielded as change");
        assert_eq!(change[0].value(), 20);

        // De-shielding the WHOLE note is the special case: balance +50, no change.
        let (path2, anchor2) = tree.witness(pos).unwrap();
        let whole = unshield_amount(&params, &alice, &received[0], path2, anchor2, 50).unwrap();
        assert_eq!(whole.value_balance(), 50);
        assert!(recover_outputs(&alice, &whole).is_empty(), "no change on a full de-shield");

        // De-shielding more than the note holds is rejected.
        let (path3, anchor3) = tree.witness(pos).unwrap();
        assert!(unshield_amount(&params, &alice, &received[0], path3, anchor3, 51).is_err());
    }
}
