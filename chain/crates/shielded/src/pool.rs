//! The shielded pool: minting value into shielded notes, and verifying the
//! Halo2 zero-knowledge proofs that authorize shielded actions.

use std::sync::OnceLock;

use orchard::builder::{Builder, BundleType};
use orchard::bundle::Authorized;
use orchard::circuit::{ProvingKey, VerifyingKey};
use orchard::tree::Anchor;
use orchard::value::NoteValue;
use orchard::Bundle;
use rand::rngs::OsRng;

use crate::keys::ShieldedAddress;
use crate::ShieldedError;

/// Process-wide verifying key, built once on first shielded verification. Building
/// it is expensive (seconds), so it is cached here rather than rebuilt per block
/// or threaded through every call site.
static VERIFYING_KEY: OnceLock<VerifyingKey> = OnceLock::new();

/// The Orchard/Halo2 proving and verifying keys for the shielded circuit.
///
/// Building these generates the circuit parameters and is expensive (it is the
/// no-trusted-setup analogue of Zcash's parameters), so build once at startup
/// and reuse. Verification needs only [`ShieldedParams::verifying_key`].
pub struct ShieldedParams {
    proving: ProvingKey,
    verifying: VerifyingKey,
}

impl ShieldedParams {
    /// Build the circuit parameters. Expensive; do this once and share it.
    pub fn build() -> Self {
        ShieldedParams {
            proving: ProvingKey::build(),
            verifying: VerifyingKey::build(),
        }
    }

    /// The verifying key, for checking proofs without the (larger) proving key.
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying
    }

    /// The proving key (crate-internal: used to generate bundle proofs).
    pub(crate) fn proving_key(&self) -> &ProvingKey {
        &self.proving
    }
}

/// A fully-authorized shielded bundle: one or more shielded actions carrying a
/// real Halo2 proof and signatures. This is the unit a SOV transaction will
/// embed once the pool is wired into the runtime.
pub struct ShieldedBundle {
    inner: Bundle<Authorized, i64>,
}

impl ShieldedBundle {
    /// The net value the bundle moves between the transparent and shielded
    /// pools. **Negative** means value entered the shielded pool (a mint or a
    /// shield); **positive** means value left it (a de-shield); **zero** is a
    /// fully-shielded transfer. For a mint of `amount`, this is `-amount`.
    pub fn value_balance(&self) -> i64 {
        *self.inner.value_balance()
    }

    /// Verify the bundle's zero-knowledge proof against the circuit verifying
    /// key. Returns `true` only if the proof is valid — this is the check a
    /// validator runs before accepting a shielded action.
    pub fn verify(&self, params: &ShieldedParams) -> bool {
        self.inner.verify_proof(params.verifying_key()).is_ok()
    }

    /// Verify against a process-wide, lazily-built verifying key (built once on
    /// first call, then cached). This is what the runtime uses, so it need not
    /// hold or thread a [`ShieldedParams`] through consensus.
    pub fn verify_cached(&self) -> bool {
        let vk = VERIFYING_KEY.get_or_init(VerifyingKey::build);
        self.inner.verify_proof(vk).is_ok()
    }

    /// The anchor (note-commitment tree root) this bundle's spends are proven
    /// against. A validator accepts the bundle only if this is a root the chain
    /// has held (see [`ShieldedState::anchor_is_known`](crate::ShieldedState::anchor_is_known)).
    pub fn anchor(&self) -> Anchor {
        *self.inner.anchor()
    }

    /// The output note commitments this bundle adds to the pool — appended to
    /// the note-commitment tree when the bundle is applied.
    pub fn note_commitments(&self) -> Vec<orchard::note::ExtractedNoteCommitment> {
        self.inner.actions().iter().map(|a| *a.cmx()).collect()
    }

    /// The nullifiers this bundle spends — inserted into the nullifier set (and
    /// rejected as a double-spend if already present) when the bundle is applied.
    pub fn nullifiers(&self) -> Vec<orchard::note::Nullifier> {
        self.inner
            .actions()
            .iter()
            .map(|a| *a.nullifier())
            .collect()
    }

    /// The nullifiers this bundle spends, as raw 32-byte values — what a wallet
    /// compares against its notes' nullifiers to mark them spent during a scan.
    pub fn nullifier_bytes(&self) -> Vec<[u8; 32]> {
        self.nullifiers().iter().map(|nf| nf.to_bytes()).collect()
    }

    /// The output note commitments as raw 32-byte values — what a wallet feeds
    /// into a witnessing tree to later spend a received note.
    pub fn note_commitment_bytes(&self) -> Vec<[u8; 32]> {
        self.note_commitments()
            .iter()
            .map(|c| c.to_bytes())
            .collect()
    }

    /// Construct from an authorized Orchard bundle (crate-internal).
    pub(crate) fn from_authorized(inner: Bundle<Authorized, i64>) -> Self {
        ShieldedBundle { inner }
    }

    /// The underlying authorized Orchard bundle (crate-internal: for note
    /// recovery and applying to state).
    pub(crate) fn inner(&self) -> &Bundle<Authorized, i64> {
        &self.inner
    }
}

/// Mint `amount` units of SOV directly into a shielded note for `recipient`.
///
/// This is a coinbase-style Orchard bundle with **no shielded inputs**, so the
/// value flows from transparent issuance (proof-of-work / staking emission)
/// into the shielded pool — the "mint lands shielded" rule. The returned bundle
/// carries a genuine Halo2 proof and is ready to verify. The note's amount and
/// recipient are hidden; only the negative value balance (`-amount`) is public,
/// because the transparent issuance side must account for it.
pub fn mint_to_shielded(
    params: &ShieldedParams,
    recipient: &ShieldedAddress,
    amount: u64,
) -> Result<ShieldedBundle, ShieldedError> {
    let mut rng = OsRng;

    // A coinbase bundle: spends disabled, outputs only, no dummy padding.
    let mut builder = Builder::new(BundleType::Coinbase, Anchor::empty_tree());
    builder
        .add_output(None, recipient.0, NoteValue::from_raw(amount), [0u8; 512])
        .map_err(|e| ShieldedError::Build(e.to_string()))?;

    let unauthorized = builder
        .build::<i64>(&mut rng)
        .map_err(|e| ShieldedError::Build(e.to_string()))?
        .ok_or(ShieldedError::EmptyBundle)?
        .0;

    // Generate the real Halo2 proof, then apply signatures. A coinbase mint has
    // no spends to authorize, so no spend-authorizing keys are supplied; the
    // binding signature over the value balance is applied automatically.
    let bundle = unauthorized
        .create_proof(&params.proving, &mut rng)
        .map_err(|e| ShieldedError::Prove(e.to_string()))?
        .apply_signatures(rng, [0u8; 32], &[])
        .map_err(|e| ShieldedError::Build(e.to_string()))?;

    Ok(ShieldedBundle { inner: bundle })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::ShieldedKey;

    #[test]
    fn mint_into_shielded_produces_a_verifiable_proof() {
        // One shared set of circuit parameters (expensive to build).
        let params = ShieldedParams::build();

        // A miner's shielded key + address (derived from seed material).
        let miner = ShieldedKey::from_seed([7u8; 32]).expect("valid key");
        let addr = miner.address();

        // Mint 50 SOV (in grains-as-units here) into a shielded note.
        let bundle = mint_to_shielded(&params, &addr, 50).expect("mint builds + proves");

        // The proof verifies, and the value balance shows value entered the pool.
        assert!(bundle.verify(&params), "real Halo2 proof must verify");
        assert_eq!(
            bundle.value_balance(),
            -50,
            "minted value enters the shielded pool"
        );
    }

    #[test]
    fn a_shielded_address_round_trips_through_raw_bytes() {
        let key = ShieldedKey::from_seed([42u8; 32]).expect("valid key");
        let addr = key.address();
        let raw = addr.to_bytes();
        let back = ShieldedAddress::from_bytes(&raw).expect("valid raw address");
        assert_eq!(addr.to_bytes(), back.to_bytes());
    }
}
