//! M-of-N multi-signature custody.
//!
//! Institutional custody rarely rests on a single key. A [`MultisigPolicy`]
//! names `N` authorized signer keys and a threshold `M`: an action is authorized
//! only once `M` distinct authorized signers have approved it. This is exactly
//! the shape of the validator finality vote — each [`MultisigApproval`] is an
//! Ed25519 signature over the proposal, independently verifiable and attributable
//! to one signer, so approvals cannot be forged, double-counted, or replayed.
//!
//! A [`Proposal`] is the action awaiting authorization, identified by its content
//! hash and bounded by an `expiry_height`. Signers approve the proposal; the
//! policy decides when the threshold of distinct valid approvals is met.
//!
//! This is an authorization primitive — it decides *whether* an action is
//! authorized. Executing the authorized payload (e.g. a transfer) is the runtime
//! integration follow-on.

use std::collections::BTreeSet;

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use sov_crypto::{Keypair, PublicKey, Signature};
use sov_primitives::{AccountId, Hash};

/// An M-of-N multisig configuration: `N` authorized signer keys, `M` (the
/// threshold) required to authorize an action.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct MultisigPolicy {
    signers: Vec<PublicKey>,
    threshold: u32,
}

impl MultisigPolicy {
    /// Build a policy from `signers` requiring `threshold` of them. Rejects an
    /// empty signer set, a zero threshold, a threshold larger than the signer
    /// count, or duplicate signers.
    pub fn new(signers: Vec<PublicKey>, threshold: u32) -> Result<Self, MultisigError> {
        if signers.is_empty() {
            return Err(MultisigError::EmptySigners);
        }
        if threshold == 0 {
            return Err(MultisigError::ZeroThreshold);
        }
        if threshold as usize > signers.len() {
            return Err(MultisigError::ThresholdExceedsSigners {
                threshold,
                signers: signers.len(),
            });
        }
        let mut seen = BTreeSet::new();
        for s in &signers {
            if !seen.insert(*s) {
                return Err(MultisigError::DuplicateSigner);
            }
        }
        Ok(MultisigPolicy { signers, threshold })
    }

    /// The number of authorized signers (`N`).
    pub fn n(&self) -> usize {
        self.signers.len()
    }

    /// The approval threshold (`M`).
    pub fn threshold(&self) -> u32 {
        self.threshold
    }

    /// The authorized signer keys.
    pub fn signers(&self) -> &[PublicKey] {
        &self.signers
    }

    /// Whether `key` is one of the authorized signers.
    pub fn is_signer(&self, key: &PublicKey) -> bool {
        self.signers.contains(key)
    }

    /// The set of distinct authorized signers who have validly approved
    /// `proposal`. Approvals from non-signers or with bad signatures are ignored;
    /// duplicate approvals from one signer count once.
    pub fn verified_signers(
        &self,
        proposal: &Proposal,
        approvals: &[MultisigApproval],
    ) -> BTreeSet<PublicKey> {
        approvals
            .iter()
            .filter(|a| self.is_signer(&a.signer) && a.verify(proposal))
            .map(|a| a.signer)
            .collect()
    }

    /// How many distinct authorized signers have validly approved `proposal`.
    pub fn approval_count(&self, proposal: &Proposal, approvals: &[MultisigApproval]) -> u32 {
        self.verified_signers(proposal, approvals).len() as u32
    }

    /// Whether `proposal` is authorized at `current_height`: it has not expired
    /// and at least `threshold` distinct authorized signers have validly approved
    /// it.
    pub fn is_authorized(
        &self,
        proposal: &Proposal,
        approvals: &[MultisigApproval],
        current_height: u64,
    ) -> bool {
        current_height <= proposal.expiry_height
            && self.approval_count(proposal, approvals) >= self.threshold
    }
}

/// An action awaiting multisig authorization.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct Proposal {
    /// The account the action is for.
    pub account: AccountId,
    /// A per-account proposal nonce, preventing replay of an old identical action.
    pub nonce: u64,
    /// The opaque action payload to authorize (e.g. the Borsh of a transaction).
    pub payload: Vec<u8>,
    /// Height after which the proposal can no longer be authorized.
    pub expiry_height: u64,
}

impl Proposal {
    /// The proposal's canonical content hash — what signers approve.
    pub fn hash(&self) -> Hash {
        Hash::digest(
            &borsh::to_vec(&(&self.account, self.nonce, &self.payload, self.expiry_height))
                .expect("Borsh serialization of a Proposal is infallible"),
        )
    }
}

/// One signer's signed approval of a specific proposal.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct MultisigApproval {
    /// The approving signer's public key.
    pub signer: PublicKey,
    /// Signature over the proposal hash, bound to `signer`.
    pub signature: Signature,
}

impl MultisigApproval {
    /// The canonical signed payload: domain-separated, binding the proposal hash
    /// to the claimed signer (so an approval cannot be re-attributed).
    fn signing_bytes(proposal_hash: Hash, signer: &PublicKey) -> Vec<u8> {
        borsh::to_vec(&("sov.multisig.v1", proposal_hash, signer))
            .expect("Borsh serialization of approval facts is infallible")
    }

    /// Create an approval of `proposal` from `keypair`.
    pub fn create(proposal: &Proposal, keypair: &Keypair) -> Self {
        let signer = keypair.public_key();
        let signature = keypair.sign(&Self::signing_bytes(proposal.hash(), &signer));
        MultisigApproval { signer, signature }
    }

    /// Verify this approval against `proposal` (the signature must be `signer`'s
    /// over this exact proposal).
    #[must_use]
    pub fn verify(&self, proposal: &Proposal) -> bool {
        let bytes = Self::signing_bytes(proposal.hash(), &self.signer);
        self.signer.verify(&bytes, &self.signature)
    }
}

/// Why a multisig policy could not be built.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MultisigError {
    /// No signers were provided.
    #[error("a multisig policy needs at least one signer")]
    EmptySigners,
    /// The threshold was zero.
    #[error("a multisig threshold must be at least 1")]
    ZeroThreshold,
    /// The threshold exceeded the number of signers.
    #[error("threshold {threshold} exceeds the {signers} signer(s)")]
    ThresholdExceedsSigners {
        /// The requested threshold.
        threshold: u32,
        /// The number of signers.
        signers: usize,
    },
    /// A signer key appeared more than once.
    #[error("duplicate signer key in multisig policy")]
    DuplicateSigner,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kp(seed: u8) -> Keypair {
        Keypair::from_seed([seed; 32])
    }
    fn id(s: &str) -> AccountId {
        AccountId::new(s).unwrap()
    }

    fn proposal() -> Proposal {
        Proposal {
            account: id("treasury.sov"),
            nonce: 0,
            payload: b"transfer 100 to vendor.sov".to_vec(),
            expiry_height: 100,
        }
    }

    #[test]
    fn policy_construction_validates() {
        let s = vec![kp(1).public_key(), kp(2).public_key(), kp(3).public_key()];
        assert!(MultisigPolicy::new(s.clone(), 2).is_ok());
        assert_eq!(
            MultisigPolicy::new(vec![], 1),
            Err(MultisigError::EmptySigners)
        );
        assert_eq!(
            MultisigPolicy::new(s.clone(), 0),
            Err(MultisigError::ZeroThreshold)
        );
        assert!(matches!(
            MultisigPolicy::new(s, 4),
            Err(MultisigError::ThresholdExceedsSigners { .. })
        ));
        let dup = vec![kp(1).public_key(), kp(1).public_key()];
        assert_eq!(
            MultisigPolicy::new(dup, 1),
            Err(MultisigError::DuplicateSigner)
        );
    }

    #[test]
    fn reaches_threshold_with_distinct_signers() {
        let policy = MultisigPolicy::new(
            vec![kp(1).public_key(), kp(2).public_key(), kp(3).public_key()],
            2,
        )
        .unwrap();
        let p = proposal();
        // One approval: not enough.
        let a1 = MultisigApproval::create(&p, &kp(1));
        assert!(!policy.is_authorized(&p, std::slice::from_ref(&a1), 0));
        assert_eq!(policy.approval_count(&p, std::slice::from_ref(&a1)), 1);
        // Two distinct signers: authorized.
        let a2 = MultisigApproval::create(&p, &kp(2));
        assert!(policy.is_authorized(&p, &[a1.clone(), a2.clone()], 0));
        assert_eq!(policy.approval_count(&p, &[a1, a2]), 2);
    }

    #[test]
    fn duplicate_approvals_count_once() {
        let policy = MultisigPolicy::new(vec![kp(1).public_key(), kp(2).public_key()], 2).unwrap();
        let p = proposal();
        let a1 = MultisigApproval::create(&p, &kp(1));
        // The same signer twice does not reach a threshold of 2.
        assert_eq!(policy.approval_count(&p, &[a1.clone(), a1.clone()]), 1);
        assert!(!policy.is_authorized(&p, &[a1.clone(), a1], 0));
    }

    #[test]
    fn approvals_from_non_signers_are_ignored() {
        let policy = MultisigPolicy::new(vec![kp(1).public_key(), kp(2).public_key()], 1).unwrap();
        let p = proposal();
        // kp(9) is not an authorized signer.
        let outsider = MultisigApproval::create(&p, &kp(9));
        assert_eq!(
            policy.approval_count(&p, std::slice::from_ref(&outsider)),
            0
        );
        assert!(!policy.is_authorized(&p, &[outsider], 0));
    }

    #[test]
    fn approval_is_bound_to_its_proposal() {
        let p = proposal();
        let a = MultisigApproval::create(&p, &kp(1));
        assert!(a.verify(&p));
        // A different proposal (different payload) is not covered by this approval.
        let mut other = p.clone();
        other.payload = b"transfer 999 to attacker.sov".to_vec();
        assert!(!a.verify(&other));
        // Re-attributing the approval to another signer breaks verification.
        let mut forged = a.clone();
        forged.signer = kp(2).public_key();
        assert!(!forged.verify(&p));
    }

    #[test]
    fn expired_proposal_is_not_authorized() {
        let policy = MultisigPolicy::new(vec![kp(1).public_key()], 1).unwrap();
        let p = proposal(); // expiry_height = 100
        let a = MultisigApproval::create(&p, &kp(1));
        assert!(policy.is_authorized(&p, std::slice::from_ref(&a), 100)); // at expiry: ok
        assert!(!policy.is_authorized(&p, &[a], 101)); // past expiry: no
    }

    #[test]
    fn borsh_roundtrip() {
        let p = proposal();
        let a = MultisigApproval::create(&p, &kp(1));
        let pb = borsh::to_vec(&p).unwrap();
        let ab = borsh::to_vec(&a).unwrap();
        assert_eq!(borsh::from_slice::<Proposal>(&pb).unwrap(), p);
        assert_eq!(borsh::from_slice::<MultisigApproval>(&ab).unwrap(), a);
    }
}
