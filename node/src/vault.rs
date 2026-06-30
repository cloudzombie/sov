//! Treasury multisig — easy-mode M-of-N for SOV accounts.
//!
//! ISOLATION CONTRACT: pure logic (no egui, no node state). It builds the multisig
//! consensus actions (`SetMultisig` to secure an account, plus the on-chain
//! `ProposeMultisig` / `ApproveMultisig` / `CancelMultisig` coordination) and
//! persists only its own PUBLIC vault directory (`~/.sov-station/vaults.json`:
//! account ids, member public keys, friendly names, thresholds — no seeds, no
//! secrets). Remove `mod vault;` + the `Tab::Vault` arm to delete the feature.
//!
//! Coordination is ON-CHAIN: a member proposes a spend with their own transaction;
//! other members approve with theirs (their signature on the transaction IS their
//! approval); at threshold the chain executes the spend as the vault. The wallet
//! just reads pending proposals (`sov_getMultisigProposals`) and submits these
//! actions — there are no codes to copy.

use std::collections::BTreeSet;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use sov_crypto::PublicKey;
use sov_types::Action;

/// A vault member: a friendly name + their public key string (`hybrid65:0x…`).
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Member {
    pub name: String,
    pub pubkey: String,
}

/// A saved vault — ALL PUBLIC DATA. `members` order IS the on-chain approval-index
/// order; never reorder it after the vault is created on-chain.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Vault {
    pub name: String,
    pub account: String,
    pub members: Vec<Member>,
    pub threshold: u16,
}

impl Vault {
    /// Validate the shape an M-of-N policy must satisfy.
    pub fn validate(&self) -> Result<(), String> {
        if self.account.trim().is_empty() {
            return Err("choose the account to secure".into());
        }
        if self.members.is_empty() {
            return Err("add at least one member".into());
        }
        if self.members.len() > 32 {
            return Err("a vault can have at most 32 members".into());
        }
        let mut seen = BTreeSet::new();
        for m in &self.members {
            parse_pubkey(&m.pubkey)?;
            if !seen.insert(m.pubkey.trim().to_string()) {
                return Err("the same key was added twice".into());
            }
        }
        if self.threshold < 1 || self.threshold as usize > self.members.len() {
            return Err(format!(
                "approvals required must be between 1 and {}",
                self.members.len()
            ));
        }
        Ok(())
    }

    pub fn signer_keys(&self) -> Result<Vec<PublicKey>, String> {
        self.members
            .iter()
            .map(|m| parse_pubkey(&m.pubkey))
            .collect()
    }

    /// The `SetMultisig` action that opts this account into the policy. Submitted ONCE
    /// by whatever key currently controls the account.
    pub fn set_multisig_action(&self) -> Result<Action, String> {
        self.validate()?;
        Ok(Action::SetMultisig {
            signers: self.signer_keys()?,
            threshold: self.threshold,
        })
    }

    /// The signer index of `pubkey` in this vault's member order (the on-chain
    /// approval index), if it is a member.
    pub fn member_index(&self, pubkey: &str) -> Option<u16> {
        let want = pubkey.trim();
        self.members
            .iter()
            .position(|m| m.pubkey.trim() == want)
            .map(|i| i as u16)
    }
}

/// `<home>/.sov-station/vaults.json` — the saved vault directory.
pub fn vaults_path() -> Result<PathBuf, String> {
    let home = std::env::var("HOME")
        .ok()
        .or_else(|| std::env::var("USERPROFILE").ok())
        .ok_or("no home directory")?;
    Ok(PathBuf::from(home).join(".sov-station").join("vaults.json"))
}

/// Load the saved vaults; an empty list on any error (best-effort, never blocks).
pub fn load_vaults() -> Vec<Vault> {
    let Ok(path) = vaults_path() else {
        return Vec::new();
    };
    std::fs::read(&path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

/// Save the vault directory (creates the dir; public data only).
pub fn save_vaults(vaults: &[Vault]) -> Result<(), String> {
    let path = vaults_path()?;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    let json = serde_json::to_vec_pretty(vaults).map_err(|e| e.to_string())?;
    std::fs::write(&path, json).map_err(|e| e.to_string())
}

/// Parse a `hybrid65:0x…` (or bare-hex Ed25519) public key string, the exact pattern
/// the wallet UI already uses.
pub fn parse_pubkey(s: &str) -> Result<PublicKey, String> {
    serde_json::from_value(Value::String(s.trim().to_string()))
        .map_err(|e| format!("not a valid public key: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sov_crypto::Keypair;

    fn kp(seed: u8) -> Keypair {
        Keypair::hybrid_from_seed([seed; 32])
    }
    fn member(name: &str, k: &Keypair) -> Member {
        Member {
            name: name.into(),
            pubkey: k.public_key().to_string(),
        }
    }
    fn vault_2of3(a: &Keypair, b: &Keypair, c: &Keypair) -> Vault {
        Vault {
            name: "National Debt Vault".into(),
            account: "treasury.reserve.sov".into(),
            members: vec![member("Me", a), member("Bessent", b), member("Deputy", c)],
            threshold: 2,
        }
    }

    #[test]
    fn set_multisig_action_has_ordered_keys_and_threshold() {
        let (a, b, c) = (kp(1), kp(2), kp(3));
        let v = vault_2of3(&a, &b, &c);
        match v.set_multisig_action().unwrap() {
            Action::SetMultisig { signers, threshold } => {
                assert_eq!(threshold, 2);
                assert_eq!(
                    signers,
                    vec![a.public_key(), b.public_key(), c.public_key()]
                );
            }
            _ => panic!("expected SetMultisig"),
        }
    }

    #[test]
    fn validate_rejects_bad_shapes() {
        let (a, b, c) = (kp(1), kp(2), kp(3));
        let mut v = vault_2of3(&a, &b, &c);
        v.threshold = 4;
        assert!(v.validate().is_err());
        v.threshold = 0;
        assert!(v.validate().is_err());
        v.threshold = 2;
        v.members.push(member("dup", &a));
        assert!(v.validate().is_err());
    }

    #[test]
    fn member_index_matches_signer_order() {
        let (a, b, c) = (kp(1), kp(2), kp(3));
        let v = vault_2of3(&a, &b, &c);
        assert_eq!(v.member_index(&a.public_key().to_string()), Some(0));
        assert_eq!(v.member_index(&b.public_key().to_string()), Some(1));
        assert_eq!(v.member_index(&c.public_key().to_string()), Some(2));
        assert_eq!(v.member_index(&kp(9).public_key().to_string()), None);
    }
}
