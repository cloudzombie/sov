//! Treasury multisig — easy-mode M-of-N for SOV accounts.
//!
//! ISOLATION CONTRACT (deliberate): this module is PURE LOGIC — no egui, no `Station`,
//! no node state — and it touches NONE of the existing wallet / keystore / consensus
//! code. It only:
//!   * builds the already-shipped [`Action::SetMultisig`] / [`Action::MultisigExec`]
//!     consensus actions, and
//!   * encodes/decodes share-able "codes" (a request to spend, an approval to sign).
//!
//! It persists nothing except its own PUBLIC vault directory
//! (`~/.sov-station/vaults.json`: account ids, member public keys, friendly names,
//! thresholds — no seeds, no secrets). Deleting that file, or removing `mod vault;`
//! and the Vault tab, removes the feature with ZERO impact on wallets or the chain.
//!
//! The flow mirrors the proven `tools/conformance` multisig sweep exactly:
//!   1. SET — opt an account into M-of-N (signed by its current controlling key).
//!   2. REQUEST — a member proposes a spend; everyone signs the IDENTICAL bytes
//!      (`multisig_signing_bytes(account, nonce, inner_action)`).
//!   3. APPROVE — each co-signer returns a signature + their signer index.
//!   4. EXEC — assemble ≥ threshold approvals into `MultisigExec` and submit.

use std::collections::BTreeSet;
use std::path::PathBuf;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use sov_crypto::{Keypair, PublicKey, Signature};
use sov_primitives::{AccountId, Balance};
use sov_types::{multisig_signing_bytes, Action, MultisigApproval};

/// Code prefixes so a pasted blob is recognized and the wrong kind is rejected early.
const REQ_TAG: &str = "SOVREQ1:";
const APV_TAG: &str = "SOVAPV1:";

/// A vault member: a friendly name + their public key string (`hybrid65:0x…`).
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Member {
    pub name: String,
    pub pubkey: String,
}

/// A saved vault — ALL PUBLIC DATA. `members` order IS the on-chain approval-index
/// order; it must never be reordered after the vault is created on-chain.
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

    /// Build a spend request against this vault at the given (current) exec nonce.
    pub fn request(&self, to: String, amount_grains: u128, nonce: u64) -> Request {
        Request {
            vault_name: self.name.clone(),
            account: self.account.clone(),
            nonce,
            to,
            amount_grains,
            members: self.members.clone(),
            threshold: self.threshold,
        }
    }
}

/// A spend REQUEST shared with co-signers. Self-contained: it carries the ordered
/// members (so each signer finds their own index), the exec nonce, and the spend — so
/// every signer signs IDENTICAL bytes without rebuilding anything independently.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Request {
    pub vault_name: String,
    pub account: String,
    pub nonce: u64,
    pub to: String,
    pub amount_grains: u128,
    pub members: Vec<Member>,
    pub threshold: u16,
}

impl Request {
    fn account_id(&self) -> Result<AccountId, String> {
        AccountId::new(&self.account).map_err(|e| e.to_string())
    }

    /// The inner action the vault performs (a transparent transfer).
    pub fn inner_action(&self) -> Result<Action, String> {
        Ok(Action::Transfer {
            to: AccountId::new(self.to.trim()).map_err(|e| e.to_string())?,
            amount: Balance::from_grains(self.amount_grains),
        })
    }

    /// The exact bytes every co-signer signs over — bound to (account, nonce, action),
    /// so an approval is single-use for this one operation.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, String> {
        Ok(multisig_signing_bytes(
            &self.account_id()?,
            self.nonce,
            &self.inner_action()?,
        ))
    }

    /// The signer index of `pk` within this request's member order, if a member.
    pub fn index_of(&self, pk: &PublicKey) -> Option<u16> {
        let want = pk.to_string();
        self.members
            .iter()
            .position(|m| m.pubkey.trim() == want)
            .map(|i| i as u16)
    }

    /// Plain-English description for a co-signer to review BEFORE approving.
    pub fn summary(&self, fmt_amount: impl Fn(u128) -> String) -> String {
        format!(
            "Send {} XUS to {} — from vault “{}” ({})",
            fmt_amount(self.amount_grains),
            self.to.trim(),
            self.vault_name,
            self.account
        )
    }
}

/// An APPROVAL a co-signer returns. Bound to (account, nonce) so it can't be reused
/// for a different operation.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Approval {
    pub account: String,
    pub nonce: u64,
    pub signer: u16,
    pub signature: Signature,
}

/// Sign a request with a co-signer's wallet key. Errors if the key is not a member.
pub fn sign_request(req: &Request, kp: &Keypair) -> Result<Approval, String> {
    let signer = req
        .index_of(&kp.public_key())
        .ok_or("this wallet's key is not a member of that vault")?;
    let signature = kp.sign(&req.signing_bytes()?);
    Ok(Approval {
        account: req.account.clone(),
        nonce: req.nonce,
        signer,
        signature,
    })
}

/// Keep only DISTINCT, VALID approvals for this request: each signature is verified
/// against the member key it claims, approvals for another op are dropped, and a
/// duplicate signer index can't inflate the count. Returns them as the on-chain type.
pub fn valid_approvals(
    req: &Request,
    approvals: &[Approval],
) -> Result<Vec<MultisigApproval>, String> {
    let msg = req.signing_bytes()?;
    let keys = req
        .members
        .iter()
        .map(|m| parse_pubkey(&m.pubkey))
        .collect::<Result<Vec<_>, _>>()?;
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for a in approvals {
        if a.account != req.account || a.nonce != req.nonce {
            continue; // an approval for a different operation
        }
        let Some(pk) = keys.get(a.signer as usize) else {
            continue; // index out of range for this policy
        };
        if !pk.verify(&msg, &a.signature) {
            continue; // signature doesn't match the claimed member key
        }
        if seen.insert(a.signer) {
            out.push(MultisigApproval {
                signer: a.signer,
                signature: a.signature,
            });
        }
    }
    Ok(out)
}

/// How many distinct valid approvals a request currently has.
pub fn approval_count(req: &Request, approvals: &[Approval]) -> usize {
    valid_approvals(req, approvals)
        .map(|v| v.len())
        .unwrap_or(0)
}

/// Assemble the `MultisigExec` action once at least `threshold` valid approvals exist.
pub fn assemble_exec(req: &Request, approvals: &[Approval]) -> Result<Action, String> {
    let valid = valid_approvals(req, approvals)?;
    if (valid.len() as u16) < req.threshold {
        return Err(format!(
            "{} of {} approvals collected — need {}",
            valid.len(),
            req.members.len(),
            req.threshold
        ));
    }
    Ok(Action::MultisigExec {
        action: Box::new(req.inner_action()?),
        approvals: valid,
    })
}

// ── share-able codes: a tag + hex(json) (alphanumeric, QR-friendly, no new deps) ──

pub fn encode_request(req: &Request) -> Result<String, String> {
    Ok(format!("{REQ_TAG}{}", hex_encode(&to_json(req)?)))
}
pub fn decode_request(code: &str) -> Result<Request, String> {
    from_code(code, REQ_TAG, "request")
}
pub fn encode_approval(a: &Approval) -> Result<String, String> {
    Ok(format!("{APV_TAG}{}", hex_encode(&to_json(a)?)))
}
pub fn decode_approval(code: &str) -> Result<Approval, String> {
    from_code(code, APV_TAG, "approval")
}

fn to_json<T: Serialize>(v: &T) -> Result<Vec<u8>, String> {
    serde_json::to_vec(v).map_err(|e| e.to_string())
}
fn from_code<T: DeserializeOwned>(code: &str, tag: &str, what: &str) -> Result<T, String> {
    let body = code
        .trim()
        .strip_prefix(tag)
        .ok_or_else(|| format!("that doesn't look like a {what} code"))?;
    let bytes = hex_decode(body.trim()).map_err(|_| format!("corrupt {what} code"))?;
    serde_json::from_slice(&bytes).map_err(|_| format!("unreadable {what} code"))
}

// ── persistence: PUBLIC vault directory only (no secrets) ──

/// `<home>/.sov-station/vaults.json` — the saved vault directory.
pub fn vaults_path() -> Result<PathBuf, String> {
    let home = std::env::var("HOME")
        .ok()
        .or_else(|| std::env::var("USERPROFILE").ok())
        .ok_or("no home directory")?;
    Ok(PathBuf::from(home).join(".sov-station").join("vaults.json"))
}

/// Load the saved vaults; an empty list on any error (the feature is best-effort and
/// must never block the app).
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

// ── helpers ──

/// Parse a `hybrid65:0x…` (or bare-hex Ed25519) public key string, the exact pattern
/// the wallet UI already uses.
pub fn parse_pubkey(s: &str) -> Result<PublicKey, String> {
    serde_json::from_value(Value::String(s.trim().to_string()))
        .map_err(|e| format!("not a valid public key: {e}"))
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}
fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
        return Err("odd length".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

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
            account: "ustreasury.tax.sov".into(),
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
        v.threshold = 4; // > members
        assert!(v.validate().is_err());
        v.threshold = 0;
        assert!(v.validate().is_err());
        v.threshold = 2;
        v.members.push(member("dup", &a)); // duplicate key
        assert!(v.validate().is_err());
    }

    #[test]
    fn full_flow_two_of_three_assembles_exec() {
        let (a, b, c) = (kp(1), kp(2), kp(3));
        let v = vault_2of3(&a, &b, &c);
        let req = v.request("alice.sov".into(), 100_000_000_000, 7);

        // Members B and C approve (A abstains) — still meets 2-of-3.
        let ap_b = sign_request(&req, &b).unwrap();
        let ap_c = sign_request(&req, &c).unwrap();
        assert_eq!(ap_b.signer, 1);
        assert_eq!(ap_c.signer, 2);
        assert_eq!(approval_count(&req, &[ap_b.clone(), ap_c.clone()]), 2);

        match assemble_exec(&req, &[ap_b.clone(), ap_c.clone()]).unwrap() {
            Action::MultisigExec { action, approvals } => {
                assert!(matches!(*action, Action::Transfer { .. }));
                assert_eq!(approvals.len(), 2);
            }
            _ => panic!("expected MultisigExec"),
        }
    }

    #[test]
    fn below_threshold_will_not_assemble() {
        let (a, b, c) = (kp(1), kp(2), kp(3));
        let req = vault_2of3(&a, &b, &c).request("alice.sov".into(), 5, 0);
        let only_one = vec![sign_request(&req, &b).unwrap()];
        assert_eq!(approval_count(&req, &only_one), 1);
        assert!(assemble_exec(&req, &only_one).is_err());
    }

    #[test]
    fn non_member_cannot_sign_and_duplicates_dont_inflate() {
        let (a, b, c, outsider) = (kp(1), kp(2), kp(3), kp(9));
        let req = vault_2of3(&a, &b, &c).request("alice.sov".into(), 5, 1);
        assert!(sign_request(&req, &outsider).is_err(), "outsider rejected");
        // The same member's approval twice counts once.
        let ap_b = sign_request(&req, &b).unwrap();
        assert_eq!(approval_count(&req, &[ap_b.clone(), ap_b.clone()]), 1);
    }

    #[test]
    fn approval_for_a_different_nonce_is_ignored() {
        let (a, b, c) = (kp(1), kp(2), kp(3));
        let v = vault_2of3(&a, &b, &c);
        let req = v.request("alice.sov".into(), 5, 10);
        let stale = v.request("alice.sov".into(), 5, 9); // earlier nonce
        let ap_b_stale = sign_request(&stale, &b).unwrap();
        let ap_c_now = sign_request(&req, &c).unwrap();
        // Only the current-nonce approval counts → below threshold.
        assert_eq!(approval_count(&req, &[ap_b_stale, ap_c_now]), 1);
    }

    #[test]
    fn codes_round_trip_and_reject_wrong_kind() {
        let (a, b, c) = (kp(1), kp(2), kp(3));
        let req = vault_2of3(&a, &b, &c).request("alice.sov".into(), 42, 3);
        let code = encode_request(&req).unwrap();
        assert!(code.starts_with(REQ_TAG));
        assert_eq!(decode_request(&code).unwrap(), req);

        let ap = sign_request(&req, &b).unwrap();
        let acode = encode_approval(&ap).unwrap();
        assert_eq!(decode_approval(&acode).unwrap(), ap);

        // A request code is not an approval code and vice-versa.
        assert!(decode_approval(&code).is_err());
        assert!(decode_request(&acode).is_err());
    }
}
