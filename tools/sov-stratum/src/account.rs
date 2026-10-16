//! Miner login → payout account.
//!
//! The Monero-dialect `login` is the miner's own payout account, not a worker
//! label the operator can ignore. A checksummed `xust1…` address is accepted and
//! reduced to the same 64-hex account id the chain uses. Named accounts and raw
//! implicit ids are accepted too. A `/worker` suffix is optional and is never
//! part of the account.

use bech32::primitives::decode::CheckedHrpstring;
use bech32::Bech32m;
use sov_primitives::AccountId;

/// Human-readable part of a checksummed transparent address (`xust1…`).
const HRP_TRANSPARENT: &str = "xust";

/// A validated stratum login.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Login {
    /// Account that receives this miner's share weight and, when they find a
    /// block, the coinbase.
    pub account: AccountId,
    /// Worker label for stats. Never paid.
    pub worker: String,
}

/// Parse `login` as `account` or `account/worker`.
///
/// `account` is either a SOV account id (`alice.sov`, or 64 lowercase hex) or
/// a checksummed `xust1…` spelling of an implicit id. The worker, if present,
/// is split on the first `/` so a dotted account name is not mistaken for one.
pub fn parse_login(raw: &str) -> Result<Login, String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err("login is empty — send your payout account".into());
    }
    if raw.len() > 256 {
        return Err("login is longer than 256 bytes".into());
    }
    let (account_part, worker) = match raw.split_once('/') {
        Some((account, worker)) => (account, worker),
        None => (raw, "default"),
    };
    if account_part.is_empty() {
        return Err("login is missing the payout account before '/'".into());
    }
    validate_worker(worker)?;
    let account = parse_account(account_part)?;
    Ok(Login {
        account,
        worker: worker.to_string(),
    })
}

/// Parse a payout account with no worker suffix.
pub fn parse_account(raw: &str) -> Result<AccountId, String> {
    let raw = raw.trim();
    if raw.len() >= 5 && raw[..5].eq_ignore_ascii_case("xust1") {
        return decode_xust(raw);
    }
    AccountId::new(raw).map_err(|e| {
        format!(
            "invalid payout account `{raw}`: {e}. \
             Send a SOV account id or a checksummed xust1 address"
        )
    })
}

fn validate_worker(worker: &str) -> Result<(), String> {
    if worker.is_empty() || worker.len() > 64 {
        return Err("worker name must be 1..=64 characters".into());
    }
    if !worker
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err("worker name may contain only [A-Za-z0-9_-]".into());
    }
    Ok(())
}

/// Decode `xust1…` into the 64-hex implicit account id.
///
/// Same bech32m checksum the wallet uses for this HRP. A 32-byte payload is
/// far under the bech32 code-length cap, so the stock Bech32m engine and the
/// wallet's length-lifted engine accept the same strings.
fn decode_xust(raw: &str) -> Result<AccountId, String> {
    let checked = CheckedHrpstring::new::<Bech32m>(raw)
        .map_err(|e| format!("invalid xust1 address (bad checksum or encoding): {e}"))?;
    let hrp = checked.hrp().to_lowercase();
    if hrp != HRP_TRANSPARENT {
        return Err(format!(
            "address prefix is `{hrp}`, not `{HRP_TRANSPARENT}` — payout login must be a transparent account"
        ));
    }
    let payload: Vec<u8> = checked.byte_iter().collect();
    if payload.len() != 32 {
        return Err(format!("xust1 payload is {} bytes, want 32", payload.len()));
    }
    let mut hex_id = String::with_capacity(64);
    for byte in payload {
        hex_id.push_str(&format!("{byte:02x}"));
    }
    AccountId::new(hex_id).map_err(|e| format!("xust1 did not yield an account id: {e}"))
}

/// Encode an implicit account id as `xust1…` for operators and tests.
#[allow(dead_code)]
pub fn encode_xust(account: &AccountId) -> Option<String> {
    if !account.is_implicit() {
        return None;
    }
    let s = account.as_str().as_bytes();
    let nibble = |b: u8| -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            _ => None,
        }
    };
    let mut bytes = Vec::with_capacity(32);
    let mut i = 0;
    while i + 1 < s.len() {
        let hi = nibble(s[i])?;
        let lo = nibble(s[i + 1])?;
        bytes.push((hi << 4) | lo);
        i += 2;
    }
    if bytes.len() != 32 {
        return None;
    }
    let hrp = bech32::Hrp::parse(HRP_TRANSPARENT).ok()?;
    bech32::encode::<Bech32m>(hrp, &bytes).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_account_and_worker_suffix() {
        let login = parse_login("alice.sov/rig-1").unwrap();
        assert_eq!(login.account.as_str(), "alice.sov");
        assert_eq!(login.worker, "rig-1");
        let bare = parse_login("bob.sov").unwrap();
        assert_eq!(bare.worker, "default");
    }

    #[test]
    fn xust1_round_trips_and_a_typo_is_rejected() {
        let id = AccountId::new("11".repeat(32)).unwrap();
        let xust = encode_xust(&id).unwrap();
        assert!(xust.starts_with("xust1"), "{xust}");
        let login = parse_login(&format!("{xust}/pc")).unwrap();
        assert_eq!(login.account, id);
        assert_eq!(login.worker, "pc");

        let mut chars: Vec<char> = xust.chars().collect();
        let last = chars.len() - 1;
        chars[last] = if chars[last] == 'q' { 'p' } else { 'q' };
        let broken: String = chars.into_iter().collect();
        let err = parse_login(&broken).unwrap_err();
        assert!(
            err.contains("checksum") || err.contains("encoding"),
            "{err}"
        );
    }

    #[test]
    fn malformed_logins_are_specific() {
        assert!(parse_login("").unwrap_err().contains("empty"));
        assert!(parse_login("NOT A VALID ID")
            .unwrap_err()
            .contains("invalid"));
        assert!(parse_login("alice.sov/bad worker")
            .unwrap_err()
            .contains("worker"));
        assert!(parse_login("/onlyworker").unwrap_err().contains("missing"));
    }
}
