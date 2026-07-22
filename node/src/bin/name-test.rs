//! Live end-to-end test of the on-chain name registry (ENS/SNS): derive a wallet
//! from a mnemonic, register a `*.sov` name, and confirm it resolves to the
//! account on the network.
//!
//!   name-test "<24-word mnemonic>" <name.sov> [rpc]

use std::time::Duration;

use serde_json::json;
use sov_crypto::Keypair;
use sov_rpc::RpcClient;
use sov_types::{Action, SignedTransaction, Transaction};
use sov_wallet::HdWallet;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mnemonic = std::env::args()
        .nth(1)
        .ok_or("usage: name-test <mnemonic> <name.sov> [rpc]")?;
    let name = std::env::args().nth(2).ok_or("need a *.sov name")?;
    let rpc = std::env::args()
        .nth(3)
        .unwrap_or_else(|| "127.0.0.1:8645".to_string());

    let seed = HdWallet::from_mnemonic(&mnemonic, "")?.derive_seed(0, 0);
    let kp = Keypair::hybrid_from_seed(seed);
    let account = kp.public_key().implicit_account_id();
    let client = RpcClient::new(rpc).with_timeout(Duration::from_secs(20));

    println!("account : {account}");
    let bal = client.call("sov_getBalance", json!({ "account": account.to_string() }))?;
    println!("balance : {bal} grains");

    let nonce = client.nonce(&account)?;
    // `None` while the `tx-domain` fork is dormant (legacy signature);
    // `Some(domain)` once active (network-bound signature the node requires).
    let domain = client.signing_domain()?;
    let tx = Transaction {
        signer: account.clone(),
        public_key: kp.public_key(),
        nonce,
        action: Action::RegisterName { name: name.clone() },
    };
    let stx = SignedTransaction::sign_in(tx, &kp, domain.as_ref())?;
    let txid = client.submit_transaction(&stx)?;
    println!("submit  : RegisterName({name}) tx {}", txid.to_hex());

    // Poll for on-chain resolution (it appears once the tx is mined).
    for _ in 0..90 {
        if let Ok(v) = client.call("sov_resolveName", json!({ "name": name })) {
            if let Some(owner) = v.as_str() {
                println!("resolve : {name} -> {owner}");
                println!(
                    "{}",
                    if owner == account.to_string() {
                        "✓ MATCH — the name resolves to our account (funds never moved)"
                    } else {
                        "✗ MISMATCH"
                    }
                );
                return Ok(());
            }
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    println!("not resolved within 90s — if balance was 0, the registration fee was unaffordable");
    Ok(())
}
