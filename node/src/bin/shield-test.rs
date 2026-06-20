//! Reproduce a shield from a wallet's own (implicit) account, printing the exact
//! outcome — a diagnostic for "my key can't shield its funds".
//!
//!   shield-test "<24-word mnemonic>" [rpc] [amount_xus]

use std::time::Duration;

use sov_crypto::Keypair;
use sov_primitives::Balance;
use sov_rpc::RpcClient;
use sov_shielded::{encode_shielded, ShieldedKey, ShieldedParams};
use sov_wallet::HdWallet;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mnemonic = std::env::args()
        .nth(1)
        .ok_or("usage: shield-test \"<mnemonic>\" [rpc] [amt]")?;
    let rpc = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "127.0.0.1:8645".to_string());
    let amount_xus: u128 = std::env::args()
        .nth(3)
        .and_then(|s| s.parse().ok())
        .unwrap_or(1);

    let seed = HdWallet::from_mnemonic(&mnemonic, "")?.derive_seed(0, 0);
    let kp = Keypair::hybrid_from_seed(seed);
    let account = kp.public_key().implicit_account_id();
    let zkey = ShieldedKey::from_seed(seed).ok_or("shielded key")?;
    let own_shielded = encode_shielded(&zkey.address());

    let client = RpcClient::new(rpc.clone()).with_timeout(Duration::from_secs(90));
    println!("rpc        : {rpc}");
    println!("account    : {account}");
    println!("shielded   : {own_shielded}");

    match client.account(&account) {
        Ok(Some(a)) => println!(
            "on-chain   : balance={} grains  key_bound={}",
            a.balance.grains(),
            a.key.is_some()
        ),
        Ok(None) => println!("on-chain   : absent (no balance)"),
        Err(e) => println!("on-chain   : query failed: {e}"),
    }

    let amount = Balance::from_sov(amount_xus)?;
    println!("\nshielding {amount_xus} XUS to own pool (building Halo2 prover, ~seconds)…");
    let params = ShieldedParams::build();
    match client.pay(&kp, &account, &own_shielded, amount, Some(&params)) {
        Ok(txid) => println!("RESULT     : OK — submitted tx {}", txid.to_hex()),
        Err(e) => println!("RESULT     : FAILED — {e}"),
    }
    Ok(())
}
