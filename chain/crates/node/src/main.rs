//! A runnable single-node SOV devnet.
//!
//! This boots a real chain from a genesis config, then submits **real,
//! genuinely-signed** transactions through the real execution engine and prints
//! what actually happened: block hashes, state roots, gas, finality, and the
//! resulting balances. Nothing here is mocked — every hash and balance is
//! computed by the protocol. Run with `cargo run -p sov-node`.

use sov_chain::{Blockchain, GenesisAccount, GenesisConfig};
use sov_crypto::Keypair;
use sov_node::Node;
use sov_primitives::{AccountId, Balance, Hash};
use sov_wallet::Wallet;

fn id(s: &str) -> AccountId {
    AccountId::new(s).expect("valid account id")
}

fn short(hash: &Hash) -> String {
    let hex = hash.to_hex();
    format!("0x{}…{}", &hex[..8], &hex[hex.len() - 6..])
}

fn main() {
    // --- Genesis: one miner account and one funded reserve account. ---
    let val_key = Keypair::from_seed([1; 32]);
    let usa_key = Keypair::from_seed([2; 32]);

    let config = GenesisConfig {
        chain_id: "sov-devnet".into(),
        timestamp_ms: 1_700_000_000_000,
        accounts: vec![
            // The devnet uses the `test` policy (trivial difficulty for instant
            // local mining, a 1M-SOV budget that leaves headroom for this demo's
            // funded account — unlike `mainnet_like`, whose full-cap budget
            // forbids any genesis allocation).
            GenesisAccount {
                account: id("val01.node.sov"),
                key: val_key.public_key(),
                balance: Balance::ZERO,
            },
            GenesisAccount {
                account: id("usa.reserve.sov"),
                key: usa_key.public_key(),
                balance: Balance::from_sov(100_000).unwrap(),
            },
        ],
        mining: sov_mining::MiningPolicy::test(),
        vesting: vec![],
    };

    let chain = Blockchain::new(&config).expect("genesis builds");
    println!("=== SOV devnet '{}' ===", chain.chain_id());
    println!("genesis block   {}", short(&chain.head().hash()));
    println!("genesis state   {}", short(&chain.ledger().state_root()));
    println!("total supply    {}", chain.ledger().total_supply().unwrap());
    println!();

    let mut node = Node::new(chain, 1024, 256);
    node.set_coinbase(id("val01.node.sov"));

    // Wallet holding the reserve account's key, used to sign real transfers.
    let mut wallet = Wallet::new();
    wallet.import(id("usa.reserve.sov"), usa_key);

    // --- Produce several blocks of real transfers. ---
    let recipients = ["ecb.reserve.sov", "sgp.reserve.sov", "che.reserve.sov"];
    let mut timestamp = 1_700_000_001_000u64;

    for (round, recipient) in recipients.iter().enumerate() {
        let nonce = node.chain().ledger().account(&id("usa.reserve.sov")).nonce;
        let amount = Balance::from_sov(1_000 * (round as u128 + 1)).unwrap();
        let stx = wallet
            .transfer(&id("usa.reserve.sov"), id(recipient), amount, nonce)
            .expect("wallet builds transfer");
        node.submit(stx).expect("mempool accepts transfer");

        let produced = node.produce(timestamp).expect("block produced");
        timestamp += 1_000;

        let h = &produced.block.header;
        println!(
            "block #{:<3} {}",
            h.height.get(),
            short(&produced.block.hash())
        );
        println!("  proposer     {}", h.proposer);
        println!("  txs          {}", produced.block.transactions.len());
        println!(
            "  receipts     {} ({})",
            produced.receipts.len(),
            if produced.receipts.iter().all(|r| r.succeeded()) {
                "all succeeded"
            } else {
                "some failed"
            }
        );
        println!("  state root   {}", short(&h.state_root));
        println!(
            "  confirmations {} (final at depth {})",
            node.chain()
                .confirmations(&produced.block.hash())
                .unwrap_or(0),
            sov_chain::FINALITY_DEPTH
        );
        println!();
    }

    // --- Final balances (all computed from real execution). ---
    println!("=== final balances ===");
    let ledger = node.chain().ledger();
    for (account, acct) in ledger.iter() {
        println!("  {:<20} {}", account.as_str(), acct.balance);
    }
    println!("  ------");
    println!(
        "  total supply         {} (conserved, cap 21000000 XUS)",
        ledger.total_supply().unwrap()
    );
    println!("  height               {}", node.chain().height());
}
