//! `RpcClient` integration test (Phase 8, p8-i3; updated for Nakamoto).
//!
//! Drives a live [`Daemon`] entirely through the client — querying state and
//! sending a wallet transfer — over the JSON-RPC server, and verifies the
//! Nakamoto issuance path: every produced block is PoW-mined by the daemon and
//! its coinbase pays the daemon's miner account (no Mine transaction exists).

use std::path::PathBuf;

use sov_chain::{GenesisAccount, GenesisConfig};
use sov_crypto::Keypair;
use sov_primitives::{AccountId, Balance};
use sov_rpc::{Daemon, RpcClient};

fn id(s: &str) -> AccountId {
    AccountId::new(s).unwrap()
}

fn unique_dir() -> PathBuf {
    std::env::temp_dir().join(format!(
        "sov-client-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ))
}

fn genesis() -> GenesisConfig {
    GenesisConfig {
        chain_id: "sov-client-test".into(),
        timestamp_ms: 1_000,
        accounts: vec![
            GenesisAccount {
                account: id("val01.node.sov"),
                key: Keypair::from_seed([1; 32]).public_key(),
                balance: Balance::ZERO,
            },
            GenesisAccount {
                account: id("usa.reserve.sov"),
                key: Keypair::from_seed([2; 32]).public_key(),
                balance: Balance::from_sov(1_000).unwrap(),
            },
        ],
        mining: {
            // Coinbase issuance ON (the test preset's base reward is zero):
            // each mined block pays 50 SOV to the daemon's miner account.
            let mut m = sov_mining::MiningPolicy::test();
            m.base_reward = Balance::from_sov(50).unwrap();
            m.halving_interval_blocks = 210_000; // constant 50 across this short run
            m
        },
        vesting: vec![],
    }
}

#[test]
fn client_queries_transfers_and_coinbase_pays_the_miner() {
    let dir = unique_dir();
    let _ = std::fs::remove_dir_all(&dir);

    let daemon = Daemon::new(
        &genesis(),
        &dir,
        1024,
        256,
        vec![(id("val01.node.sov"), Keypair::from_seed([1; 32]))],
    )
    .unwrap();
    let rpc = daemon.serve_rpc("127.0.0.1:0", 2).unwrap();
    let client = RpcClient::new(rpc.local_addr().to_string());

    // --- queries ---
    assert_eq!(client.chain_id().unwrap(), "sov-client-test");
    assert_eq!(client.height().unwrap(), 0);
    assert_eq!(
        client.balance(&id("usa.reserve.sov")).unwrap(),
        Balance::from_sov(1_000).unwrap()
    );
    assert!(client.account(&id("nobody.sov")).unwrap().is_none());

    // The scheduled coinbase reward is exposed over RPC (50 SOV at genesis
    // emission).
    assert_eq!(
        client.mint_reward().unwrap(),
        Balance::from_sov(50).unwrap()
    );

    // --- wallet: a client-built, client-signed transfer ---
    let usa = Keypair::from_seed([2; 32]);
    client
        .transfer(
            &usa,
            &id("usa.reserve.sov"),
            &id("ecb.reserve.sov"),
            Balance::from_sov(250).unwrap(),
        )
        .unwrap();
    assert_eq!(client.mempool_size().unwrap(), 1);
    daemon.produce_once(2_000).unwrap();
    assert_eq!(client.height().unwrap(), 1);
    assert_eq!(
        client.balance(&id("usa.reserve.sov")).unwrap(),
        Balance::from_sov(750).unwrap()
    );
    assert_eq!(
        client.balance(&id("ecb.reserve.sov")).unwrap(),
        Balance::from_sov(250).unwrap()
    );

    // --- Nakamoto issuance: the block was MINED by the daemon (real PoW seal)
    // and its coinbase paid the daemon's miner account (the first keystore
    // account, val01) the scheduled 50-SOV reward. There is no Mine tx.
    assert_eq!(
        client.balance(&id("val01.node.sov")).unwrap(),
        Balance::from_sov(50).unwrap(),
        "the daemon's miner account is credited the block coinbase"
    );

    rpc.shutdown();
    let _ = std::fs::remove_dir_all(&dir);
}
