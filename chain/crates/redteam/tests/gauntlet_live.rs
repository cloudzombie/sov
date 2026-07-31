//! **Live Gauntlet, in CI** — boot a real `sov-node` behind the JSON-RPC server,
//! fund a pot-like account, and run [`probe_gauntlet`] against it over a real TCP
//! socket. This exercises the ENTIRE live battery (PQ half-strip, domain-swap
//! replay, zero/empty sig, nonce games, implicit-id near-miss, multisig-seize,
//! IntentSettle bypass, carrier laundering, and every other value/authority exit)
//! through the node's real admission path — no mainnet node required.
//!
//! The pot is funded in genesis under a "cold" key the attacker never sees, mirroring
//! the real challenge: the owner holds the key, the harness does not. Every vector is
//! a forgery signed by an attacker key, so each is refused at admission — nothing
//! enters the mempool, and not a grain moves.

use std::sync::{Arc, Mutex};

use sov_chain::{Blockchain, GenesisAccount, GenesisConfig};
use sov_crypto::Keypair;
use sov_node::Node;
use sov_primitives::{AccountId, Balance};
use sov_redteam::{gauntlet_any_vulnerable, probe_gauntlet, POT};
use sov_rpc::RpcServer;

/// Genesis that funds the mainnet pot id with 500 XUS under an owner-held "cold"
/// key (seed `[171; 32]`), which the attack path never has.
fn pot_genesis() -> GenesisConfig {
    GenesisConfig {
        chain_id: "sov-redteam-gauntlet".into(),
        timestamp_ms: 1_000,
        accounts: vec![
            GenesisAccount {
                account: AccountId::new("val01.node.sov").unwrap(),
                key: Keypair::from_seed([1; 32]).public_key(),
                balance: Balance::ZERO,
            },
            GenesisAccount {
                account: AccountId::new(POT).unwrap(),
                key: Keypair::hybrid_from_seed([171; 32]).public_key(),
                balance: Balance::from_sov(500).unwrap(),
            },
        ],
        mining: sov_mining::MiningPolicy::test(),
        vesting: vec![],
    }
}

#[test]
fn live_gauntlet_over_real_rpc_finds_no_breach() {
    let chain = Blockchain::new(&pot_genesis()).unwrap();
    let mut node = Node::new(chain, 1024, 256);
    node.set_coinbase(AccountId::new("val01.node.sov").unwrap());
    let node = Arc::new(Mutex::new(node));
    let handle = RpcServer::new(Arc::clone(&node))
        .start("127.0.0.1:0", 2)
        .expect("rpc server binds");
    let addr = handle.local_addr().to_string();

    let report = probe_gauntlet(&addr);

    // No blocking error, and the pot really was funded (so the vectors ran).
    assert!(report.error.is_none(), "gauntlet error: {:?}", report.error);
    assert_eq!(
        report.balance_before,
        Some(Balance::from_sov(500).unwrap().grains()),
        "the pot must be funded for the battery to be meaningful",
    );

    // The load-bearing invariants: not a grain moved, nothing was admitted, and NO
    // vector breached. A breach here is a real vulnerability, and it fails the test.
    assert!(report.pot_intact(), "THE POT MOVED across the live battery");
    assert_eq!(report.balance_before, report.balance_after, "pot balance Δ");
    assert_eq!(report.nonce_before, report.nonce_after, "pot nonce changed");
    assert_eq!(
        report.authorizer_before, report.authorizer_after,
        "pot authorizer changed — a seize landed",
    );
    assert_eq!(
        report.mempool_admissions(),
        Some(0),
        "a forgery was admitted into the mempool",
    );
    assert_eq!(report.vectors_breached(), 0, "a vector breached the pot");
    assert!(
        !gauntlet_any_vulnerable(&report),
        "gauntlet reported a VULNERABLE outcome",
    );

    // The battery actually resolved a substantial number of vectors (not all-info
    // because the node was somehow unreachable).
    assert!(
        report.vectors_attempted() >= 20,
        "expected the full battery to run; only {} vectors resolved",
        report.vectors_attempted(),
    );

    handle.shutdown();
}
