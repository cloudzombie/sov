//! Multi-node peer-to-peer integration tests (Phase 8, p8-i1; Nakamoto form).
//!
//! These run real [`P2p`] engines over loopback TCP — separate nodes, separate
//! sockets, real Borsh framing, real Ed25519 handshakes — and prove the
//! guarantees a live Nakamoto network needs:
//!
//! 1. **Gossip.** A mined block produced on one node propagates to a peer, which
//!    re-validates and imports it (the block's proof of work is its authority).
//! 2. **Catch-up sync.** A node that joins late, with an empty chain, syncs to
//!    the network height by requesting the blocks it is missing.
//! 3. **Authenticated handshake.** A peer presenting the wrong genesis is never
//!    trusted: none of its blocks or transactions are applied.
//! 4. **Confirmation-depth finality.** Peers agree on a block's confirmations,
//!    and it reports final on every node once buried `FINALITY_DEPTH` deep.
//! 5. **Persistence.** Followers persist synced blocks and replay them offline;
//!    a partitioned, cold-restarted node reconverges with no fork.

use std::path::PathBuf;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use sov_chain::{GenesisAccount, GenesisConfig, FINALITY_DEPTH};
use sov_crypto::Keypair;
use sov_mining::MiningPolicy;
use sov_network::{NetMessage, TcpNode};
use sov_primitives::{AccountId, Balance, Hash};
use sov_rpc::{Daemon, P2p, P2pConfig, P2pHandle, SyncShared};
use std::sync::Arc;
use sov_types::{Action, SignedTransaction, Transaction};

const CHAIN_ID: &str = "sov-p2p-testnet";
/// Seed for the founding operator `val01.node.sov` (node A's miner identity).
const VAL01_SEED: [u8; 32] = [1; 32];
/// Seed for the funded treasury account `usa.reserve.sov`.
const USA_SEED: [u8; 32] = [2; 32];
/// Seed for the second operator `val02.node.sov` (node B's miner identity).
const VAL02_SEED: [u8; 32] = [3; 32];

fn id(s: &str) -> AccountId {
    AccountId::new(s).unwrap()
}

/// A devnet genesis: one founding operator and a funded treasury.
fn genesis() -> GenesisConfig {
    GenesisConfig {
        chain_id: CHAIN_ID.into(),
        timestamp_ms: 0,
        accounts: vec![
            GenesisAccount {
                account: id("val01.node.sov"),
                key: Keypair::from_seed(VAL01_SEED).public_key(),
                balance: Balance::ZERO,
            },
            GenesisAccount {
                account: id("usa.reserve.sov"),
                key: Keypair::from_seed(USA_SEED).public_key(),
                balance: Balance::from_sov(1_000).unwrap(),
            },
        ],
        mining: MiningPolicy::test(),
        vesting: vec![],
    }
}

/// A two-operator genesis: two miner identities (A and B each run one) plus a
/// funded treasury — the multi-node case the testnet runs.
fn genesis_2op() -> GenesisConfig {
    GenesisConfig {
        chain_id: CHAIN_ID.into(),
        timestamp_ms: 0,
        accounts: vec![
            GenesisAccount {
                account: id("val01.node.sov"),
                key: Keypair::from_seed(VAL01_SEED).public_key(),
                balance: Balance::ZERO,
            },
            GenesisAccount {
                account: id("val02.node.sov"),
                key: Keypair::from_seed(VAL02_SEED).public_key(),
                balance: Balance::ZERO,
            },
            GenesisAccount {
                account: id("usa.reserve.sov"),
                key: Keypair::from_seed(USA_SEED).public_key(),
                balance: Balance::from_sov(1_000).unwrap(),
            },
        ],
        mining: MiningPolicy::test(),
        vesting: vec![],
    }
}

/// A signed transfer from the treasury (`usa.reserve.sov`) of `sov` SOV to `to`.
fn usa_transfer(to: &str, sov: u128, nonce: u64) -> SignedTransaction {
    let kp = Keypair::from_seed(USA_SEED);
    let tx = Transaction {
        signer: id("usa.reserve.sov"),
        public_key: kp.public_key(),
        nonce,
        action: Action::Transfer {
            to: id(to),
            amount: Balance::from_sov(sov).unwrap(),
        },
    };
    SignedTransaction::sign(tx, &kp).unwrap()
}

/// A unique temp directory for a node's block log (parallel-test safe).
fn unique_dir(tag: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("sov-p2p-{tag}-{nanos}"))
}

/// Build a node: a daemon over `genesis` with `operators` (the first is its
/// miner identity), plus a started P2P engine bound to an ephemeral loopback
/// port and attached for gossip.
fn build_node(
    genesis: &GenesisConfig,
    tag: &str,
    account: &str,
    seed: [u8; 32],
    operators: Vec<(AccountId, Keypair)>,
) -> (Daemon, P2pHandle) {
    let daemon = Daemon::new(genesis, unique_dir(tag), 1024, 256, operators).unwrap();
    let config = P2pConfig {
        chain_id: genesis.chain_id.clone(),
        genesis_hash: daemon.genesis_hash(),
        account: id(account),
        keypair: Keypair::from_seed(seed),
    };
    let p2p = P2p::bind(daemon.node(), config, "127.0.0.1:0")
        .unwrap()
        .with_block_log(daemon.block_log());
    let daemon = daemon.with_gossip(p2p.tcp());
    let handle = p2p.start();
    (daemon, handle)
}

/// Poll `cond` until it is true or `secs` elapse.
fn wait_until(secs: u64, mut cond: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < deadline {
        if cond() {
            return true;
        }
        thread::sleep(Duration::from_millis(20));
    }
    cond()
}

#[test]
fn gossiped_block_propagates_and_applies() {
    let g = genesis();
    // A mines (coinbase to val01) and gossips; B is a plain follower.
    let (a, a_p2p) = build_node(
        &g,
        "g-a",
        "peera.node.sov",
        [10; 32],
        vec![(id("val01.node.sov"), Keypair::from_seed(VAL01_SEED))],
    );
    let (b, b_p2p) = build_node(&g, "g-b", "peerb.node.sov", [11; 32], vec![]);
    a_p2p.connect(&b_p2p.local_addr().to_string()).unwrap();

    // Mine a block on A.
    a.node()
        .lock()
        .unwrap()
        .submit(usa_transfer("ecb.reserve.sov", 100, 0))
        .unwrap();
    let produced = a.node().lock().unwrap().produce(1_000).unwrap();
    let block_hash = produced.block.hash();

    // Re-broadcast until B has imported A's block. Re-broadcasting tolerates the
    // brief window before the authenticated handshake completes, so the test is
    // robust rather than timing-dependent.
    let a_tcp = a_p2p.tcp();
    let synced = wait_until(15, || {
        a_tcp.broadcast(&NetMessage::NewBlock(produced.block.clone()));
        let node = b.node();
        let n = node.lock().unwrap();
        n.chain().height() == 1 && n.chain().head().hash() == block_hash
    });
    assert!(synced, "B imported A's mined block over real TCP");
    assert_eq!(
        b.balance(&id("ecb.reserve.sov")),
        Balance::from_sov(100).unwrap(),
        "B applied the block's state transition"
    );

    a_p2p.shutdown();
    b_p2p.shutdown();
}

#[test]
fn late_joiner_catches_up_via_block_sync() {
    let g = genesis();
    let (a, a_p2p) = build_node(
        &g,
        "c-a",
        "peera.node.sov",
        [20; 32],
        vec![(id("val01.node.sov"), Keypair::from_seed(VAL01_SEED))],
    );
    // A builds a five-block chain entirely on its own, before any peer connects.
    for nonce in 0..5u64 {
        a.node()
            .lock()
            .unwrap()
            .submit(usa_transfer("ecb.reserve.sov", 1, nonce))
            .unwrap();
        a.node()
            .lock()
            .unwrap()
            .produce(1_000 + nonce * 1_000)
            .unwrap();
    }
    assert_eq!(a.height(), 5);

    // C joins late with an empty chain and must sync by requesting missing blocks.
    let (c, c_p2p) = build_node(&g, "c-c", "peerc.node.sov", [21; 32], vec![]);
    c_p2p.connect(&a_p2p.local_addr().to_string()).unwrap();

    assert!(
        wait_until(20, || c.height() == 5),
        "C synced to A's height by requesting the blocks it was missing"
    );
    assert_eq!(
        c.balance(&id("ecb.reserve.sov")),
        Balance::from_sov(5).unwrap(),
        "C re-derived state from the synced blocks"
    );

    a_p2p.shutdown();
    c_p2p.shutdown();
}

/// The REAL testnet config: genesis + node identities are **hybrid post-quantum**
/// keys (Ed25519 + ML-DSA-65), not bare Ed25519. The hybrid `Hello` signature is far
/// larger, so this proves the authenticated handshake AND the resulting block sync
/// work end-to-end with the keys a production node actually uses — the cross-machine
/// "connected but not indexing" report is NOT a hybrid-key handshake/sync regression.
#[test]
fn late_joiner_syncs_with_hybrid_pq_keys() {
    let g = GenesisConfig {
        chain_id: CHAIN_ID.into(),
        timestamp_ms: 0,
        accounts: vec![
            GenesisAccount {
                account: id("val01.node.sov"),
                key: Keypair::hybrid_from_seed(VAL01_SEED).public_key(),
                balance: Balance::ZERO,
            },
            GenesisAccount {
                account: id("usa.reserve.sov"),
                key: Keypair::hybrid_from_seed(USA_SEED).public_key(),
                balance: Balance::from_sov(1_000).unwrap(),
            },
        ],
        mining: MiningPolicy::test(),
        vesting: vec![],
    };
    // Node identities (the P2P `Hello` signing keys) are hybrid too.
    let build_hybrid = |tag: &str, account: &str, seed: [u8; 32], ops: Vec<(AccountId, Keypair)>| {
        let daemon = Daemon::new(&g, unique_dir(tag), 1024, 256, ops).unwrap();
        let config = P2pConfig {
            chain_id: g.chain_id.clone(),
            genesis_hash: daemon.genesis_hash(),
            account: id(account),
            keypair: Keypair::hybrid_from_seed(seed),
        };
        let p2p = P2p::bind(daemon.node(), config, "127.0.0.1:0")
            .unwrap()
            .with_block_log(daemon.block_log());
        let daemon = daemon.with_gossip(p2p.tcp());
        let handle = p2p.start();
        (daemon, handle)
    };

    let (a, a_p2p) = build_hybrid(
        "hy-a",
        "peera.node.sov",
        [20; 32],
        vec![(id("val01.node.sov"), Keypair::hybrid_from_seed(VAL01_SEED))],
    );
    // A mines five blocks, each carrying a HYBRID-signed transfer, before any peer joins.
    for nonce in 0..5u64 {
        let kp = Keypair::hybrid_from_seed(USA_SEED);
        let tx = Transaction {
            signer: id("usa.reserve.sov"),
            public_key: kp.public_key(),
            nonce,
            action: Action::Transfer {
                to: id("ecb.reserve.sov"),
                amount: Balance::from_sov(1).unwrap(),
            },
        };
        let stx = SignedTransaction::sign(tx, &kp).unwrap();
        a.node().lock().unwrap().submit(stx).unwrap();
        a.node().lock().unwrap().produce(1_000 + nonce * 1_000).unwrap();
    }
    assert_eq!(a.height(), 5);

    let (c, c_p2p) = build_hybrid("hy-c", "peerc.node.sov", [21; 32], vec![]);
    c_p2p.connect(&a_p2p.local_addr().to_string()).unwrap();

    assert!(
        wait_until(20, || c.height() == 5),
        "a late joiner syncs over a HYBRID-PQ authenticated handshake"
    );
    assert_eq!(
        c.balance(&id("ecb.reserve.sov")),
        Balance::from_sov(5).unwrap(),
        "C re-derived state from the hybrid-synced blocks"
    );

    a_p2p.shutdown();
    c_p2p.shutdown();
}

#[test]
fn diverged_peer_backtracks_to_common_ancestor_and_reorgs() {
    // B missed A's first block and mined its own height-1 block. When it later
    // connects to A's heavier height-2 chain, height-only sync used to ask for
    // A's block 2 forever (whose parent B did not know). The Nakamoto sync path
    // must walk backward to the common ancestor, store A's height-1 side branch,
    // then walk forward and reorg onto A's heavier chain.
    let g = genesis_2op();
    let a = Daemon::new(
        &g,
        unique_dir("fork-a"),
        1024,
        256,
        vec![(id("val01.node.sov"), Keypair::from_seed(VAL01_SEED))],
    )
    .unwrap();
    let b = Daemon::new(
        &g,
        unique_dir("fork-b"),
        1024,
        256,
        vec![(id("val02.node.sov"), Keypair::from_seed(VAL02_SEED))],
    )
    .unwrap();

    // A branch: two blocks, total payment 11 SOV.
    a.node()
        .lock()
        .unwrap()
        .submit(usa_transfer("ecb.reserve.sov", 10, 0))
        .unwrap();
    a.node().lock().unwrap().produce(1_000).unwrap();
    a.node()
        .lock()
        .unwrap()
        .submit(usa_transfer("ecb.reserve.sov", 1, 1))
        .unwrap();
    let a_head = a
        .node()
        .lock()
        .unwrap()
        .produce(2_000)
        .unwrap()
        .block
        .hash();
    assert_eq!(a.height(), 2);

    // B branch: conflicting height-1 block, total payment 20 SOV.
    b.node()
        .lock()
        .unwrap()
        .submit(usa_transfer("ecb.reserve.sov", 20, 0))
        .unwrap();
    let b_head = b
        .node()
        .lock()
        .unwrap()
        .produce(1_500)
        .unwrap()
        .block
        .hash();
    assert_eq!(b.height(), 1);
    assert_ne!(a_head, b_head);

    let a_p2p = P2p::bind(
        a.node(),
        P2pConfig {
            chain_id: g.chain_id.clone(),
            genesis_hash: a.genesis_hash(),
            account: id("val01.node.sov"),
            keypair: Keypair::from_seed([31; 32]),
        },
        "127.0.0.1:0",
    )
    .unwrap()
    .start();
    let b_p2p = P2p::bind(
        b.node(),
        P2pConfig {
            chain_id: g.chain_id.clone(),
            genesis_hash: b.genesis_hash(),
            account: id("val02.node.sov"),
            keypair: Keypair::from_seed([32; 32]),
        },
        "127.0.0.1:0",
    )
    .unwrap()
    .with_block_log(b.block_log())
    .start();
    b_p2p.connect(&a_p2p.local_addr().to_string()).unwrap();

    let reorged = wait_until(30, || {
        let node = b.node();
        let n = node.lock().unwrap();
        n.chain().height() == 2 && n.chain().head().hash() == a_head
    });
    assert!(reorged, "B backtracked, fetched A's fork, and reorged");
    assert_eq!(
        b.balance(&id("ecb.reserve.sov")),
        Balance::from_sov(11).unwrap(),
        "B now reflects A's heavier branch, not its old height-1 block"
    );

    a_p2p.shutdown();
    b_p2p.shutdown();
}

#[test]
fn node_that_mined_its_own_multiblock_fork_recovers_by_deep_reorg() {
    // THE bootstrap-recovery scenario behind the cross-machine "two chains" report: a
    // node that was mining ITS OWN chain (here B built a 3-block fork) before it ever
    // connected must, on joining the heavier network (A's 6-block chain), backtrack to
    // the common ancestor, download A's blocks as a side branch, and DEEP-REORG onto
    // them — abandoning its own fork. (Going forward, the mining gate stops this fork
    // from forming in the first place; this proves an ALREADY-forked node still heals.)
    let g = genesis_2op();
    let a = Daemon::new(
        &g,
        unique_dir("deep-a"),
        1024,
        256,
        vec![(id("val01.node.sov"), Keypair::from_seed(VAL01_SEED))],
    )
    .unwrap();
    let b = Daemon::new(
        &g,
        unique_dir("deep-b"),
        1024,
        256,
        vec![(id("val02.node.sov"), Keypair::from_seed(VAL02_SEED))],
    )
    .unwrap();

    // A: a 6-block chain, paying 1 SOV per block (total 6 to ecb).
    for nonce in 0..6u64 {
        a.node()
            .lock()
            .unwrap()
            .submit(usa_transfer("ecb.reserve.sov", 1, nonce))
            .unwrap();
        a.node().lock().unwrap().produce(1_000 + nonce * 1_000).unwrap();
    }
    let a_head = a.node().lock().unwrap().chain().head().hash();
    assert_eq!(a.height(), 6);

    // B: its OWN conflicting 3-block fork, paying 7 SOV per block (total 21 on its fork).
    for nonce in 0..3u64 {
        b.node()
            .lock()
            .unwrap()
            .submit(usa_transfer("ecb.reserve.sov", 7, nonce))
            .unwrap();
        b.node().lock().unwrap().produce(1_500 + nonce * 1_000).unwrap();
    }
    assert_eq!(b.height(), 3);
    assert_eq!(b.balance(&id("ecb.reserve.sov")), Balance::from_sov(21).unwrap());

    let a_p2p = P2p::bind(
        a.node(),
        P2pConfig {
            chain_id: g.chain_id.clone(),
            genesis_hash: a.genesis_hash(),
            account: id("val01.node.sov"),
            keypair: Keypair::from_seed([33; 32]),
        },
        "127.0.0.1:0",
    )
    .unwrap()
    .start();
    let b_p2p = P2p::bind(
        b.node(),
        P2pConfig {
            chain_id: g.chain_id.clone(),
            genesis_hash: b.genesis_hash(),
            account: id("val02.node.sov"),
            keypair: Keypair::from_seed([34; 32]),
        },
        "127.0.0.1:0",
    )
    .unwrap()
    .with_block_log(b.block_log())
    .start();
    b_p2p.connect(&a_p2p.local_addr().to_string()).unwrap();

    let reorged = wait_until(30, || {
        let node = b.node();
        let n = node.lock().unwrap();
        n.chain().height() == 6 && n.chain().head().hash() == a_head
    });
    assert!(
        reorged,
        "B abandoned its own 3-block fork and deep-reorged onto A's heavier 6-block chain"
    );
    assert_eq!(
        b.balance(&id("ecb.reserve.sov")),
        Balance::from_sov(6).unwrap(),
        "B's state now reflects A's chain (6), not its abandoned fork (21)"
    );

    a_p2p.shutdown();
    b_p2p.shutdown();
}

#[test]
fn two_miners_share_one_chain_and_both_earn_blocks() {
    // THE end-to-end guarantee: two nodes BOTH mining (each its own identity), peered,
    // must converge on ONE chain and EACH win blocks — rewards shared — not fork-war or
    // have one miner lap the other forever. This exercises the real production paths
    // together: CONTINUOUS-GRIND mining (the Monero/Zcash model — a memoryless PoW lottery
    // at the chain's live difficulty), the PER-BLOCK difficulty retarget (which regulates
    // the rate to `target_block_ms` for any number of miners), P2P gossip + sync, the IBD
    // gate (download first only when far behind), and the deterministic fork-choice
    // tie-break (equal-work competitors converge on the smaller hash).
    //
    // Fairness here comes from the memoryless grind, NOT a timer: whoever's hashing finds
    // the next block first wins, ~50/50 between equal miners — so over enough blocks BOTH
    // appear as proposers regardless of who started first.
    let g = {
        let mut g = genesis_2op();
        // Fast blocks so the difficulty converges and the test runs in seconds; far above
        // loopback propagation, so both miners always race the same tip.
        g.mining.target_block_ms = 250;
        g
    };

    // Build a fully-live mining node: a daemon CONTINUOUSLY grinding via `run`, plus a P2P
    // engine sharing ONE `SyncShared` so the miner is gated only during a real download.
    let build_miner = |tag: &str, miner: &str, miner_seed: [u8; 32], p2p_seed: [u8; 32]| {
        let sync = Arc::new(SyncShared::new());
        let d = Daemon::new(
            &g,
            unique_dir(tag),
            1024,
            256,
            vec![(id(miner), Keypair::from_seed(miner_seed))],
        )
        .unwrap();
        let p2p = P2p::bind(
            d.node(),
            P2pConfig {
                chain_id: g.chain_id.clone(),
                genesis_hash: d.genesis_hash(),
                account: id(miner),
                keypair: Keypair::from_seed(p2p_seed),
            },
            "127.0.0.1:0",
        )
        .unwrap()
        .with_block_log(d.block_log())
        .with_sync_status(Arc::clone(&sync));
        let d = d.with_gossip(p2p.tcp()).with_sync_status(Arc::clone(&sync));
        let net = p2p.start();
        let dae = d.run("127.0.0.1:0", 1, 0).unwrap(); // block_time_ms unused (difficulty governs)
        (dae, net)
    };

    let (a_dae, a_net) = build_miner("two-a", "val01.node.sov", VAL01_SEED, [51; 32]);
    let (b_dae, b_net) = build_miner("two-b", "val02.node.sov", VAL02_SEED, [52; 32]);
    b_net.connect(&a_net.local_addr().to_string()).unwrap();

    // Wait until BOTH conditions hold: (1) the nodes are CONVERGED on one chain (they
    // agree on a buried block), and (2) BOTH miners have earned blocks on it. Polling for
    // fairness to MANIFEST is robust to the early difficulty-ramp blocks (won by whoever
    // started first) — once difficulty converges, the memoryless grind shares blocks, so
    // both proposers appear. If one miner could never win (the old bug), this times out.
    let (val01, val02) = (id("val01.node.sov"), id("val02.node.sov"));
    let fair = wait_until(90, || {
        let an = a_dae.node();
        let an = an.lock().unwrap();
        let bn = b_dae.node();
        let bn = bn.lock().unwrap();
        let (ah, bh) = (an.chain().height(), bn.chain().height());
        if ah < 25 || bh < 25 {
            return false;
        }
        // Converged on one chain (agree on a buried block).
        let common = ah.min(bh).saturating_sub(3).max(1);
        let converged = an.chain().block_by_height(common).map(|b| b.hash())
            == bn.chain().block_by_height(common).map(|b| b.hash());
        if !converged {
            return false;
        }
        // Both miners appear as proposers on the agreed chain (rewards shared).
        let (mut a_won, mut b_won) = (false, false);
        for height in 1..=ah {
            if let Some(blk) = an.chain().block_by_height(height) {
                if blk.header.proposer == val01 {
                    a_won = true;
                } else if blk.header.proposer == val02 {
                    b_won = true;
                }
            }
        }
        a_won && b_won
    });
    assert!(
        fair,
        "two miners converged on one chain AND both earned blocks (fair shared mining)"
    );

    a_net.shutdown();
    b_net.shutdown();
    a_dae.shutdown();
    b_dae.shutdown();
}

#[test]
fn peer_with_wrong_genesis_is_rejected() {
    let g = genesis();
    let (a, a_p2p) = build_node(
        &g,
        "r-a",
        "peera.node.sov",
        [30; 32],
        vec![(id("val01.node.sov"), Keypair::from_seed(VAL01_SEED))],
    );

    // X connects but presents a handshake bound to the wrong genesis hash. Its
    // transactions are otherwise perfectly valid — the only reason to reject them
    // is the failed authentication.
    let x_tcp = TcpNode::bind("127.0.0.1:0").unwrap();
    x_tcp.connect(&a_p2p.local_addr().to_string()).unwrap();
    let wrong_genesis = Hash::digest(b"not the real genesis");
    let x_kp = Keypair::from_seed([99; 32]);
    // Wrong genesis (and an unbound channel) — rejected regardless of binding.
    let bad_hello = NetMessage::hello(CHAIN_ID, wrong_genesis, id("attacker.node.sov"), &[], &x_kp);
    let tx = usa_transfer("ecb.reserve.sov", 500, 0);

    // For a sustained interval, keep announcing the bad handshake and gossiping the
    // transaction. A must never accept it.
    let leaked = wait_until(4, || {
        x_tcp.broadcast(&bad_hello);
        x_tcp.broadcast(&NetMessage::NewTransaction(tx.clone()));
        a.node().lock().unwrap().mempool_len() > 0
    });
    assert!(
        !leaked,
        "A rejected all data from a peer presenting the wrong genesis"
    );

    a_p2p.shutdown();
}

#[test]
fn daemon_gossips_produced_blocks_to_followers() {
    let g = genesis();
    // A drives its real daemon production+gossip path; B follows.
    let (a, a_p2p) = build_node(
        &g,
        "d-a",
        "peera.node.sov",
        [40; 32],
        vec![(id("val01.node.sov"), Keypair::from_seed(VAL01_SEED))],
    );
    let (b, b_p2p) = build_node(&g, "d-b", "peerb.node.sov", [41; 32], vec![]);
    a_p2p.connect(&b_p2p.local_addr().to_string()).unwrap();

    // Mine four blocks via the daemon, which gossips each as it is committed.
    for nonce in 0..4u64 {
        a.node()
            .lock()
            .unwrap()
            .submit(usa_transfer("ecb.reserve.sov", 2, nonce))
            .unwrap();
        assert!(a.produce_once(1_000 + nonce * 1_000).unwrap());
    }
    assert_eq!(a.height(), 4);

    assert!(
        wait_until(20, || b.height() == 4),
        "follower received the daemon's gossiped blocks (with catch-up as backstop)"
    );
    assert_eq!(
        b.balance(&id("ecb.reserve.sov")),
        Balance::from_sov(8).unwrap()
    );

    a_p2p.shutdown();
    b_p2p.shutdown();
}

#[test]
fn finality_is_confirmation_depth_on_every_peer() {
    // Nakamoto finality across the network: A mines a block, then keeps mining
    // until it is FINALITY_DEPTH deep. B, syncing the same chain, reports the
    // same confirmations and the same finality — no votes were exchanged,
    // because none exist.
    let g = genesis();
    let (a, a_p2p) = build_node(
        &g,
        "f-a",
        "peera.node.sov",
        [45; 32],
        vec![(id("val01.node.sov"), Keypair::from_seed(VAL01_SEED))],
    );
    let (b, b_p2p) = build_node(&g, "f-b", "peerb.node.sov", [46; 32], vec![]);
    a_p2p.connect(&b_p2p.local_addr().to_string()).unwrap();

    // Block 1 carries a payment; then bury it FINALITY_DEPTH deep.
    a.node()
        .lock()
        .unwrap()
        .submit(usa_transfer("ecb.reserve.sov", 9, 0))
        .unwrap();
    let first = a
        .node()
        .lock()
        .unwrap()
        .produce(1_000)
        .unwrap()
        .block
        .hash();
    assert!(!a.node().lock().unwrap().chain().is_final(&first));
    for i in 1..FINALITY_DEPTH {
        a.node().lock().unwrap().produce(1_000 + i * 1_000).unwrap();
    }
    {
        let node = a.node();
        let n = node.lock().unwrap();
        assert_eq!(n.chain().confirmations(&first), Some(FINALITY_DEPTH));
        assert!(n.chain().is_final(&first), "buried deep enough on A");
    }

    // B syncs and reaches the identical verdict from its own chain state.
    let agreed = wait_until(20, || {
        let node = b.node();
        let n = node.lock().unwrap();
        n.chain().height() == FINALITY_DEPTH
            && n.chain().confirmations(&first) == Some(FINALITY_DEPTH)
            && n.chain().is_final(&first)
    });
    assert!(
        agreed,
        "B independently reports the same confirmation-depth finality"
    );

    a_p2p.shutdown();
    b_p2p.shutdown();
}

#[test]
fn follower_persists_synced_blocks_and_replays_offline() {
    // A follower must persist blocks it receives over P2P (not only ones it
    // produces), so on restart it replays its OWN log instead of re-syncing the
    // whole chain — and can come back up even with no peers reachable.
    let g = genesis_2op();
    let b_dir = unique_dir("persist-b");

    // A: the miner (val01), with gossip so its blocks reach B.
    let (a, a_p2p) = build_node(
        &g,
        "persist-a",
        "val01.node.sov",
        [90; 32],
        vec![(id("val01.node.sov"), Keypair::from_seed(VAL01_SEED))],
    );
    let a_addr = a_p2p.local_addr().to_string();

    // B: a follower (val02 identity) on a PERSISTENT dir, persisting synced blocks.
    let make_b = || {
        Daemon::new(
            &g,
            b_dir.clone(),
            1024,
            256,
            vec![(id("val02.node.sov"), Keypair::from_seed(VAL02_SEED))],
        )
        .unwrap()
    };
    let b = make_b();
    let b_p2p = P2p::bind(
        b.node(),
        P2pConfig {
            chain_id: g.chain_id.clone(),
            genesis_hash: b.genesis_hash(),
            account: id("val02.node.sov"),
            keypair: Keypair::from_seed([91; 32]),
        },
        "127.0.0.1:0",
    )
    .unwrap()
    .with_block_log(b.block_log())
    .start();
    b_p2p.connect(&a_addr).unwrap();

    // A mines three blocks; B syncs them over the network.
    for n in 0..3u64 {
        a.node()
            .lock()
            .unwrap()
            .submit(usa_transfer("ecb.reserve.sov", 1, n))
            .unwrap();
        assert!(a.produce_once(1_000_000 * (n + 1)).unwrap());
    }
    assert!(wait_until(20, || b.height() == 3), "B synced to height 3");

    // Take B fully offline: stop its network engine AND drop the daemon.
    b_p2p.shutdown();
    drop(b);

    // Reopen B from disk with NO peer connection. It must replay its own persisted
    // (checksummed) block log back to height 3.
    let b2 = make_b();
    assert_eq!(
        b2.height(),
        3,
        "follower replayed P2P-synced blocks from its own log, offline"
    );
    assert_eq!(
        b2.balance(&id("ecb.reserve.sov")),
        Balance::from_sov(3).unwrap(),
        "state re-derived from the persisted synced blocks"
    );

    a_p2p.shutdown();
}

#[test]
fn chaos_partition_and_restart_converge_without_forks() {
    // A soak over the resilience paths together: A is always online and mines
    // every block. Each round B is partitioned (its link dropped) while A mines a
    // block, then B is COLD-RESTARTED from its checksummed on-disk logs and
    // reconnects. It must catch up and converge — same height, same head — with
    // NO fork, every round, over the encrypted, channel-bound transport.
    let g = genesis_2op();
    let a_dir = unique_dir("chaos-a");
    let b_dir = unique_dir("chaos-b");

    let a = Daemon::new(
        &g,
        a_dir,
        1024,
        256,
        vec![(id("val01.node.sov"), Keypair::from_seed(VAL01_SEED))],
    )
    .unwrap();
    let a_p2p = P2p::bind(
        a.node(),
        P2pConfig {
            chain_id: g.chain_id.clone(),
            genesis_hash: a.genesis_hash(),
            account: id("val01.node.sov"),
            keypair: Keypair::from_seed([80; 32]),
        },
        "127.0.0.1:0",
    )
    .unwrap()
    .start();
    let a_addr = a_p2p.local_addr().to_string();

    // Build B from its persistent dir and dial A.
    let bring_b_up = |b: &Daemon| -> P2pHandle {
        let handle = P2p::bind(
            b.node(),
            P2pConfig {
                chain_id: g.chain_id.clone(),
                genesis_hash: b.genesis_hash(),
                account: id("val02.node.sov"),
                keypair: Keypair::from_seed([81; 32]),
            },
            "127.0.0.1:0",
        )
        .unwrap()
        .with_block_log(b.block_log())
        .start();
        handle.connect(&a_addr).unwrap();
        handle
    };
    let new_b = || {
        Daemon::new(
            &g,
            b_dir.clone(),
            1024,
            256,
            vec![(id("val02.node.sov"), Keypair::from_seed(VAL02_SEED))],
        )
        .unwrap()
    };

    let mut b = new_b();
    let mut b_p2p = Some(bring_b_up(&b));

    for round in 0..3u64 {
        let h0 = a.height();

        // Partition: cut B's link so it misses the next block live.
        if let Some(h) = b_p2p.take() {
            h.shutdown();
        }

        // A mines and PERSISTS (fsync + checksum) the next block. One transfer
        // per round, so the treasury nonce is exactly `round`.
        a.node()
            .lock()
            .unwrap()
            .submit(usa_transfer("ecb.reserve.sov", 1, round))
            .unwrap();
        assert!(
            a.produce_once(1_000_000 * (h0 + 1)).unwrap(),
            "round {round}: A mined a block"
        );
        let bh = a.node().lock().unwrap().chain().head().hash();

        // Cold-restart B from disk, then heal the partition.
        drop(b);
        b = new_b();
        b_p2p = Some(bring_b_up(&b));

        // Converge: same height, same head — no fork.
        let bref = &b;
        let converged = wait_until(30, || {
            let an = a.node();
            let an = an.lock().unwrap();
            let bn = bref.node();
            let bn = bn.lock().unwrap();
            an.chain().height() == h0 + 1
                && bn.chain().height() == h0 + 1
                && an.chain().head().hash() == bh
                && bn.chain().head().hash() == bh
        });
        assert!(
            converged,
            "round {round}: nodes converged on one head without a fork"
        );
    }

    a_p2p.shutdown();
    if let Some(h) = b_p2p {
        h.shutdown();
    }
}
