//! **Live-fire BACK-DOOR probe** — join the P2P network as a hostile peer and gossip
//! forged blocks and transactions over the encrypted Noise-XX + ML-KEM wire.
//!
//! The front door is the RPC (`sov_submitTransaction`); the BACK door is peer gossip —
//! `NetMessage::NewBlock` / `NewTransaction` — which flows into the node's `import_block`
//! / mempool. This is the nation-state surface: the SOV network is permissionless, so an
//! attacker CAN complete the handshake and gossip anything. The only question is whether
//! they can push a forged/mined block or a stolen coinbase THROUGH. This probe stands up
//! a real adversarial [`TcpNode`](sov_network::TcpNode) peer, authenticates to the target, gossips a battery of
//! forgeries, and reads the target's head over RPC after each — a forgery "succeeds" only
//! if the node adopts it as its tip.
//!
//! HONEST SCOPE — the hard truth this proves: no wire-forged block can carry valid
//! mainnet RandomX proof-of-work without real hashpower, so every forged block is
//! rejected at the seal (if it links to the head) or at the parent gate (if it does not),
//! and the tip never moves. The coinbase-theft and supply-inflation attacks need a VALID
//! seal to even be evaluated — the seal binds `proposer` and `state_root`, and import
//! re-checks the supply invariant — so those are proven by the IN-PROCESS battery, which
//! can seal cheaply. After a couple of invalid blocks the node BANS our peer (the
//! eclipse/DoS defense ejecting the attacker); that ejection is itself a defense we
//! report. Nothing lands: no block is adopted, no tx enters the mempool.

use std::net::{SocketAddr, ToSocketAddrs};
use std::time::Duration;

use sov_crypto::Keypair;
use sov_network::{NetMessage, TcpNode};
use sov_primitives::Balance;
use sov_primitives::{AccountId, BlockHeight, Hash};
use sov_rpc::RpcClient;
use sov_types::{Action, Block, BlockHeader, SignedTransaction, Transaction};

use crate::Outcome;

/// The fallback mainnet genesis hash, if the target won't serve block 0.
const MAINNET_GENESIS: &str = "cb0272ff88e64c18cde0257f7fae1c8236b02651f10cc7a02456fd682ee2e72d";

/// The result of the back-door probe.
pub struct P2pReport {
    /// The P2P `host:port` we attacked.
    pub p2p_target: String,
    /// The RPC `host:port` we observed the tip through.
    pub rpc_target: String,
    /// The chain id the node reported.
    pub chain_id: Option<String>,
    /// True if the chain id names mainnet.
    pub is_mainnet: bool,
    /// True if our hostile peer completed the handshake and authenticated.
    pub authenticated: bool,
    /// The node's head (height, hash) before the barrage.
    pub head_before: Option<(u64, String)>,
    /// The node's head (height, hash) after — must be unchanged, or advanced only by the
    /// node's OWN honest mining (never to one of our forged block hashes).
    pub head_after: Option<(u64, String)>,
    /// True if the node banned/dropped our peer during the run (a defense).
    pub ejected: bool,
    /// One outcome per attack (empty if we never authenticated).
    pub outcomes: Vec<Outcome>,
    /// A message when the probe could not run (unreachable / handshake failed).
    pub error: Option<String>,
}

/// Split a user target into (rpc `host:port`, p2p `host:port`), defaulting the ports.
fn split_targets(target: &str) -> (String, String) {
    let t = target.trim();
    let t = t
        .strip_prefix("http://")
        .or_else(|| t.strip_prefix("https://"))
        .unwrap_or(t);
    let t = t.split('/').next().unwrap_or(t);
    let (host, rpc_port) = match t.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.to_string()),
        None => (t.to_string(), "8645".to_string()),
    };
    let rpc = format!("{host}:{rpc_port}");
    let p2p = format!("{host}:9645");
    (rpc, p2p)
}

// ── forged-block builders ────────────────────────────────────────────────────

/// A forged block extending some parent at some height. Its roots are garbage and its
/// nonce is unmined, so it can never carry valid PoW — the point is to prove the node
/// rejects it. `proposer` is where the (never-granted) reward would go.
fn forged_block(
    height: u64,
    prev_hash: Hash,
    proposer: AccountId,
    timestamp_ms: u64,
    bits: u32,
) -> Block {
    Block {
        header: BlockHeader {
            height: BlockHeight::new(height),
            prev_hash,
            tx_root: Hash::digest(b"forged-tx-root"),
            receipts_root: Hash::digest(b"forged-receipts"),
            state_root: Hash::digest(b"forged-state"),
            timestamp_ms,
            proposer,
            version_bits: 0,
            bits,
            nonce: 0,
        },
        transactions: vec![],
    }
}

/// A fabricated parent hash nobody has ever seen.
fn nowhere() -> Hash {
    Hash::digest(b"sov-redteam-fabricated-parent")
}

fn attacker_id() -> AccountId {
    Keypair::hybrid_from_seed([88; 32])
        .public_key()
        .implicit_account_id()
}

// ── forged-tx builders (gossiped over the wire, not the RPC) ─────────────────

fn implicit_transfer(account_seed: u8, key_seed: u8) -> SignedTransaction {
    let account_kp = Keypair::hybrid_from_seed([account_seed; 32]);
    let key_kp = Keypair::hybrid_from_seed([key_seed; 32]);
    let to = Keypair::hybrid_from_seed([201; 32])
        .public_key()
        .implicit_account_id();
    let tx = Transaction {
        signer: account_kp.public_key().implicit_account_id(),
        public_key: key_kp.public_key(),
        nonce: 0,
        action: Action::Transfer {
            to,
            amount: Balance::from_sov(1).unwrap(),
        },
    };
    SignedTransaction::sign(tx, &key_kp).unwrap()
}

// ── verdict helpers ──────────────────────────────────────────────────────────

fn head_of(client: &RpcClient) -> Option<(u64, String)> {
    client
        .head()
        .ok()
        .map(|b| (b.header.height.get(), b.hash().to_hex()))
}

/// Gossip a forged block and judge: the node must NOT adopt it as its head.
fn send_block(
    node: &TcpNode,
    victim: SocketAddr,
    client: &RpcClient,
    name: &'static str,
    block: Block,
) -> Outcome {
    let forged_hash = block.hash().to_hex();
    let sent = node.send(victim, &NetMessage::NewBlock(block));
    if !sent {
        return Outcome::info(
            "p2p block",
            name,
            "our peer was already dropped — node ejected us",
        );
    }
    std::thread::sleep(Duration::from_millis(600));
    match head_of(client) {
        Some((_, hash)) if hash == forged_hash => Outcome::vulnerable(
            "p2p block",
            name,
            format!("ACCEPTED — the node adopted our forged block as its head ({forged_hash})"),
        ),
        Some((h, _)) => Outcome::defended(
            "p2p block",
            name,
            format!("rejected — tip unmoved (still honest head at height {h})"),
        ),
        None => Outcome::info("p2p block", name, "could not read the node's head over RPC"),
    }
}

/// Gossip a forged transaction and judge: it must NOT enter the mempool.
fn send_tx(
    node: &TcpNode,
    victim: SocketAddr,
    client: &RpcClient,
    name: &'static str,
    stx: SignedTransaction,
) -> Outcome {
    let before = client.mempool_size().unwrap_or(0);
    let sent = node.send(victim, &NetMessage::NewTransaction(stx));
    if !sent {
        return Outcome::info(
            "p2p tx",
            name,
            "our peer was already dropped — node ejected us",
        );
    }
    std::thread::sleep(Duration::from_millis(500));
    let after = client.mempool_size().unwrap_or(before);
    if after > before {
        Outcome::vulnerable(
            "p2p tx",
            name,
            format!("ADMITTED to the mempool via gossip ({before} → {after})"),
        )
    } else {
        Outcome::defended(
            "p2p tx",
            name,
            format!("rejected — mempool unchanged ({before} → {after})"),
        )
    }
}

/// Stand up a hostile peer against `target` (RPC `host[:port]`; P2P assumed on :9645) and
/// gossip forged blocks/txs over the real encrypted wire.
pub fn probe_backdoor(target: &str) -> P2pReport {
    let (rpc_target, p2p_target) = split_targets(target);
    let client = RpcClient::new(rpc_target.clone()).with_timeout(Duration::from_secs(12));

    let mut report = P2pReport {
        p2p_target: p2p_target.clone(),
        rpc_target: rpc_target.clone(),
        chain_id: client.chain_id().ok(),
        is_mainnet: false,
        authenticated: false,
        head_before: None,
        head_after: None,
        ejected: false,
        outcomes: Vec::new(),
        error: None,
    };
    report.is_mainnet = report
        .chain_id
        .as_deref()
        .map(|c| c.contains("mainnet"))
        .unwrap_or(false);

    // We need the node reachable over RPC (to observe the tip) and its chain identity.
    let Some(chain_id) = report.chain_id.clone() else {
        report.error = Some(format!("node unreachable over RPC at {rpc_target}"));
        return report;
    };
    let genesis = client
        .block_by_height(0)
        .ok()
        .flatten()
        .map(|b| b.hash())
        .or_else(|| Hash::from_hex(MAINNET_GENESIS).ok())
        .expect("a genesis hash");
    report.head_before = head_of(&client);
    let Some((head_h, head_hash)) = report.head_before.clone() else {
        report.error = Some("could not read the node's head".into());
        return report;
    };
    let head_hash = Hash::from_hex(&head_hash).unwrap_or_else(|_| nowhere());
    let head_bits = client.head().map(|b| b.header.bits).unwrap_or(0x1e00_ffff);
    let head_ts = client.head().map(|b| b.header.timestamp_ms).unwrap_or(0);

    // Resolve the victim's P2P socket address.
    let Some(victim) = p2p_target
        .to_socket_addrs()
        .ok()
        .and_then(|mut it| it.next())
    else {
        report.error = Some(format!("could not resolve P2P address {p2p_target}"));
        return report;
    };

    // Stand up our hostile peer and dial the victim.
    let node = match TcpNode::bind("0.0.0.0:0") {
        Ok(n) => n,
        Err(e) => {
            report.error = Some(format!("could not bind local peer: {e}"));
            return report;
        }
    };
    if let Err(e) = node.connect(&p2p_target) {
        report.error = Some(format!("could not dial {p2p_target}: {e}"));
        return report;
    }

    // Wait for the Noise + ML-KEM handshake to complete, then get our channel binding.
    let mut binding = None;
    for _ in 0..120 {
        if let Some(b) = node.peer_handshake_hash(&victim) {
            binding = Some(b);
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let Some(binding) = binding else {
        report.error =
            Some("P2P handshake did not complete (node not accepting peers on :9645?)".into());
        node.shutdown();
        return report;
    };

    // Authenticate: send a signed Hello bound to THIS channel. Any keypair + any account
    // name works — the network is permissionless (we just avoid the victim's own id).
    let keypair = Keypair::hybrid_from_seed([77; 32]);
    let account = AccountId::new("redteam-probe.sov").unwrap();
    node.send(
        victim,
        &NetMessage::hello(chain_id, genesis, account, &binding, &keypair),
    );

    // The victim reciprocates a Hello/Status ONLY after it authenticates us, so its
    // reply is our synchronization signal that mutual auth is done (and that our forged
    // gossip will now be processed rather than ignored). Meanwhile, the victim gossips
    // its peer list and our transport auto-dials it — prune every connection that is NOT
    // the target so we never touch the real network; we only ever attack the one node.
    for _ in 0..80 {
        std::thread::sleep(Duration::from_millis(100));
        for (from, m) in node.drain() {
            if from == victim && matches!(m, NetMessage::Hello { .. } | NetMessage::Status { .. }) {
                report.authenticated = true;
            }
        }
        for p in node.connected_peers() {
            if p.ip() != victim.ip() {
                node.disconnect(&p);
            }
        }
        if report.authenticated {
            break;
        }
    }
    if !report.authenticated {
        report.error = Some("handshake completed but the node never authenticated our peer".into());
        node.shutdown();
        return report;
    }

    // ── the battery ──
    // First, the unconnectable forgeries (fabricated parents) — dropped without penalty,
    // so they run cleanly while we are still connected.
    report.outcomes.push(send_block(
        &node,
        victim,
        &client,
        "orphan block (fabricated parent)",
        forged_block(
            head_h + 1,
            nowhere(),
            attacker_id(),
            head_ts + 150_000,
            head_bits,
        ),
    ));
    report.outcomes.push(send_block(
        &node,
        victim,
        &client,
        "rewrite history (old height, fake parent)",
        forged_block(
            head_h.saturating_sub(3),
            nowhere(),
            attacker_id(),
            head_ts,
            head_bits,
        ),
    ));
    report.outcomes.push(send_block(
        &node,
        victim,
        &client,
        "future-height leap (+10000)",
        forged_block(
            head_h + 10_000,
            nowhere(),
            attacker_id(),
            head_ts + 150_000,
            head_bits,
        ),
    ));

    // Forged transactions over the gossip path (the mempool back door).
    let mut forged_sig = implicit_transfer(30, 30);
    forged_sig.signature = crate::tamper_signature(forged_sig.signature, crate::Half::Ed25519);
    report.outcomes.push(send_tx(
        &node,
        victim,
        &client,
        "gossip a forged-signature tx",
        forged_sig,
    ));
    report.outcomes.push(send_tx(
        &node,
        victim,
        &client,
        "gossip an impersonation tx (wrong key)",
        implicit_transfer(31, 32),
    ));

    // Finally the CONNECTING forgeries: they link to the real head, so they reach full
    // validation (and cost misbehavior points). This proves the seal gate rejects a
    // correctly-linked but unmined block — and typically trips the ban that ejects us.
    report.outcomes.push(send_block(
        &node,
        victim,
        &client,
        "unmined block on the real head (no PoW)",
        forged_block(
            head_h + 1,
            head_hash,
            attacker_id(),
            head_ts + 150_000,
            head_bits,
        ),
    ));
    report.outcomes.push(send_block(
        &node,
        victim,
        &client,
        "steal the coinbase on the real head",
        forged_block(
            head_h + 1,
            head_hash,
            attacker_id(),
            head_ts + 150_001,
            head_bits,
        ),
    ));

    // Did the node eject us?
    report.ejected = !node.connected_peers().contains(&victim);
    report.head_after = head_of(&client);
    node.shutdown();
    report
}

/// Any VULNERABLE outcome?
pub fn any_vulnerable(report: &P2pReport) -> bool {
    report
        .outcomes
        .iter()
        .any(|o| o.verdict == crate::Verdict::Vulnerable)
}

/// The tip never adopted a forged block: either unchanged, or advanced only by the node's
/// own honest mining (never to a forged hash — that case is caught as VULNERABLE above).
pub fn tip_held(report: &P2pReport) -> bool {
    !any_vulnerable(report)
}
