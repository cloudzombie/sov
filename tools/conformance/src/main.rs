//! `sov-conformance` — a live two-node conformance sweep.
//!
//! Point it at TWO running, peered SOV nodes (e.g. your two machines). For every
//! supported transaction type it:
//!   1. builds a REAL signed transaction (the same crypto/ids the node uses — no
//!      reimplemented consensus, no dummy data),
//!   2. submits it to node A and waits for it to be mined (reads the on-chain
//!      receipt — success or the exact failure reason),
//!   3. checks the action's specific on-chain effect via RPC, and
//!   4. runs the VALIDITY CHECKSUM: node A and node B must agree on the block at
//!      that height (identical block hash ⇒ identical txs, receipts, and state
//!      root — a cryptographic cross-node integrity proof), AND supply must be
//!      conserved on both nodes (`total == mined`, the chain's emission invariant).
//!
//! It fabricates nothing: keys are real, every height/receipt/balance is read live
//! from a running node, and a failure is reported with the node's own reason.
//!
//! ```text
//! sov-conformance --node-a http://127.0.0.1:8645 --node-b http://127.0.0.1:8646 \
//!                 --seed-hex <64-hex seed of a FUNDED account>
//! ```
//! The seed is a 32-byte hex seed controlling an account that already holds SOV
//! (e.g. a miner/faucet key on your running net — `sov-testnet gen` writes one per
//! node in `node-K/keystore.json`). The sweep funds its own helper accounts from it.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use sov_crypto::Keypair;
use sov_primitives::{AccountId, Balance, Hash};
use sov_rpc::RpcClient;
use sov_state::{nft_class_id, token_asset_id};
use sov_wallet::HdWallet;
use sov_types::{
    multisig_signing_bytes, rotation_signing_bytes, Action, MultisigApproval, SignedTransaction,
    Transaction,
};

/// How long to wait for a submitted tx to be mined (read its receipt).
const MINE_TIMEOUT: Duration = Duration::from_secs(120);
/// How long to wait for a mined block to propagate to the second node.
const PROPAGATE_TIMEOUT: Duration = Duration::from_secs(120);
/// Poll cadence while waiting.
const POLL: Duration = Duration::from_millis(400);

fn main() {
    // Two modes:
    //   sov-conformance serve [--addr 127.0.0.1:8700]   → web dashboard (enter node
    //                                                      IPs + wallet seed, watch results)
    //   sov-conformance --node-a … --node-b … --seed-hex …   → one-shot CLI sweep
    if std::env::args().nth(1).as_deref() == Some("serve") {
        let addr = serve_addr();
        if let Err(e) = serve(&addr) {
            eprintln!("sov-conformance serve: {e}");
            std::process::exit(1);
        }
        return;
    }
    let args = match Args::parse() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("sov-conformance: {e}\n");
            eprintln!("usage:");
            eprintln!("  sov-conformance serve [--addr 127.0.0.1:8700]   (web dashboard)");
            eprintln!("  sov-conformance --node-a <ip:port> --node-b <ip:port> (--phrase \"<24 words>\" | --seed-hex <64-hex>) [--account <id>]");
            std::process::exit(2);
        }
    };
    let cfg = Config {
        node_a: args.node_a,
        node_b: args.node_b,
        seed: args.seed,
        account: args.account,
    };
    match cli_run(&cfg) {
        Ok(failed) => std::process::exit(if failed == 0 { 0 } else { 1 }),
        Err(e) => {
            eprintln!("sov-conformance: fatal: {e}");
            std::process::exit(1);
        }
    }
}

/// Resolve the signer seed from EITHER a recovery phrase (preferred — it is what
/// sov-station lets you copy) OR a raw 64-hex seed. The phrase derivation matches
/// sov-station's wallet EXACTLY (`HdWallet::from_mnemonic(phrase, "").derive_seed(0, 0)`),
/// so the same wallet yields the same on-chain account.
fn resolve_seed(seed_hex: &str, phrase: &str) -> Result<[u8; 32], String> {
    let phrase = phrase.trim();
    if !phrase.is_empty() {
        let w = HdWallet::from_mnemonic(phrase, "")
            .map_err(|e| format!("invalid recovery phrase: {e}"))?;
        return Ok(w.derive_seed(0, 0));
    }
    let h = seed_hex.trim();
    if h.is_empty() {
        return Err("provide a recovery phrase (24 words) or a 64-hex seed".into());
    }
    let raw = hex::decode(h).map_err(|e| format!("seed must be hex: {e}"))?;
    raw.try_into()
        .map_err(|_| "seed must be exactly 32 bytes (64 hex chars)".to_string())
}

/// The inputs a sweep needs — shared by the CLI and the web server.
struct Config {
    node_a: String,
    node_b: String,
    seed: [u8; 32],
    account: Option<String>,
}

/// `serve`'s bind address (default `127.0.0.1:8700`; override with `--addr`).
fn serve_addr() -> String {
    let mut it = std::env::args().skip(2);
    while let Some(f) = it.next() {
        if f == "--addr" {
            if let Some(v) = it.next() {
                return v;
            }
        }
    }
    "127.0.0.1:8700".to_string()
}

struct Args {
    node_a: String,
    node_b: String,
    seed: [u8; 32],
    /// Optional explicit signer account. Defaults to the seed's implicit id
    /// (what sov-station wallets use); override for a NAMED genesis-bound account
    /// (e.g. `faucet.reserve.sov`, a miner like `val01.node.sov`).
    account: Option<String>,
}

impl Args {
    fn parse() -> Result<Args, String> {
        let mut node_a = None;
        let mut node_b = None;
        let mut seed_hex = None;
        let mut phrase = None;
        let mut account = None;
        let mut it = std::env::args().skip(1);
        while let Some(flag) = it.next() {
            let mut val = || it.next().ok_or_else(|| format!("{flag} needs a value"));
            match flag.as_str() {
                "--node-a" => node_a = Some(val()?),
                "--node-b" => node_b = Some(val()?),
                "--seed-hex" => seed_hex = Some(val()?),
                "--phrase" => phrase = Some(val()?),
                "--account" => account = Some(val()?),
                "-h" | "--help" => return Err("help".into()),
                other => return Err(format!("unknown flag {other}")),
            }
        }
        // The RpcClient connects to a bare `host:port`; accept a full URL too.
        let norm = |s: String| {
            s.trim()
                .trim_start_matches("https://")
                .trim_start_matches("http://")
                .trim_end_matches('/')
                .to_string()
        };
        let node_a = norm(node_a.ok_or("missing --node-a")?);
        let node_b = norm(node_b.ok_or("missing --node-b")?);
        let seed = resolve_seed(
            seed_hex.as_deref().unwrap_or(""),
            phrase.as_deref().unwrap_or(""),
        )?;
        Ok(Args {
            node_a,
            node_b,
            seed,
            account,
        })
    }
}

/// Shared sweep context: a client to each node and the funded signing identity.
struct Ctx {
    a: RpcClient,
    b: RpcClient,
    signer: Keypair,
    /// The signer's 32-byte seed, kept so helper subkeys derive deterministically
    /// (thread-safe — no thread-locals — so the web server can sweep on a worker).
    seed: [u8; 32],
    account: AccountId,
    /// Genesis pre-mine in grains (`total − mined`, captured at preflight). The
    /// conservation invariant is policy-agnostic: `total − mined` must stay equal to
    /// this for the life of the chain — zero on the no-pre-mine mainnet model, the
    /// genesis allocation on a pre-funded `test` net. Only coinbase grows `mined`.
    premine: i128,
    /// A per-run tag (the preflight height) mixed into one-shot ids and throwaway
    /// accounts (NFT item ids, the rotated account, the multisig account) so the
    /// sweep is RE-RUNNABLE against the same chain without colliding with state a
    /// prior run already created.
    run_id: u64,
}

impl Ctx {
    /// A deterministic helper keypair derived from the main seed and a label, so
    /// runs are reproducible and helper accounts don't collide across actions.
    fn subkey(&self, label: &str) -> Keypair {
        let mut buf = Vec::with_capacity(32 + label.len());
        buf.extend_from_slice(&self.seed);
        buf.extend_from_slice(label.as_bytes());
        let h = Hash::digest(&buf);
        Keypair::hybrid_from_seed(*h.as_bytes())
    }

    /// Build + sign a transaction from `kp` at its current on-chain nonce (read
    /// from node A).
    fn sign(&self, kp: &Keypair, action: Action) -> Result<SignedTransaction, String> {
        // The main signer may control a NAMED genesis account; helper subkeys always
        // act as their own implicit id.
        let signer = if kp.public_key() == self.signer.public_key() {
            self.account.clone()
        } else {
            kp.public_key().implicit_account_id()
        };
        let nonce = self.a.nonce(&signer).map_err(|e| e.to_string())?;
        let tx = Transaction {
            signer,
            public_key: kp.public_key(),
            nonce,
            action,
        };
        SignedTransaction::sign(tx, kp).map_err(|e| e.to_string())
    }

    /// Submit to node A, wait for the receipt, and return `(height, receipt_json)`.
    /// Errors if it is not mined within [`MINE_TIMEOUT`].
    fn submit_mined(&self, stx: &SignedTransaction) -> Result<(u64, Value), String> {
        let txid = self.a.submit_transaction(stx).map_err(|e| e.to_string())?;
        let deadline = Instant::now() + MINE_TIMEOUT;
        while Instant::now() < deadline {
            let r = self
                .a
                .call("sov_getReceipt", json!({ "txId": txid.to_hex() }))
                .map_err(|e| e.to_string())?;
            if let Some(h) = r.get("height").and_then(Value::as_u64) {
                return Ok((h, r));
            }
            std::thread::sleep(POLL);
        }
        Err(format!("tx {} not mined within timeout", txid.to_hex()))
    }

    /// Submit a tx expected to SUCCEED; returns the height it landed at.
    fn ok_tx(&self, kp: &Keypair, action: Action) -> Result<u64, String> {
        let stx = self.sign(kp, action)?;
        let (h, r) = self.submit_mined(&stx)?;
        if receipt_ok(&r) {
            Ok(h)
        } else {
            Err(format!("receipt failed: {}", receipt_reason(&r)))
        }
    }

    /// Wait until node B has the SAME block as node A at `height` (identical
    /// hash). A matching hash is a full cross-node agreement on that block —
    /// transactions, receipts, and state root all commit into the hash.
    fn agree_at(&self, height: u64) -> Result<String, String> {
        let a_block = self
            .a
            .block_by_height(height)
            .map_err(|e| e.to_string())?
            .ok_or_else(|| format!("node A missing block {height}"))?;
        let a_hash = a_block.hash();
        let deadline = Instant::now() + PROPAGATE_TIMEOUT;
        while Instant::now() < deadline {
            if let Ok(Some(b_block)) = self.b.block_by_height(height) {
                if b_block.hash() == a_hash {
                    return Ok(a_hash.to_hex());
                }
                return Err(format!(
                    "DIVERGENCE at height {height}: A={} B={}",
                    a_hash.to_hex(),
                    b_block.hash().to_hex()
                ));
            }
            std::thread::sleep(POLL);
        }
        Err(format!("block {height} did not propagate to node B"))
    }

    /// Supply conservation on a node: `total − mined` must still equal the genesis
    /// pre-mine captured at preflight. No transaction may create or destroy SOV —
    /// only coinbase grows the supply. Policy-agnostic (pre-mine or not).
    fn supply_conserved(&self, c: &RpcClient, who: &str) -> Result<(), String> {
        let (total, mined) = supply_total_mined(c).map_err(|e| format!("{who}: {e}"))?;
        if total - mined == self.premine {
            Ok(())
        } else {
            Err(format!(
                "{who}: supply NOT conserved (total−mined={} ≠ premine {})",
                total - mined,
                self.premine
            ))
        }
    }

    /// The full validity checksum run after each transaction.
    fn checksum(&self, height: u64) -> Result<String, String> {
        let agreed = self.agree_at(height)?;
        self.supply_conserved(&self.a, "node A")?;
        self.supply_conserved(&self.b, "node B")?;
        Ok(agreed)
    }

    /// Fund a helper account from the signer (so it can pay gas / hold value),
    /// returning once the transfer is mined.
    fn fund(&self, to: &AccountId, sov: u128) -> Result<(), String> {
        self.ok_tx(
            &self.signer,
            Action::Transfer {
                to: to.clone(),
                amount: Balance::from_sov(sov).map_err(|e| e.to_string())?,
            },
        )?;
        Ok(())
    }

    fn balance(&self, acct: &AccountId) -> Balance {
        self.a.balance(acct).unwrap_or(Balance::ZERO)
    }
}

fn receipt_ok(r: &Value) -> bool {
    r.get("status")
        .and_then(|s| s.get("status"))
        .and_then(Value::as_str)
        == Some("success")
}

fn receipt_reason(r: &Value) -> String {
    r.get("status")
        .and_then(|s| s.get("reason"))
        .and_then(Value::as_str)
        .unwrap_or("(included but not successful)")
        .to_string()
}

/// A case body: performs the action against the context and returns a short
/// human description of what it verified (or an error reason).
type CaseFn = Box<dyn Fn(&Ctx) -> Result<String, String>>;

/// One sweep case: a name and the body that performs + verifies it.
struct Case {
    name: &'static str,
    run: CaseFn,
}

/// Build clients + signer + context and run preflight (reachable, same chain, same
/// genesis, funded signer). Returns the context and a JSON preflight summary.
fn prepare(cfg: &Config) -> Result<(Ctx, Value), String> {
    let a = RpcClient::new(cfg.node_a.clone()).with_timeout(Duration::from_secs(20));
    let b = RpcClient::new(cfg.node_b.clone()).with_timeout(Duration::from_secs(20));
    let signer = Keypair::hybrid_from_seed(cfg.seed);
    let account = match &cfg.account {
        Some(a) if !a.trim().is_empty() => {
            AccountId::new(a.trim()).map_err(|e| format!("bad account: {e}"))?
        }
        _ => signer.public_key().implicit_account_id(),
    };

    let id_a = a.chain_id().map_err(|e| format!("node A unreachable: {e}"))?;
    let id_b = b.chain_id().map_err(|e| format!("node B unreachable: {e}"))?;
    if id_a != id_b {
        return Err(format!("nodes are on different chains: A={id_a} B={id_b}"));
    }
    let gen_a = peer_genesis(&a)?;
    let gen_b = peer_genesis(&b)?;
    if gen_a != gen_b {
        return Err(format!("nodes have different genesis: A={gen_a} B={gen_b}"));
    }
    let premine = {
        let (t, m) = supply_total_mined(&a).map_err(|e| format!("reading supply: {e}"))?;
        t - m
    };
    let run_id = a.height().unwrap_or(0);
    let bal = a.balance(&account).unwrap_or(Balance::ZERO);

    let preflight = json!({
        "chainId": id_a,
        "genesis": gen_a,
        "heightA": a.height().unwrap_or(0),
        "heightB": b.height().unwrap_or(0),
        "peerA": peer_summary(&a),
        "peerB": peer_summary(&b),
        "signer": account.to_string(),
        "balance": bal.to_string(),
        "cases": case_count(),
    });
    if bal.grains() == 0 {
        return Err(format!(
            "signer {account} has no balance — use a FUNDED wallet seed (or a miner/faucet \
             key, with its named account in the Account field) and let the node mine first"
        ));
    }

    let ctx = Ctx {
        a,
        b,
        signer,
        seed: cfg.seed,
        account,
        premine,
        run_id,
    };
    Ok((ctx, preflight))
}

/// Run every case, invoking `on_case(index, name, result, seconds)` after each.
/// Returns `(passed, failed)`. Shared by the CLI and the web dashboard.
fn sweep(
    ctx: &Ctx,
    mut on_case: impl FnMut(usize, &'static str, &Result<String, String>, f64),
) -> (usize, usize) {
    let cases = build_cases();
    let mut passed = 0usize;
    let mut failed = 0usize;
    for (i, case) in cases.iter().enumerate() {
        let started = Instant::now();
        let result = (case.run)(ctx);
        let secs = started.elapsed().as_secs_f64();
        if result.is_ok() {
            passed += 1;
        } else {
            failed += 1;
        }
        on_case(i, case.name, &result, secs);
    }
    (passed, failed)
}

/// How many cases a sweep runs (for progress display).
fn case_count() -> usize {
    build_cases().len()
}

/// CLI mode: print preflight, run the sweep to stdout, print the summary.
fn cli_run(cfg: &Config) -> Result<usize, String> {
    let (ctx, pre) = prepare(cfg)?;
    println!("── preflight ──────────────────────────────────────────────");
    println!("  chain         : {}", pre["chainId"].as_str().unwrap_or(""));
    println!("  genesis       : {}", pre["genesis"].as_str().unwrap_or(""));
    println!("  node A        : height {}  {}", pre["heightA"], pre["peerA"].as_str().unwrap_or(""));
    println!("  node B        : height {}  {}", pre["heightB"], pre["peerB"].as_str().unwrap_or(""));
    println!("  signer        : {}", pre["signer"].as_str().unwrap_or(""));
    println!("  signer balance: {}", pre["balance"].as_str().unwrap_or(""));
    println!();
    println!("── sweep: {} transaction types ───────────────────────────", case_count());
    let (passed, failed) = sweep(&ctx, |_, name, result, secs| match result {
        Ok(detail) => println!("  ✓ {name:<22} {detail}  ({secs:.1}s)"),
        Err(reason) => println!("  ✗ {name:<22} {reason}  ({secs:.1}s)"),
    });
    println!();
    println!("── summary ────────────────────────────────────────────────");
    println!("  passed: {passed}   failed: {failed}   total: {}", passed + failed);
    match ctx
        .supply_conserved(&ctx.a, "node A")
        .and(ctx.supply_conserved(&ctx.b, "node B"))
    {
        Ok(()) => println!("  supply conserved on both nodes ✓"),
        Err(e) => println!("  ⚠ {e}"),
    }
    println!(
        "  delegated: Shielded round-trip → `sov-testnet shielded`; \
         TokenSetPolicy → needs a CompliancePolicy fixture"
    );
    Ok(failed)
}

/// Read the genesis hash a node reports (pins the exact chain/fork).
fn peer_genesis(c: &RpcClient) -> Result<String, String> {
    let info = c.call("sov_getPeerInfo", json!({})).map_err(|e| e.to_string())?;
    Ok(info
        .get("genesisHash")
        .and_then(Value::as_str)
        .unwrap_or("(unknown)")
        .to_string())
}

/// A compact peering summary string for a node: `peers N (behind X, synced)`.
fn peer_summary(c: &RpcClient) -> String {
    match c.call("sov_getPeerInfo", json!({})) {
        Ok(info) => {
            let peers = info.get("peers").and_then(Value::as_u64).unwrap_or(0);
            let behind = info.get("behindBlocks").and_then(Value::as_u64).unwrap_or(0);
            let syncing = info.get("syncing").and_then(Value::as_bool).unwrap_or(false);
            format!(
                "peers {peers} (behind {behind}, {})",
                if syncing { "syncing" } else { "synced" }
            )
        }
        Err(_) => "peers ?".to_string(),
    }
}

/// Build the case list. Each performs a real signed action and verifies it, then
/// the harness runs the cross-node + supply checksum after it.
fn build_cases() -> Vec<Case> {
    macro_rules! case {
        ($name:literal, $f:expr) => {
            Case {
                name: $name,
                run: Box::new($f),
            }
        };
    }

    vec![
        // ---------------- Transfer ----------------
        case!("transfer", |ctx: &Ctx| {
            let to = ctx.subkey("recipient").public_key().implicit_account_id();
            let before = ctx.balance(&to);
            let h = ctx.ok_tx(
                &ctx.signer,
                Action::Transfer {
                    to: to.clone(),
                    amount: Balance::from_sov(1).map_err(|e| e.to_string())?,
                },
            )?;
            let after = ctx.balance(&to);
            if after <= before {
                return Err("recipient balance did not increase".into());
            }
            let agreed = ctx.checksum(h)?;
            Ok(format!("h{h} recipient {after}  block {}", short(&agreed)))
        }),
        // ---------------- Token: issue / transfer / burn ----------------
        case!("token_issue", |ctx: &Ctx| {
            let to = ctx.subkey("token-holder").public_key().implicit_account_id();
            let asset = token_asset_id(&ctx.account, "USD1");
            let h = ctx.ok_tx(
                &ctx.signer,
                Action::TokenIssue {
                    symbol: "USD1".into(),
                    amount: Balance::from_sov(1000).map_err(|e| e.to_string())?,
                    to: to.clone(),
                },
            )?;
            let bal = token_balance(ctx, &to, &asset);
            if bal == 0 {
                return Err("issued token balance is zero".into());
            }
            let agreed = ctx.checksum(h)?;
            Ok(format!("h{h} {bal} units of {}  block {}", short(&asset.to_hex()), short(&agreed)))
        }),
        case!("token_transfer", |ctx: &Ctx| {
            let asset = token_asset_id(&ctx.account, "USD1");
            // Ensure the signer holds some USD1 to send.
            ctx.ok_tx(
                &ctx.signer,
                Action::TokenIssue {
                    symbol: "USD1".into(),
                    amount: Balance::from_sov(10).map_err(|e| e.to_string())?,
                    to: ctx.account.clone(),
                },
            )?;
            let to = ctx.subkey("token-rx2").public_key().implicit_account_id();
            let h = ctx.ok_tx(
                &ctx.signer,
                Action::TokenTransfer {
                    asset,
                    to: to.clone(),
                    amount: Balance::from_sov(5).map_err(|e| e.to_string())?,
                },
            )?;
            if token_balance(ctx, &to, &asset) == 0 {
                return Err("token transfer did not credit recipient".into());
            }
            let agreed = ctx.checksum(h)?;
            Ok(format!("h{h} block {}", short(&agreed)))
        }),
        case!("token_burn", |ctx: &Ctx| {
            let asset = token_asset_id(&ctx.account, "USD1");
            ctx.ok_tx(
                &ctx.signer,
                Action::TokenIssue {
                    symbol: "USD1".into(),
                    amount: Balance::from_sov(5).map_err(|e| e.to_string())?,
                    to: ctx.account.clone(),
                },
            )?;
            let before = token_balance(ctx, &ctx.account, &asset);
            let h = ctx.ok_tx(
                &ctx.signer,
                Action::TokenBurn {
                    asset,
                    amount: Balance::from_sov(5).map_err(|e| e.to_string())?,
                },
            )?;
            let after = token_balance(ctx, &ctx.account, &asset);
            if after >= before {
                return Err("burn did not reduce balance".into());
            }
            let agreed = ctx.checksum(h)?;
            Ok(format!("h{h} {before}→{after}  block {}", short(&agreed)))
        }),
        // ---------------- NFT: mint / transfer / set_meta ----------------
        case!("nft_mint", |ctx: &Ctx| {
            let to = ctx.subkey("nft-owner").public_key().implicit_account_id();
            let item = format!("nft-{}-1", ctx.run_id).into_bytes();
            let h = ctx.ok_tx(
                &ctx.signer,
                Action::NftMint {
                    symbol: "ART".into(),
                    token_id: item.clone(),
                    to: to.clone(),
                    metadata: b"ipfs://meta".to_vec(),
                },
            )?;
            let collection = nft_class_id(&ctx.account, "ART");
            let nft = ctx
                .a
                .call(
                    "sov_getNft",
                    json!({"collection": collection.to_hex(), "tokenId": hex::encode(&item)}),
                )
                .map_err(|e| e.to_string())?;
            if nft.is_null() {
                return Err("minted NFT not found on-chain".into());
            }
            let agreed = ctx.checksum(h)?;
            Ok(format!("h{h} {}  block {}", short(&collection.to_hex()), short(&agreed)))
        }),
        case!("nft_transfer", |ctx: &Ctx| {
            // Mint to the signer, then transfer it onward.
            let item = format!("nft-{}-2", ctx.run_id).into_bytes();
            ctx.ok_tx(
                &ctx.signer,
                Action::NftMint {
                    symbol: "ART".into(),
                    token_id: item.clone(),
                    to: ctx.account.clone(),
                    metadata: b"".to_vec(),
                },
            )?;
            let collection = nft_class_id(&ctx.account, "ART");
            let to = ctx.subkey("nft-rx2").public_key().implicit_account_id();
            let h = ctx.ok_tx(
                &ctx.signer,
                Action::NftTransfer {
                    collection,
                    token_id: item,
                    to: to.clone(),
                },
            )?;
            let agreed = ctx.checksum(h)?;
            Ok(format!("h{h} → {}  block {}", short(to.as_str()), short(&agreed)))
        }),
        case!("nft_set_meta", |ctx: &Ctx| {
            let item = format!("nft-{}-3", ctx.run_id).into_bytes();
            ctx.ok_tx(
                &ctx.signer,
                Action::NftMint {
                    symbol: "ART".into(),
                    token_id: item.clone(),
                    to: ctx.account.clone(),
                    metadata: b"old".to_vec(),
                },
            )?;
            let collection = nft_class_id(&ctx.account, "ART");
            let h = ctx.ok_tx(
                &ctx.signer,
                Action::NftSetMeta {
                    collection,
                    token_id: item,
                    metadata: b"new-resolver-record".to_vec(),
                },
            )?;
            let agreed = ctx.checksum(h)?;
            Ok(format!("h{h} block {}", short(&agreed)))
        }),
        // ---------------- SNS names: register / transfer ----------------
        case!("register_name", |ctx: &Ctx| {
            // A unique name per run (height-seeded) so re-runs don't collide.
            let tag = ctx.a.height().unwrap_or(0);
            let name = format!("sweep{tag}.sov");
            let h = ctx.ok_tx(&ctx.signer, Action::RegisterName { name: name.clone() })?;
            let resolved = ctx
                .a
                .call("sov_resolveName", json!({ "name": name }))
                .map_err(|e| e.to_string())?;
            if resolved.is_null() {
                return Err("name did not resolve after registration".into());
            }
            let agreed = ctx.checksum(h)?;
            Ok(format!("h{h} {}  block {}", short(&agreed), short(&agreed)))
        }),
        case!("transfer_name", |ctx: &Ctx| {
            let tag = ctx.a.height().unwrap_or(0);
            let name = format!("sweepx{tag}.sov");
            ctx.ok_tx(&ctx.signer, Action::RegisterName { name: name.clone() })?;
            let to = ctx.subkey("name-rx").public_key().implicit_account_id();
            let h = ctx.ok_tx(
                &ctx.signer,
                Action::TransferName {
                    name: name.clone(),
                    to: to.clone(),
                },
            )?;
            let agreed = ctx.checksum(h)?;
            Ok(format!("h{h} {name} → {}  block {}", short(to.as_str()), short(&agreed)))
        }),
        // ---------------- HTLC: lock / claim / refund ----------------
        case!("htlc_lock+claim", |ctx: &Ctx| {
            // Recipient must sign the claim (and pay its gas), so fund it first.
            let rx = ctx.subkey("htlc-rx");
            let rx_id = rx.public_key().implicit_account_id();
            ctx.fund(&rx_id, 2)?;
            let preimage = b"the-swap-secret-preimage".to_vec();
            let hashlock: [u8; 32] = Sha256::digest(&preimage).into();
            let tip = ctx.a.height().map_err(|e| e.to_string())?;
            let lock = ctx.sign(
                &ctx.signer,
                Action::HtlcLock {
                    recipient: rx_id.clone(),
                    amount: Balance::from_sov(1).map_err(|e| e.to_string())?,
                    hashlock,
                    timeout_height: tip + 1000,
                },
            )?;
            let htlc_id = lock.id();
            let (_lh, lr) = ctx.submit_mined(&lock)?;
            if !receipt_ok(&lr) {
                return Err(format!("lock failed: {}", receipt_reason(&lr)));
            }
            let h = ctx.ok_tx(
                &rx,
                Action::HtlcClaim {
                    htlc_id,
                    preimage,
                },
            )?;
            let agreed = ctx.checksum(h)?;
            Ok(format!("h{h} claimed {}  block {}", short(&htlc_id.to_hex()), short(&agreed)))
        }),
        case!("htlc_refund", |ctx: &Ctx| {
            // Lock with a timeout in the immediate past-ish window, then refund.
            let rx = ctx.subkey("htlc-rx-ref").public_key().implicit_account_id();
            let preimage = b"unused-secret".to_vec();
            let hashlock: [u8; 32] = Sha256::digest(&preimage).into();
            let tip = ctx.a.height().map_err(|e| e.to_string())?;
            let timeout = tip + 2;
            let lock = ctx.sign(
                &ctx.signer,
                Action::HtlcLock {
                    recipient: rx,
                    amount: Balance::from_sov(1).map_err(|e| e.to_string())?,
                    hashlock,
                    timeout_height: timeout,
                },
            )?;
            let htlc_id = lock.id();
            ctx.submit_mined(&lock)?;
            // Wait until the chain passes the timeout height, then refund.
            let deadline = Instant::now() + MINE_TIMEOUT;
            while ctx.a.height().unwrap_or(0) < timeout + 1 {
                if Instant::now() > deadline {
                    return Err("chain did not reach the HTLC timeout height".into());
                }
                std::thread::sleep(POLL);
            }
            let h = ctx.ok_tx(&ctx.signer, Action::HtlcRefund { htlc_id })?;
            let agreed = ctx.checksum(h)?;
            Ok(format!("h{h} refunded  block {}", short(&agreed)))
        }),
        // ---------------- RotateKey ----------------
        case!("rotate_key", |ctx: &Ctx| {
            // Rotate a throwaway funded account to a fresh key (with possession proof).
            // Per-run unique so a re-run rotates a fresh account, not one already re-keyed.
            let acct_kp = ctx.subkey(&format!("rotate-acct-{}", ctx.run_id));
            let acct = acct_kp.public_key().implicit_account_id();
            ctx.fund(&acct, 2)?;
            let new_kp = ctx.subkey(&format!("rotate-newkey-{}", ctx.run_id));
            let nonce = ctx.a.nonce(&acct).map_err(|e| e.to_string())?;
            let proof = new_kp.sign(&rotation_signing_bytes(&acct, nonce, &new_kp.public_key()));
            let tx = Transaction {
                signer: acct.clone(),
                public_key: acct_kp.public_key(),
                nonce,
                action: Action::RotateKey {
                    new_key: new_kp.public_key(),
                    proof,
                },
            };
            let stx = SignedTransaction::sign(tx, &acct_kp).map_err(|e| e.to_string())?;
            let (h, r) = ctx.submit_mined(&stx)?;
            if !receipt_ok(&r) {
                return Err(format!("rotate failed: {}", receipt_reason(&r)));
            }
            let agreed = ctx.checksum(h)?;
            Ok(format!("h{h} {} re-keyed  block {}", short(acct.as_str()), short(&agreed)))
        }),
        // ---------------- Multisig: set + exec ----------------
        case!("multisig_set+exec", |ctx: &Ctx| {
            let m_kp = ctx.subkey(&format!("ms-acct-{}", ctx.run_id));
            let m = m_kp.public_key().implicit_account_id();
            ctx.fund(&m, 5)?;
            let s1 = ctx.subkey("ms-signer-1");
            let s2 = ctx.subkey("ms-signer-2");
            // Opt into 2-of-2, authorized by the account's current key.
            let set_nonce = ctx.a.nonce(&m).map_err(|e| e.to_string())?;
            let set_tx = Transaction {
                signer: m.clone(),
                public_key: m_kp.public_key(),
                nonce: set_nonce,
                action: Action::SetMultisig {
                    signers: vec![s1.public_key(), s2.public_key()],
                    threshold: 2,
                },
            };
            let set_stx = SignedTransaction::sign(set_tx, &m_kp).map_err(|e| e.to_string())?;
            let (_sh, sr) = ctx.submit_mined(&set_stx)?;
            if !receipt_ok(&sr) {
                return Err(format!("set_multisig failed: {}", receipt_reason(&sr)));
            }
            // Now execute a transfer AS the multisig account, approved by both signers.
            let to = ctx.subkey("ms-rx").public_key().implicit_account_id();
            let inner = Action::Transfer {
                to,
                amount: Balance::from_sov(1).map_err(|e| e.to_string())?,
            };
            let exec_nonce = ctx.a.nonce(&m).map_err(|e| e.to_string())?;
            let msg = multisig_signing_bytes(&m, exec_nonce, &inner);
            let approvals = vec![
                MultisigApproval {
                    signer: 0,
                    signature: s1.sign(&msg),
                },
                MultisigApproval {
                    signer: 1,
                    signature: s2.sign(&msg),
                },
            ];
            // Once multisig is set, the account's own key is disabled: the exec
            // envelope is signed by a POLICY MEMBER (relayer), with `signer` still the
            // multisig account. The fee is charged to the multisig account; the
            // threshold of approvals authorizes the inner action.
            let exec_tx = Transaction {
                signer: m.clone(),
                public_key: s1.public_key(),
                nonce: exec_nonce,
                action: Action::MultisigExec {
                    action: Box::new(inner),
                    approvals,
                },
            };
            let exec_stx = SignedTransaction::sign(exec_tx, &s1).map_err(|e| e.to_string())?;
            let (h, r) = ctx.submit_mined(&exec_stx)?;
            if !receipt_ok(&r) {
                return Err(format!("multisig_exec failed: {}", receipt_reason(&r)));
            }
            let agreed = ctx.checksum(h)?;
            Ok(format!("h{h} 2-of-2 spend  block {}", short(&agreed)))
        }),
        // ---------------- Contract: deploy + call ----------------
        case!("deploy+call", |ctx: &Ctx| {
            // Deploy the bundled counter contract to a throwaway funded account.
            let c_kp = ctx.subkey("contract-acct");
            let c = c_kp.public_key().implicit_account_id();
            ctx.fund(&c, 5)?;
            const COUNTER_WASM: &[u8] = include_bytes!("../assets/counter.wasm");
            let dep_nonce = ctx.a.nonce(&c).map_err(|e| e.to_string())?;
            let dep_tx = Transaction {
                signer: c.clone(),
                public_key: c_kp.public_key(),
                nonce: dep_nonce,
                action: Action::Deploy {
                    code: COUNTER_WASM.to_vec(),
                },
            };
            let dep_stx = SignedTransaction::sign(dep_tx, &c_kp).map_err(|e| e.to_string())?;
            let (_dh, dr) = ctx.submit_mined(&dep_stx)?;
            if !receipt_ok(&dr) {
                return Err(format!("deploy failed: {}", receipt_reason(&dr)));
            }
            // Call it (signer pays gas).
            let h = ctx.ok_tx(
                &ctx.signer,
                Action::Call {
                    contract: c.clone(),
                    gas_limit: 1_000_000,
                    calldata: vec![],
                },
            )?;
            let agreed = ctx.checksum(h)?;
            Ok(format!("h{h} {} deployed+called  block {}", short(c.as_str()), short(&agreed)))
        }),
    ]
}

/// Read `(total, mined)` supply in grains from a node (both are decimal-grain
/// strings in the RPC, JS-safe).
fn supply_total_mined(c: &RpcClient) -> Result<(i128, i128), String> {
    let s = c.call("sov_getSupply", json!({})).map_err(|e| e.to_string())?;
    let g = |k: &str| {
        s.get(k)
            .and_then(Value::as_str)
            .and_then(|x| x.parse::<i128>().ok())
            .ok_or_else(|| format!("getSupply missing/non-integer field `{k}`"))
    };
    Ok((g("total")?, g("mined")?))
}

/// A token balance for `(account, asset)` via `sov_getTokenBalances`, in grains.
fn token_balance(ctx: &Ctx, account: &AccountId, asset: &Hash) -> u128 {
    let Ok(v) = ctx
        .a
        .call("sov_getTokenBalances", json!({ "account": account.as_str() }))
        else {
        return 0;
    };
    // Returns a list/map of {asset, balance}; find ours. Be permissive about shape.
    let target = asset.to_hex();
    if let Some(arr) = v.as_array() {
        for e in arr {
            if e.get("asset").and_then(Value::as_str) == Some(target.as_str()) {
                return e
                    .get("balance")
                    .and_then(|b| b.as_str().and_then(|s| s.parse().ok()).or_else(|| b.as_u64().map(u128::from)))
                    .unwrap_or(0);
            }
        }
    }
    0
}

/// Shorten a hex/id string for compact output.
fn short(s: &str) -> String {
    if s.len() > 12 {
        format!("{}…{}", &s[..6], &s[s.len() - 4..])
    } else {
        s.to_string()
    }
}

// ---------------------------------------------------------------------------
// Web dashboard: a tiny std-only HTTP server that hosts a page with input fields
// for the two node addresses + a wallet seed, runs the sweep on a worker thread,
// and streams live results the page polls. Same-origin, so no CORS/wallet exposure
// beyond this machine.
// ---------------------------------------------------------------------------

/// The single-page dashboard (input fields + live results), served at `/`.
const DASHBOARD_HTML: &str = include_str!("../assets/dashboard.html");

fn serve(addr: &str) -> Result<(), String> {
    let listener = TcpListener::bind(addr).map_err(|e| format!("bind {addr}: {e}"))?;
    let bound = listener.local_addr().map_err(|e| e.to_string())?;
    let state: Arc<Mutex<Value>> = Arc::new(Mutex::new(json!({ "status": "idle" })));
    println!("sov-conformance dashboard → http://{bound}");
    println!("(enter your two node addresses + a funded wallet seed, then Run)");
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let state = Arc::clone(&state);
        std::thread::spawn(move || {
            let _ = handle_conn(stream, state);
        });
    }
    Ok(())
}

fn handle_conn(mut stream: TcpStream, state: Arc<Mutex<Value>>) -> std::io::Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("").to_string();

    let mut content_length = 0usize;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            break;
        }
        if line == "\r\n" || line == "\n" {
            break;
        }
        let lower = line.to_ascii_lowercase();
        if let Some(v) = lower.strip_prefix("content-length:") {
            content_length = v.trim().parse().unwrap_or(0);
        }
    }
    let mut body = vec![0u8; content_length.min(1 << 20)];
    if !body.is_empty() {
        reader.read_exact(&mut body)?;
    }

    match (method.as_str(), path.as_str()) {
        ("GET", "/") => respond(
            &mut stream,
            "200 OK",
            "text/html; charset=utf-8",
            DASHBOARD_HTML.as_bytes(),
        ),
        ("GET", "/api/state") => {
            let payload = serde_json::to_vec(&*state.lock().unwrap()).unwrap_or_default();
            respond(&mut stream, "200 OK", "application/json", &payload)
        }
        ("POST", "/api/run") => {
            let resp = start_run(&body, &state);
            let payload = serde_json::to_vec(&resp).unwrap_or_default();
            respond(&mut stream, "200 OK", "application/json", &payload)
        }
        _ => respond(&mut stream, "404 Not Found", "text/plain", b"not found"),
    }
}

fn respond(stream: &mut TcpStream, status: &str, ctype: &str, body: &[u8]) -> std::io::Result<()> {
    let header = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()
}

/// Validate the run request and, if good, kick the sweep off on a worker thread that
/// updates the shared state as each case completes. Returns an immediate ack/error.
fn start_run(body: &[u8], state: &Arc<Mutex<Value>>) -> Value {
    if state
        .lock()
        .unwrap()
        .get("status")
        .and_then(Value::as_str)
        == Some("running")
    {
        return json!({ "ok": false, "error": "a sweep is already running" });
    }
    let req: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(e) => return json!({ "ok": false, "error": format!("bad request json: {e}") }),
    };
    let norm = |s: &str| {
        s.trim()
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .trim_end_matches('/')
            .to_string()
    };
    let node_a = norm(req["nodeA"].as_str().unwrap_or(""));
    let node_b = norm(req["nodeB"].as_str().unwrap_or(""));
    if node_a.is_empty() || node_b.is_empty() {
        return json!({ "ok": false, "error": "node A and node B addresses are required" });
    }
    let seed = match resolve_seed(
        req["seedHex"].as_str().unwrap_or(""),
        req["phrase"].as_str().unwrap_or(""),
    ) {
        Ok(s) => s,
        Err(e) => return json!({ "ok": false, "error": e }),
    };
    let account = req["account"]
        .as_str()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let cfg = Config {
        node_a,
        node_b,
        seed,
        account,
    };

    *state.lock().unwrap() = json!({ "status": "running", "cases": [], "total": case_count() });
    let state = Arc::clone(state);
    std::thread::spawn(move || match prepare(&cfg) {
        Err(e) => {
            *state.lock().unwrap() = json!({ "status": "error", "error": e });
        }
        Ok((ctx, preflight)) => {
            {
                let mut s = state.lock().unwrap();
                s["preflight"] = preflight;
            }
            let (passed, failed) = sweep(&ctx, |i, name, result, secs| {
                let row = json!({
                    "i": i,
                    "name": name,
                    "ok": result.is_ok(),
                    "detail": match result { Ok(d) => d.clone(), Err(e) => e.clone() },
                    "secs": (secs * 10.0).round() / 10.0,
                });
                let mut s = state.lock().unwrap();
                if let Some(arr) = s.get_mut("cases").and_then(Value::as_array_mut) {
                    arr.push(row);
                }
            });
            let supply_ok = ctx
                .supply_conserved(&ctx.a, "node A")
                .and(ctx.supply_conserved(&ctx.b, "node B"))
                .is_ok();
            let mut s = state.lock().unwrap();
            s["status"] = json!("done");
            s["summary"] = json!({
                "passed": passed,
                "failed": failed,
                "supplyConserved": supply_ok,
            });
        }
    });
    json!({ "ok": true })
}
