//! The W8 lifecycle matrix (S8b, achievable-now subset) — every step ASSERTS
//! against live nodes; steps that need later program slices are explicit SKIPs
//! stating exactly what they wait on. No fixed-sleep correctness anywhere:
//! every wait polls an observed condition under a bounded deadline.

use std::path::PathBuf;
use std::time::Duration;

use serde_json::{json, Value};

use crate::backend::Backend;
use crate::net::{
    Net, CHAIN_ID, EXPECTED_GENESIS_HASH, GAS_PRICE_GRAINS, GRAINS_PER_XUS, MAINNET_GENESIS_HASH,
    TESTNET1_GENESIS_HASH,
};
use crate::report::StepResult;
use crate::rpc::{grains_of, receipt_succeeded, Rpc};
use crate::util::{labeled_value, parse_tx_id, poll, run_cmd_timeout};

/// Confirmation depth used when comparing chains across nodes: digests are
/// compared `DEPTH` below the lowest tip, so a momentary tip race (two miners
/// sealing within propagation time) never fails an assertion that consensus
/// itself resolves a block later.
const DEPTH: u64 = 2;

/// The `tx-domain` deployment the E2E rehearsal namespace bakes (see
/// `e2e_rehearsal_deployments()` in `chain/crates/rpc/src/daemon.rs`). PINNED
/// here too so a silent drift in the node's preset fails this step loudly
/// instead of quietly re-timing the activation the matrix depends on.
const ACT_DEPLOYMENT: &str = "tx-domain";
/// Signaling bit the rehearsal deployment uses (mirrors mainnet's bit 0).
const ACT_BIT: u64 = 0;
/// Signaling window length, in blocks.
const ACT_PERIOD: u64 = 32;
/// First window boundary at which signaling may begin (`Defined → Started`).
const ACT_START_HEIGHT: u64 = 384;
/// Threshold: `num`/`den` of a window must signal for lock-in (9/10, as mainnet).
const ACT_THRESHOLD_NUM: u64 = 9;
/// Denominator of [`ACT_THRESHOLD_NUM`].
const ACT_THRESHOLD_DEN: u64 = 10;
/// Whole XUS shielded by the never-stranded step before activation, then
/// de-shielded in full after it.
const STRANDED_TEST_XUS: u128 = 4;

/// Shared context the matrix threads through the steps.
pub struct Ctx<'a> {
    pub backend: &'a mut dyn Backend,
    pub net: &'a Net,
    pub rpcd: PathBuf,
    pub wallet: PathBuf,
    /// Names of the nodes currently expected to be RUNNING (node-5 joins late).
    pub running: Vec<String>,
}

impl Ctx<'_> {
    fn rpc(&self, name: &str) -> Rpc {
        Rpc::new(self.net.plan(name).rpc.clone())
    }
    fn running_rpcs(&self) -> Vec<(String, Rpc)> {
        self.running
            .iter()
            .map(|n| (n.clone(), self.rpc(n)))
            .collect()
    }
}

/// Run the full matrix in order. A hard FAIL aborts the chain-dependent steps
/// that follow (each recorded as a skip naming the aborted dependency — never a
/// silent pass); the always-skipped future-slice steps keep their real reasons.
pub fn run_matrix(ctx: &mut Ctx) -> Vec<StepResult> {
    let mut out: Vec<StepResult> = Vec::new();
    let mut aborted: Option<&'static str> = None;

    type StepFn = fn(&mut Ctx) -> Result<(String, Value), String>;
    let live_steps: [(&'static str, StepFn); 8] = [
        ("genesis-determinism", step_genesis),
        ("p2p-mesh-and-late-join-sync", step_mesh_and_late_join),
        ("mining-block-production", step_mining),
        // Shields BEFORE the activation window opens, drives the deployment all
        // the way to Active, cold-boots a node, and only then spends the note.
        ("shielded-v1-never-stranded", step_never_stranded),
        // Audits, post-hoc and race-free, the activation the step above drove.
        ("bip9-activation-rehearsal", step_bip9_activation),
        ("shielded-v1-lifecycle", step_shielded_lifecycle),
        ("restart-replay-survival", step_restart_replay),
        ("cross-node-conformance", step_conformance),
    ];
    for (name, f) in live_steps {
        if let Some(failed) = aborted {
            out.push(StepResult::skip(
                name,
                format!("not run: aborted after `{failed}` failed"),
                json!({ "aborted_by": failed }),
            ));
            continue;
        }
        println!("--- step: {name}");
        match f(ctx) {
            Ok((detail, evidence)) => {
                println!("    PASS: {detail}");
                out.push(StepResult::pass(name, detail, evidence));
            }
            Err(e) => {
                println!("    FAIL: {e}");
                out.push(StepResult::fail(name, e, json!({})));
                aborted = Some(name);
            }
        }
    }

    // Steps that CANNOT exist yet — explicit, precise skips (never silent).
    out.push(never_stranded_v2_skip(ctx));
    for (name, what) in [
        (
            "shield-v2",
            "a real STARK-proved v2 shield mined into pool-v2",
        ),
        (
            "z-send-v2",
            "a private v2 transfer with recipient note scan",
        ),
        ("unshield-v2", "a v2 de-shield under the drain limiter"),
        ("v1-to-v2-migration", "the v1→v2 migration flow end-to-end"),
        (
            "reorg-with-v2-state",
            "a forced reorg across a v2 tx (nullifier + turnstile survival)",
        ),
    ] {
        out.push(StepResult::skip(
            name,
            format!(
                "waits on W2 (consensus wiring: `Action::ShieldedV2`, pool-v2 state, v2 \
                 verifier gated behind the bit-2 deployment) — {what} cannot exist until \
                 that slice lands; v0.1.99-era binaries have no v2 action to submit"
            ),
            json!({ "waits_on": "v0.2.0 program W2 (S2a-S2f)" }),
        ));
    }
    out
}

// ---------------------------------------------------------------------------
// 1. genesis determinism
// ---------------------------------------------------------------------------

fn step_genesis(ctx: &mut Ctx) -> Result<(String, Value), String> {
    let nodes = ctx.running_rpcs();
    let mut per_node = serde_json::Map::new();
    let mut genesis: Option<String> = None;
    for (name, rpc) in &nodes {
        // Nodes were health-checked at start; genesis is present from block 0.
        let digest = rpc
            .digest(0)?
            .ok_or_else(|| format!("{name}: no genesis digest"))?;
        // Normalize to bare hex: the RPC serializes hashes `0x…`-prefixed,
        // while the frozen pins are `Hash::to_hex` (bare) form.
        let hash = digest
            .get("hash")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("{name}: genesis digest lacks `hash`"))?
            .trim_start_matches("0x")
            .to_string();
        let chain_id = rpc.chain_id()?;
        if chain_id != CHAIN_ID {
            return Err(format!(
                "{name}: chain id `{chain_id}` != pinned `{CHAIN_ID}`"
            ));
        }
        match &genesis {
            None => genesis = Some(hash.clone()),
            Some(g) if *g != hash => {
                return Err(format!(
                    "genesis mismatch: {name} has {hash}, first node has {g}"
                ))
            }
            _ => {}
        }
        per_node.insert(name.clone(), json!(hash));
    }
    let genesis = genesis.ok_or("no nodes to check")?;

    // ISOLATION: this must NOT be mainnet's (or testnet-1's) frozen identity.
    if genesis == MAINNET_GENESIS_HASH {
        return Err(
            "genesis equals the frozen MAINNET hash — the harness refused (never touch mainnet)"
                .into(),
        );
    }
    if genesis == TESTNET1_GENESIS_HASH {
        return Err("genesis equals the frozen testnet-1 hash — the harness refused".into());
    }
    // REPRODUCIBILITY: the pinned spec must reproduce the pinned hash.
    if EXPECTED_GENESIS_HASH.is_empty() {
        return Err(format!(
            "EXPECTED_GENESIS_HASH is not pinned yet — observed {genesis}; pin it in \
             tools/e2e-vm/src/net.rs and re-run (an unpinned harness must not pass)"
        ));
    }
    if genesis != EXPECTED_GENESIS_HASH {
        return Err(format!(
            "genesis {genesis} != pinned {EXPECTED_GENESIS_HASH} — consensus genesis \
             bytes drifted; investigate before trusting anything else"
        ));
    }
    Ok((
        format!(
            "{} nodes agree on genesis {genesis} (≠ mainnet, ≠ testnet-1, == pin)",
            nodes.len()
        ),
        json!({
            "genesis_hash": genesis,
            "pinned": EXPECTED_GENESIS_HASH,
            "mainnet_pin_differs": true,
            "per_node": per_node,
        }),
    ))
}

// ---------------------------------------------------------------------------
// 2. P2P mesh + late-join sync
// ---------------------------------------------------------------------------

fn step_mesh_and_late_join(ctx: &mut Ctx) -> Result<(String, Value), String> {
    let nodes = ctx.running_rpcs();
    // Every initial node authenticates at least one peer.
    let mut links = serde_json::Map::new();
    for (name, rpc) in &nodes {
        let info = poll(
            &format!("{name} to authenticate a peer"),
            Duration::from_secs(90),
            Duration::from_millis(500),
            || {
                let info = rpc.peer_info()?;
                let tcp = info.get("tcpLinks").and_then(Value::as_u64).unwrap_or(0);
                let peers = info.get("peers").and_then(Value::as_u64).unwrap_or(0);
                Ok((tcp >= 1 && peers >= 1).then_some(info))
            },
        )?;
        links.insert(
            name.clone(),
            json!({
                "tcpLinks": info.get("tcpLinks"),
                "peers": info.get("peers"),
            }),
        );
    }
    // Heights converge on one chain.
    let (h, digest) = converged(&nodes, 3, Duration::from_secs(120))?;

    // Late joiner: give the chain some depth first, then start node-5 and
    // require it to sync to (and past) the tip it was born behind.
    let tip0 = poll(
        "chain to reach height 8 before the late join",
        Duration::from_secs(120),
        Duration::from_millis(500),
        || {
            let h = min_height(&nodes)?;
            Ok((h >= 8).then_some(h))
        },
    )?;
    let plan5 = ctx.net.plan("node-5").clone();
    ctx.backend.start(&plan5, &ctx.rpcd)?;
    ctx.running.push("node-5".to_string());
    let rpc5 = ctx.rpc("node-5");
    poll(
        "node-5 RPC to come up",
        Duration::from_secs(60),
        Duration::from_millis(300),
        || Ok(rpc5.healthy().then_some(())),
    )?;
    let synced_h = poll(
        &format!("node-5 to sync past the join-time tip {tip0}"),
        Duration::from_secs(180),
        Duration::from_millis(500),
        || {
            let h5 = rpc5.height()?;
            Ok((h5 >= tip0).then_some(h5))
        },
    )?;
    // And its chain is THE chain: digest agreement with node-1 below the tip.
    let ref_rpc = ctx.rpc("node-1");
    let check_h = tip0.saturating_sub(DEPTH);
    let d5 = rpc5
        .digest(check_h)?
        .ok_or(format!("node-5 lacks block {check_h} after sync"))?;
    let d1 = ref_rpc
        .digest(check_h)?
        .ok_or(format!("node-1 lacks block {check_h}"))?;
    if d5.get("hash") != d1.get("hash") {
        return Err(format!(
            "late joiner forked: node-5 block {check_h} = {:?}, node-1 = {:?}",
            d5.get("hash"),
            d1.get("hash")
        ));
    }
    Ok((
        format!(
            "4-node mesh authed; converged at height {h}; late joiner synced 0→{synced_h} \
             and agrees at height {check_h}"
        ),
        json!({
            "links": links,
            "converged_height": h,
            "converged_hash": digest.get("hash"),
            "late_join_tip_at_start": tip0,
            "late_join_synced_to": synced_h,
            "late_join_agreement_height": check_h,
        }),
    ))
}

// ---------------------------------------------------------------------------
// 3. mining + block production
// ---------------------------------------------------------------------------

fn step_mining(ctx: &mut Ctx) -> Result<(String, Value), String> {
    let nodes = ctx.running_rpcs();
    let h0 = min_height(&nodes)?;
    let target = h0 + 10;
    poll(
        &format!("all nodes to advance from {h0} to {target}"),
        Duration::from_secs(180),
        Duration::from_millis(500),
        || {
            let h = min_height(&nodes)?;
            Ok((h >= target).then_some(h))
        },
    )?;
    // ≥3 distinct miners must have produced blocks (real multi-miner PoW, not
    // one node's private chain). The coinbase recipient in each digest is the
    // authoritative producer record.
    let ref_rpc = ctx.rpc("node-1");
    let miners = poll(
        "three distinct miners to appear in coinbases",
        Duration::from_secs(300),
        Duration::from_secs(1),
        || {
            let tip = ref_rpc.height()?;
            let mut seen = std::collections::BTreeSet::new();
            for h in 1..=tip {
                if let Some(d) = ref_rpc.digest(h)? {
                    if let Some(acct) = d
                        .pointer("/coinbase/recipients/0/account")
                        .and_then(Value::as_str)
                    {
                        seen.insert(acct.to_string());
                    }
                }
                if seen.len() >= 3 {
                    break;
                }
            }
            if seen.len() >= 3 {
                Ok(Some(seen))
            } else {
                Err(format!(
                    "only {} distinct producer(s) so far: {seen:?}",
                    seen.len()
                ))
            }
        },
    )?;
    // Everyone still agrees on one chain after the advance.
    let (h, digest) = converged(&nodes, target, Duration::from_secs(120))?;
    let difficulty = ref_rpc.difficulty()?;
    Ok((
        format!(
            "chain advanced {h0}→≥{target} under real PoW; {} distinct miners; all {} nodes \
             agree at height {h}",
            miners.len(),
            nodes.len()
        ),
        json!({
            "from_height": h0,
            "reached_height": target,
            "distinct_miners": miners,
            "agreed_height": h,
            "agreed_hash": digest.get("hash"),
            "difficulty": difficulty,
        }),
    ))
}

// ---------------------------------------------------------------------------
// 4. shielded (Orchard/v1) lifecycle — via the real sov-wallet CLI
// ---------------------------------------------------------------------------

fn step_shielded_lifecycle(ctx: &mut Ctx) -> Result<(String, Value), String> {
    let obs = ctx.rpc("node-4"); // all reads + wallet submissions go through the observer
    let val01 = ctx.net.key("val01.e2e.sov").clone();
    let user1 = ctx.net.key("user1.e2e.sov").clone();
    let user2 = ctx.net.key("user2.e2e.sov").clone();
    let obs_addr = obs.addr.clone();
    let xus = |n: u128| n * GRAINS_PER_XUS;

    // The pool must start EMPTY — nothing has ever shielded on this chain.
    let pool0 = obs.pool_grains()?;
    if pool0 != 0 {
        return Err(format!("shielded pool started non-empty: {pool0} grains"));
    }

    // Wait for the miner to have MINED spendable coins (no pre-mine: this is
    // real emission — 12.5 XUS/block to the producer).
    poll(
        "val01 to hold ≥ 10 mined XUS",
        Duration::from_secs(240),
        Duration::from_secs(1),
        || {
            let b = obs.balance_grains("val01.e2e.sov")?;
            Ok((b >= xus(10)).then_some(b))
        },
    )?;

    // (a) Fund user1's transparent account (fee headroom for its carrier txs).
    // The recipient is credited EXACTLY the amount (the sender pays the fee).
    let fund = wallet(
        ctx,
        &obs_addr,
        &[
            "transfer",
            &val01.seed_hex,
            "val01.e2e.sov",
            "user1.e2e.sov",
            "3",
        ],
    )?;
    let fund_tx = parse_tx_id(&fund).ok_or("no tx id in transfer output")?;
    await_success(&obs, &fund_tx, "funding transfer", Duration::from_secs(90))?;
    poll_balance_eq(&obs, "user1.e2e.sov", xus(3), Duration::from_secs(60))?;

    // (b) SHIELD: transparent val01 → user1's xus1… address, 5 XUS. The CLI
    // builds a REAL Halo2 proof; the node verifies it in consensus.
    let shield = wallet(
        ctx,
        &obs_addr,
        &[
            "transfer",
            &val01.seed_hex,
            "val01.e2e.sov",
            &user1.shielded_addr,
            "5",
        ],
    )?;
    let shield_tx = parse_tx_id(&shield).ok_or("no tx id in shield output")?;
    let shield_rcpt = await_success(&obs, &shield_tx, "shield", Duration::from_secs(180))?;
    poll_pool_eq(&obs, xus(5), "pool after shield", Duration::from_secs(60))?;
    let zb1 = zbalance(ctx, &obs_addr, &user1.seed_hex)?;
    if zb1 != ("5".to_string(), 1) {
        return Err(format!(
            "user1 z-balance after shield: expected (5 XUS, 1 note), got {zb1:?}"
        ));
    }

    // (c) UNSHIELD 2 XUS back to user1's transparent account. Exact-delta law:
    // credited amount minus the real on-chain fee (receipt gas × pinned
    // mainnet-like gas price) — computed from the chain, not assumed.
    let bal_before_unshield = obs.balance_grains("user1.e2e.sov")?;
    let unshield = wallet(
        ctx,
        &obs_addr,
        &["unshield", &user1.seed_hex, "user1.e2e.sov", "2"],
    )?;
    let unshield_tx = parse_tx_id(&unshield).ok_or("no tx id in unshield output")?;
    let unshield_rcpt = await_success(&obs, &unshield_tx, "unshield", Duration::from_secs(180))?;
    let g1 = gas_used(&unshield_rcpt)?;
    poll_pool_eq(&obs, xus(3), "pool after unshield", Duration::from_secs(60))?;
    let expect_after_unshield = bal_before_unshield + xus(2) - GAS_PRICE_GRAINS * u128::from(g1);
    poll_balance_eq(
        &obs,
        "user1.e2e.sov",
        expect_after_unshield,
        Duration::from_secs(60),
    )?;
    let zb2 = zbalance(ctx, &obs_addr, &user1.seed_hex)?;
    if zb2 != ("3".to_string(), 1) {
        return Err(format!(
            "user1 z-balance after unshield: expected (3 XUS, 1 change note), got {zb2:?}"
        ));
    }

    // (d) Z-SEND 1 XUS fully privately user1 → user2. Pool value must NOT move
    // (value stays inside the pool); only the carrier fee touches transparent.
    let bal_before_zsend = obs.balance_grains("user1.e2e.sov")?;
    let zsend = wallet(
        ctx,
        &obs_addr,
        &[
            "z-send",
            &user1.seed_hex,
            &user2.shielded_addr,
            "1",
            "--signer",
            "user1.e2e.sov",
        ],
    )?;
    let zsend_tx = parse_tx_id(&zsend).ok_or("no tx id in z-send output")?;
    let zsend_rcpt = await_success(&obs, &zsend_tx, "z-send", Duration::from_secs(180))?;
    let g2 = gas_used(&zsend_rcpt)?;
    let pool_after = obs.pool_grains()?;
    if pool_after != xus(3) {
        return Err(format!("pool moved on a z-send: {pool_after} grains != {} (private transfers must not change pool value)", xus(3)));
    }
    let expect_after_zsend = bal_before_zsend - GAS_PRICE_GRAINS * u128::from(g2);
    poll_balance_eq(
        &obs,
        "user1.e2e.sov",
        expect_after_zsend,
        Duration::from_secs(60),
    )?;
    let zb3 = zbalance(ctx, &obs_addr, &user1.seed_hex)?;
    if zb3 != ("2".to_string(), 1) {
        return Err(format!(
            "user1 z-balance after z-send: expected (2 XUS, 1 note), got {zb3:?}"
        ));
    }
    let zb4 = zbalance(ctx, &obs_addr, &user2.seed_hex)?;
    if zb4 != ("1".to_string(), 1) {
        return Err(format!(
            "user2 z-balance after z-send: expected (1 XUS, 1 note), got {zb4:?}"
        ));
    }

    Ok((
        "shield 5 → z-balance 5 → unshield 2 → z-send 1: every pool/balance delta exact; \
         recipient notes appear, spent notes drop"
            .to_string(),
        json!({
            "fund_tx": fund_tx,
            "shield_tx": shield_tx, "shield_gas": gas_used(&shield_rcpt)?,
            "unshield_tx": unshield_tx, "unshield_gas": g1,
            "zsend_tx": zsend_tx, "zsend_gas": g2,
            "pool_grains_trajectory": [0, xus(5).to_string(), xus(3).to_string(), xus(3).to_string()],
            "user1_transparent_after_unshield_grains": expect_after_unshield.to_string(),
            "user1_transparent_after_zsend_grains": expect_after_zsend.to_string(),
            "user1_notes": { "after_shield": "5 XUS × 1", "after_unshield": "3 XUS × 1", "after_zsend": "2 XUS × 1" },
            "user2_notes": { "after_zsend": "1 XUS × 1" },
        }),
    ))
}

// ---------------------------------------------------------------------------
// 5. restart / replay survival (the v0.1.99 boot-order lesson, live)
// ---------------------------------------------------------------------------

fn step_restart_replay(ctx: &mut Ctx) -> Result<(String, Value), String> {
    // Kill (SIGKILL — an UNCLEAN exit on purpose), delete the snapshot, and
    // require the log alone to reproduce the state on cold boot.
    let mut evidence = cold_boot_observer(ctx)?;
    let hpin = evidence
        .get("pinned_height")
        .and_then(Value::as_u64)
        .expect("cold_boot_observer records the pinned height");
    let h4 = evidence
        .get("pre_kill_height")
        .and_then(Value::as_u64)
        .expect("cold_boot_observer records the pre-kill height");
    let ref_hash = evidence
        .get("pinned_hash")
        .cloned()
        .expect("cold_boot_observer records the pinned hash");

    // And it rejoins the LIVE network: converges with everyone at the current tip.
    let nodes = ctx.running_rpcs();
    let (hc, _d) = converged(&nodes, h4, Duration::from_secs(180))?;
    // Cross-check the reference against another node too (the victim did not
    // define truth for the network).
    let d1 = ctx
        .rpc("node-1")
        .digest(hpin)?
        .ok_or(format!("node-1 lacks block {hpin}"))?;
    if d1.get("hash") != Some(&ref_hash) {
        return Err(format!(
            "node-1 disagrees with the pre-kill reference at {hpin}"
        ));
    }
    if let Value::Object(map) = &mut evidence {
        map.insert("reconverged_height".into(), json!(hc));
    }
    Ok((
        format!(
            "killed node-4 (SIGKILL), deleted its snapshot; cold boot replayed the log and \
             reproduced block {hpin} (hash + state root), then reconverged at height {hc}"
        ),
        evidence,
    ))
}

// ---------------------------------------------------------------------------
// 6. cross-node conformance
// ---------------------------------------------------------------------------

fn step_conformance(ctx: &mut Ctx) -> Result<(String, Value), String> {
    let nodes = ctx.running_rpcs();
    let tip = min_height(&nodes)?;
    if tip < 8 {
        return Err(format!(
            "chain too short for conformance sampling (tip {tip})"
        ));
    }
    // Sampled heights across the whole history, deduped, all below the tip race
    // zone. Block hash commits to txs, receipts, AND state root, so per-height
    // hash agreement is cryptographic proof of identical state computation.
    let mut samples: Vec<u64> = vec![1, tip / 4, tip / 2, (3 * tip) / 4, tip - DEPTH];
    samples.sort_unstable();
    samples.dedup();
    let mut sampled = Vec::new();
    for h in &samples {
        let mut first: Option<(Value, Value)> = None;
        for (name, rpc) in &nodes {
            let d = rpc.digest(*h)?.ok_or(format!("{name} lacks block {h}"))?;
            let pair = (
                d.get("hash").cloned().unwrap_or(Value::Null),
                d.get("stateRoot").cloned().unwrap_or(Value::Null),
            );
            match &first {
                None => first = Some(pair),
                Some(f) if *f != pair => {
                    return Err(format!(
                        "conformance split at height {h}: {name} reports {:?}, first node {:?}",
                        pair, f
                    ))
                }
                _ => {}
            }
        }
        let (hash, root) = first.expect("at least one node");
        sampled.push(json!({ "height": h, "hash": hash, "stateRoot": root }));
    }

    // Supply: sampled when all tips ALIGN on a height (bounded retries — at a
    // 2s cadence alignment recurs constantly). On an aligned height, all nodes
    // must report the identical supply object; total must equal mined (no
    // pre-mine — conservation), and the shielded fraction must equal the pool
    // the lifecycle left behind (3 XUS).
    let expected_pool = (3 * GRAINS_PER_XUS).to_string();
    let mut aligned: Option<(u64, Value)> = None;
    for _ in 0..150 {
        let mut heights = Vec::new();
        let mut supplies = Vec::new();
        for (_, rpc) in &nodes {
            heights.push(rpc.height()?);
            supplies.push(rpc.supply()?);
        }
        if heights.windows(2).all(|w| w[0] == w[1]) {
            let h = heights[0];
            if supplies.windows(2).any(|w| w[0] != w[1]) {
                return Err(format!(
                    "supply DIVERGED at aligned height {h}: {supplies:?}"
                ));
            }
            aligned = Some((h, supplies.remove(0)));
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    let (h_aligned, supply) =
        aligned.ok_or("tips never aligned across 150 samples — cadence anomaly, investigate")?;
    let total = supply
        .get("total")
        .and_then(grains_of)
        .ok_or("supply lacks total")?;
    let mined = supply
        .get("mined")
        .and_then(grains_of)
        .ok_or("supply lacks mined")?;
    if total != mined {
        return Err(format!(
            "conservation violated: total {total} != mined {mined} on a no-pre-mine chain"
        ));
    }
    let shielded = supply
        .get("shielded")
        .and_then(grains_of)
        .ok_or("supply lacks shielded")?;
    if shielded.to_string() != expected_pool {
        return Err(format!(
            "shielded supply {shielded} != expected pool {expected_pool} grains"
        ));
    }
    Ok((
        format!(
            "{} nodes agree on hash+stateRoot at heights {:?}; supply identical at aligned \
             height {h_aligned} (total==mined=={total}, shielded=={shielded})",
            nodes.len(),
            samples
        ),
        json!({
            "sampled": sampled,
            "aligned_height": h_aligned,
            "supply": supply,
        }),
    ))
}

// ---------------------------------------------------------------------------
// 4. shielded-v1 NEVER STRANDED — value survives a real activation boundary
// ---------------------------------------------------------------------------

/// **"Old shielded notes better not be stuck. Nothing ever better get stuck."**
///
/// The proof, on the harness's own isolated chain, in one self-contained step:
///
/// 1. the shielded pool is EMPTY and the `tx-domain` deployment is genuinely
///    pre-activation (`Defined`/`Started`, signing domain inactive);
/// 2. shield [`STRANDED_TEST_XUS`] into pool v1 (Orchard) — pool delta EXACT,
///    and the shield is mined strictly BELOW the signaling start height, so the
///    note provably predates the fork;
/// 3. the deployment is driven to `Active` by REAL miner signaling (no stub, no
///    simulation) — the same BIP-9 machinery mainnet used at h11520;
/// 4. the observer node is SIGKILLed, its snapshot deleted, and cold-booted from
///    `blocks.log` alone: the pre-activation note must survive the replay (pool
///    value exact, head hash + state root reproduced, note still scannable);
/// 5. only THEN is the note spent — under the post-activation `Bound` signature
///    regime — and it must work: exact pool delta, exact transparent credit, the
///    note's nullifier published (so the wallet sees zero unspent notes), a
///    second spend of the same note REFUSED, and supply conservation intact.
///
/// Every wait polls observed chain state under a bounded deadline; nothing here
/// sleeps for correctness.
fn step_never_stranded(ctx: &mut Ctx) -> Result<(String, Value), String> {
    let obs = ctx.rpc("node-4");
    let obs_addr = obs.addr.clone();
    let val01 = ctx.net.key("val01.e2e.sov").clone();
    let user2 = ctx.net.key("user2.e2e.sov").clone();
    let xus = |n: u128| n * GRAINS_PER_XUS;
    let amount = STRANDED_TEST_XUS;

    // -- (0) PRE-ACTIVATION PRECONDITIONS --------------------------------------
    // The deployment must exist (the rehearsal preset) and must NOT have locked
    // in or activated yet, or "pre-activation note" would be a lie.
    let dep0 = tx_domain_deployment(&obs)?;
    check_deployment_params(&dep0)?;
    let state0 = deployment_state(&dep0)?;
    if state0 != "Defined" && state0 != "Started" {
        return Err(format!(
            "`{ACT_DEPLOYMENT}` is already `{state0}` at the start of this step — the shield \
             below would NOT predate activation. The harness must reach this step before \
             height {}; raise E2E_REHEARSAL_START_HEIGHT in chain/crates/rpc/src/daemon.rs \
             (the earlier steps got slower).",
            ACT_START_HEIGHT + 2 * ACT_PERIOD
        ));
    }
    let domain0 = obs.signing_domain()?;
    if domain0.get("active").and_then(Value::as_bool) != Some(false) {
        return Err(format!(
            "signing domain is already active before the fork: {domain0}"
        ));
    }
    let pool0 = obs.pool_grains()?;
    if pool0 != 0 {
        return Err(format!("shielded pool started non-empty: {pool0} grains"));
    }

    // -- (1) SHIELD, PRE-ACTIVATION -------------------------------------------
    poll(
        "val01 to hold ≥ 10 mined XUS",
        Duration::from_secs(240),
        Duration::from_secs(1),
        || {
            let b = obs.balance_grains("val01.e2e.sov")?;
            Ok((b >= xus(10)).then_some(b))
        },
    )?;
    // Fee headroom for the post-activation carrier transaction.
    let fund = wallet(
        ctx,
        &obs_addr,
        &[
            "transfer",
            &val01.seed_hex,
            "val01.e2e.sov",
            "user2.e2e.sov",
            "3",
        ],
    )?;
    let fund_tx = parse_tx_id(&fund).ok_or("no tx id in funding transfer output")?;
    await_success(&obs, &fund_tx, "funding transfer", Duration::from_secs(120))?;
    poll_balance_eq(&obs, "user2.e2e.sov", xus(3), Duration::from_secs(90))?;

    let shield = wallet(
        ctx,
        &obs_addr,
        &[
            "transfer",
            &val01.seed_hex,
            "val01.e2e.sov",
            &user2.shielded_addr,
            &amount.to_string(),
        ],
    )?;
    let shield_tx = parse_tx_id(&shield).ok_or("no tx id in shield output")?;
    let shield_rcpt = await_success(&obs, &shield_tx, "shield", Duration::from_secs(300))?;
    let shield_height = shield_rcpt
        .get("height")
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("shield receipt lacks `height`: {shield_rcpt}"))?;
    // EXACT pool delta — the pool was 0, it must now be exactly the shield.
    poll_pool_eq(
        &obs,
        xus(amount),
        "pool after the pre-activation shield",
        Duration::from_secs(90),
    )?;
    let zb_shield = zbalance(ctx, &obs_addr, &user2.seed_hex)?;
    if zb_shield != (amount.to_string(), 1) {
        return Err(format!(
            "z-balance after the pre-activation shield: expected ({amount} XUS, 1 note), got \
             {zb_shield:?}"
        ));
    }
    // The note provably PREDATES the fork, on BOTH counts:
    //   * it was mined strictly below the activation height, and
    //   * the deployment had not activated at any point up to now (Active is
    //     terminal, so "not Active now" proves "not Active when it was mined").
    let activation_height = ACT_START_HEIGHT + 2 * ACT_PERIOD;
    let state_after_shield = deployment_state(&tx_domain_deployment(&obs)?)?;
    if state_after_shield == "Active" {
        return Err(format!(
            "`{ACT_DEPLOYMENT}` was already Active by the time the shield was mined (height \
             {shield_height}) — this step can no longer prove the note predates activation. \
             Raise E2E_REHEARSAL_START_HEIGHT in chain/crates/rpc/src/daemon.rs (and \
             ACT_START_HEIGHT here) so the shield finishes well below it."
        ));
    }
    if shield_height >= activation_height {
        return Err(format!(
            "the shield landed at height {shield_height}, at/after the activation height \
             {activation_height} — the note does not predate the fork. Raise \
             E2E_REHEARSAL_START_HEIGHT in chain/crates/rpc/src/daemon.rs (and \
             ACT_START_HEIGHT here)."
        ));
    }

    // -- (2) DRIVE THE ACTIVATION (real signaling, no simulation) --------------
    let (trace, activation) = drive_activation_to_active(&obs)?;

    // -- (3) COLD BOOT: the note must survive a replay from the LOG ------------
    let replay = cold_boot_observer(ctx)?;
    // After the cold boot the pool value must be UNCHANGED and exact.
    let pool_after_replay = obs.pool_grains()?;
    if pool_after_replay != xus(amount) {
        return Err(format!(
            "pool value changed across the cold boot: {pool_after_replay} grains != {} — a \
             replayed node disagrees with the pre-kill chain about shielded value",
            xus(amount)
        ));
    }
    // And the note is still THERE, scanned out of the cold-booted node's chain.
    let zb_replay = zbalance(ctx, &obs_addr, &user2.seed_hex)?;
    if zb_replay != (amount.to_string(), 1) {
        return Err(format!(
            "the pre-activation note did NOT survive the cold boot: expected ({amount} XUS, 1 \
             note) after replay, got {zb_replay:?}"
        ));
    }

    // -- (4) SPEND IT, POST-ACTIVATION ----------------------------------------
    // The fork is Active with grace G = 0, so this carrier transaction MUST be
    // chain-bound (`Bound` regime) — assert the node says so before signing.
    let domain1 = obs.signing_domain()?;
    if domain1.get("active").and_then(Value::as_bool) != Some(true) {
        return Err(format!(
            "the fork is Active but sov_getSigningDomain still reports inactive: {domain1}"
        ));
    }
    if domain1.get("chainId").and_then(Value::as_str) != Some(CHAIN_ID) {
        return Err(format!(
            "post-activation signing domain names the wrong chain: {domain1}"
        ));
    }
    let bal_before = obs.balance_grains("user2.e2e.sov")?;
    let supply_before = obs.supply()?;
    let unshield = wallet(
        ctx,
        &obs_addr,
        &[
            "unshield",
            &user2.seed_hex,
            "user2.e2e.sov",
            &amount.to_string(),
        ],
    )?;
    let unshield_tx = parse_tx_id(&unshield).ok_or("no tx id in unshield output")?;
    let unshield_rcpt = await_success(
        &obs,
        &unshield_tx,
        "post-activation unshield of the pre-activation note",
        Duration::from_secs(300),
    )?;
    let unshield_height = unshield_rcpt
        .get("height")
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("unshield receipt lacks `height`: {unshield_rcpt}"))?;
    if unshield_height < activation.active_height {
        return Err(format!(
            "the spend was mined at height {unshield_height}, BELOW the activation height {} — \
             it did not actually cross the fork boundary",
            activation.active_height
        ));
    }
    let gas = gas_used(&unshield_rcpt)?;

    // EXACT pool delta: the whole note left the pool, nothing more, nothing less.
    poll_pool_eq(
        &obs,
        0,
        "pool after the post-activation de-shield",
        Duration::from_secs(90),
    )?;
    // EXACT transparent credit: amount in, real on-chain fee out.
    let expect_transparent = bal_before + xus(amount) - GAS_PRICE_GRAINS * u128::from(gas);
    poll_balance_eq(
        &obs,
        "user2.e2e.sov",
        expect_transparent,
        Duration::from_secs(90),
    )?;
    // The note is genuinely CONSUMED. `NoteStore::ingest_block` (sov-shielded)
    // marks a note spent exactly when the note's derived nullifier appears in an
    // on-chain bundle, so "0 unspent notes" here is a direct observation that the
    // nullifier was published in consensus — not wallet bookkeeping.
    let zb_spent = zbalance(ctx, &obs_addr, &user2.seed_hex)?;
    if zb_spent != ("0".to_string(), 0) {
        return Err(format!(
            "the spent note's nullifier is NOT on-chain: expected (0 XUS, 0 unspent notes) \
             after de-shielding the whole note, got {zb_spent:?}"
        ));
    }
    // ...and it cannot be spent twice.
    let respend = wallet_expect_failure(
        ctx,
        &obs_addr,
        &[
            "z-send",
            &user2.seed_hex,
            &ctx.net.key("user1.e2e.sov").shielded_addr,
            "1",
            "--signer",
            "user2.e2e.sov",
        ],
    )?;

    // Supply conservation across the whole episode.
    let supply_after = obs.supply()?;
    let total = supply_after
        .get("total")
        .and_then(grains_of)
        .ok_or("supply lacks total")?;
    let mined = supply_after
        .get("mined")
        .and_then(grains_of)
        .ok_or("supply lacks mined")?;
    if total != mined {
        return Err(format!(
            "conservation violated after the cross-activation spend: total {total} != mined \
             {mined} on a no-pre-mine chain"
        ));
    }
    let shielded = supply_after
        .get("shielded")
        .and_then(grains_of)
        .ok_or("supply lacks shielded")?;
    if shielded != 0 {
        return Err(format!(
            "shielded supply is {shielded} grains after the pool was fully drained — the \
             turnstile and the pool disagree"
        ));
    }

    Ok((
        format!(
            "{amount} XUS shielded at height {shield_height} (pre-fork); `{ACT_DEPLOYMENT}` \
             driven Defined→Started→LockedIn→Active by real signaling (active at {}); node-4 \
             cold-booted from blocks.log with the note intact; the note then de-shielded at \
             height {unshield_height} under the Bound regime — exact deltas, nullifier \
             published, re-spend refused, supply conserved",
            activation.active_height
        ),
        json!({
            "fund_tx": fund_tx,
            "shield_tx": shield_tx,
            "shield_height": shield_height,
            "shield_pool_grains": xus(amount).to_string(),
            "deployment": {
                "name": ACT_DEPLOYMENT,
                "bit": ACT_BIT,
                "period": ACT_PERIOD,
                "start_height": ACT_START_HEIGHT,
                "threshold": format!("{ACT_THRESHOLD_NUM}/{ACT_THRESHOLD_DEN}"),
                "observed_trace": trace,
                "started_height": activation.started_height,
                "lockedin_height": activation.lockedin_height,
                "active_height": activation.active_height,
            },
            "cold_boot": replay,
            "pool_after_replay_grains": pool_after_replay.to_string(),
            "unshield_tx": unshield_tx,
            "unshield_height": unshield_height,
            "unshield_gas": gas,
            "pool_after_spend_grains": "0",
            "user2_transparent_before_grains": bal_before.to_string(),
            "user2_transparent_after_grains": expect_transparent.to_string(),
            "unspent_notes_after_spend": 0,
            "respend_refused_with": respend,
            "supply_before": supply_before,
            "supply_after": supply_after,
        }),
    ))
}

/// One deployment's observed activation heights.
struct Activation {
    started_height: u64,
    lockedin_height: u64,
    active_height: u64,
}

/// Poll `sov_getDeployments` until `tx-domain` is `Active`, recording the height
/// at which each state was first OBSERVED.
///
/// Assertions here are deliberately race-free: a poll cannot be made to observe a
/// state at an exact block, so each first-observation height is only required to
/// fall inside the window in which that state is actually in force (a full
/// [`ACT_PERIOD`] of slack — 32 blocks — which no scheduler hiccup can exceed
/// while a 250 ms poll runs against a 2 s cadence). The EXACT, race-free facts —
/// the per-window signal counts and the activation boundary — are asserted from
/// the committed block headers by [`step_bip9_activation`].
fn drive_activation_to_active(rpc: &Rpc) -> Result<(Vec<Value>, Activation), String> {
    let mut trace: Vec<Value> = Vec::new();
    let mut seen: Vec<(String, u64)> = Vec::new();
    let deadline_blocks = ACT_START_HEIGHT + 4 * ACT_PERIOD;
    poll(
        &format!("`{ACT_DEPLOYMENT}` to reach Active (real miner signaling)"),
        // Bounded by the schedule, not by hope: activation is due at
        // start + 2*period. The deadline is a WEDGE detector, not a cadence
        // assumption — real block rate on an isolated net swings while LWMA
        // tracks the box's hashrate, so it is generous; the `deadline_blocks`
        // check below is the tight, height-based bound.
        Duration::from_secs(3_600),
        Duration::from_millis(250),
        || {
            let dep = tx_domain_deployment(rpc)?;
            let height = dep
                .get("__height")
                .and_then(Value::as_u64)
                .ok_or("deployments reply lacks height")?;
            let state = deployment_state(&dep)?;
            if seen.last().map(|(s, _)| s.as_str()) != Some(state.as_str()) {
                seen.push((state.clone(), height));
                trace.push(json!({ "state": state, "first_seen_height": height }));
            }
            if state == "Failed" {
                return Err(format!(
                    "`{ACT_DEPLOYMENT}` reached `Failed` at height {height} — miners did not \
                     signal; the rehearsal preset or the signal mask is broken"
                ));
            }
            if height > deadline_blocks && state != "Active" {
                return Err(format!(
                    "chain is at height {height}, well past the scheduled activation, and \
                     `{ACT_DEPLOYMENT}` is still `{state}`"
                ));
            }
            Ok((state == "Active").then_some(()))
        },
    )?;

    // The trace must be MONOTONE through the BIP-9 lifecycle and must contain
    // every state — no jumping straight to Active, never going backwards.
    let order = |s: &str| match s {
        "Defined" => Some(0u8),
        "Started" => Some(1),
        "LockedIn" => Some(2),
        "Active" => Some(3),
        _ => None,
    };
    let mut last = 0u8;
    for (state, height) in &seen {
        let rank = order(state)
            .ok_or_else(|| format!("unknown deployment state `{state}` at height {height}"))?;
        if rank < last {
            return Err(format!(
                "deployment state went BACKWARDS to `{state}` at height {height}: {seen:?}"
            ));
        }
        last = rank;
    }
    let at = |want: &str| -> Result<u64, String> {
        seen.iter()
            .find(|(s, _)| s == want)
            .map(|(_, h)| *h)
            .ok_or_else(|| {
                format!(
                    "never observed `{ACT_DEPLOYMENT}` in state `{want}` — the \
                     Defined→Started→LockedIn→Active lifecycle was not driven in full: {seen:?}"
                )
            })
    };
    let started_height = at("Started")?;
    let lockedin_height = at("LockedIn")?;
    let active_height = at("Active")?;
    // Each state must have been observed inside the window where it is in force.
    for (label, seen_at, from) in [
        ("Started", started_height, ACT_START_HEIGHT),
        ("LockedIn", lockedin_height, ACT_START_HEIGHT + ACT_PERIOD),
        ("Active", active_height, ACT_START_HEIGHT + 2 * ACT_PERIOD),
    ] {
        if seen_at < from || seen_at >= from + ACT_PERIOD {
            return Err(format!(
                "`{label}` first observed at height {seen_at}, outside the window \
                 [{from}, {}) in which it is in force — the activation schedule is not the \
                 pinned one",
                from + ACT_PERIOD
            ));
        }
    }
    Ok((
        trace,
        Activation {
            started_height,
            lockedin_height,
            active_height,
        },
    ))
}

/// SIGKILL node-4, delete its chainstate snapshot, and cold-boot it from
/// `blocks.log` alone; assert it reproduces the pre-kill block hash + state root
/// and rejoins the network. Returns the evidence object.
///
/// This is the same machinery [`step_restart_replay`] uses — factored out so the
/// never-stranded step exercises it across an ACTIVATED chain (a log whose blocks
/// span both signature regimes) with a live pre-activation note in it.
fn cold_boot_observer(ctx: &mut Ctx) -> Result<Value, String> {
    let victim = "node-4";
    let plan = ctx.net.plan(victim).clone();
    let rpc4 = ctx.rpc(victim);

    poll(
        "node-4's chainstate.snapshot to exist (written every 50 blocks)",
        Duration::from_secs(300),
        Duration::from_secs(1),
        || {
            Ok(ctx
                .backend
                .data_file_exists(&plan, "chainstate.snapshot")?
                .then_some(()))
        },
    )?;
    let h4 = rpc4.height()?;
    let hpin = h4.saturating_sub(DEPTH);
    let ref_digest = rpc4
        .digest(hpin)?
        .ok_or(format!("node-4 lacks its own block {hpin}"))?;
    let ref_hash = ref_digest.get("hash").cloned().unwrap_or(Value::Null);
    let ref_root = ref_digest.get("stateRoot").cloned().unwrap_or(Value::Null);

    ctx.backend.stop(victim)?;
    if !ctx.backend.remove_data_file(&plan, "chainstate.snapshot")? {
        return Err("chainstate.snapshot vanished between the existence check and deletion".into());
    }
    if !ctx.backend.data_file_exists(&plan, "blocks.log")? {
        return Err("node-4 has no blocks.log — nothing to replay from".into());
    }
    ctx.backend.start(&plan, &ctx.rpcd)?;
    poll(
        "node-4 to serve RPC after cold boot",
        Duration::from_secs(180),
        Duration::from_millis(300),
        || Ok(rpc4.healthy().then_some(())),
    )?;
    poll(
        &format!("node-4 to replay back past height {hpin}"),
        Duration::from_secs(240),
        Duration::from_millis(500),
        || {
            let h = rpc4.height()?;
            Ok((h >= hpin).then_some(h))
        },
    )?;
    let replayed = rpc4
        .digest(hpin)?
        .ok_or(format!("node-4 lacks block {hpin} after replay"))?;
    if replayed.get("hash") != Some(&ref_hash) {
        return Err(format!(
            "replay produced a DIFFERENT block {hpin}: {:?} != pre-kill {ref_hash:?}",
            replayed.get("hash")
        ));
    }
    if replayed.get("stateRoot") != Some(&ref_root) {
        return Err(format!(
            "replay produced a DIFFERENT state root at {hpin}: {:?} != pre-kill {ref_root:?}",
            replayed.get("stateRoot")
        ));
    }
    Ok(json!({
        "victim": victim,
        "pre_kill_height": h4,
        "pinned_height": hpin,
        "pinned_hash": ref_hash,
        "pinned_state_root": ref_root,
        "snapshot_deleted": true,
    }))
}

// ---------------------------------------------------------------------------
// 5. BIP-9 activation rehearsal — post-hoc, race-free audit of the activation
// ---------------------------------------------------------------------------

/// Re-derives the activation outcome from RAW COMMITTED HEADERS, independently of
/// the node's own state machine: it counts, block by block, how many headers in
/// each signaling window actually set the deployment's bit, checks that count
/// against the pinned 9/10 threshold, and asserts the exact activation boundary.
/// Nothing here polls or races — every input is immutable chain history.
fn step_bip9_activation(ctx: &mut Ctx) -> Result<(String, Value), String> {
    let rpc = ctx.rpc("node-1");
    let dep = tx_domain_deployment(&rpc)?;
    check_deployment_params(&dep)?;
    let state = deployment_state(&dep)?;
    if state != "Active" {
        return Err(format!(
            "`{ACT_DEPLOYMENT}` is `{state}`, not `Active` — the activation the previous step \
             drove did not hold"
        ));
    }

    // The signaling window that decides lock-in, and the one after it.
    let signaling_window = ACT_START_HEIGHT;
    let lockin_window = ACT_START_HEIGHT + ACT_PERIOD;
    let active_height = ACT_START_HEIGHT + 2 * ACT_PERIOD;
    let tip = rpc.height()?;
    if tip < active_height {
        return Err(format!(
            "tip {tip} is below the activation height {active_height} — cannot audit"
        ));
    }
    let mut counts = serde_json::Map::new();
    for window in [signaling_window, lockin_window] {
        let mut signaled = 0u64;
        for h in window..window + ACT_PERIOD {
            let block = rpc
                .block(h)?
                .ok_or_else(|| format!("node-1 lacks block {h}"))?;
            let bits = block
                .pointer("/header/version_bits")
                .and_then(Value::as_u64)
                .ok_or_else(|| format!("block {h} header lacks version_bits"))?;
            if bits & (1 << ACT_BIT) != 0 {
                signaled += 1;
            }
        }
        // BIP-9 threshold, exact integer arithmetic — no floating point.
        if signaled * ACT_THRESHOLD_DEN < ACT_THRESHOLD_NUM * ACT_PERIOD {
            return Err(format!(
                "window [{window}, {}) signaled bit {ACT_BIT} in only {signaled}/{ACT_PERIOD} \
                 blocks — below the {ACT_THRESHOLD_NUM}/{ACT_THRESHOLD_DEN} threshold, yet the \
                 node reports the deployment Active. The node's state machine and the \
                 committed headers DISAGREE.",
                window + ACT_PERIOD
            ));
        }
        counts.insert(
            format!("window_{window}"),
            json!({ "signaled": signaled, "of": ACT_PERIOD }),
        );
    }
    // The signature regime flipped exactly at the boundary the schedule dictates:
    // dormant at the last pre-activation block, live at the activation block.
    let domain = rpc.signing_domain()?;
    if domain.get("active").and_then(Value::as_bool) != Some(true) {
        return Err(format!(
            "deployment Active but signing domain is not: {domain}"
        ));
    }
    if domain
        .get("genesis")
        .and_then(Value::as_str)
        .map(str::to_string)
        != Some(EXPECTED_GENESIS_HASH.to_string())
    {
        return Err(format!(
            "the post-activation signing domain does not bind THIS chain's genesis \
             ({EXPECTED_GENESIS_HASH}): {domain}"
        ));
    }
    Ok((
        format!(
            "`{ACT_DEPLOYMENT}` (bit {ACT_BIT}) Active: recounted from committed headers, \
             {ACT_PERIOD}/{ACT_PERIOD} blocks signaled in the window at {signaling_window} \
             (threshold {ACT_THRESHOLD_NUM}/{ACT_THRESHOLD_DEN}); activation height \
             {active_height}; signatures now bound to {CHAIN_ID}/{EXPECTED_GENESIS_HASH}"
        ),
        json!({
            "deployment": dep,
            "recounted_signal_windows": counts,
            "activation_height": active_height,
            "signing_domain": domain,
        }),
    ))
}

// ---------------------------------------------------------------------------
// the v2 half of the never-stranded law — precise SKIP (no fake, no stub)
// ---------------------------------------------------------------------------

/// The other half of forward-compatibility law F8: a note in pool **v1** must
/// still be spendable after pool **v2** is introduced and activated. That leg
/// cannot exist yet — `Action::ShieldedV2` is not in `chain/crates/types`, there
/// is no pool-v2 state in `chain/crates/chain`, and the bit-2 deployment has no
/// row — so it is reported as a SKIP with its exact dependency, never as a pass.
fn never_stranded_v2_skip(ctx: &mut Ctx) -> StepResult {
    // Show the LIVE gap rather than asserting it from memory: the deployment
    // table this chain actually runs (bit 2 is absent).
    let live = ctx
        .rpc("node-1")
        .deployments()
        .unwrap_or_else(|e| json!({ "error": e }));
    StepResult::skip(
        "shielded-v1-never-stranded-across-pool-v2",
        "waits on W2 (`Action::ShieldedV2`, pool-v2 ledger state, the bit-2 deployment row): \
         the v1-across-a-consensus-activation half of law F8 runs for real in \
         `shielded-v1-never-stranded`, but the v1-across-the-introduction-of-pool-v2 half \
         needs a v2 pool to introduce. When W2 lands, this step shields into v1, activates \
         bit 2, and re-spends the v1 note after pool v2 is Active — no code here simulates \
         that today."
            .to_string(),
        json!({
            "waits_on": "v0.2.0 program W2 (S2a-S2f) + D13 bit-2 deployment",
            "enforces": "notes/v0.2.0-program.md law F8 (safe-exit protocol)",
            "live_sov_getDeployments": live,
        }),
    )
}

// ---------------------------------------------------------------------------
// shared helpers
// ---------------------------------------------------------------------------

/// The `tx-domain` deployment row from `sov_getDeployments`, with the reply's
/// chain height folded in as `__height` so a caller reads state and height from
/// ONE consistent snapshot (never two calls that could straddle a block).
fn tx_domain_deployment(rpc: &Rpc) -> Result<Value, String> {
    let reply = rpc.deployments()?;
    let height = reply
        .get("height")
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("sov_getDeployments lacks `height`: {reply}"))?;
    let mut row = reply
        .get("deployments")
        .and_then(Value::as_array)
        .ok_or_else(|| format!("sov_getDeployments lacks `deployments`: {reply}"))?
        .iter()
        .find(|d| d.get("name").and_then(Value::as_str) == Some(ACT_DEPLOYMENT))
        .cloned()
        .ok_or_else(|| {
            format!(
                "this chain runs NO `{ACT_DEPLOYMENT}` deployment — the node binary lacks the \
                 E2E rehearsal preset (`e2e_rehearsal_deployments()` in \
                 chain/crates/rpc/src/daemon.rs, keyed on the reserved `sov-e2e-` chain-id \
                 prefix). Rebuild the release binaries from this branch. Live reply: {reply}"
            )
        })?;
    if let Value::Object(map) = &mut row {
        map.insert("__height".into(), json!(height));
    }
    Ok(row)
}

/// The deployment row's `state` string (`Defined|Started|LockedIn|Active|Failed`).
fn deployment_state(row: &Value) -> Result<String, String> {
    row.get("state")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| format!("deployment row lacks `state`: {row}"))
}

/// Assert the LIVE deployment parameters equal the ones this matrix pins. A
/// silent drift in the node's preset would re-time the activation every
/// assertion below depends on, so it fails here, loudly, first.
fn check_deployment_params(row: &Value) -> Result<(), String> {
    for (field, expected) in [
        ("bit", ACT_BIT),
        ("period", ACT_PERIOD),
        ("startHeight", ACT_START_HEIGHT),
    ] {
        let got = row
            .get(field)
            .and_then(Value::as_u64)
            .ok_or_else(|| format!("deployment row lacks `{field}`: {row}"))?;
        if got != expected {
            return Err(format!(
                "`{ACT_DEPLOYMENT}` {field} is {got}, not the pinned {expected} — the node's \
                 rehearsal preset drifted from tools/e2e-vm's pins"
            ));
        }
    }
    if row.get("lockinontimeout").and_then(Value::as_bool) != Some(false) {
        return Err(format!(
            "`{ACT_DEPLOYMENT}` has lock-in-on-timeout ENABLED — activation would not prove \
             real miner signaling: {row}"
        ));
    }
    Ok(())
}

fn min_height(nodes: &[(String, Rpc)]) -> Result<u64, String> {
    let mut min = u64::MAX;
    for (_, rpc) in nodes {
        min = min.min(rpc.height()?);
    }
    if min == u64::MAX {
        return Err("no nodes".into());
    }
    Ok(min)
}

/// Wait until every node's chain reaches at least `min_h` AND all nodes report
/// the identical digest `DEPTH` below the lowest tip. Returns that (height,
/// digest) — the network-wide agreed chain point.
fn converged(
    nodes: &[(String, Rpc)],
    min_h: u64,
    timeout: Duration,
) -> Result<(u64, Value), String> {
    poll(
        "nodes to converge on one chain",
        timeout,
        Duration::from_millis(500),
        || {
            let h = min_height(nodes)?;
            if h < min_h {
                return Err(format!("lowest tip {h} < required {min_h}"));
            }
            let ph = h.saturating_sub(DEPTH);
            let mut first: Option<Value> = None;
            for (name, rpc) in nodes {
                let d = match rpc.digest(ph)? {
                    Some(d) => d,
                    None => return Err(format!("{name} lacks block {ph}")),
                };
                match &first {
                    None => first = Some(d),
                    Some(f) => {
                        if f.get("hash") != d.get("hash") {
                            return Err(format!("split at {ph}: {name} disagrees"));
                        }
                    }
                }
            }
            Ok(first.map(|d| (ph, d)))
        },
    )
}

/// Run a `sov-wallet` command against `addr`; error carries stderr+stdout.
fn wallet(ctx: &Ctx, addr: &str, args: &[&str]) -> Result<String, String> {
    let mut full: Vec<&str> = vec![addr];
    full.extend_from_slice(args);
    // Generous cap: shielded commands build a Halo2 prover and re-scan the
    // chain before proving. The deadline bounds a WEDGE, not normal latency.
    let out = run_cmd_timeout(&ctx.wallet, &full, None, Duration::from_secs(900))?;
    if !out.status_ok {
        return Err(format!(
            "sov-wallet {} failed: {} {}",
            args.first().unwrap_or(&""),
            out.stderr.trim(),
            out.stdout.lines().last().unwrap_or("")
        ));
    }
    Ok(out.stdout)
}

/// Run a `sov-wallet` command that MUST FAIL, returning the refusal text. A
/// command that unexpectedly SUCCEEDS is a hard error — this is how the harness
/// proves a spent note cannot be spent again (an assertion that would be
/// worthless if a silent success could pass).
fn wallet_expect_failure(ctx: &Ctx, addr: &str, args: &[&str]) -> Result<String, String> {
    let mut full: Vec<&str> = vec![addr];
    full.extend_from_slice(args);
    let out = run_cmd_timeout(&ctx.wallet, &full, None, Duration::from_secs(900))?;
    if out.status_ok {
        return Err(format!(
            "sov-wallet {} SUCCEEDED but must have been refused (a spent note was re-spendable): \
             {}",
            args.first().unwrap_or(&""),
            out.stdout.trim()
        ));
    }
    let reason = out.stderr.trim();
    let reason = if reason.is_empty() {
        out.stdout.trim()
    } else {
        reason
    };
    Ok(reason.lines().last().unwrap_or("(no message)").to_string())
}

/// user's shielded position via the real CLI: (balance XUS string, note count).
fn zbalance(ctx: &Ctx, addr: &str, seed_hex: &str) -> Result<(String, u64), String> {
    let out = wallet(ctx, addr, &["z-balance", seed_hex])?;
    let bal = labeled_value(&out, "shielded balance")
        .and_then(|v| v.strip_suffix("XUS").map(|s| s.trim().to_string()))
        .ok_or("z-balance output lacks `shielded balance`")?;
    let notes = labeled_value(&out, "unspent notes")
        .and_then(|v| v.parse::<u64>().ok())
        .ok_or("z-balance output lacks `unspent notes`")?;
    Ok((bal, notes))
}

/// Poll a receipt until SUCCESS; a `failed` receipt (with its on-chain reason)
/// or a timeout is a hard error.
fn await_success(rpc: &Rpc, tx_id: &str, what: &str, timeout: Duration) -> Result<Value, String> {
    poll(
        &format!("{what} tx {tx_id} to apply on-chain"),
        timeout,
        Duration::from_millis(500),
        || match rpc.receipt(tx_id)? {
            Some(r) if receipt_succeeded(&r) => Ok(Some(r)),
            Some(r) => Err(format!("tx applied but FAILED on-chain: {r}")),
            None => Ok(None),
        },
    )
    .and_then(|r| {
        if receipt_succeeded(&r) {
            Ok(r)
        } else {
            Err(format!("{what}: receipt not successful: {r}"))
        }
    })
}

fn gas_used(receipt: &Value) -> Result<u64, String> {
    receipt
        .get("gas_used")
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("receipt lacks gas_used: {receipt}"))
}

/// Poll until `account`'s balance EQUALS `expected` grains, then hold that as
/// the assertion (an overshoot never passes; the timeout reports the last
/// observed value).
fn poll_balance_eq(
    rpc: &Rpc,
    account: &str,
    expected: u128,
    timeout: Duration,
) -> Result<(), String> {
    poll(
        &format!("{account} balance to equal {expected} grains"),
        timeout,
        Duration::from_millis(500),
        || {
            let b = rpc.balance_grains(account)?;
            if b == expected {
                Ok(Some(()))
            } else {
                Err(format!("currently {b} grains"))
            }
        },
    )
}

/// Poll until the pool value EQUALS `expected` grains (exact, never ≥).
fn poll_pool_eq(rpc: &Rpc, expected: u128, what: &str, timeout: Duration) -> Result<(), String> {
    poll(
        &format!("{what} to equal {expected} grains"),
        timeout,
        Duration::from_millis(500),
        || {
            let p = rpc.pool_grains()?;
            if p == expected {
                Ok(Some(()))
            } else {
                Err(format!("currently {p} grains"))
            }
        },
    )
}
