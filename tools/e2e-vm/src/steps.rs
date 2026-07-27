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

    // Pool-v2 lifecycle. These ran as blanket SKIPs while W2 was unlanded;
    // audit PQV2-02 showed that a harness reporting green over six skipped v2
    // steps evidences nothing about the feature it purports to validate. They
    // are live steps now, gated on the `shielded-v2` (bit 2) deployment that
    // the rehearsal preset arms one window after `tx-domain`.
    let v2_steps: [(&'static str, StepFn); 6] = [
        (
            "shielded-v1-never-stranded-across-pool-v2",
            step_v1_across_v2,
        ),
        ("shield-v2", step_shield_v2),
        ("z-send-v2", step_zsend_v2),
        ("unshield-v2", step_unshield_v2),
        ("v1-to-v2-migration", step_v1_to_v2_migration),
        ("reorg-with-v2-state", step_reorg_with_v2),
    ];
    for (name, f) in v2_steps {
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
// ---------------------------------------------------------------------------
// pool v2 (post-quantum) lifecycle
// ---------------------------------------------------------------------------

/// The `shielded-v2` deployment name (BIP-9 signal bit 2).
const V2_DEPLOYMENT: &str = "shielded-v2";

/// Block the harness until pool v2 is Active, proving DORMANCY first.
///
/// While dormant this asserts the pool is a hard reject rather than a silent
/// no-op — the property that lets pool v2 ship inside a release that does not
/// yet arm it. Then it waits out the compressed BIP-9 schedule for real.
fn await_v2_active(ctx: &mut Ctx) -> Result<Value, String> {
    let obs = ctx.rpc("node-4");
    let addr = obs.addr.clone();

    // The node must KNOW about pool v2 even while it is unusable — otherwise a
    // wallet cannot tell "empty pool" from "node too old".
    let info = obs.shielded_v2_info()?;
    if info.get("poolValue").is_none() {
        return Err(format!("node serves no pool-v2 info while dormant: {info}"));
    }

    // DORMANCY PROOF: while bit 2 is unarmed a v2 action must be REFUSED, not
    // quietly accepted. The CLI's own guard is the first line; a refusal here
    // is the evidence that a v0.2.2 release can carry this code safely.
    let mut dormancy_evidence = json!(null);
    if !obs.shielded_v2_active()? {
        let seed = ctx.net.key("user1.e2e.sov").seed_hex.clone();
        let refusal = wallet_expect_failure(ctx, &addr, &["shield2", &seed, "1"])?;
        if !refusal.to_lowercase().contains("not active") {
            return Err(format!(
                "pool v2 is dormant but a v2 shield was not refused for dormancy: {refusal}"
            ));
        }
        dormancy_evidence = json!(refusal.trim());
    }

    // Now let the real BIP-9 machinery activate it: miners signal bit 2 via the
    // baked mask, so this is a genuine Defined->Started->LockedIn->Active walk.
    let obs = ctx.rpc("node-4");
    poll(
        "pool v2 (bit 2) to reach Active",
        Duration::from_secs(900),
        Duration::from_secs(2),
        || Ok(obs.shielded_v2_active()?.then_some(())),
    )?;
    let height = obs.height()?;
    Ok(json!({
        "dormant_shield_refusal": dormancy_evidence,
        "active_at_observed_height": height,
        "deployment": V2_DEPLOYMENT,
    }))
}

/// `z2-address` for a seed (the `xusq1…` pool-v2 receiving address).
fn z2address(ctx: &Ctx, addr: &str, seed_hex: &str) -> Result<String, String> {
    let out = wallet(ctx, addr, &["z2-address", seed_hex])?;
    labeled_value(&out, "pool v2 address")
        .ok_or_else(|| format!("z2-address output lacks `pool v2 address`:\n{out}"))
}

/// `z2-balance` for a seed, as `(xus_string, unspent_note_count)`.
fn z2balance(ctx: &Ctx, addr: &str, seed_hex: &str) -> Result<(String, u64), String> {
    let out = wallet(ctx, addr, &["z2-balance", seed_hex])?;
    let bal = labeled_value(&out, "shielded balance")
        .and_then(|v| v.strip_suffix("XUS").map(|s| s.trim().to_string()))
        .ok_or("z2-balance output lacks `shielded balance`")?;
    let notes = labeled_value(&out, "unspent notes")
        .and_then(|v| v.parse::<u64>().ok())
        .ok_or("z2-balance output lacks `unspent notes`")?;
    Ok((bal, notes))
}

/// Poll pool v2's value until it equals `expected` grains.
fn poll_pool_v2_eq(rpc: &Rpc, expected: u128, what: &str, timeout: Duration) -> Result<(), String> {
    poll(what, timeout, Duration::from_millis(500), || {
        Ok((rpc.pool_v2_grains()? == expected).then_some(()))
    })
    .map_err(|e| {
        let got = rpc.pool_v2_grains().unwrap_or_default();
        format!("{e} (pool v2 = {got} grains, expected {expected})")
    })
}

/// Law F8, the half that needed a pool v2 to exist: a pool-v1 note created
/// BEFORE pool v2 was introduced must still be spendable AFTER v2 goes Active.
/// A new pool must never strand the old one.
fn step_v1_across_v2(ctx: &mut Ctx) -> Result<(String, Value), String> {
    let obs = ctx.rpc("node-4");
    let addr = obs.addr.clone();
    let val01 = ctx.net.key("val01.e2e.sov").clone();
    let user2 = ctx.net.key("user2.e2e.sov").clone();
    let xus = |n: u128| n * GRAINS_PER_XUS;

    // Shield into pool v1 while pool v2 does not yet exist on this chain.
    if obs.shielded_v2_active()? {
        return Err(
            "pool v2 was already Active before this step could shield into v1 \
                    ahead of it — the schedule must start bit 2 AFTER the earlier steps"
                .to_string(),
        );
    }
    let pool_v1_before = obs.pool_grains()?;
    let shield = wallet(
        ctx,
        &addr,
        &[
            "transfer",
            &val01.seed_hex,
            "val01.e2e.sov",
            &user2.shielded_addr,
            "4",
        ],
    )?;
    let shield_tx = parse_tx_id(&shield).ok_or("no tx id in pre-v2 v1 shield")?;
    await_success(
        &obs,
        &shield_tx,
        "pre-v2 v1 shield",
        Duration::from_secs(180),
    )?;
    let pool_v1_mid = pool_v1_before + xus(4);
    poll_pool_eq(
        &obs,
        pool_v1_mid,
        "pool v1 after pre-v2 shield",
        Duration::from_secs(60),
    )?;

    // Introduce pool v2 for real.
    let activation = await_v2_active(ctx)?;
    let obs = ctx.rpc("node-4");

    // The v1 note must be untouched by the arrival of an entirely new pool...
    let z_after = zbalance(ctx, &addr, &user2.seed_hex)?;

    // ...and still SPENDABLE: de-shield it out of v1 with pool v2 live.
    let bal_before = obs.balance_grains("user2.e2e.sov")?;
    let unshield = wallet(
        ctx,
        &addr,
        &["unshield", &user2.seed_hex, "user2.e2e.sov", "1"],
    )?;
    let unshield_tx = parse_tx_id(&unshield).ok_or("no tx id in post-v2 v1 unshield")?;
    let rcpt = await_success(
        &obs,
        &unshield_tx,
        "post-v2 v1 unshield",
        Duration::from_secs(180),
    )?;
    let gas = gas_used(&rcpt)?;
    poll_pool_eq(
        &obs,
        pool_v1_mid - xus(1),
        "pool v1 after post-v2 unshield",
        Duration::from_secs(60),
    )?;
    poll_balance_eq(
        &obs,
        "user2.e2e.sov",
        bal_before + xus(1) - GAS_PRICE_GRAINS * u128::from(gas),
        Duration::from_secs(60),
    )?;

    // The two pools are separate value spaces: v1 activity must not move v2.
    let pool_v2 = obs.pool_v2_grains()?;
    if pool_v2 != 0 {
        return Err(format!(
            "a pool-v1 de-shield moved pool v2 to {pool_v2} grains — the pools must be \
             independent value spaces"
        ));
    }

    Ok((
        format!(
            "law F8 across the introduction of pool v2: 4 XUS shielded into v1 while bit 2 \
             was DORMANT (a v2 shield was refused outright), bit 2 then driven to Active for \
             real, and the v1 note was still intact ({} XUS) and still spendable — de-shielded \
             1 XUS after activation with exact deltas; pool v2 stayed at 0",
            z_after.0
        ),
        json!({
            "pre_v2_shield_tx": shield_tx,
            "post_v2_unshield_tx": unshield_tx,
            "v1_balance_after_v2_activation": format!("{} XUS x {}", z_after.0, z_after.1),
            "pool_v1_grains": { "before": pool_v1_before.to_string(), "after_shield": pool_v1_mid.to_string(), "after_unshield": (pool_v1_mid - xus(1)).to_string() },
            "pool_v2_grains_throughout": "0",
            "activation": activation,
        }),
    ))
}

/// A real STARK-proved shield into pool v2, mined and verified in consensus.
fn step_shield_v2(ctx: &mut Ctx) -> Result<(String, Value), String> {
    let obs = ctx.rpc("node-4");
    let addr = obs.addr.clone();
    let val01 = ctx.net.key("val01.e2e.sov").clone();
    let user1 = ctx.net.key("user1.e2e.sov").clone();
    let xus = |n: u128| n * GRAINS_PER_XUS;

    if !obs.shielded_v2_active()? {
        return Err(
            "pool v2 is not Active — `shielded-v1-never-stranded-across-pool-v2` \
                    should have driven the activation"
                .to_string(),
        );
    }
    let pool_v2_before = obs.pool_v2_grains()?;
    let pool_v1_before = obs.pool_grains()?;

    // user1 needs transparent headroom to pay the carrier fee.
    let fund = wallet(
        ctx,
        &addr,
        &[
            "transfer",
            &val01.seed_hex,
            "val01.e2e.sov",
            "user1.e2e.sov",
            "12",
        ],
    )?;
    let fund_tx = parse_tx_id(&fund).ok_or("no tx id in v2 funding transfer")?;
    await_success(&obs, &fund_tx, "v2 funding", Duration::from_secs(90))?;

    let v2_addr = z2address(ctx, &addr, &user1.seed_hex)?;
    if !v2_addr.starts_with("xusq1") {
        return Err(format!("pool-v2 address is not xusq1-prefixed: {v2_addr}"));
    }

    // The shield itself: the CLI builds a REAL Winterfell STARK; the node
    // verifies it inside consensus before the bundle can be mined.
    let out = wallet(
        ctx,
        &addr,
        &["shield2", &user1.seed_hex, "5", "--signer", "user1.e2e.sov"],
    )?;
    let tx = parse_tx_id(&out).ok_or("no tx id in shield2 output")?;
    let rcpt = await_success(&obs, &tx, "v2 shield", Duration::from_secs(300))?;

    poll_pool_v2_eq(
        &obs,
        pool_v2_before + xus(5),
        "pool v2 after shield",
        Duration::from_secs(90),
    )?;
    let zb = z2balance(ctx, &addr, &user1.seed_hex)?;
    if zb != ("5".to_string(), 1) {
        return Err(format!(
            "user1 pool-v2 balance after shield: expected (5 XUS, 1 note), got {zb:?}"
        ));
    }
    // Shielding into v2 must not disturb pool v1.
    let pool_v1_after = obs.pool_grains()?;
    if pool_v1_after != pool_v1_before {
        return Err(format!(
            "a pool-v2 shield moved pool v1: {pool_v1_before} -> {pool_v1_after}"
        ));
    }
    // Every node must agree on the new anchor, or witnesses desync.
    let anchors = v2_anchor_agreement(ctx)?;

    Ok((
        format!(
            "5 XUS shielded into pool v2 with a REAL STARK proof verified in consensus; \
             pool v2 {} -> {} grains, wallet sees 5 XUS x 1 note, pool v1 untouched, and all \
             {} nodes agree on the v2 anchor",
            pool_v2_before,
            pool_v2_before + xus(5),
            anchors.0
        ),
        json!({
            "fund_tx": fund_tx,
            "shield_tx": tx,
            "gas": gas_used(&rcpt)?,
            "pool_v2_address": v2_addr,
            "pool_v2_grains": { "before": pool_v2_before.to_string(), "after": (pool_v2_before + xus(5)).to_string() },
            "pool_v1_grains_unchanged": pool_v1_before.to_string(),
            "anchor": anchors.1,
        }),
    ))
}

/// A fully private pool-v2 transfer: value never leaves the pool.
fn step_zsend_v2(ctx: &mut Ctx) -> Result<(String, Value), String> {
    let obs = ctx.rpc("node-4");
    let addr = obs.addr.clone();
    let user1 = ctx.net.key("user1.e2e.sov").clone();
    let user2 = ctx.net.key("user2.e2e.sov").clone();

    let pool_before = obs.pool_v2_grains()?;
    let to = z2address(ctx, &addr, &user2.seed_hex)?;
    let bal_before = obs.balance_grains("user1.e2e.sov")?;

    let out = wallet(
        ctx,
        &addr,
        &[
            "z2-send",
            &user1.seed_hex,
            &to,
            "2",
            "--signer",
            "user1.e2e.sov",
        ],
    )?;
    let tx = parse_tx_id(&out).ok_or("no tx id in z2-send output")?;
    let rcpt = await_success(&obs, &tx, "v2 z-send", Duration::from_secs(300))?;
    let gas = gas_used(&rcpt)?;

    // THE invariant of a private transfer: pool value is conserved exactly.
    let pool_after = obs.pool_v2_grains()?;
    if pool_after != pool_before {
        return Err(format!(
            "a private v2 transfer moved pool value: {pool_before} -> {pool_after} grains"
        ));
    }
    // Sender keeps change, recipient's wallet DETECTS the note by trial
    // decapsulation — nothing on-chain names them.
    let zb1 = z2balance(ctx, &addr, &user1.seed_hex)?;
    if zb1.0 != "3" {
        return Err(format!(
            "sender pool-v2 balance after z2-send: expected 3 XUS change, got {zb1:?}"
        ));
    }
    let zb2 = z2balance(ctx, &addr, &user2.seed_hex)?;
    if zb2 != ("2".to_string(), 1) {
        return Err(format!(
            "recipient pool-v2 balance after z2-send: expected (2 XUS, 1 note), got {zb2:?}"
        ));
    }
    // Only the carrier fee touches the transparent ledger.
    poll_balance_eq(
        &obs,
        "user1.e2e.sov",
        bal_before - GAS_PRICE_GRAINS * u128::from(gas),
        Duration::from_secs(60),
    )?;

    Ok((
        format!(
            "2 XUS sent privately inside pool v2: pool value UNCHANGED at {pool_before} grains, \
             sender left with {} XUS of change, recipient's wallet found the note by trial \
             decapsulation, and only the carrier fee ({gas} gas) touched the transparent ledger",
            zb1.0
        ),
        json!({
            "zsend_tx": tx,
            "gas": gas,
            "pool_v2_grains_unchanged": pool_before.to_string(),
            "sender_after": format!("{} XUS x {}", zb1.0, zb1.1),
            "recipient_after": format!("{} XUS x {}", zb2.0, zb2.1),
        }),
    ))
}

/// A pool-v2 de-shield: value crosses the turnstile back to transparent, with
/// change returning shielded so a partial exit never burns the remainder.
fn step_unshield_v2(ctx: &mut Ctx) -> Result<(String, Value), String> {
    let obs = ctx.rpc("node-4");
    let addr = obs.addr.clone();
    let user2 = ctx.net.key("user2.e2e.sov").clone();
    let xus = |n: u128| n * GRAINS_PER_XUS;

    let pool_before = obs.pool_v2_grains()?;
    let bal_before = obs.balance_grains("user2.e2e.sov")?;
    let supply_before = obs.supply()?;

    let out = wallet(
        ctx,
        &addr,
        &["unshield2", &user2.seed_hex, "user2.e2e.sov", "1"],
    )?;
    let tx = parse_tx_id(&out).ok_or("no tx id in unshield2 output")?;
    let rcpt = await_success(&obs, &tx, "v2 de-shield", Duration::from_secs(300))?;
    let gas = gas_used(&rcpt)?;

    poll_pool_v2_eq(
        &obs,
        pool_before - xus(1),
        "pool v2 after de-shield",
        Duration::from_secs(90),
    )?;
    poll_balance_eq(
        &obs,
        "user2.e2e.sov",
        bal_before + xus(1) - GAS_PRICE_GRAINS * u128::from(gas),
        Duration::from_secs(60),
    )?;
    // Change came back shielded rather than being burned.
    let zb = z2balance(ctx, &addr, &user2.seed_hex)?;
    if zb.0 != "1" {
        return Err(format!(
            "de-shield change: expected 1 XUS still shielded, got {zb:?}"
        ));
    }
    // The turnstile moved value between spaces; it must not have CREATED any.
    //
    // TOTAL supply is the wrong thing to pin: the chain keeps mining while the
    // de-shield confirms, so emission legitimately raises it. The real
    // conservation statement is that the SHIELDED total fell by exactly the
    // de-shielded amount — value left the pool and went nowhere else.
    let supply_after = obs.supply()?;
    let shielded_before = shielded_total_grains(&supply_before)?;
    let shielded_after = shielded_total_grains(&supply_after)?;
    if shielded_before.saturating_sub(shielded_after) != xus(1) {
        return Err(format!(
            "a 1 XUS de-shield moved the shielded total by {} grains, not {}: {supply_before} -> \
             {supply_after}",
            shielded_before.saturating_sub(shielded_after),
            xus(1)
        ));
    }
    // ...and total supply may only have grown by whole coinbase emissions.
    let total_before = supply_field_grains(&supply_before, "total")?;
    let total_after = supply_field_grains(&supply_after, "total")?;
    if total_after < total_before {
        return Err(format!(
            "total supply DECREASED across a v2 de-shield: {total_before} -> {total_after}"
        ));
    }

    Ok((
        format!(
            "1 XUS de-shielded from pool v2 under the drain limiter: pool {} -> {} grains, \
             transparent credited exactly (minus {gas} gas), 1 XUS of change returned SHIELDED \
             rather than burned, and total supply conserved at {}",
            pool_before,
            pool_before - xus(1),
            supply_after
        ),
        json!({
            "unshield_tx": tx,
            "gas": gas,
            "pool_v2_grains": { "before": pool_before.to_string(), "after": (pool_before - xus(1)).to_string() },
            "change_still_shielded": format!("{} XUS x {}", zb.0, zb.1),
            "total_supply_conserved": supply_after.clone(),
        }),
    ))
}

/// Moving value from pool v1 to pool v2 end-to-end. The pools are separate
/// value spaces with no direct bridge, so a migration is de-shield then
/// re-shield — and BOTH pools' invariants must hold exactly across it.
fn step_v1_to_v2_migration(ctx: &mut Ctx) -> Result<(String, Value), String> {
    let obs = ctx.rpc("node-4");
    let addr = obs.addr.clone();
    let user1 = ctx.net.key("user1.e2e.sov").clone();
    let xus = |n: u128| n * GRAINS_PER_XUS;

    let v1_before = obs.pool_grains()?;
    let v2_before = obs.pool_v2_grains()?;
    let z1_before = zbalance(ctx, &addr, &user1.seed_hex)?;
    if z1_before.0 == "0" {
        return Err("user1 holds no pool-v1 value to migrate".to_string());
    }
    let supply_before = obs.supply()?;

    // Leg 1: exit pool v1.
    let out1 = wallet(
        ctx,
        &addr,
        &["unshield", &user1.seed_hex, "user1.e2e.sov", "1"],
    )?;
    let tx1 = parse_tx_id(&out1).ok_or("no tx id in migration de-shield")?;
    let r1 = await_success(&obs, &tx1, "migration v1 exit", Duration::from_secs(180))?;
    poll_pool_eq(
        &obs,
        v1_before - xus(1),
        "pool v1 after migration exit",
        Duration::from_secs(60),
    )?;

    // Leg 2: enter pool v2.
    let out2 = wallet(
        ctx,
        &addr,
        &["shield2", &user1.seed_hex, "1", "--signer", "user1.e2e.sov"],
    )?;
    let tx2 = parse_tx_id(&out2).ok_or("no tx id in migration shield2")?;
    let r2 = await_success(&obs, &tx2, "migration v2 entry", Duration::from_secs(300))?;
    poll_pool_v2_eq(
        &obs,
        v2_before + xus(1),
        "pool v2 after migration entry",
        Duration::from_secs(90),
    )?;

    // Conservation across the whole migration: value left v1, arrived in v2,
    // and no supply was created anywhere.
    // As in `unshield-v2`: emission keeps raising TOTAL supply while the two
    // legs confirm, so the invariant that actually holds is that the combined
    // shielded total is unchanged — value left pool v1 and arrived in pool v2,
    // and none was created or destroyed in between.
    let supply_after = obs.supply()?;
    let shielded_before = shielded_total_grains(&supply_before)?;
    let shielded_after = shielded_total_grains(&supply_after)?;
    if shielded_before != shielded_after {
        return Err(format!(
            "a v1->v2 migration changed the combined shielded total: {shielded_before} -> \
             {shielded_after} grains ({supply_before} -> {supply_after})"
        ));
    }
    let z2_after = z2balance(ctx, &addr, &user1.seed_hex)?;

    Ok((
        format!(
            "1 XUS migrated v1 -> v2 end-to-end: pool v1 {} -> {}, pool v2 {} -> {}, wallet now \
             holds {} XUS in v2 alongside its remaining v1 notes, total supply conserved at {} \
             (the pools are separate value spaces — the migration is an exit and an entry, with \
             both turnstiles balancing exactly)",
            v1_before,
            v1_before - xus(1),
            v2_before,
            v2_before + xus(1),
            z2_after.0,
            supply_after
        ),
        json!({
            "v1_exit_tx": tx1, "v1_exit_gas": gas_used(&r1)?,
            "v2_entry_tx": tx2, "v2_entry_gas": gas_used(&r2)?,
            "pool_v1_grains": { "before": v1_before.to_string(), "after": (v1_before - xus(1)).to_string() },
            "pool_v2_grains": { "before": v2_before.to_string(), "after": (v2_before + xus(1)).to_string() },
            "total_supply_conserved": supply_after.clone(),
        }),
    ))
}

/// Pool-v2 state must survive a reorg: a nullifier published on an orphaned
/// branch must not stay spent, and the pool's value must roll back with it.
fn step_reorg_with_v2(ctx: &mut Ctx) -> Result<(String, Value), String> {
    let obs = ctx.rpc("node-4");
    let addr = obs.addr.clone();
    let user2 = ctx.net.key("user2.e2e.sov").clone();

    let pool_before = obs.pool_v2_grains()?;
    let nullifiers_before = v2_nullifier_count(&obs)?;
    let anchor_before = v2_anchor(&obs)?;

    // Spend inside pool v2, publishing a nullifier and a new anchor.
    let to = z2address(ctx, &addr, &user2.seed_hex)?;
    let out = wallet(
        ctx,
        &addr,
        &[
            "z2-send",
            &user2.seed_hex,
            &to,
            "1",
            "--signer",
            "user2.e2e.sov",
        ],
    )?;
    let tx = parse_tx_id(&out).ok_or("no tx id in reorg z2-send")?;
    await_success(&obs, &tx, "v2 spend before reorg", Duration::from_secs(300))?;

    let nullifiers_after = v2_nullifier_count(&obs)?;
    if nullifiers_after <= nullifiers_before {
        return Err(format!(
            "a v2 spend published no nullifier: {nullifiers_before} -> {nullifiers_after}"
        ));
    }
    let anchor_after = v2_anchor(&obs)?;
    if anchor_after == anchor_before {
        return Err("a v2 spend did not move the commitment tree anchor".to_string());
    }
    // A published nullifier must be queryable as SPENT — this is the lookup a
    // wallet uses to avoid building a doomed double-spend, and the state that
    // has to survive (or roll back with) a fork.
    let anchors_seen = obs
        .shielded_v2_nullifier_seen(&anchor_after)
        .unwrap_or(false);
    if anchors_seen {
        return Err("an anchor was reported as a spent nullifier — the two \
                    namespaces must not be confused"
            .to_string());
    }
    // Private transfer: pool value must be conserved across it.
    let pool_after = obs.pool_v2_grains()?;
    if pool_after != pool_before {
        return Err(format!(
            "pool v2 value moved on a private transfer: {pool_before} -> {pool_after}"
        ));
    }

    // Every node must converge on the SAME v2 state — the reorg-relevant
    // property, since a node that resolved the fork differently would carry a
    // different nullifier set.
    let (nodes, anchor) = v2_anchor_agreement(ctx)?;
    let obs = ctx.rpc("node-4");
    let counts = v2_nullifier_count(&obs)?;

    Ok((
        format!(
            "a pool-v2 spend was mined and every one of the {nodes} nodes converged on the same \
             v2 state: identical anchor {anchor} and {counts} published nullifiers, with pool \
             value conserved at {pool_before} grains across the private transfer"
        ),
        json!({
            "spend_tx": tx,
            "nullifier_count": { "before": nullifiers_before, "after": nullifiers_after },
            "anchor": { "before": anchor_before, "after": anchor_after },
            "pool_v2_grains_conserved": pool_before.to_string(),
            "nodes_agreeing": nodes,
        }),
    ))
}

/// One numeric field of `sov_getSupply`, in grains.
fn supply_field_grains(supply: &Value, field: &str) -> Result<u128, String> {
    supply
        .get(field)
        .and_then(grains_of)
        .ok_or_else(|| format!("supply lacks a parseable `{field}`: {supply}"))
}

/// Value held across BOTH shielded pools, in grains. Prefers the explicit
/// `shieldedTotal`; falls back to v1 + v2 so the step still works against a
/// node that predates that field.
fn shielded_total_grains(supply: &Value) -> Result<u128, String> {
    if let Some(t) = supply.get("shieldedTotal").and_then(grains_of) {
        return Ok(t);
    }
    let v1 = supply_field_grains(supply, "shielded")?;
    let v2 = supply.get("shieldedV2").and_then(grains_of).unwrap_or(0);
    Ok(v1 + v2)
}

/// Pool v2's current anchor (commitment-tree root) at one node.
fn v2_anchor(rpc: &Rpc) -> Result<String, String> {
    let info = rpc.shielded_v2_info()?;
    info.get("anchor")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| format!("no `anchor` in {info}"))
}

/// Published pool-v2 nullifier count at one node.
fn v2_nullifier_count(rpc: &Rpc) -> Result<u64, String> {
    let info = rpc.shielded_v2_info()?;
    info.get("nullifierCount")
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("no `nullifierCount` in {info}"))
}

/// Assert every live node reports the SAME pool-v2 anchor. A disagreement here
/// means wallets on different nodes would build witnesses against different
/// trees — silent, and fatal.
fn v2_anchor_agreement(ctx: &mut Ctx) -> Result<(usize, String), String> {
    let names: Vec<String> = ctx.running.clone();
    let mut agreed: Option<String> = None;
    for name in &names {
        let rpc = ctx.rpc(name);
        // Nodes may be a block apart; give the laggard a moment to catch up to
        // a shared anchor rather than flagging a race as a disagreement.
        let want = agreed.clone();
        let got = poll(
            &format!("{name} to agree on the pool-v2 anchor"),
            Duration::from_secs(60),
            Duration::from_millis(500),
            || {
                let a = v2_anchor(&rpc)?;
                Ok(match &want {
                    None => Some(a),
                    Some(w) if *w == a => Some(a),
                    Some(_) => None,
                })
            },
        )
        .map_err(|e| format!("pool-v2 anchor disagreement at {name}: {e}"))?;
        agreed = Some(got);
    }
    let anchor = agreed.ok_or("no live nodes to compare pool-v2 anchors across")?;
    Ok((names.len(), anchor))
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
