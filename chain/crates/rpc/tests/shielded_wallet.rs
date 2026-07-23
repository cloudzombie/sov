//! End-to-end SHIELDED-lifecycle smoke test for the `sov-wallet` CLI: drives the
//! REAL binary (`CARGO_BIN_EXE_sov-wallet`) against a live [`Daemon`] through the
//! full z-lifecycle — shield (`transfer` to a `xus1…` address) → `z-balance`
//! shows the note → `unshield` back to the transparent account → `z-balance`
//! shows the spend + change → `z-send` to a second wallet — asserting balances
//! at every step.
//!
//! Marked `#[ignore]`: every shielded CLI step builds the Halo2 prover and
//! produces a real proof, which is minutes-slow in a debug build. Run it in
//! release, where the whole round-trip is well under a minute of proving:
//!
//! ```text
//! cargo test --release -p sov-rpc --test shielded_wallet -- --ignored --nocapture
//! ```

use std::path::PathBuf;
use std::process::{Child, Command, Output};
use std::time::{Duration, Instant};

use sov_chain::{GenesisAccount, GenesisConfig};
use sov_crypto::Keypair;
use sov_primitives::{AccountId, Balance};
use sov_rpc::{Daemon, RpcClient};
use sov_shielded::{encode_shielded, ShieldedKey};

/// The funded treasury wallet (hybrid key, genesis-bound) the test shields from.
const USA_SEED: [u8; 32] = [7; 32];
/// A second, empty wallet — the `z-send` recipient.
const BOB_SEED: [u8; 32] = [8; 32];
/// The daemon's miner keystore account.
const VAL01_SEED: [u8; 32] = [1; 32];

fn id(s: &str) -> AccountId {
    AccountId::new(s).unwrap()
}

fn unique_dir() -> PathBuf {
    std::env::temp_dir().join(format!(
        "sov-zwallet-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ))
}

fn genesis() -> GenesisConfig {
    GenesisConfig {
        chain_id: "sov-zwallet-test".into(),
        timestamp_ms: 1_000,
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
        mining: sov_mining::MiningPolicy::test(),
        vesting: vec![],
    }
}

/// Run the sov-wallet binary to completion, mining a block whenever its
/// transaction lands in the mempool (the CLI waits for on-chain receipts, so
/// someone must produce blocks while it polls). Returns the captured output.
fn wallet(daemon: &Daemon, client: &RpcClient, args: &[&str]) -> Output {
    let mut child: Child = Command::new(env!("CARGO_BIN_EXE_sov-wallet"))
        .args(args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn sov-wallet");
    // Prover build + proving can take minutes in debug; be generous.
    let deadline = Instant::now() + Duration::from_secs(1_800);
    loop {
        if let Some(_status) = child.try_wait().expect("wait on sov-wallet") {
            let out = child.wait_with_output().expect("collect sov-wallet output");
            println!(
                "--- sov-wallet {:?}\n{}{}",
                args.first().map(|_| args.join(" ")).unwrap_or_default(),
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr),
            );
            return out;
        }
        if client.mempool_size().unwrap_or(0) > 0 {
            produce(daemon, client);
        }
        assert!(Instant::now() < deadline, "sov-wallet timed out: {args:?}");
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// Mine one block at a timestamp strictly after the current head's (the chain
/// enforces monotonic timestamps).
fn produce(daemon: &Daemon, client: &RpcClient) {
    let ts = client.head().expect("head").header.timestamp_ms + 2_000;
    daemon.produce_once(ts).expect("produce block");
}

fn stdout(out: &Output) -> String {
    assert!(
        out.status.success(),
        "sov-wallet failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
#[ignore = "heavy: builds the Halo2 prover + real proofs three times — run in release"]
fn shielded_lifecycle_round_trip_via_the_cli() {
    let dir = unique_dir();
    let _ = std::fs::remove_dir_all(&dir);
    let daemon = Daemon::new(
        &genesis(),
        &dir,
        1024,
        256,
        vec![(id("val01.node.sov"), Keypair::hybrid_from_seed(VAL01_SEED))],
    )
    .unwrap();
    let rpc = daemon.serve_rpc("127.0.0.1:0", 2).unwrap();
    let addr = rpc.local_addr().to_string();
    let client = RpcClient::new(addr.clone());

    let usa_seed_hex = hex::encode(USA_SEED);
    let usa_z = encode_shielded(&ShieldedKey::from_seed(USA_SEED).unwrap().address());
    let bob_seed_hex = hex::encode(BOB_SEED);
    let bob_z = encode_shielded(&ShieldedKey::from_seed(BOB_SEED).unwrap().address());

    // --- 1. SHIELD: transfer 40 XUS from the transparent treasury into the pool.
    let out = wallet(
        &daemon,
        &client,
        &[
            &addr,
            "transfer",
            &usa_seed_hex,
            "usa.reserve.sov",
            &usa_z,
            "40",
        ],
    );
    stdout(&out);
    // The shield may still be in the mempool when the CLI returns (transfer does
    // not wait for a receipt) — mine until it lands.
    while client.mempool_size().unwrap() > 0 {
        produce(&daemon, &client);
    }
    assert_eq!(
        client.balance(&id("usa.reserve.sov")).unwrap(),
        Balance::from_sov(960).unwrap(),
        "shielding debits the transparent account"
    );

    // --- 2. Z-BALANCE: the wallet sees exactly one 40-XUS unspent note.
    let out = stdout(&wallet(
        &daemon,
        &client,
        &[&addr, "z-balance", &usa_seed_hex],
    ));
    assert!(out.contains("unspent notes    : 1"), "{out}");
    assert!(out.contains("shielded balance : 40 XUS"), "{out}");
    assert!(out.contains("pool value       : 40"), "{out}");

    // --- 3. UNSHIELD 15 XUS back to the treasury (change stays shielded).
    let out = stdout(&wallet(
        &daemon,
        &client,
        &[&addr, "unshield", &usa_seed_hex, "usa.reserve.sov", "15"],
    ));
    assert!(
        out.contains("unshielded 15 XUS -> usa.reserve.sov"),
        "{out}"
    );
    assert_eq!(
        client.balance(&id("usa.reserve.sov")).unwrap(),
        Balance::from_sov(975).unwrap(),
        "the de-shielded value credits the transparent account"
    );

    // --- 4. Z-BALANCE: the 40-XUS note is SPENT; a 25-XUS change note remains.
    let out = stdout(&wallet(
        &daemon,
        &client,
        &[&addr, "z-balance", &usa_seed_hex],
    ));
    assert!(out.contains("unspent notes    : 1"), "{out}");
    assert!(out.contains("shielded balance : 25 XUS"), "{out}");

    // --- 5. Z-SEND 10 XUS fully privately to Bob's shielded address; the
    // treasury account only carries (signs) the value-balance-zero tx.
    let out = stdout(&wallet(
        &daemon,
        &client,
        &[
            &addr,
            "z-send",
            &usa_seed_hex,
            &bob_z,
            "10",
            "--signer",
            "usa.reserve.sov",
        ],
    ));
    assert!(out.contains("z-sent 10 XUS"), "{out}");

    // Sender keeps a 15-XUS change note; Bob received a 10-XUS note; the pool
    // still holds 25 XUS total and the transparent balance is untouched.
    let out = stdout(&wallet(
        &daemon,
        &client,
        &[&addr, "z-balance", &usa_seed_hex],
    ));
    assert!(out.contains("shielded balance : 15 XUS"), "{out}");
    let out = stdout(&wallet(
        &daemon,
        &client,
        &[&addr, "z-balance", &bob_seed_hex],
    ));
    assert!(out.contains("unspent notes    : 1"), "{out}");
    assert!(out.contains("shielded balance : 10 XUS"), "{out}");
    assert_eq!(
        client.balance(&id("usa.reserve.sov")).unwrap(),
        Balance::from_sov(975).unwrap(),
        "a z-send moves no transparent value"
    );

    rpc.shutdown();
    let _ = std::fs::remove_dir_all(&dir);
}
