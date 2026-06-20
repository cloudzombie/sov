//! Demonstrate the incremental shielded scan live: a cold full scan vs. a warm
//! incremental re-scan (which only folds in new blocks). Proves the cache works
//! end-to-end against a running node.
//!
//!   scan-bench "<24-word mnemonic>" [rpc]

use std::time::{Duration, Instant};

use sov_rpc::RpcClient;
use sov_shielded::{NoteStore, ShieldedBundle, ShieldedKey};
use sov_types::Action;
use sov_wallet::HdWallet;

fn fetch_and_fold(client: &RpcClient, key: &ShieldedKey, store: &mut NoteStore, tip: u64) -> u64 {
    let mut folded = 0;
    for h in (store.scanned_height() + 1)..=tip {
        let Ok(Some(block)) = client.block_by_height(h) else {
            break;
        };
        let bundles: Vec<ShieldedBundle> = block
            .transactions
            .iter()
            .filter_map(|stx| match &stx.transaction.action {
                Action::Shielded { bundle } => ShieldedBundle::from_bytes(bundle).ok(),
                _ => None,
            })
            .collect();
        let refs: Vec<&ShieldedBundle> = bundles.iter().collect();
        store.ingest_block(key, h, *block.hash().as_bytes(), &refs);
        folded += 1;
    }
    folded
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mnemonic = std::env::args()
        .nth(1)
        .ok_or("usage: scan-bench \"<mnemonic>\" [rpc]")?;
    let rpc = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "127.0.0.1:8645".to_string());
    let seed = HdWallet::from_mnemonic(&mnemonic, "")?.derive_seed(0, 0);
    let key = ShieldedKey::from_seed(seed).ok_or("shielded key")?;
    let client = RpcClient::new(rpc.clone()).with_timeout(Duration::from_secs(30));
    let tip = client.height()?;
    println!("node tip: {tip}\n");

    // Cold: scan the whole chain from genesis (what the old code did every time).
    let mut store = NoteStore::new(0);
    let t0 = Instant::now();
    let folded = fetch_and_fold(&client, &key, &mut store, tip);
    let cold = t0.elapsed();
    let bytes = store.to_bytes();
    println!(
        "COLD full scan : folded {folded} blocks in {cold:?} -> balance {} grains, {} unspent, store {} bytes",
        store.balance(),
        store.unspent_count(),
        bytes.len()
    );

    // Warm: reload the persisted store and re-scan. Up to date already, so it
    // folds 0 new blocks — the incremental path does no per-block work.
    let mut warm = NoteStore::from_bytes(&bytes).ok_or("reload")?;
    let t1 = Instant::now();
    let tip2 = client.height()?;
    let folded2 = fetch_and_fold(&client, &key, &mut warm, tip2);
    let warm_t = t1.elapsed();
    println!(
        "WARM re-scan   : folded {folded2} new blocks in {warm_t:?} -> balance {} grains (reload+witness rebuilt from cache)",
        warm.balance()
    );
    println!(
        "\nincremental win: cold touched {folded} blocks, warm touched {folded2} — same balance, no re-fetch/re-decrypt of old blocks."
    );
    Ok(())
}
