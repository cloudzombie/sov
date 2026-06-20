//! Seed-free audit of the shielded pool on a live node: walks every block and
//! decodes each `Action::Shielded` bundle, classifying it by its public value
//! balance and spend/output counts. Reveals what shielded transactions actually
//! happened (shield / transfer / de-shield) without needing any viewing key.
//!
//!   shielded-audit [rpc_addr]   (default 127.0.0.1:8645)

use std::time::Duration;

use sov_rpc::RpcClient;
use sov_shielded::ShieldedBundle;
use sov_types::Action;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let rpc = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:8645".to_string());
    let client = RpcClient::new(rpc.clone()).with_timeout(Duration::from_secs(15));
    let head = client.height()?;
    println!("auditing shielded bundles on {rpc} (head {head})\n");

    let (mut shields, mut transfers, mut deshields) = (0u64, 0u64, 0u64);
    let mut total_commitments = 0u64;
    let mut total_nullifiers = 0u64;

    for h in 1..=head {
        let Some(block) = client.block_by_height(h)? else {
            continue;
        };
        for stx in &block.transactions {
            let Action::Shielded { bundle } = &stx.transaction.action else {
                continue;
            };
            let Ok(b) = ShieldedBundle::from_bytes(bundle) else {
                println!("  block {h}: UNDECODABLE shielded bundle");
                continue;
            };
            let vb = b.value_balance();
            let nfs = b.nullifier_bytes().len();
            let cmx = b.note_commitment_bytes().len();
            total_nullifiers += nfs as u64;
            total_commitments += cmx as u64;
            let kind = if vb < 0 {
                shields += 1;
                "SHIELD     (transparent -> pool)"
            } else if vb > 0 {
                deshields += 1;
                "DE-SHIELD  (pool -> transparent)"
            } else {
                transfers += 1;
                "TRANSFER   (pool -> pool, fully private)"
            };
            println!(
                "  block {h:>5}  signer {:<24}  {kind}  value_balance={vb:>14}  spends(nullifiers)={nfs}  outputs(commitments)={cmx}",
                stx.transaction.signer.to_string(),
            );
        }
    }

    println!("\nsummary:");
    println!("  shields   : {shields}");
    println!("  transfers : {transfers}  (fully-private pool->pool)");
    println!("  de-shields: {deshields}");
    println!("  total commitments added to the tree: {total_commitments}");
    println!("  total nullifiers published (spends) : {total_nullifiers}");
    Ok(())
}
