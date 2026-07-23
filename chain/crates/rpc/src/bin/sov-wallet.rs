//! `sov-wallet` — query balances and submit transfers over JSON-RPC, and derive
//! or restore account keys offline.
//!
//! ```text
//! sov-wallet <rpc_addr> balance  <account>
//! sov-wallet <rpc_addr> transfer <seed_hex> <from> <to> <sov>
//! sov-wallet <rpc_addr> z-balance <seed_hex>
//!     # scan the chain for the seed's SHIELDED notes: note count, per-note
//!     # values, total shielded balance, and the pool's live drain-limiter state
//! sov-wallet <rpc_addr> unshield <seed_hex> <to_transparent_account> <xus> [--ed25519]
//!     # spend shielded notes back to a transparent account (the tx signer —
//!     # it MUST be controlled by the seed's key). Change returns shielded.
//! sov-wallet <rpc_addr> z-send <seed_hex> <to: xus1…|uxus1…> <xus>
//!     [--signer <account>] [--ed25519]
//!     # fully-private shielded → shielded transfer with shielded change; the
//!     # carrier tx is signed by --signer (default: the seed's implicit account)
//! sov-wallet new [account-name] [--words 12|24] [--ed25519]
//!     # offline: generate a FRESH account — a new mnemonic (printed for your eyes
//!     # only) + its public key. Share only the public_key; keep the mnemonic secret.
//! sov-wallet keygen <seed_hex> [account-name] [--ed25519]
//!     # offline: derive the key bundle (public_key + shielded + unified) a seed controls
//! sov-wallet import "<12/24-word mnemonic>" [account-name]
//!     [--account N] [--index N] [--passphrase P] [--ed25519]
//!     # offline: restore a wallet from a BIP-39 phrase via the standard SOV
//!     # BIP-44 path m/44'/SOV'/account'/0'/index'. DEFAULT is the hybrid
//!     # post-quantum key; the same phrase always restores the same wallet.
//! ```

use std::error::Error;
use std::time::{Duration, Instant};
use std::{env, process};

use serde_json::{json, Value};
use sov_crypto::Keypair;
use sov_primitives::{AccountId, Balance, Hash, GRAINS_PER_SOV};
use sov_rpc::RpcClient;
use sov_shielded::{
    encode_shielded, shielded_transfer_with_change, unshield_amount_multi, AnyAddress, NoteStore,
    Receiver, ShieldedBundle, ShieldedKey, ShieldedParams,
};
use sov_types::{Action, SignedTransaction, Transaction};
use sov_wallet::{HdWallet, SOV_COIN_TYPE};

fn main() {
    if let Err(e) = run() {
        eprintln!("sov-wallet: {e}");
        process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();

    // `keygen` is an OFFLINE command (no running node): derive the key bundle a
    // chain-spec account lists from its 32-byte signing seed. The same seed goes
    // in the node's keystore, so the two always correspond.
    if args.get(1).map(String::as_str) == Some("keygen") {
        let seed_hex = args
            .get(2)
            .ok_or("usage: sov-wallet keygen <seed_hex> [account-name] [--ed25519]")?;
        let seed: [u8; 32] = hex::decode(seed_hex)?
            .try_into()
            .map_err(|_| "seed must be 32 bytes of hex".to_string())?;
        let legacy = args.iter().any(|a| a == "--ed25519");
        let account_name = args
            .get(3)
            .filter(|a| !a.starts_with("--"))
            .map(String::as_str);
        print_account_keys(seed, legacy, account_name)?;
        return Ok(());
    }

    // `import` is an OFFLINE command: restore a wallet from an existing BIP-39
    // mnemonic (12/24 words). It derives the deterministic SLIP-0010 leaf at the
    // standard SOV BIP-44 path `m/44'/SOV'/account'/0'/index'` and prints the same
    // key bundle as `keygen`. The DEFAULT is the hybrid post-quantum key, so the
    // restored wallet is quantum-resistant; the same phrase always restores the
    // same keys, byte-for-byte, every time.
    if args.get(1).map(String::as_str) == Some("import") {
        let mnemonic = args.get(2).ok_or(
            "usage: sov-wallet import \"<12/24-word mnemonic>\" [account-name] \
             [--account N] [--index N] [--passphrase P] [--ed25519]",
        )?;
        let legacy = args.iter().any(|a| a == "--ed25519");
        let account = flag_u32(&args, "--account")?.unwrap_or(0);
        let index = flag_u32(&args, "--index")?.unwrap_or(0);
        let passphrase = flag_value(&args, "--passphrase").unwrap_or_default();
        let account_name = args
            .get(3)
            .filter(|a| !a.starts_with("--"))
            .map(String::as_str);
        // Rejects an invalid phrase (wordlist or checksum) before deriving anything.
        let wallet = HdWallet::from_mnemonic(mnemonic, &passphrase)
            .map_err(|e| format!("cannot restore wallet: {e}"))?;
        let seed = wallet.derive_seed(account, index);
        println!("path       : m/44'/{SOV_COIN_TYPE}'/{account}'/0'/{index}'");
        print_account_keys(seed, legacy, account_name)?;
        return Ok(());
    }

    // `new` is an OFFLINE command: generate a FRESH account entirely locally — a
    // brand-new BIP-39 mnemonic from OS entropy, plus the keys it derives. The
    // mnemonic is the SECRET backup; it is printed for your eyes only and never
    // leaves this machine. Share only the `public_key` line. Default scheme is the
    // hybrid post-quantum key; `--words 12` for a shorter phrase; `--ed25519` for
    // a legacy key. Recover the identical wallet later with `sov-wallet import`.
    if args.get(1).map(String::as_str) == Some("new") {
        let words = flag_u32(&args, "--words")?.unwrap_or(24) as usize;
        let legacy = args.iter().any(|a| a == "--ed25519");
        let account_name = args
            .get(2)
            .filter(|a| !a.starts_with("--"))
            .map(String::as_str);
        let mnemonic = sov_wallet::generate_mnemonic(words)
            .map_err(|e| format!("cannot generate mnemonic: {e}"))?;
        // Derive from the fresh phrase at the standard SOV account path.
        let wallet = HdWallet::from_mnemonic(&mnemonic, "")
            .map_err(|e| format!("generated mnemonic failed to derive: {e}"))?;
        let seed = wallet.derive_seed(0, 0);
        println!("================= SECRET — WRITE THIS DOWN, NEVER SHARE =================");
        println!("mnemonic ({words} words) — the ONLY backup; whoever holds it owns the account:");
        println!("  {mnemonic}");
        println!("========================================================================");
        println!();
        println!("PUBLIC — safe to share; this is what gets registered/hardcoded on-chain:");
        println!("path       : m/44'/{SOV_COIN_TYPE}'/0'/0'/0'");
        print_account_keys(seed, legacy, account_name)?;
        println!();
        println!("Recover this exact wallet any time, on any machine, with:");
        match account_name {
            Some(n) => println!("  sov-wallet import \"<the mnemonic above>\" {n}"),
            None => println!("  sov-wallet import \"<the mnemonic above>\""),
        }
        return Ok(());
    }

    let addr = args.get(1).ok_or(
        "usage: sov-wallet <rpc_addr> <balance|transfer|z-balance|unshield|z-send|keygen> ...",
    )?;
    let command = args
        .get(2)
        .ok_or("expected a command: balance | transfer | z-balance | unshield | z-send")?;
    let client = RpcClient::new(addr.clone());

    match command.as_str() {
        "balance" => {
            let account = AccountId::new(args.get(3).ok_or("usage: balance <account>")?)?;
            println!("{account}: {}", client.balance(&account)?);
        }
        "transfer" => {
            let seed_hex = args.get(3).ok_or(
                "usage: transfer <seed_hex> <from> <to: name|xus1…|uxus1…> <xus> [--ed25519]",
            )?;
            let seed: [u8; 32] = hex::decode(seed_hex)?
                .try_into()
                .map_err(|_| "seed must be 32 bytes of hex".to_string())?;
            // Hybrid post-quantum is the default; --ed25519 signs legacy.
            let keypair = if args.iter().any(|a| a == "--ed25519") {
                Keypair::from_seed(seed)
            } else {
                Keypair::hybrid_from_seed(seed)
            };
            let from = AccountId::new(args.get(4).ok_or("missing <from> account")?)?;
            // The recipient is ANY address tier: a named account, a xus1…
            // shielded address, or a uxus1… unified address (routed
            // privacy-first — shielded when the address carries a receiver).
            let to = args.get(5).ok_or("missing <to> address")?;
            let sov: u128 = args.get(6).ok_or("missing <xus> amount")?.parse()?;
            let amount = Balance::from_sov(sov)?;

            let parsed = sov_shielded::AnyAddress::parse(to)
                .map_err(|e| format!("invalid recipient `{to}`: {e}"))?;
            let shielded_route = matches!(parsed.receiver(), sov_shielded::Receiver::Shielded(_));
            let params = if shielded_route {
                println!("recipient routes to the SHIELDED pool — building the Halo2 prover (one-time, then proving; ~30s total)...");
                Some(sov_shielded::ShieldedParams::build())
            } else {
                None
            };
            let tx_id = client.pay(&keypair, &from, to, amount, params.as_ref())?;
            println!(
                "submitted: {from} -> {to} {sov} XUS (tx {})",
                tx_id.to_hex()
            );
        }
        // Scan the chain for the seed's shielded notes and report the private
        // balance next to the pool's live drain-limiter state. Read-only.
        "z-balance" => {
            let seed = seed_arg(&args, 3, "usage: z-balance <seed_hex>")?;
            let zkey = ShieldedKey::from_seed(seed).ok_or("shielded key derivation failed")?;
            // Scan with a generous per-call timeout: block fetches are chunky.
            let client = RpcClient::new(addr.clone()).with_timeout(Duration::from_secs(30));
            let store = scan_notes(&client, &zkey)?;
            println!("shielded address : {}", encode_shielded(&zkey.address()));
            println!("scanned height   : {}", store.scanned_height());
            let unspent = store.unspent();
            println!("unspent notes    : {}", unspent.len());
            let mut values: Vec<u64> = unspent.iter().map(|(n, _)| n.value()).collect();
            values.sort_unstable_by(|a, b| b.cmp(a));
            for (i, v) in values.iter().enumerate() {
                println!("  note {:<3}       : {} XUS", i + 1, xus(u128::from(*v)));
            }
            println!(
                "shielded balance : {} XUS",
                xus(u128::from(store.balance()))
            );
            print_shielded_info(&client)?;
        }
        // De-shield: spend shielded notes back to a transparent account (the
        // carrier-tx signer, which the chain credits with the de-shielded value).
        // Mirrors SOV Station: largest-first selection, one multi-spend bundle,
        // shielded change back to the own z-address, receipt-confirmed.
        "unshield" => {
            let usage = "usage: unshield <seed_hex> <to_transparent_account> <xus> [--ed25519]";
            let seed = seed_arg(&args, 3, usage)?;
            let account = AccountId::new(args.get(4).ok_or(usage)?)?;
            let sov: u128 = args.get(5).ok_or(usage)?.parse()?;
            let amount = Balance::from_sov(sov)?;
            let amount_grains = u64::try_from(amount.grains()).map_err(|_| "amount too large")?;
            let keypair = keypair_from(seed, args.iter().any(|a| a == "--ed25519"));
            let client = RpcClient::new(addr.clone()).with_timeout(Duration::from_secs(90));

            // Pre-check the pool's per-window drain budget: a de-shield over it
            // would be mined and REJECTED on-chain, so fail early instead.
            if let Some(info) = shielded_info(&client) {
                if let Some(budget) = info_grains(&info, "deshieldableNowGrains") {
                    if amount.grains() > budget {
                        let resets = info
                            .get("windowResetsAtHeight")
                            .and_then(Value::as_u64)
                            .unwrap_or(0);
                        return Err(format!(
                            "only {} XUS can be de-shielded in the current window \
                             (per-window drain limit; window resets at height {resets}) — \
                             reduce the amount or wait for the reset",
                            xus(budget),
                        )
                        .into());
                    }
                }
            }

            let zkey = ShieldedKey::from_seed(seed).ok_or("shielded key derivation failed")?;
            let store = scan_notes(&client, &zkey)?;
            if u128::from(store.balance()) < amount.grains() {
                return Err(format!(
                    "insufficient shielded balance: {} XUS available, {sov} XUS requested",
                    xus(u128::from(store.balance())),
                )
                .into());
            }
            // Coin selection (as in SOV Station): accumulate notes LARGEST-first
            // until they cover the amount, then spend them all in ONE bundle.
            // Capped at MAX_DESHIELD_NOTES to bound proof time + tx size; if the
            // cap can't cover the request, de-shield what it holds this round and
            // leave the rest shielded for a follow-up — value is paced, not trapped.
            const MAX_DESHIELD_NOTES: usize = 32;
            let unspent = store.unspent();
            let mut ranked: Vec<_> = unspent.iter().collect();
            ranked.sort_by_key(|it| std::cmp::Reverse(it.0.value()));
            let mut selected = Vec::new();
            let mut acc: u64 = 0;
            let mut anchor_opt = None;
            for (n, pos) in ranked.into_iter().take(MAX_DESHIELD_NOTES) {
                let (path, anchor) = store.witness(*pos).ok_or("could not witness a note")?;
                anchor_opt = Some(anchor);
                acc = acc.saturating_add(n.value());
                selected.push((n.clone(), path));
                if acc >= amount_grains {
                    break;
                }
            }
            let anchor = anchor_opt.ok_or("no unspent shielded notes to de-shield")?;
            let effective = amount_grains.min(acc);
            if effective < amount_grains {
                println!(
                    "note cap: de-shielding {} XUS this round (the largest \
                     {MAX_DESHIELD_NOTES} notes) — run again for the remainder",
                    xus(u128::from(effective)),
                );
            }
            println!(
                "proving the de-shield of {} note(s) — building the Halo2 prover \
                 then proving (~30s total)...",
                selected.len()
            );
            let params = ShieldedParams::build();
            let bundle = unshield_amount_multi(&params, &zkey, &selected, anchor, effective)
                .map_err(|e| e.to_string())?;
            let txid = submit_shielded_bundle(&client, &keypair, &account, &bundle)?;
            println!("submitted — waiting for on-chain confirmation...");
            await_receipt(&client, &txid, 90)?;
            println!(
                "unshielded {} XUS -> {account} (tx {})",
                xus(u128::from(effective)),
                txid.to_hex()
            );
        }
        // Fully-private shielded → shielded transfer: spend ONE of the seed's
        // notes to a xus1…/uxus1… recipient, with private change back to the
        // sender. Sender, recipient, and amount all stay in the pool; only the
        // fee-paying carrier tx (value_balance = 0) is visible on-chain.
        "z-send" => {
            let usage =
                "usage: z-send <seed_hex> <to: xus1…|uxus1…> <xus> [--signer <account>] [--ed25519]";
            let seed = seed_arg(&args, 3, usage)?;
            let to = args.get(4).ok_or(usage)?;
            let sov: u128 = args.get(5).ok_or(usage)?.parse()?;
            let amount = Balance::from_sov(sov)?;
            let amount_grains = u64::try_from(amount.grains()).map_err(|_| "amount too large")?;
            let keypair = keypair_from(seed, args.iter().any(|a| a == "--ed25519"));
            // The recipient must carry a SHIELDED receiver (privacy-first for a
            // unified address) — a transparent target belongs to `transfer`.
            let recipient_addr = match AnyAddress::parse(to)
                .map_err(|e| format!("invalid recipient `{to}`: {e}"))?
                .receiver()
            {
                Receiver::Shielded(a) => a,
                Receiver::Transparent(_) => {
                    return Err(
                        "recipient must be a shielded (xus1…) or unified (uxus1…) address; \
                         use `transfer` for transparent sends"
                            .into(),
                    )
                }
            };
            // The transparent account that carries (and pays the fee for) the tx;
            // it MUST be controlled by the seed's key. Default: the implicit id.
            let signer = match flag_value(&args, "--signer") {
                Some(s) => AccountId::new(&s)?,
                None => keypair.public_key().implicit_account_id(),
            };
            let client = RpcClient::new(addr.clone()).with_timeout(Duration::from_secs(90));
            let zkey = ShieldedKey::from_seed(seed).ok_or("shielded key derivation failed")?;
            let store = scan_notes(&client, &zkey)?;
            // A private spend consumes ONE note: pick the smallest unspent note
            // that covers the amount (minimizes change); fail clearly otherwise.
            let unspent = store.unspent();
            let (note, pos) = unspent
                .iter()
                .filter(|(n, _)| n.value() >= amount_grains)
                .min_by_key(|(n, _)| n.value())
                .ok_or_else(|| {
                    let largest = unspent.iter().map(|(n, _)| n.value()).max().unwrap_or(0);
                    format!(
                        "no single shielded note covers {sov} XUS (largest note is {} XUS) — \
                         consolidate first (unshield, then re-shield)",
                        xus(u128::from(largest)),
                    )
                })?;
            let (path, anchor) = store.witness(*pos).ok_or("could not witness the note")?;
            println!(
                "proving the private transfer — building the Halo2 prover then \
                 proving (~30s total)..."
            );
            let params = ShieldedParams::build();
            let bundle = shielded_transfer_with_change(
                &params,
                &zkey,
                note,
                path,
                anchor,
                &recipient_addr,
                amount_grains,
            )
            .map_err(|e| e.to_string())?;
            let txid = submit_shielded_bundle(&client, &keypair, &signer, &bundle)?;
            println!("submitted (carrier signer {signer}) — waiting for on-chain confirmation...");
            await_receipt(&client, &txid, 90)?;
            println!("z-sent {sov} XUS -> {to} (tx {})", txid.to_hex());
        }
        other => {
            return Err(format!(
                "unknown command `{other}` (expected balance | transfer | z-balance | \
                 unshield | z-send)"
            )
            .into());
        }
    }
    Ok(())
}

/// Parse the 32-byte hex seed at positional `idx` (seeds only ever travel via
/// argv and are never echoed back).
fn seed_arg(args: &[String], idx: usize, usage: &str) -> Result<[u8; 32], Box<dyn Error>> {
    let seed_hex = args.get(idx).ok_or(usage)?;
    Ok(hex::decode(seed_hex)?
        .try_into()
        .map_err(|_| "seed must be 32 bytes of hex".to_string())?)
}

/// The signing keypair a seed controls: hybrid post-quantum by default,
/// `--ed25519` for a legacy key — matching `transfer` and `keygen`.
fn keypair_from(seed: [u8; 32], legacy: bool) -> Keypair {
    if legacy {
        Keypair::from_seed(seed)
    } else {
        Keypair::hybrid_from_seed(seed)
    }
}

/// Render `grains` as a plain XUS decimal (trailing zeros trimmed).
fn xus(grains: u128) -> String {
    let whole = grains / GRAINS_PER_SOV;
    let frac = grains % GRAINS_PER_SOV;
    if frac == 0 {
        format!("{whole}")
    } else {
        let s = format!("{frac:08}");
        format!("{whole}.{}", s.trim_end_matches('0'))
    }
}

/// Whether a receipt JSON value (as returned by `sov_getReceipt` /
/// `sov_getBlockReceipts`) records a SUCCESSFUL execution — the same fail-closed
/// check SOV Station uses: anything not explicitly successful is skipped.
fn receipt_succeeded(v: &Value) -> bool {
    v.get("status")
        .and_then(|s| s.get("status"))
        .and_then(Value::as_str)
        == Some("success")
}

/// Scan the whole chain for `zkey`'s shielded notes, exactly as SOV Station does:
/// fetch each block plus its receipts, keep ONLY shielded bundles whose
/// transaction actually APPLIED (a mined-but-rejected bundle must never credit
/// notes the chain refused), and fold them through [`NoteStore::ingest_block`] —
/// which also tracks nullifiers, so SPENT notes drop out of `unspent()`.
///
/// The CLI scans fresh from genesis every run (no cache file): deterministic,
/// stateless, and immune to reorg-stale caches; cost is one pass over the chain.
fn scan_notes(client: &RpcClient, zkey: &ShieldedKey) -> Result<NoteStore, Box<dyn Error>> {
    let tip = client.height()?;
    let mut store = NoteStore::new(0);
    if tip > 0 {
        println!("scanning blocks 1..={tip} for shielded notes...");
    }
    for h in 1..=tip {
        let block = client
            .block_by_height(h)?
            .ok_or_else(|| format!("block {h} unavailable — re-run to rescan"))?;
        let receipts = client.call("sov_getBlockReceipts", json!({ "height": h }))?;
        let receipts = receipts.as_array();
        let bundles: Vec<ShieldedBundle> = block
            .transactions
            .iter()
            .enumerate()
            .filter_map(|(i, stx)| match &stx.transaction.action {
                Action::Shielded { bundle }
                    if receipts
                        .and_then(|rs| rs.get(i))
                        .map(receipt_succeeded)
                        .unwrap_or(false) =>
                {
                    ShieldedBundle::from_bytes(bundle).ok()
                }
                _ => None,
            })
            .collect();
        let refs: Vec<&ShieldedBundle> = bundles.iter().collect();
        store.ingest_block(zkey, h, *block.hash().as_bytes(), &refs);
    }
    Ok(store)
}

/// The pool's `sov_getShieldedInfo` snapshot, or `None` on an older node that
/// does not serve it (callers then skip the pre-check rather than block).
fn shielded_info(client: &RpcClient) -> Option<Value> {
    client.call("sov_getShieldedInfo", json!({})).ok()
}

/// A stringified-grains field of the shielded-info snapshot, parsed.
fn info_grains(info: &Value, field: &str) -> Option<u128> {
    info.get(field)
        .and_then(Value::as_str)
        .and_then(|s| s.parse::<u128>().ok())
}

/// Print the pool summary + live de-shield drain-limiter state.
fn print_shielded_info(client: &RpcClient) -> Result<(), Box<dyn Error>> {
    let Some(info) = shielded_info(client) else {
        println!("pool info        : unavailable (node does not serve sov_getShieldedInfo)");
        return Ok(());
    };
    let pool: Balance = serde_json::from_value(info.get("poolValue").cloned().unwrap_or_default())
        .unwrap_or(Balance::ZERO);
    println!("pool value       : {pool}");
    if let Some(now) = info_grains(&info, "deshieldableNowGrains") {
        println!("deshieldable now : {} XUS", xus(now));
    }
    if let (Some(limit), Some(window), Some(resets)) = (
        info_grains(&info, "deshieldLimitGrains"),
        info.get("deshieldWindowBlocks").and_then(Value::as_u64),
        info.get("windowResetsAtHeight").and_then(Value::as_u64),
    ) {
        if window == 0 {
            println!("drain limiter    : off (no per-window cap)");
        } else {
            println!(
                "drain limiter    : {} XUS per {window} blocks (window resets at height {resets})",
                xus(limit),
            );
        }
    }
    Ok(())
}

/// Wrap a proved shielded `bundle` in a carrier transaction signed by `signer`'s
/// keypair and submit it: queue-aware next nonce + Phase-2 signing domain (`None`
/// = dormant/legacy), exactly as SOV Station submits shielded actions.
fn submit_shielded_bundle(
    client: &RpcClient,
    keypair: &Keypair,
    signer: &AccountId,
    bundle: &ShieldedBundle,
) -> Result<Hash, Box<dyn Error>> {
    let nonce = client.next_nonce(signer)?;
    let domain = client.signing_domain()?;
    let tx = Transaction {
        signer: signer.clone(),
        public_key: keypair.public_key(),
        nonce,
        action: Action::Shielded {
            bundle: bundle.to_bytes(),
        },
    };
    let stx = SignedTransaction::sign_in(tx, keypair, domain.as_ref())?;
    Ok(client.submit_transaction(&stx)?)
}

/// Poll for `txid`'s receipt until it is mined, returning `Ok(())` only when it
/// actually APPLIED on-chain, or the on-chain failure reason (e.g. the de-shield
/// drain limit) — so a rejected-but-included transaction is never reported as
/// confirmed.
fn await_receipt(client: &RpcClient, txid: &Hash, secs: u64) -> Result<(), Box<dyn Error>> {
    let deadline = Instant::now() + Duration::from_secs(secs);
    loop {
        if let Ok(v) = client.call("sov_getReceipt", json!({ "txId": txid.to_hex() })) {
            let status = v.get("status");
            match status.and_then(|s| s.get("status")).and_then(Value::as_str) {
                Some("success") => return Ok(()),
                Some("failed") => {
                    let reason = status
                        .and_then(|s| s.get("reason"))
                        .and_then(Value::as_str)
                        .unwrap_or("rejected on-chain");
                    return Err(reason.to_string().into());
                }
                _ => {} // not mined yet
            }
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "tx {} still pending (not yet mined) — check the receipt shortly",
                txid.to_hex()
            )
            .into());
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}

/// Print the full key bundle a 32-byte seed controls — the shared output of both
/// `keygen` (raw seed) and `import` (mnemonic-derived seed). All three address
/// tiers come from this one seed:
///   - the signing **public_key** (hybrid post-quantum by default — the value a
///     named account registers as its controlling key; `--ed25519` for legacy);
///   - the **shielded** `xus1…` Orchard receiver (the private pool);
///   - the **unified** `uxus1…` address (carries both; senders route
///     privacy-first), emitted when an account name is supplied.
///
/// The `seed_hex` is printed so it can be placed in a node keystore verbatim.
fn print_account_keys(
    seed: [u8; 32],
    legacy: bool,
    account_name: Option<&str>,
) -> Result<(), Box<dyn Error>> {
    let keypair = if legacy {
        Keypair::from_seed(seed)
    } else {
        Keypair::hybrid_from_seed(seed)
    };
    let key = keypair.public_key();
    println!("seed_hex   : {}", hex::encode(seed));
    println!("scheme     : {}", key.scheme());
    println!(
        "public_key : {}",
        serde_json::to_value(key)?.as_str().unwrap_or_default()
    );
    let zkey =
        sov_shielded::ShieldedKey::from_seed(seed).ok_or("shielded key derivation failed")?;
    println!(
        "shielded   : {}",
        sov_shielded::encode_shielded(&zkey.address())
    );
    if let Some(name) = account_name {
        let account = AccountId::new(name)?;
        let ua = sov_shielded::UnifiedAddress::new(Some(account), Some(zkey.address()))
            .map_err(|e| format!("unified address: {e}"))?;
        println!("unified    : {}", ua.encode());
    }
    Ok(())
}

/// The value following `--flag` in `args`, if present (a simple `--key value`).
fn flag_value(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

/// Parse a `--flag N` as a `u32`, if the flag is present.
fn flag_u32(args: &[String], flag: &str) -> Result<Option<u32>, Box<dyn Error>> {
    match flag_value(args, flag) {
        Some(v) => Ok(Some(v.parse().map_err(|e| format!("{flag}: {e}"))?)),
        None => Ok(None),
    }
}
