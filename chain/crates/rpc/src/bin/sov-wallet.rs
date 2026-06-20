//! `sov-wallet` — query balances and submit transfers over JSON-RPC, and derive
//! or restore account keys offline.
//!
//! ```text
//! sov-wallet <rpc_addr> balance  <account>
//! sov-wallet <rpc_addr> transfer <seed_hex> <from> <to> <sov>
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
use std::{env, process};

use sov_crypto::Keypair;
use sov_primitives::{AccountId, Balance};
use sov_rpc::RpcClient;
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

    let addr = args
        .get(1)
        .ok_or("usage: sov-wallet <rpc_addr> <balance|transfer|keygen> ...")?;
    let command = args
        .get(2)
        .ok_or("expected a command: balance | transfer")?;
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
        other => {
            return Err(format!("unknown command `{other}` (expected balance | transfer)").into());
        }
    }
    Ok(())
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
