//! The zero-consensus-surface proof for the `xust1…` checksummed transparent
//! address form (v0.2.11 §3A.3): the checksum lives ONLY at the wallet
//! boundary, so a transfer whose recipient was entered as a checksummed
//! `xust1…` string is BYTE-IDENTICAL on the wire to one whose recipient was
//! pasted as raw 64-hex. The chain cannot tell the difference, no node needs
//! to understand the new form, and no consensus rule is touched.

use sov_crypto::Keypair;
use sov_primitives::{AccountId, Balance};
use sov_shielded::{decode_transparent, encode_transparent, AnyAddress};
use sov_wallet::Wallet;

/// The recipient the 2026-08-06 sweep paid as raw hex — a real implicit id
/// shape (64 lowercase hex chars).
const RAW_HEX: &str = "a35755d3a35755d3a35755d3a35755d3a35755d3a35755d3a35755d34c1e24aa";

#[test]
fn on_wire_transfer_is_byte_identical_for_raw_hex_and_xust1_recipients() {
    // The two entry paths an operator has: paste raw hex, or paste xust1….
    let via_hex = AccountId::new(RAW_HEX).unwrap();
    let xust = encode_transparent(&via_hex).expect("implicit ids always encode");
    let via_checksum = decode_transparent(&xust).unwrap();
    assert_eq!(via_hex, via_checksum, "both paths yield the same AccountId");

    // Build and sign the SAME transfer through each path. Signing is
    // deterministic (Ed25519 + ML-DSA in FIPS 204 deterministic mode), so if
    // the recipient bytes are identical, everything downstream is too.
    let mut wallet = Wallet::new();
    let from = AccountId::new("usa.reserve.sov").unwrap();
    wallet.import(from.clone(), Keypair::from_seed([7u8; 32]));
    let amount = Balance::from_sov(5).unwrap();
    let stx_hex = wallet.transfer(&from, via_hex, amount, 3).unwrap();
    let stx_xust = wallet.transfer(&from, via_checksum, amount, 3).unwrap();

    // The consensus encoding (what a block commits to) is byte-identical…
    assert_eq!(
        borsh::to_vec(&stx_hex).unwrap(),
        borsh::to_vec(&stx_xust).unwrap(),
        "consensus (borsh) bytes must be identical for both entry paths"
    );
    // …the RPC submission payload (`sov_submitTransaction` sends the serde
    // form) is identical…
    assert_eq!(
        serde_json::to_value(&stx_hex).unwrap(),
        serde_json::to_value(&stx_xust).unwrap(),
        "the JSON-RPC submission payload must be identical"
    );
    // …and so is the transaction id the chain will record.
    assert_eq!(stx_hex.id(), stx_xust.id());
}

#[test]
fn any_address_routes_xust1_exactly_like_raw_hex() {
    // The shared parser (used by RpcClient::pay, sov-wallet, and Station)
    // resolves both spellings to the SAME transparent receiver.
    let id = AccountId::new(RAW_HEX).unwrap();
    let xust = encode_transparent(&id).unwrap();
    assert_eq!(
        AnyAddress::parse(RAW_HEX).unwrap(),
        AnyAddress::parse(&xust).unwrap(),
        "raw hex and xust1… must parse to the identical recipient"
    );
}
