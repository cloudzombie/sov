//! Generate a fresh SOV wallet (24-word mnemonic) whose account matches sov-station's
//! derivation exactly, WITHOUT ever printing the mnemonic to stdout. The mnemonic is
//! written to the file path given as the first argument (for a secure, off-git note);
//! only the public implicit account id is printed.
//!
//!   cargo run -q --example genwallet -p sov-redteam -- /path/to/secret-note.txt
use std::io::Write;

fn main() {
    let path = std::env::args()
        .nth(1)
        .expect("usage: genwallet <mnemonic-out-path>");
    let mnemonic = sov_wallet::generate_mnemonic(24).expect("generate mnemonic");
    let seed = sov_wallet::HdWallet::from_mnemonic(&mnemonic, "")
        .expect("valid mnemonic")
        .derive_seed(0, 0);
    let account = sov_crypto::Keypair::hybrid_from_seed(seed)
        .public_key()
        .implicit_account_id();
    // Mnemonic → file only; never to stdout.
    let mut f = std::fs::File::create(&path).expect("write note");
    writeln!(f, "MNEMONIC={mnemonic}").expect("write");
    println!("{account}"); // public id only
}
