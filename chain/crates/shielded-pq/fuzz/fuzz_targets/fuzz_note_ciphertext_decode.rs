//! Arbitrary bytes → the TOTAL note-ciphertext decoder and the note
//! plaintext parser (S1c).
//!
//! Oracles: neither decoder may panic; accepted ciphertext encodings must
//! re-encode byte-identically.

#![no_main]

use libfuzzer_sys::fuzz_target;
use sov_shielded_pq::note::Note;
use sov_shielded_pq::wire::{decode_note_ciphertext, encode_note_ciphertext};

fuzz_target!(|data: &[u8]| {
    if let Ok(ct) = decode_note_ciphertext(data) {
        assert_eq!(
            encode_note_ciphertext(&ct),
            data,
            "note-ciphertext encoding accepted a non-canonical form"
        );
    }
    // The 72-byte note plaintext parser is total as well (Option-typed).
    if data.len() >= 72 {
        let plaintext: [u8; 72] = data[..72].try_into().expect("72 bytes");
        let _ = Note::from_plaintext(&plaintext);
    }
});
