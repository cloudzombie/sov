//! Share gossip: the wire format, and the rules that make hostile input boring.
//!
//! # Why this is a separate channel, not a new `NetMessage`
//!
//! Shares could have been added to `sov-network`'s [`NetMessage`] enum. They are
//! deliberately not. That enum is decoded by the transport every consensus peer
//! depends on for block and transaction relay, and putting a second, unrelated
//! protocol through the same decoder widens the blast radius of a bug here from
//! "the pool misbehaves" to "block relay misbehaves".
//!
//! Instead the sharechain listens on its **own port** with its **own** message
//! type, and reuses `sov_network::PqChannel` — the same Noise + ML-KEM sealing
//! the node uses — for the bytes on the wire. The cryptography is reused; the
//! decoder is not shared. That is what "its own logical channel" means in
//! `notes/activation-pool-mining.md`.
//!
//! # What the transport is and is not responsible for
//!
//! It is worth being precise, because it is easy to over-trust a secure channel.
//!
//! Encryption buys confidentiality and peer authentication. It buys **nothing**
//! about whether a share is honest: an authenticated peer can send a forged
//! share exactly as easily as an anonymous one. Share integrity comes from
//! somewhere else entirely — the seal (a share's id IS its sealed candidate
//! hash) and [`crate::ShareChain::accept`], which every peer runs independently.
//!
//! So the rule this module lives by: **decode is total, and nothing it produces
//! is trusted.** A decoded message is a *claim*. It becomes state only after the
//! sharechain's own rules accept it.
//!
//! # Bounds
//!
//! Every length is checked against a constant before a single byte is
//! allocated, because the length is attacker-chosen. There is no path here that
//! allocates from a number read off the wire.

use crate::{Share, ShareId};
use sov_primitives::AccountId;

/// Largest gossip frame accepted, in bytes.
///
/// A share is small; a batch is bounded by [`MAX_SHARES_PER_MESSAGE`]. This is
/// the outer wall — a peer claiming a larger frame is dropped before anything is
/// read, so a "length" field can never be used to make us allocate.
pub const MAX_FRAME_BYTES: usize = 1024 * 1024;

/// Most shares one `Shares` message may carry.
///
/// Bounds both the work a single message can demand and the memory a batch can
/// occupy. A peer with more to send simply sends more messages.
pub const MAX_SHARES_PER_MESSAGE: usize = 256;

/// Most uncles a single share may declare.
///
/// Uncles are references to real shares; a share citing thousands is not
/// plausible, it is trying to make validation expensive.
pub const MAX_UNCLES: usize = 8;

/// Longest account id accepted on the wire.
pub const MAX_ACCOUNT_LEN: usize = 64;

/// A gossip message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ShareMessage {
    /// Opening statement: which sharechain this peer thinks it is on, and where
    /// it is. The genesis id is checked so two different pools cannot merge
    /// their accounting by accident.
    Hello {
        /// The sharechain's genesis share id.
        genesis: ShareId,
        /// The peer's current best tip, if it has one.
        tip: Option<ShareId>,
    },
    /// One newly found share.
    Announce(Share),
    /// Ask for shares descending from `after`.
    GetShares {
        /// The requester's tip; the responder sends what follows it.
        after: Option<ShareId>,
    },
    /// A batch, oldest first.
    Shares(Vec<Share>),
}

/// Why a frame was rejected.
///
/// Every variant is a *drop*, never a panic and never a partial apply. The
/// distinctions exist so a peer can be scored on what kind of wrong it was.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WireError {
    /// The frame ended mid-field.
    Truncated,
    /// The leading tag matches no message.
    UnknownTag(u8),
    /// A declared length exceeds its bound.
    TooLarge,
    /// Bytes remained after a complete message — ambiguous framing, so refused
    /// rather than guessed at.
    TrailingBytes,
    /// An account id was not valid UTF-8 or not a legal account.
    BadAccount,
}

impl std::fmt::Display for WireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            WireError::Truncated => "frame ended mid-field",
            WireError::UnknownTag(_) => "unknown message tag",
            WireError::TooLarge => "declared length exceeds its bound",
            WireError::TrailingBytes => "trailing bytes after a complete message",
            WireError::BadAccount => "invalid account id",
        };
        write!(f, "{s}")
    }
}

impl std::error::Error for WireError {}

/// A cursor that can only fail, never panic.
struct Reader<'a> {
    buf: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Reader { buf, at: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], WireError> {
        let end = self.at.checked_add(n).ok_or(WireError::TooLarge)?;
        if end > self.buf.len() {
            return Err(WireError::Truncated);
        }
        let out = &self.buf[self.at..end];
        self.at = end;
        Ok(out)
    }
    fn u8(&mut self) -> Result<u8, WireError> {
        Ok(self.take(1)?[0])
    }
    fn u32(&mut self) -> Result<u32, WireError> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn u64(&mut self) -> Result<u64, WireError> {
        let b = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Ok(u64::from_le_bytes(a))
    }
    fn u128(&mut self) -> Result<u128, WireError> {
        let b = self.take(16)?;
        let mut a = [0u8; 16];
        a.copy_from_slice(b);
        Ok(u128::from_le_bytes(a))
    }
    fn id(&mut self) -> Result<ShareId, WireError> {
        let b = self.take(32)?;
        let mut a = [0u8; 32];
        a.copy_from_slice(b);
        Ok(a)
    }
    fn opt_id(&mut self) -> Result<Option<ShareId>, WireError> {
        match self.u8()? {
            0 => Ok(None),
            _ => Ok(Some(self.id()?)),
        }
    }
    /// A length-prefixed account id. The length is checked against
    /// [`MAX_ACCOUNT_LEN`] BEFORE any slice is taken.
    fn account(&mut self) -> Result<AccountId, WireError> {
        let n = self.u8()? as usize;
        if n == 0 || n > MAX_ACCOUNT_LEN {
            return Err(WireError::TooLarge);
        }
        let b = self.take(n)?;
        let s = std::str::from_utf8(b).map_err(|_| WireError::BadAccount)?;
        AccountId::new(s).map_err(|_| WireError::BadAccount)
    }
    fn done(&self) -> bool {
        self.at == self.buf.len()
    }
}

fn put_opt_id(out: &mut Vec<u8>, id: &Option<ShareId>) {
    match id {
        None => out.push(0),
        Some(v) => {
            out.push(1);
            out.extend_from_slice(v);
        }
    }
}

fn put_share(out: &mut Vec<u8>, s: &Share) {
    out.extend_from_slice(&s.id);
    put_opt_id(out, &s.prev);
    out.push(s.uncles.len() as u8);
    for u in &s.uncles {
        out.extend_from_slice(u);
    }
    let acct = s.finder.as_str().as_bytes();
    out.push(acct.len() as u8);
    out.extend_from_slice(acct);
    out.extend_from_slice(&s.work.to_le_bytes());
    out.push(u8::from(s.is_block));
    out.extend_from_slice(&s.timestamp_ms.to_le_bytes());
}

fn get_share(r: &mut Reader<'_>) -> Result<Share, WireError> {
    let id = r.id()?;
    let prev = r.opt_id()?;
    let n = r.u8()? as usize;
    if n > MAX_UNCLES {
        return Err(WireError::TooLarge);
    }
    let mut uncles = Vec::with_capacity(n);
    for _ in 0..n {
        uncles.push(r.id()?);
    }
    let finder = r.account()?;
    let work = r.u128()?;
    let is_block = r.u8()? != 0;
    let timestamp_ms = r.u64()?;
    Ok(Share {
        id,
        prev,
        uncles,
        finder,
        work,
        is_block,
        timestamp_ms,
    })
}

/// Encode a message.
pub fn encode(msg: &ShareMessage) -> Vec<u8> {
    let mut out = Vec::new();
    match msg {
        ShareMessage::Hello { genesis, tip } => {
            out.push(1);
            out.extend_from_slice(genesis);
            put_opt_id(&mut out, tip);
        }
        ShareMessage::Announce(s) => {
            out.push(2);
            put_share(&mut out, s);
        }
        ShareMessage::GetShares { after } => {
            out.push(3);
            put_opt_id(&mut out, after);
        }
        ShareMessage::Shares(v) => {
            out.push(4);
            out.extend_from_slice(&(v.len() as u32).to_le_bytes());
            for s in v {
                put_share(&mut out, s);
            }
        }
    }
    out
}

/// Decode a message. Total: every input either yields a message or an error.
///
/// Nothing here trusts the frame. Counts are bounded before allocation, the
/// cursor cannot read past the end, and trailing bytes are refused rather than
/// ignored — an encoder and a decoder that disagree about where a message ends
/// is how one peer is made to see a different message than another.
pub fn decode(buf: &[u8]) -> Result<ShareMessage, WireError> {
    if buf.len() > MAX_FRAME_BYTES {
        return Err(WireError::TooLarge);
    }
    let mut r = Reader::new(buf);
    let msg = match r.u8()? {
        1 => ShareMessage::Hello {
            genesis: r.id()?,
            tip: r.opt_id()?,
        },
        2 => ShareMessage::Announce(get_share(&mut r)?),
        3 => ShareMessage::GetShares { after: r.opt_id()? },
        4 => {
            let n = r.u32()? as usize;
            if n > MAX_SHARES_PER_MESSAGE {
                return Err(WireError::TooLarge);
            }
            // Capacity from a BOUNDED count, never straight from the wire.
            let mut v = Vec::with_capacity(n);
            for _ in 0..n {
                v.push(get_share(&mut r)?);
            }
            ShareMessage::Shares(v)
        }
        t => return Err(WireError::UnknownTag(t)),
    };
    if !r.done() {
        return Err(WireError::TrailingBytes);
    }
    Ok(msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn acct(s: &str) -> AccountId {
        AccountId::new(s).expect("valid")
    }

    fn a_share() -> Share {
        Share {
            id: [7u8; 32],
            prev: Some([6u8; 32]),
            uncles: vec![[5u8; 32], [4u8; 32]],
            finder: acct("alice.sov"),
            work: 123_456_789,
            is_block: true,
            timestamp_ms: 1_700_000_000_000,
        }
    }

    #[test]
    fn every_message_round_trips() {
        let msgs = vec![
            ShareMessage::Hello {
                genesis: [1u8; 32],
                tip: None,
            },
            ShareMessage::Hello {
                genesis: [1u8; 32],
                tip: Some([2u8; 32]),
            },
            ShareMessage::Announce(a_share()),
            ShareMessage::GetShares { after: None },
            ShareMessage::GetShares {
                after: Some([9u8; 32]),
            },
            ShareMessage::Shares(vec![a_share(), a_share()]),
            ShareMessage::Shares(vec![]),
        ];
        for m in msgs {
            let bytes = encode(&m);
            assert_eq!(decode(&bytes), Ok(m.clone()), "round trip failed for {m:?}");
        }
    }

    /// **Every truncation of every message must be an error, never a panic.**
    /// A peer can cut a frame anywhere, and the decoder is the first thing
    /// hostile bytes touch.
    #[test]
    fn every_truncation_is_refused_and_none_panics() {
        for m in [
            ShareMessage::Announce(a_share()),
            ShareMessage::Shares(vec![a_share(), a_share()]),
            ShareMessage::Hello {
                genesis: [1u8; 32],
                tip: Some([2u8; 32]),
            },
        ] {
            let full = encode(&m);
            for cut in 0..full.len() {
                let out = decode(&full[..cut]);
                assert!(
                    out.is_err(),
                    "a {cut}-byte prefix of {m:?} decoded to {out:?}"
                );
            }
        }
    }

    /// Every single-byte corruption must be refused or decode to something
    /// coherent — never panic, never allocate wildly.
    #[test]
    fn every_single_byte_corruption_is_survivable() {
        let full = encode(&ShareMessage::Shares(vec![a_share(), a_share()]));
        for i in 0..full.len() {
            for bit in 0..8u32 {
                let mut bad = full.clone();
                bad[i] ^= 1 << bit;
                // The ONLY requirement: it returns. A panic here is a remote
                // crash, and a wild allocation is a remote OOM.
                let _ = decode(&bad);
            }
        }
    }

    /// A declared share count beyond the bound must be refused BEFORE any
    /// allocation — this is the classic "length field" memory attack.
    #[test]
    fn an_absurd_share_count_is_refused_without_allocating() {
        let mut bytes = vec![4u8]; // Shares tag
        bytes.extend_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(decode(&bytes), Err(WireError::TooLarge));

        // One past the bound is refused too — the bound is the bound.
        let mut bytes = vec![4u8];
        bytes.extend_from_slice(&((MAX_SHARES_PER_MESSAGE as u32) + 1).to_le_bytes());
        assert_eq!(decode(&bytes), Err(WireError::TooLarge));
    }

    /// Same for uncles: a share citing thousands is trying to make validation
    /// expensive, not describing reality.
    #[test]
    fn an_absurd_uncle_count_is_refused() {
        let mut bytes = vec![2u8]; // Announce
        bytes.extend_from_slice(&[7u8; 32]); // id
        bytes.push(0); // prev: None
        bytes.push(255); // uncles: 255, over the bound
        assert_eq!(decode(&bytes), Err(WireError::TooLarge));
    }

    /// An oversized or empty account length is refused before the slice is
    /// taken.
    #[test]
    fn a_bad_account_length_is_refused() {
        for len in [0u8, (MAX_ACCOUNT_LEN as u8) + 1, 255] {
            let mut bytes = vec![2u8];
            bytes.extend_from_slice(&[7u8; 32]);
            bytes.push(0); // prev
            bytes.push(0); // no uncles
            bytes.push(len);
            bytes.extend_from_slice(&[b'a'; 32]);
            let out = decode(&bytes);
            assert!(
                matches!(out, Err(WireError::TooLarge) | Err(WireError::Truncated)),
                "account length {len} gave {out:?}"
            );
        }
    }

    /// Non-UTF-8 and non-account bytes are refused rather than lossily
    /// converted — a lossy id would let two peers disagree about who gets paid.
    #[test]
    fn a_non_utf8_account_is_refused() {
        let mut bytes = vec![2u8];
        bytes.extend_from_slice(&[7u8; 32]);
        bytes.push(0);
        bytes.push(0);
        bytes.push(4);
        bytes.extend_from_slice(&[0xff, 0xfe, 0xfd, 0xfc]);
        bytes.extend_from_slice(&0u128.to_le_bytes());
        bytes.push(0);
        bytes.extend_from_slice(&0u64.to_le_bytes());
        assert_eq!(decode(&bytes), Err(WireError::BadAccount));
    }

    /// Trailing bytes are refused. If an encoder and a decoder disagree about
    /// where a message ends, one peer can be shown a different message than
    /// another from the same frame.
    #[test]
    fn trailing_bytes_are_refused() {
        let mut bytes = encode(&ShareMessage::GetShares { after: None });
        bytes.push(0xAA);
        assert_eq!(decode(&bytes), Err(WireError::TrailingBytes));
    }

    #[test]
    fn an_unknown_tag_and_an_empty_frame_are_refused() {
        assert_eq!(decode(&[]), Err(WireError::Truncated));
        assert_eq!(decode(&[99]), Err(WireError::UnknownTag(99)));
    }

    /// A frame beyond the outer wall is refused before it is even parsed.
    #[test]
    fn an_oversized_frame_is_refused_outright() {
        let huge = vec![0u8; MAX_FRAME_BYTES + 1];
        assert_eq!(decode(&huge), Err(WireError::TooLarge));
    }
}
