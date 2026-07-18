//! The peer-to-peer wire protocol: messages nodes exchange to stay in sync.
//!
//! Every message is Borsh-encoded for a compact, deterministic wire form. The
//! set covers the two things that must propagate for a Nakamoto chain to live —
//! transactions (into mempools) and blocks (the proof-of-work itself; finality
//! is confirmation depth, so no votes travel the wire) — plus a minimal
//! request/response for catching a lagging peer up by height.

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use sov_crypto::{Keypair, PublicKey, Signature};
use sov_primitives::{AccountId, Hash};
use sov_types::{Block, BlockHeader, SignedTransaction};

/// A protocol message exchanged between peers.
// The block-carrying variants (`NewBlock`, `BlockResponse`) are inherently larger
// than the control messages; a gossip message is short-lived (one per send), not
// stored in bulk, so the size gap is by design — boxing would only add indirection.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub enum NetMessage {
    /// Handshake / liveness: a peer's current head height and hash.
    Status {
        /// The peer's head height.
        height: u64,
        /// The peer's head block hash.
        head: Hash,
        /// Cumulative proof-of-work of `head`, encoded as fixed-width big-endian
        /// bytes so lexicographic ordering matches numeric work ordering.
        chain_work: [u8; 32],
    },
    /// Gossip a transaction for inclusion in mempools.
    NewTransaction(SignedTransaction),
    /// Gossip a newly produced block.
    NewBlock(Block),
    /// Request the block at a height (catch-up).
    GetBlock {
        /// The requested height.
        height: u64,
    },
    /// Response to [`NetMessage::GetBlock`]; `None` if the peer lacks it.
    BlockResponse(Option<Block>),
    /// Request up to `count` consecutive blocks starting at `start` (batched
    /// catch-up). Lets a lagging node fetch many blocks per round-trip instead of
    /// one-at-a-time, so a long reorg/sync completes in seconds, not minutes — and
    /// with far fewer messages, staying well under the per-peer rate limit.
    GetBlocks {
        /// First height to return.
        start: u64,
        /// Maximum number of consecutive blocks to return (server-capped).
        count: u16,
    },
    /// Response to [`NetMessage::GetBlocks`]: consecutive blocks from `start`, in
    /// ascending height order (possibly fewer than requested, empty if none).
    BlocksResponse(Vec<Block>),
    /// Peer discovery: a list of known peer addresses (`host:port`). On receipt,
    /// a node dials any addresses it does not already know, so knowledge of the
    /// network propagates transitively.
    Peers(Vec<String>),
    /// Authenticated handshake: a peer proves it is on the same chain — matching
    /// `chain_id` and `genesis_hash` — controls `public_key`, AND is speaking over
    /// the specific encrypted channel identified by `channel_binding` (the Noise
    /// handshake hash), by signing all of it. Binding to the channel defeats a
    /// man-in-the-middle: a relayed handshake carries the sender's channel hash,
    /// which will not equal the receiver's hash for its own leg. A peer that fails
    /// this is never trusted with blocks or transactions.
    Hello {
        /// The peer's network/chain id.
        chain_id: String,
        /// The peer's genesis block hash — pins the exact chain and fork.
        genesis_hash: Hash,
        /// The peer's claimed account identity.
        account: AccountId,
        /// The public key that produced `signature`.
        public_key: PublicKey,
        /// The Noise handshake hash of the connection this Hello is sent over —
        /// cryptographically ties the authenticated identity to the encrypted pipe.
        channel_binding: Vec<u8>,
        /// Ed25519 signature over [`handshake_bytes`]`(chain_id, genesis_hash, channel_binding)`.
        signature: Signature,
    },
    /// Software/protocol version advertisement (v0.1.86+). Sent once per peer right after
    /// the encrypted channel is up so each side learns the other's wire-protocol version
    /// and human agent string — the network becomes version-aware, and a node can refuse
    /// or feature-gate a peer by version instead of silently forking on an upgrade. This
    /// is a NEW, APPENDED variant (never a change to `Hello`, whose Borsh encoding must
    /// stay stable): a pre-v0.1.86 peer simply cannot decode it and takes one small,
    /// self-decaying malformed-frame penalty — sub-ban, harmless over the coordinated
    /// upgrade window. Carries no authority (it is unsigned telemetry); trust decisions
    /// still flow only from the signed `Hello`.
    Version {
        /// Wire-protocol version — bumped only when the P2P protocol changes in a way
        /// peers must negotiate. Distinct from the human release string.
        protocol_version: u32,
        /// Human agent string, e.g. `"sov/0.1.86"` — shown by `sov_getPeerInfo`.
        agent: String,
        /// The advertiser's current chain head height (a cheap liveness/sync hint).
        height: u64,
    },
    /// **Pull-based peer discovery** (v0.1.86+): ask a peer to send back the addresses it
    /// knows, answered with a [`Peers`](NetMessage::Peers) reply. Complements the existing
    /// push gossip so a node with few peers can actively widen its address book instead of
    /// waiting for a push. Sent ONLY to peers already known to speak v0.1.86+ (they
    /// advertised a `Version`), so a pre-v0.1.86 node is never handed a frame it cannot
    /// decode. An APPENDED variant (after `Version`) — same wire-compat rule.
    GetAddr,
    /// **Headers-first fork-point discovery** (protocol v2, v0.1.89+): a lagging node
    /// on a stale tip sends a Bitcoin-style **block locator** — its own active-chain
    /// block hashes at exponentially-spaced heights (tip, tip-1, tip-2, tip-4, …,
    /// genesis) — and the serving peer names the fork point in ONE round-trip by
    /// replying with [`Headers`](NetMessage::Headers) from the first locator hash on
    /// its active chain. Replaces the O(N) one-block-per-round-trip backward walk that
    /// crawled when a node fell hundreds of blocks behind. Sent ONLY to peers that
    /// advertised protocol >= 2 (older peers keep the legacy single-block backtrack,
    /// so a v0.1.86–88 node is never handed a frame it cannot decode). An APPENDED
    /// variant (after `GetAddr`) — same wire-compat rule.
    GetHeaders {
        /// Active-chain block hashes, ordered tip → genesis, exponentially spaced
        /// (tip, tip-1, tip-2, tip-4, …), ALWAYS ending with the genesis hash.
        locator: Vec<Hash>,
        /// Stop serving once a header with this hash has been included;
        /// [`Hash::ZERO`] = no stop, serve up to the server's batch cap.
        stop: Hash,
    },
    /// Response to [`GetHeaders`](NetMessage::GetHeaders): consecutive block headers
    /// in ascending height order, starting at fork_point + 1 along the server's
    /// active chain (empty if the server's head IS the fork point). Headers only —
    /// the requester learns the fork point from the first header's `prev_hash` and
    /// then downloads full blocks forward via the existing
    /// [`GetBlocks`](NetMessage::GetBlocks); every block is still fully validated on
    /// import, so a lying server yields at worst a bad fork-point guess whose blocks
    /// then fail validation (and it is penalized).
    Headers(Vec<BlockHeader>),
    // WIRE-COMPATIBILITY RULE: Borsh encodes an enum variant by its declaration-order
    // index, so a NEW variant MUST be appended HERE, at the end — never inserted
    // between existing ones, which would shift every later discriminant and break the
    // handshake with peers on an older binary. (`GetBlocks`/`BlocksResponse` sit
    // mid-enum because they shipped that way in v0.1.6; they are deliberately left in
    // place — moving them now would break compatibility with deployed nodes for a
    // purely cosmetic reordering. `GetHeaders`/`Headers` are appended after `GetAddr`
    // for the same reason.) NetMessage is wire-only; it is never persisted, so its
    // ordering does not affect the block log or genesis KAT.
}

/// The current P2P wire-protocol version this build speaks. Bumped only on a
/// protocol change peers must negotiate; v0.1.86 was the first versioned protocol
/// (v1). v2 adds headers-first fork-point discovery
/// ([`GetHeaders`](NetMessage::GetHeaders) / [`Headers`](NetMessage::Headers)).
pub const PROTOCOL_VERSION: u32 = 2;

/// The lowest protocol version this build will still peer with. `0` = accept every
/// peer (pre-v0.1.86 nodes advertise nothing and are treated as version 0), so the
/// v0.1.86 rollout refuses no one; a FUTURE mandatory upgrade raises this to shun
/// laggards at the handshake instead of silently forking them.
pub const MIN_SUPPORTED_PROTOCOL: u32 = 0;

impl NetMessage {
    /// Encode to the canonical Borsh wire bytes.
    pub fn encode(&self) -> Vec<u8> {
        borsh::to_vec(self).expect("Borsh serialization of a NetMessage is infallible")
    }

    /// Build a [`NetMessage::Version`] advertising this build's protocol version, the
    /// human `agent` string (e.g. `"sov/0.1.86"`), and current chain `height`.
    pub fn version(agent: impl Into<String>, height: u64) -> NetMessage {
        NetMessage::Version {
            protocol_version: PROTOCOL_VERSION,
            agent: agent.into(),
            height,
        }
    }

    /// Decode from wire bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, NetworkError> {
        borsh::from_slice(bytes).map_err(|_| NetworkError::Decode)
    }

    /// Build a signed [`NetMessage::Hello`] handshake for `account` on the chain
    /// identified by `chain_id` / `genesis_hash`.
    pub fn hello(
        chain_id: impl Into<String>,
        genesis_hash: Hash,
        account: AccountId,
        channel_binding: &[u8],
        keypair: &Keypair,
    ) -> NetMessage {
        let chain_id = chain_id.into();
        let signature = keypair.sign(&handshake_bytes(&chain_id, &genesis_hash, channel_binding));
        NetMessage::Hello {
            chain_id,
            genesis_hash,
            account,
            public_key: keypair.public_key(),
            channel_binding: channel_binding.to_vec(),
            signature,
        }
    }

    /// If this is a valid handshake for the expected chain AND the expected channel
    /// — same `chain_id`, `genesis_hash`, and `channel_binding` (the receiver's own
    /// Noise handshake hash for this connection), with a signature that verifies
    /// against its own `public_key` — return the authenticated account; else `None`.
    pub fn authenticated_account(
        &self,
        expected_chain_id: &str,
        expected_genesis: &Hash,
        expected_binding: &[u8],
    ) -> Option<&AccountId> {
        match self {
            NetMessage::Hello {
                chain_id,
                genesis_hash,
                account,
                public_key,
                channel_binding,
                signature,
            } if chain_id == expected_chain_id
                && genesis_hash == expected_genesis
                && channel_binding.as_slice() == expected_binding
                && public_key.verify(
                    &handshake_bytes(chain_id, genesis_hash, channel_binding),
                    signature,
                )
                // Interim implicit-id guard (no wire-format change): the signed
                // `handshake_bytes` do NOT yet cover `account`, so a valid keypair could
                // otherwise CLAIM any account id (which drives peer dedup/identity). When
                // the claimed id is an IMPLICIT (hash-of-pubkey) id, require it to derive
                // from this very key — closing the spoof for implicit ids without the
                // coordinated P2P v3 fork that would sign the account field. Named /
                // ledger-bound ids are not implicit, so this never rejects them.
                && !implicit_account_spoofed(account, public_key) =>
            {
                Some(account)
            }
            _ => None,
        }
    }

    /// Whether this `Hello` presents an **implicit** (key-derived) account id that does
    /// NOT match the id derived from its own `public_key` — an interim spoof of an
    /// implicit identity that [`authenticated_account`](Self::authenticated_account)
    /// already rejects. Exposed so the P2P layer can log a precise reason and penalize
    /// the peer. Returns `false` for a non-`Hello` message and for any non-implicit
    /// (named / ledger-bound) account id, which this wire check does not police.
    pub fn implicit_account_mismatch(&self) -> bool {
        match self {
            NetMessage::Hello {
                account,
                public_key,
                ..
            } => implicit_account_spoofed(account, public_key),
            _ => false,
        }
    }
}

/// An implicit (64-hex, hash-of-pubkey) account id is only honest when it equals the
/// id derived from `public_key`; a mismatch is a spoof. A non-implicit id (a named or
/// ledger-bound account) is validated by its on-chain key binding, not here, so it is
/// never flagged.
fn implicit_account_spoofed(account: &AccountId, public_key: &PublicKey) -> bool {
    account.is_implicit() && *account != public_key.implicit_account_id()
}

/// The canonical bytes a [`NetMessage::Hello`] signs: chain id, genesis hash, and
/// the channel binding (Noise handshake hash). Binding all three means a handshake
/// signed for one chain/fork, or relayed onto a different encrypted channel, cannot
/// be replayed.
pub fn handshake_bytes(chain_id: &str, genesis_hash: &Hash, channel_binding: &[u8]) -> Vec<u8> {
    let mut bytes = chain_id.as_bytes().to_vec();
    bytes.extend_from_slice(genesis_hash.as_bytes());
    bytes.extend_from_slice(channel_binding);
    bytes
}

/// Errors at the network layer.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum NetworkError {
    /// A received message could not be decoded.
    #[error("failed to decode network message")]
    Decode,
    /// A message was addressed to an unknown peer.
    #[error("unknown peer")]
    UnknownPeer,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_roundtrips() {
        let msg = NetMessage::Status {
            height: 42,
            head: Hash::digest(b"head"),
            chain_work: [0x2a; 32],
        };
        let bytes = msg.encode();
        assert_eq!(NetMessage::decode(&bytes).unwrap(), msg);
    }

    #[test]
    fn get_block_roundtrips() {
        let msg = NetMessage::GetBlock { height: 7 };
        assert_eq!(NetMessage::decode(&msg.encode()).unwrap(), msg);
    }

    #[test]
    fn version_message_roundtrips_and_carries_this_builds_protocol() {
        let msg = NetMessage::version("sov/v0.1.86", 6751);
        assert_eq!(NetMessage::decode(&msg.encode()).unwrap(), msg);
        match msg {
            NetMessage::Version {
                protocol_version,
                agent,
                height,
            } => {
                assert_eq!(protocol_version, PROTOCOL_VERSION);
                assert_eq!(agent, "sov/v0.1.86");
                assert_eq!(height, 6751);
            }
            _ => panic!("expected Version"),
        }
    }

    #[test]
    fn getaddr_roundtrips() {
        let msg = NetMessage::GetAddr;
        assert_eq!(NetMessage::decode(&msg.encode()).unwrap(), msg);
        // Appended after Version, so its discriminant is higher than every original variant.
        assert!(NetMessage::GetAddr.encode()[0] > NetMessage::Peers(vec![]).encode()[0]);
    }

    #[test]
    fn version_is_the_last_variant_so_older_variants_keep_their_discriminants() {
        // Borsh encodes an enum variant by declaration-order index. `Version` was APPENDED,
        // so every pre-existing variant must still encode to its original leading byte —
        // this is what lets a v0.1.85 node still decode Status/NewBlock/Hello unchanged.
        // Status is variant 0; its encoding must still begin with 0x00.
        let status = NetMessage::Status {
            height: 1,
            head: Hash::digest(b"h"),
            chain_work: [0u8; 32],
        };
        assert_eq!(status.encode()[0], 0, "Status stays discriminant 0");
        // A pre-v0.1.86 peer receiving a Version (a higher, unknown discriminant) fails to
        // decode it — a graceful, penalized drop of that one frame, never a silent misparse.
        let ver_disc = NetMessage::version("sov/x", 0).encode()[0];
        assert!(
            ver_disc > 0,
            "Version is appended after the original variants"
        );
    }

    #[test]
    fn get_headers_and_headers_roundtrip_and_are_appended() {
        use sov_primitives::BlockHeight;

        let msg = NetMessage::GetHeaders {
            locator: vec![Hash::digest(b"tip"), Hash::digest(b"genesis")],
            stop: Hash::ZERO,
        };
        assert_eq!(NetMessage::decode(&msg.encode()).unwrap(), msg);

        let header = BlockHeader {
            height: BlockHeight::new(7),
            prev_hash: Hash::digest(b"parent"),
            tx_root: Hash::ZERO,
            receipts_root: Hash::ZERO,
            state_root: Hash::digest(b"state"),
            timestamp_ms: 1_000,
            proposer: AccountId::new("val01.node.sov").unwrap(),
            version_bits: 0,
            bits: 0x207f_ffff,
            nonce: 42,
        };
        let msg = NetMessage::Headers(vec![header]);
        assert_eq!(NetMessage::decode(&msg.encode()).unwrap(), msg);

        // Both are APPENDED after GetAddr, so every pre-existing variant keeps its
        // discriminant — a v1 (v0.1.86–88) peer still decodes the whole old surface.
        let get_headers_disc = NetMessage::GetHeaders {
            locator: vec![],
            stop: Hash::ZERO,
        }
        .encode()[0];
        let headers_disc = NetMessage::Headers(vec![]).encode()[0];
        let get_addr_disc = NetMessage::GetAddr.encode()[0];
        assert!(get_headers_disc > get_addr_disc, "GetHeaders after GetAddr");
        assert!(headers_disc > get_headers_disc, "Headers after GetHeaders");
    }

    #[test]
    fn garbage_fails_to_decode() {
        assert_eq!(
            NetMessage::decode(&[0xff, 0xff, 0xff]),
            Err(NetworkError::Decode)
        );
    }

    #[test]
    fn hello_requires_matching_channel_binding() {
        let kp = Keypair::from_seed([1; 32]);
        let genesis = Hash::digest(b"genesis");
        let account = AccountId::new("val01.node.sov").unwrap();
        let binding = b"noise-handshake-hash-A";
        let h = NetMessage::hello("sov", genesis, account, binding, &kp);

        // Correct chain id + genesis + channel binding authenticates.
        assert!(h.authenticated_account("sov", &genesis, binding).is_some());
        // A relayed handshake over a DIFFERENT channel (MITM) is rejected.
        assert!(h
            .authenticated_account("sov", &genesis, b"noise-handshake-hash-B")
            .is_none());
        // Wrong genesis is still rejected.
        assert!(h
            .authenticated_account("sov", &Hash::digest(b"other"), binding)
            .is_none());
    }

    #[test]
    fn hello_with_a_spoofed_implicit_account_is_rejected() {
        // Interim implicit-id guard: the handshake signature does not yet cover the
        // `account` field, so a valid keypair could otherwise CLAIM any account id. When
        // the claimed id is IMPLICIT (hash-of-pubkey), it must derive from this very key.
        let kp = Keypair::from_seed([7; 32]);
        let genesis = Hash::digest(b"genesis");
        let binding = b"noise-handshake-hash-A";

        // Honest: the implicit id derived from THIS key authenticates and is not flagged.
        let honest_id = kp.public_key().implicit_account_id();
        assert!(honest_id.is_implicit());
        let honest = NetMessage::hello("sov", genesis, honest_id.clone(), binding, &kp);
        assert!(!honest.implicit_account_mismatch());
        assert_eq!(
            honest.authenticated_account("sov", &genesis, binding),
            Some(&honest_id),
        );

        // Spoof: a DIFFERENT key's implicit id, signed by `kp`. The signature verifies,
        // but the implicit id does not derive from `kp`, so auth must fail.
        let victim_id = Keypair::from_seed([9; 32])
            .public_key()
            .implicit_account_id();
        assert_ne!(victim_id, honest_id);
        let spoof = NetMessage::hello("sov", genesis, victim_id, binding, &kp);
        assert!(spoof.implicit_account_mismatch());
        assert!(
            spoof
                .authenticated_account("sov", &genesis, binding)
                .is_none(),
            "an implicit id that does not derive from the signing key must be rejected"
        );

        // A named (non-implicit) account is NOT policed by this wire check — it is
        // validated by its on-chain key binding — so it still authenticates normally.
        let named = AccountId::new("val01.node.sov").unwrap();
        assert!(!named.is_implicit());
        let named_hello = NetMessage::hello("sov", genesis, named.clone(), binding, &kp);
        assert!(!named_hello.implicit_account_mismatch());
        assert_eq!(
            named_hello.authenticated_account("sov", &genesis, binding),
            Some(&named),
        );
    }
}
