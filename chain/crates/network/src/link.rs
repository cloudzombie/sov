//! `SealedLink` — one encrypted, framed, byte-level connection.
//!
//! # Why this module exists
//!
//! The sealed link — Noise XX handshake, hybrid ML-KEM key agreement, inner PQ
//! seal, Noise chunking, length prefix — used to live inside [`crate::tcp`],
//! welded to [`NetMessage`](crate::NetMessage). That made it unusable by
//! anything that is not block/transaction relay, and the only ways to give a
//! second protocol an encrypted channel were to widen `NetMessage` (putting an
//! unrelated decoder in front of consensus transport) or to copy the framing
//! (a second implementation of security-critical code, free to drift).
//!
//! Both are bad trades, so the link was **moved** here instead — not copied.
//! `tcp.rs` now calls into this module, so there is exactly ONE implementation
//! of the handshake and framing, and it is the one consensus transport has
//! always used.
//!
//! # What it is responsible for
//!
//! Confidentiality, integrity and authenticity **of the pipe**: bytes in equal
//! bytes out, or the frame is refused. It carries opaque `Vec<u8>` and knows
//! nothing about what they mean.
//!
//! It is emphatically NOT responsible for whether the *content* is honest. An
//! authenticated peer can send a well-sealed lie. Every protocol built on this
//! must validate what it decodes — the link only guarantees the bytes are the
//! ones the peer sent.
//!
//! # Layering (unchanged by the move)
//!
//! Outbound: `plaintext → PQ seal → chunk → Noise encrypt → 4-byte length`.
//! Inbound is the mirror. The inner hybrid layer is sealed FIRST, so recorded
//! traffic stays confidential unless BOTH key exchanges fall.

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::Mutex;

use fips203::ml_kem_768;
use fips203::traits::{Decaps as _, Encaps as _, KeyGen as _, SerDes as _};
use snow::{Builder, TransportState};

use crate::pq::{channel_binding, PqChannel};

/// Largest plaintext frame the link will carry, in bytes.
pub const MAX_FRAME: usize = 8 * 1024 * 1024;

/// Most plaintext one Noise message may carry (65535 minus the AEAD tag).
const NOISE_MAX_PLAINTEXT: usize = 65535 - 16;

/// The Noise pattern. XX gives mutual authentication with per-connection
/// ephemeral static keys.
pub(crate) const NOISE_PARAMS: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";

/// The outcome of reading one frame.
#[derive(Debug)]
pub enum LinkRead {
    /// A plaintext frame.
    Frame(Vec<u8>),
    /// The peer hung up. Expected churn, not an error.
    Closed,
    /// A bogus length, a decrypt failure, or a chunk that ran past its declared
    /// size. The caller should drop the peer: after a desync the byte stream is
    /// no longer interpretable.
    Malformed,
}

/// One encrypted connection, carrying opaque bytes.
pub struct SealedLink {
    stream: Mutex<TcpStream>,
    noise: Mutex<TransportState>,
    /// The inner hybrid (X25519 + ML-KEM-768) AEAD layer. Every frame is sealed
    /// here FIRST, then chunked through the Noise cipher.
    pq: Mutex<PqChannel>,
    /// The complete Noise + ML-KEM channel binding, identical on both ends.
    /// This covers both KEM messages so a signed identity cannot be relayed
    /// across substituted KEM exchanges if X25519 is broken.
    handshake_hash: Vec<u8>,
}

impl SealedLink {
    /// Perform the full handshake (Noise XX, then the hybrid PQ exchange) over
    /// an established TCP stream. Fail-closed: a peer that cannot complete
    /// either step never becomes a link. There is no classical-only fallback.
    pub fn establish(stream: &mut TcpStream, initiator: bool) -> io::Result<SealedLink> {
        let (mut transport, noise_hash) = noise_handshake(stream, initiator)?;
        let (pq, handshake_hash) = pq_handshake(stream, &mut transport, initiator, &noise_hash)?;
        Ok(SealedLink {
            stream: Mutex::new(stream.try_clone()?),
            noise: Mutex::new(transport),
            pq: Mutex::new(pq),
            handshake_hash,
        })
    }

    /// Build a link from parts already negotiated by the caller. `handshake_hash`
    /// must be the complete channel binding returned by `pq_handshake`, not
    /// the earlier Noise-only handshake hash.
    pub fn from_parts(
        stream: TcpStream,
        noise: TransportState,
        pq: PqChannel,
        handshake_hash: Vec<u8>,
    ) -> SealedLink {
        SealedLink {
            stream: Mutex::new(stream),
            noise: Mutex::new(noise),
            pq: Mutex::new(pq),
            handshake_hash,
        }
    }

    /// This connection's complete Noise + ML-KEM channel binding.
    /// The historical method name is retained for callers; it never returns
    /// the earlier Noise-only hash.
    pub fn handshake_hash(&self) -> &[u8] {
        &self.handshake_hash
    }

    /// Encrypt and write one frame: seal with the inner hybrid PQ layer first,
    /// then chunk through the Noise cipher.
    ///
    /// The stream lock is held across encryption *and* the socket write, so
    /// concurrent senders cannot interleave and the on-wire order always
    /// matches both nonce streams. (Lock order everywhere: stream → pq → noise.)
    pub fn send(&self, plaintext: &[u8]) -> io::Result<()> {
        if plaintext.len() > MAX_FRAME {
            return Err(io::Error::other("frame exceeds maximum size"));
        }
        let mut stream = self.stream.lock().unwrap();
        let inner = self.pq.lock().unwrap().seal(plaintext);
        let mut out = Vec::with_capacity(inner.len() + 64);
        out.extend_from_slice(&(inner.len() as u32).to_be_bytes());
        {
            let mut noise = self.noise.lock().unwrap();
            let mut buf = [0u8; 65535];
            // An empty payload still needs one chunk so the reader makes progress.
            for chunk in inner.chunks(NOISE_MAX_PLAINTEXT) {
                let n = noise
                    .write_message(chunk, &mut buf)
                    .map_err(|e| io::Error::other(format!("noise encrypt: {e}")))?;
                out.extend_from_slice(&(n as u16).to_be_bytes());
                out.extend_from_slice(&buf[..n]);
            }
        }
        stream.write_all(&out)?;
        stream.flush()
    }

    /// Read and decrypt one frame from `reader` (a clone of this link's stream).
    ///
    /// Every length on the wire is attacker-chosen, so each is bounded before it
    /// is used, and the initial allocation is capped so a tiny frame declaring a
    /// huge length cannot force a multi-megabyte reservation.
    pub fn recv(&self, reader: &mut TcpStream) -> LinkRead {
        let mut len_bytes = [0u8; 4];
        if reader.read_exact(&mut len_bytes).is_err() {
            return LinkRead::Closed; // hung up between frames — expected churn
        }
        let total = u32::from_be_bytes(len_bytes) as usize;
        // +16: the declared length covers the inner AEAD tag over the plaintext.
        if total == 0 || total > MAX_FRAME + 16 {
            return LinkRead::Malformed;
        }
        let mut inner = Vec::with_capacity(total.min(64 * 1024));
        let mut buf = [0u8; 65535];
        while inner.len() < total {
            let mut clen = [0u8; 2];
            if reader.read_exact(&mut clen).is_err() {
                return LinkRead::Closed; // truncated mid-frame — treat as a close
            }
            let clen = u16::from_be_bytes(clen) as usize;
            if clen == 0 || clen > buf.len() {
                return LinkRead::Malformed;
            }
            let mut ct = vec![0u8; clen];
            if reader.read_exact(&mut ct).is_err() {
                return LinkRead::Closed;
            }
            let n = match self.noise.lock().unwrap().read_message(&ct, &mut buf) {
                Ok(n) => n,
                Err(_) => return LinkRead::Malformed, // AEAD/decrypt failure
            };
            if inner.len() + n > total {
                return LinkRead::Malformed; // a chunk decrypted past the declared size
            }
            inner.extend_from_slice(&buf[..n]);
        }
        match self.pq.lock().unwrap().open(&inner) {
            Some(plaintext) => LinkRead::Frame(plaintext),
            None => LinkRead::Malformed,
        }
    }

    /// A clone of the underlying stream, for a dedicated read thread.
    pub fn try_clone_stream(&self) -> io::Result<TcpStream> {
        self.stream.lock().unwrap().try_clone()
    }

    /// The peer's address.
    pub fn peer_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.stream.lock().unwrap().peer_addr()
    }
}

/// Perform a Noise XX handshake over `stream`, returning the transport-mode cipher
/// and the Noise handshake hash (identical on both ends). This is only an
/// intermediate transcript: [`pq_handshake`] includes the KEM messages in the
/// final `Hello` channel binding. The static key is generated per connection;
/// peer identity is authenticated by the application-level signed
/// [`Hello`](crate::NetMessage::Hello) once the channel is up.
pub(crate) fn noise_handshake(
    stream: &mut TcpStream,
    initiator: bool,
) -> io::Result<(TransportState, Vec<u8>)> {
    let params = NOISE_PARAMS
        .parse()
        .map_err(|_| io::Error::other("invalid Noise params"))?;
    let builder = Builder::new(params);
    let keypair = builder
        .generate_keypair()
        .map_err(|e| io::Error::other(format!("noise keygen: {e}")))?;
    let builder = builder.local_private_key(&keypair.private);
    let mut hs = if initiator {
        builder.build_initiator()
    } else {
        builder.build_responder()
    }
    .map_err(|e| io::Error::other(format!("noise build: {e}")))?;

    let mut buf = [0u8; 65535];
    // XX is three messages: -> e ; <- e,ee,s,es ; -> s,se. The initiator writes
    // the 1st and 3rd, the responder the 2nd.
    if initiator {
        let n = hs
            .write_message(&[], &mut buf)
            .map_err(|e| io::Error::other(format!("noise msg1: {e}")))?;
        write_raw(stream, &buf[..n])?;
        let msg = read_raw(stream)?;
        hs.read_message(&msg, &mut buf)
            .map_err(|e| io::Error::other(format!("noise msg2: {e}")))?;
        let n = hs
            .write_message(&[], &mut buf)
            .map_err(|e| io::Error::other(format!("noise msg3: {e}")))?;
        write_raw(stream, &buf[..n])?;
    } else {
        let msg = read_raw(stream)?;
        hs.read_message(&msg, &mut buf)
            .map_err(|e| io::Error::other(format!("noise msg1: {e}")))?;
        let n = hs
            .write_message(&[], &mut buf)
            .map_err(|e| io::Error::other(format!("noise msg2: {e}")))?;
        write_raw(stream, &buf[..n])?;
        let msg = read_raw(stream)?;
        hs.read_message(&msg, &mut buf)
            .map_err(|e| io::Error::other(format!("noise msg3: {e}")))?;
    }
    // Capture the handshake hash before consuming the handshake state. Both ends
    // derive the identical value, so it uniquely identifies this channel.
    let handshake_hash = hs.get_handshake_hash().to_vec();
    let transport = hs
        .into_transport_mode()
        .map_err(|e| io::Error::other(format!("noise transport: {e}")))?;
    Ok((transport, handshake_hash))
}

/// Run the hybrid post-quantum key exchange inside the freshly-established
/// Noise channel: the initiator sends an ephemeral ML-KEM-768 encapsulation
/// key; the responder encapsulates and returns the ciphertext; both derive
/// the same 32-byte KEM secret and build the inner [`PqChannel`]. Also return
/// the final authentication binding over the Noise hash and both exact KEM
/// messages. Any failure aborts the connection — there is **no fallback** to
/// a classical-only channel or to a Noise-only authentication binding.
pub(crate) fn pq_handshake(
    stream: &mut TcpStream,
    noise: &mut TransportState,
    initiator: bool,
    handshake_hash: &[u8],
) -> io::Result<(PqChannel, Vec<u8>)> {
    if initiator {
        let (ek, dk) = ml_kem_768::KG::try_keygen()
            .map_err(|e| io::Error::other(format!("ml-kem keygen: {e}")))?;
        let ek_bytes = ek.into_bytes();
        noise_send(stream, noise, &ek_bytes)?;
        let ct_bytes = noise_recv(stream, noise)?;
        let ct: [u8; ml_kem_768::CT_LEN] = ct_bytes
            .try_into()
            .map_err(|_| io::Error::other("ml-kem ciphertext has the wrong length"))?;
        let binding = channel_binding(handshake_hash, &ek_bytes, &ct).to_vec();
        let ct = ml_kem_768::CipherText::try_from_bytes(ct)
            .map_err(|e| io::Error::other(format!("ml-kem ciphertext: {e}")))?;
        let secret = dk
            .try_decaps(&ct)
            .map_err(|e| io::Error::other(format!("ml-kem decaps: {e}")))?;
        Ok((
            PqChannel::new(handshake_hash, &secret.into_bytes(), true),
            binding,
        ))
    } else {
        let ek_bytes = noise_recv(stream, noise)?;
        let ek: [u8; ml_kem_768::EK_LEN] = ek_bytes
            .try_into()
            .map_err(|_| io::Error::other("ml-kem encaps key has the wrong length"))?;
        let ek_bytes = ek;
        let ek = ml_kem_768::EncapsKey::try_from_bytes(ek_bytes)
            .map_err(|e| io::Error::other(format!("ml-kem encaps key: {e}")))?;
        let (secret, ct) = ek
            .try_encaps()
            .map_err(|e| io::Error::other(format!("ml-kem encaps: {e}")))?;
        let ct_bytes = ct.into_bytes();
        noise_send(stream, noise, &ct_bytes)?;
        let binding = channel_binding(handshake_hash, &ek_bytes, &ct_bytes).to_vec();
        Ok((
            PqChannel::new(handshake_hash, &secret.into_bytes(), false),
            binding,
        ))
    }
}

/// Write a raw, *unencrypted* length-prefixed frame — used only for the Noise
/// handshake messages, before the encrypted channel exists.
pub(crate) fn write_raw(stream: &mut TcpStream, data: &[u8]) -> io::Result<()> {
    stream.write_all(&(data.len() as u32).to_be_bytes())?;
    stream.write_all(data)?;
    stream.flush()
}

/// Read a raw, *unencrypted* length-prefixed handshake frame.
pub(crate) fn read_raw(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut len = [0u8; 4];
    stream.read_exact(&mut len)?;
    let n = u32::from_be_bytes(len) as usize;
    if n == 0 || n > 65535 {
        return Err(io::Error::other("invalid handshake frame length"));
    }
    let mut data = vec![0u8; n];
    stream.read_exact(&mut data)?;
    Ok(data)
}

/// Send one Noise-encrypted message (single chunk; the KEM material fits well
/// under the 64 KiB Noise cap), framed with a 4-byte length.
pub(crate) fn noise_send(
    stream: &mut TcpStream,
    noise: &mut TransportState,
    data: &[u8],
) -> io::Result<()> {
    let mut buf = [0u8; 65535];
    let n = noise
        .write_message(data, &mut buf)
        .map_err(|e| io::Error::other(format!("noise encrypt: {e}")))?;
    write_raw(stream, &buf[..n])
}

/// Receive one Noise-encrypted message framed with a 4-byte length.
pub(crate) fn noise_recv(
    stream: &mut TcpStream,
    noise: &mut TransportState,
) -> io::Result<Vec<u8>> {
    let ct = read_raw(stream)?;
    let mut buf = [0u8; 65535];
    let n = noise
        .read_message(&ct, &mut buf)
        .map_err(|e| io::Error::other(format!("noise decrypt: {e}")))?;
    Ok(buf[..n].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn sealed_link_exposes_complete_binding_and_interoperates_in_both_directions() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let responder = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let (mut noise, noise_hash) = noise_handshake(&mut stream, false).unwrap();

            // Negotiate the responder half explicitly, retaining the exact wire
            // messages as an independent check of the initiator's binding.
            let ek_bytes: [u8; ml_kem_768::EK_LEN] = noise_recv(&mut stream, &mut noise)
                .unwrap()
                .try_into()
                .unwrap();
            let ek = ml_kem_768::EncapsKey::try_from_bytes(ek_bytes).unwrap();
            let (secret, ct) = ek.try_encaps().unwrap();
            let ct_bytes = ct.into_bytes();
            noise_send(&mut stream, &mut noise, &ct_bytes).unwrap();
            let binding = channel_binding(&noise_hash, &ek_bytes, &ct_bytes).to_vec();
            assert_ne!(binding, noise_hash, "the old binding is never exposed");
            let pq = PqChannel::new(&noise_hash, &secret.into_bytes(), false);
            let mut reader = stream.try_clone().unwrap();
            let link = SealedLink::from_parts(stream, noise, pq, binding.clone());
            match link.recv(&mut reader) {
                LinkRead::Frame(frame) => assert_eq!(frame, b"initiator frame"),
                other => panic!("expected initiator frame, got {other:?}"),
            }
            link.send(b"responder frame").unwrap();
            binding
        });

        let mut stream = TcpStream::connect(addr).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let link = SealedLink::establish(&mut stream, true).unwrap();
        link.send(b"initiator frame").unwrap();
        match link.recv(&mut stream) {
            LinkRead::Frame(frame) => assert_eq!(frame, b"responder frame"),
            other => panic!("expected responder frame, got {other:?}"),
        }
        assert_eq!(link.handshake_hash(), responder.join().unwrap());
    }
}
