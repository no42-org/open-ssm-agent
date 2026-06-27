/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: MIT
 */

//! AES-256-GCM payload seal (AD-27), per `docs/design/aead-nonce.md`.
//!
//! The broker is untrusted, so every `Envelope.ciphertext` is end-to-end sealed.
//! Uniqueness of the `(key, nonce)` pair — on which AES-GCM's security rests — is
//! made **structural**:
//!
//! - **Per-session key.** A fresh X25519 ECDH establishes a shared secret each
//!   session; HKDF derives it into the session keys. A reconnect runs a new
//!   exchange, so the same `seq` under a new session never reuses a nonce.
//! - **Per-direction subkeys.** The session secret is split into independent
//!   `c2a` (coordinator→agent) and `a2c` keys, so the two peers never share a
//!   nonce space.
//! - **Nonce = seq.** The 96-bit nonce is the cleartext envelope `seq`
//!   (big-endian) in the low 8 bytes; monotonic per session.
//!
//! The cleartext routing fields travel as AAD, so the untrusted broker cannot
//! splice a valid ciphertext onto different routing without failing the tag.
//!
//! This module is the primitive; wiring the public-key exchange into the session
//! handshake comes with the control-handshake story.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Direction of an envelope, selecting the per-direction key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    /// Coordinator → agent.
    CoordToAgent,
    /// Agent → coordinator.
    AgentToCoord,
}

const LABEL_C2A: &[u8] = b"osa/v1 c2a";
const LABEL_A2C: &[u8] = b"osa/v1 a2c";

/// AEAD open failed: the ciphertext, AAD, nonce, direction, or key did not match.
#[derive(Debug, thiserror::Error)]
#[error("AEAD authentication failed")]
pub struct OpenError;

/// The session handshake failed.
#[derive(Debug, thiserror::Error)]
pub enum HandshakeError {
    /// The peer's public key is a low-order point, which would force a
    /// predictable (attacker-known) shared secret. Rejected.
    #[error("peer public key is a low-order point")]
    WeakPeerKey,
}

/// One side's ephemeral X25519 secret plus the public key to hand the peer.
pub struct Handshake {
    secret: StaticSecret,
    /// Public key to send to the peer (over the already-authenticated channel).
    pub public: [u8; 32],
}

impl Handshake {
    /// Generate a fresh ephemeral X25519 keypair.
    pub fn new() -> Result<Self, getrandom::Error> {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed)?;
        let secret = StaticSecret::from(seed);
        let public = PublicKey::from(&secret).to_bytes();
        seed.zeroize(); // the StaticSecret keeps its own (clamped) copy
        Ok(Self { secret, public })
    }

    /// Complete the exchange with the peer's public key, deriving the session
    /// keys. `binding` (e.g. both peers' certificate DERs, in an agreed canonical
    /// order) plus both ephemeral public keys are folded into the KDF, so the
    /// keys are bound to this exact exchange and peer pair (channel binding).
    ///
    /// Fails with [`HandshakeError::WeakPeerKey`] if `peer_public` is a low-order
    /// point that would yield a predictable shared secret.
    pub fn derive(
        self,
        peer_public: &[u8; 32],
        binding: &[u8],
    ) -> Result<SessionKeys, HandshakeError> {
        let shared = self.secret.diffie_hellman(&PublicKey::from(*peer_public));
        if !shared.was_contributory() {
            return Err(HandshakeError::WeakPeerKey);
        }
        // Bind both ephemeral pubkeys in a canonical (role-independent) order so
        // each side computes the same transcript.
        let (lo, hi) = if self.public <= *peer_public {
            (self.public, *peer_public)
        } else {
            (*peer_public, self.public)
        };
        let mut transcript = Vec::with_capacity(binding.len() + 64);
        transcript.extend_from_slice(binding);
        transcript.extend_from_slice(&lo);
        transcript.extend_from_slice(&hi);
        let keys = SessionKeys::from_shared(shared.as_bytes(), &transcript);
        transcript.zeroize();
        Ok(keys)
    }
}

/// Per-session symmetric keys, one per direction. Zeroized on drop.
#[derive(ZeroizeOnDrop)]
pub struct SessionKeys {
    c2a: [u8; 32],
    a2c: [u8; 32],
}

impl SessionKeys {
    fn from_shared(shared: &[u8; 32], binding: &[u8]) -> Self {
        let hk = Hkdf::<Sha256>::new(Some(binding), shared);
        let mut c2a = [0u8; 32];
        let mut a2c = [0u8; 32];
        hk.expand(LABEL_C2A, &mut c2a)
            .expect("32 is a valid HKDF-SHA256 output length");
        hk.expand(LABEL_A2C, &mut a2c)
            .expect("32 is a valid HKDF-SHA256 output length");
        let keys = Self { c2a, a2c };
        // Wipe the stack copies (the keys live on in `keys`, zeroized on drop).
        c2a.zeroize();
        a2c.zeroize();
        keys
    }

    fn cipher(&self, dir: Direction) -> Aes256Gcm {
        let key = match dir {
            Direction::CoordToAgent => &self.c2a,
            Direction::AgentToCoord => &self.a2c,
        };
        Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key))
    }

    /// Seal `plaintext` for `seq` in `dir`, authenticating `aad` (the cleartext
    /// routing header). Returns ciphertext‖tag.
    ///
    /// # Caller contract (load-bearing)
    /// `seq` becomes the GCM nonce, so the caller MUST never seal two payloads
    /// with the same `(dir, seq)` under one session. Reuse is catastrophic — it
    /// leaks plaintext XOR **and** enables tag forgery. The envelope layer owns
    /// `seq` and assigns it strictly monotonically per direction; this primitive
    /// trusts that.
    pub fn seal(&self, dir: Direction, seq: u64, aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        self.cipher(dir)
            .encrypt(
                &nonce(seq),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            // Only fails if the message exceeds AES-GCM's ~64 GiB limit, which a
            // control/stream chunk never does.
            .expect("plaintext within AES-GCM size limit")
    }

    /// Open a sealed payload. Fails if the ciphertext or `aad` was tampered, or
    /// the wrong `seq`/`dir`/key is used.
    ///
    /// Successful authentication does **not** imply freshness: a replayed
    /// `(seq, aad, ciphertext)` opens cleanly. The caller MUST reject
    /// non-increasing `seq` per direction — that is the
    /// [`ReorderBuffer`](crate::stream::ReorderBuffer)'s dedup at the session
    /// layer (AD-8).
    pub fn open(
        &self,
        dir: Direction,
        seq: u64,
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, OpenError> {
        self.cipher(dir)
            .decrypt(
                &nonce(seq),
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| OpenError)
    }
}

/// 96-bit GCM nonce: four zero bytes followed by `seq` big-endian.
fn nonce(seq: u64) -> Nonce<<Aes256Gcm as aes_gcm::AeadCore>::NonceSize> {
    let mut bytes = [0u8; 12];
    bytes[4..].copy_from_slice(&seq.to_be_bytes());
    *Nonce::from_slice(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two peers run the exchange and derive identical session keys.
    fn session_pair() -> (SessionKeys, SessionKeys) {
        let a = Handshake::new().unwrap();
        let b = Handshake::new().unwrap();
        let (apub, bpub) = (a.public, b.public);
        let binding = b"certA||certB";
        (
            a.derive(&bpub, binding).unwrap(),
            b.derive(&apub, binding).unwrap(),
        )
    }

    #[test]
    fn round_trips_across_the_pair() {
        let (ka, kb) = session_pair();
        let ct = ka.seal(Direction::CoordToAgent, 7, b"hdr", b"hello");
        let pt = kb.open(Direction::CoordToAgent, 7, b"hdr", &ct).unwrap();
        assert_eq!(pt, b"hello");
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let (ka, kb) = session_pair();
        let mut ct = ka.seal(Direction::AgentToCoord, 1, b"hdr", b"data");
        ct[0] ^= 0x01;
        assert!(kb.open(Direction::AgentToCoord, 1, b"hdr", &ct).is_err());
    }

    #[test]
    fn tampered_aad_is_rejected() {
        let (ka, kb) = session_pair();
        let ct = ka.seal(Direction::CoordToAgent, 1, b"hdr", b"data");
        // Same ciphertext, different routing header → tag fails.
        assert!(kb.open(Direction::CoordToAgent, 1, b"HDR", &ct).is_err());
    }

    #[test]
    fn wrong_direction_key_is_rejected() {
        let (ka, kb) = session_pair();
        let ct = ka.seal(Direction::CoordToAgent, 1, b"hdr", b"data");
        // Opening a c2a ciphertext with the a2c key must fail.
        assert!(kb.open(Direction::AgentToCoord, 1, b"hdr", &ct).is_err());
    }

    #[test]
    fn wrong_seq_is_rejected() {
        let (ka, kb) = session_pair();
        let ct = ka.seal(Direction::CoordToAgent, 1, b"hdr", b"data");
        assert!(kb.open(Direction::CoordToAgent, 2, b"hdr", &ct).is_err());
    }

    #[test]
    fn a_new_session_cannot_open_an_old_ciphertext() {
        // Reconnect safety: a fresh exchange yields different keys, so the same
        // seq reused across sessions never collides into a usable (key, nonce).
        let (ka, _) = session_pair();
        let (_, kb2) = session_pair();
        let ct = ka.seal(Direction::CoordToAgent, 0, b"hdr", b"data");
        assert!(kb2.open(Direction::CoordToAgent, 0, b"hdr", &ct).is_err());
    }

    #[test]
    fn binding_separates_sessions() {
        let a = Handshake::new().unwrap();
        let b = Handshake::new().unwrap();
        let (apub, bpub) = (a.public, b.public);
        let ka = a.derive(&bpub, b"binding-1").unwrap();
        let kb = b.derive(&apub, b"binding-2").unwrap(); // different binding
        let ct = ka.seal(Direction::CoordToAgent, 0, b"", b"x");
        assert!(kb.open(Direction::CoordToAgent, 0, b"", &ct).is_err());
    }

    #[test]
    fn nonce_is_seq_big_endian_in_low_bytes() {
        let n = nonce(0x0102_0304_0506_0708);
        assert_eq!(n.as_slice(), &[0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn weak_peer_key_is_rejected() {
        let a = Handshake::new().unwrap();
        // An all-zero (low-order) peer public key must be refused.
        assert!(matches!(
            a.derive(&[0u8; 32], b"bind"),
            Err(HandshakeError::WeakPeerKey)
        ));
    }

    #[test]
    fn empty_plaintext_round_trips() {
        let (ka, kb) = session_pair();
        let ct = ka.seal(Direction::AgentToCoord, 3, b"", b"");
        assert_eq!(kb.open(Direction::AgentToCoord, 3, b"", &ct).unwrap(), b"");
    }

    #[test]
    fn max_seq_round_trips() {
        let (ka, kb) = session_pair();
        let ct = ka.seal(Direction::CoordToAgent, u64::MAX, b"h", b"x");
        assert_eq!(
            kb.open(Direction::CoordToAgent, u64::MAX, b"h", &ct)
                .unwrap(),
            b"x"
        );
    }
}
