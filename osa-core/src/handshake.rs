/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: MIT
 */

//! Authenticated session handshake (AD-27, #20), per `docs/design/session-handshake.md`.
//!
//! The coordinator and agent talk **through the untrusted broker**, so the
//! per-session AES-256-GCM key exchange must be authenticated — the seal's
//! cert-DER channel binding alone does not stop a broker man-in-the-middle from
//! substituting its own ephemeral X25519 keys. Here each side **signs its
//! ephemeral public key** (ECDSA P-256, the identity-key algorithm) over a
//! transcript bound to a fresh `sid`; the peer verifies the signature against the
//! authenticated identity before deriving keys. This is a signature-authenticated
//! Diffie–Hellman (station-to-station).
//!
//! This module is the **pure crypto**: transcripts, ECDSA sign/verify, and the
//! key agreement (built on [`crate::seal::Handshake`]). Cert-chain verification,
//! `host_id` extraction, and the MQTT flow live in the bins (they hold the certs
//! and the x509 tooling).
//!
//! # Caller contract (enforced in the bins, #20b)
//!
//! - **`sid` freshness.** Every field but `sid` is fresh per handshake (the
//!   ephemerals come from a CSPRNG), but anti-replay and per-session key
//!   separation rest on the caller minting a **fresh, unique, unforgeable `sid`**
//!   (CSPRNG, ≥16 bytes) for each session. This module treats `sid` as opaque and
//!   does not enforce uniqueness; a replayed `ClientHello` is otherwise bounded
//!   (each [`respond`] mints a fresh `server_eph`, so the attacker cannot complete
//!   the session without the client ephemeral secret).
//! - **Identity binding.** [`respond`]'s `agent_public_key_sec1` **must** be the
//!   SubjectPublicKey of the same `cert_der` it binds — the caller derives both
//!   from one parsed, chain-verified cert. Passing a key from a *different* cert
//!   would verify a signature against one identity while binding another into the
//!   session, defeating the whole construction. This crate cannot enforce the
//!   correspondence (it has no x509 parser); the cert-parse site in the bin does.

use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::pkcs8::DecodePrivateKey;

use crate::seal::{Handshake, HandshakeError, SessionKeys};

const CLIENT_CTX: &[u8] = b"osa/v1 hs c2s";
const SERVER_CTX: &[u8] = b"osa/v1 hs s2c";

/// A handshake step failed.
#[derive(Debug, thiserror::Error)]
pub enum HsError {
    #[error("identity signing key could not be loaded")]
    BadKey,
    #[error("peer public key could not be loaded")]
    BadPeerKey,
    #[error("handshake signature did not verify")]
    BadSignature,
    #[error("peer ephemeral key is unusable: {0}")]
    BadEphemeral(#[from] HandshakeError),
    #[error("entropy source failed")]
    Rng,
}

fn push_field(buf: &mut Vec<u8>, field: &[u8]) {
    buf.extend_from_slice(&(field.len() as u64).to_be_bytes());
    buf.extend_from_slice(field);
}

/// What the agent signs in `ClientHello`: ctx ‖ len(sid)‖sid ‖ epoch ‖ len(eph)‖eph.
/// The monotonic session `epoch` (4.3, reconnect-safe) is folded into the SIGNED
/// transcript, so the untrusted broker cannot forge or downgrade it: the
/// coordinator rejects a session-open whose epoch is not strictly greater than the
/// highest it has accepted for that host (anti-resurrection).
pub fn client_transcript(sid: &[u8], epoch: u64, client_eph: &[u8; 32]) -> Vec<u8> {
    let mut t = Vec::with_capacity(CLIENT_CTX.len() + sid.len() + 72);
    t.extend_from_slice(CLIENT_CTX);
    push_field(&mut t, sid);
    t.extend_from_slice(&epoch.to_be_bytes());
    push_field(&mut t, client_eph);
    t
}

/// What the coordinator (CA) signs in `ServerHello`: it binds **both** ephemerals
/// and the `sid`, so a MITM cannot splice a different client ephemeral.
pub fn server_transcript(sid: &[u8], client_eph: &[u8; 32], server_eph: &[u8; 32]) -> Vec<u8> {
    let mut t = Vec::with_capacity(SERVER_CTX.len() + sid.len() + 96);
    t.extend_from_slice(SERVER_CTX);
    push_field(&mut t, sid);
    push_field(&mut t, client_eph);
    push_field(&mut t, server_eph);
    t
}

/// The HKDF binding for the session keys: the full authenticated transcript
/// (sid + both ephemerals + the agent cert), so the keys are tied to this exact,
/// authenticated exchange.
fn session_binding(
    sid: &[u8],
    client_eph: &[u8; 32],
    server_eph: &[u8; 32],
    cert_der: &[u8],
) -> Vec<u8> {
    let mut b = Vec::with_capacity(sid.len() + cert_der.len() + 96);
    push_field(&mut b, sid);
    push_field(&mut b, client_eph);
    push_field(&mut b, server_eph);
    push_field(&mut b, cert_der);
    b
}

/// Sign `msg` with an ECDSA P-256 identity key (PKCS#8 PEM, as serialized at
/// enrollment). Returns a fixed 64-byte `r‖s` signature.
pub fn sign(signing_key_pem: &str, msg: &[u8]) -> Result<Vec<u8>, HsError> {
    let key = SigningKey::from_pkcs8_pem(signing_key_pem).map_err(|_| HsError::BadKey)?;
    let sig: Signature = key.sign(msg);
    Ok(sig.to_bytes().to_vec())
}

/// Verify a 64-byte `r‖s` signature over `msg` against a peer's ECDSA P-256 public
/// key in SEC1 form (the raw point bytes a cert's SubjectPublicKey carries).
pub fn verify(public_key_sec1: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), HsError> {
    let vk = VerifyingKey::from_sec1_bytes(public_key_sec1).map_err(|_| HsError::BadPeerKey)?;
    let signature = Signature::from_slice(sig).map_err(|_| HsError::BadSignature)?;
    vk.verify(msg, &signature)
        .map_err(|_| HsError::BadSignature)
}

/// The agent's in-flight handshake state between sending `ClientHello` and
/// receiving `ServerHello`. Holds the ephemeral secret (consumed on finish).
pub struct Initiator {
    eph: Handshake,
    sid: Vec<u8>,
    cert_der: Vec<u8>,
}

/// The signed `ClientHello` content the agent puts on the wire (alongside its
/// `cert_der`, which the caller carries).
pub struct ClientHello {
    pub client_eph: [u8; 32],
    pub sig: Vec<u8>,
}

impl Initiator {
    /// Begin a session for `sid`: generate an ephemeral and sign it with the
    /// agent's identity key. `cert_der` is the agent's own cert (folded into the
    /// key binding so it matches what the coordinator binds).
    pub fn start(
        sid: &[u8],
        epoch: u64,
        cert_der: &[u8],
        signing_key_pem: &str,
    ) -> Result<(Self, ClientHello), HsError> {
        let eph = Handshake::new().map_err(|_| HsError::Rng)?;
        let client_eph = eph.public;
        let sig = sign(signing_key_pem, &client_transcript(sid, epoch, &client_eph))?;
        Ok((
            Self {
                eph,
                sid: sid.to_vec(),
                cert_der: cert_der.to_vec(),
            },
            ClientHello { client_eph, sig },
        ))
    }

    /// Finish on `ServerHello`: verify the coordinator's signature against the
    /// **pinned CA** public key, then derive the session keys. Returns keys only
    /// if the signature and ephemeral are valid.
    pub fn finish(
        self,
        server_eph: &[u8; 32],
        server_sig: &[u8],
        ca_public_key_sec1: &[u8],
    ) -> Result<SessionKeys, HsError> {
        let client_eph = self.eph.public;
        verify(
            ca_public_key_sec1,
            &server_transcript(&self.sid, &client_eph, server_eph),
            server_sig,
        )?;
        let binding = session_binding(&self.sid, &client_eph, server_eph, &self.cert_der);
        Ok(self.eph.derive(server_eph, &binding)?)
    }
}

/// The signed `ServerHello` content + the derived session keys (coordinator side).
pub struct ServerResponse {
    pub server_eph: [u8; 32],
    pub sig: Vec<u8>,
    pub keys: SessionKeys,
}

/// Coordinator: respond to a `ClientHello` whose `cert_der` has **already** been
/// verified by the caller (chains to the CA, unrevoked, SAN matches the tenant).
/// Verifies the client's signature against the cert's public key, signs the
/// `ServerHello` with the CA key, and derives the session keys.
pub fn respond(
    sid: &[u8],
    epoch: u64,
    client_eph: &[u8; 32],
    client_sig: &[u8],
    agent_public_key_sec1: &[u8],
    cert_der: &[u8],
    ca_signing_key_pem: &str,
) -> Result<ServerResponse, HsError> {
    verify(
        agent_public_key_sec1,
        &client_transcript(sid, epoch, client_eph),
        client_sig,
    )?;
    let eph = Handshake::new().map_err(|_| HsError::Rng)?;
    let server_eph = eph.public;
    let sig = sign(
        ca_signing_key_pem,
        &server_transcript(sid, client_eph, &server_eph),
    )?;
    let binding = session_binding(sid, client_eph, &server_eph, cert_der);
    let keys = eph.derive(client_eph, &binding)?;
    Ok(ServerResponse {
        server_eph,
        sig,
        keys,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seal::Direction;
    use p256::ecdsa::SigningKey;
    use p256::pkcs8::EncodePrivateKey;

    /// A session epoch for the tests (4.3); the exact value is immaterial to the
    /// crypto, only that both sides use the same one.
    const EPOCH: u64 = 1;

    /// A fixed ECDSA P-256 identity from a deterministic scalar:
    /// (PKCS#8 PEM private, SEC1 public-point bytes). Deterministic so the tests
    /// are reproducible while still exercising real ECDSA sign/verify.
    fn identity() -> (String, Vec<u8>) {
        identity_from(7)
    }

    fn identity_from(scalar: u8) -> (String, Vec<u8>) {
        let sk = SigningKey::from_slice(&[scalar; 32]).unwrap();
        let pem = sk.to_pkcs8_pem(Default::default()).unwrap().to_string();
        (pem, sk.verifying_key().to_sec1_bytes().to_vec())
    }

    #[test]
    fn an_authenticated_handshake_yields_matching_session_keys() {
        let (agent_key, agent_pub) = identity_from(11);
        let (ca_key, ca_pub) = identity_from(22);
        let cert_der = b"agent-cert-der";
        let sid = b"session-1";

        // Agent → ClientHello.
        let (initiator, hello) = Initiator::start(sid, EPOCH, cert_der, &agent_key).unwrap();
        // Coordinator (cert already verified) → ServerHello + its keys.
        let resp = respond(
            sid,
            EPOCH,
            &hello.client_eph,
            &hello.sig,
            &agent_pub,
            cert_der,
            &ca_key,
        )
        .unwrap();
        // Agent finishes → its keys.
        let agent_keys = initiator
            .finish(&resp.server_eph, &resp.sig, &ca_pub)
            .unwrap();

        // Both sides derived the *same* session: a payload sealed by one opens
        // with the other's keys.
        let ct = resp
            .keys
            .seal(Direction::CoordToAgent, 0, b"hdr", b"dispatch");
        let pt = agent_keys
            .open(Direction::CoordToAgent, 0, b"hdr", &ct)
            .unwrap();
        assert_eq!(pt, b"dispatch");
    }

    #[test]
    fn a_forged_client_signature_is_rejected() {
        let (agent_key, agent_pub) = identity_from(11);
        let (ca_key, _ca_pub) = identity_from(22);
        let (other_key, _) = identity_from(99); // not the agent's key
        let cert_der = b"agent-cert-der";
        let sid = b"session-1";

        // Signature made by the wrong key; verifying against the agent's real
        // public key must fail (a MITM cannot impersonate the agent).
        let (_init, hello) = Initiator::start(sid, EPOCH, cert_der, &other_key).unwrap();
        assert!(matches!(
            respond(
                sid,
                EPOCH,
                &hello.client_eph,
                &hello.sig,
                &agent_pub,
                cert_der,
                &ca_key
            ),
            Err(HsError::BadSignature)
        ));

        // Tampering the ephemeral after signing is likewise rejected.
        let (_init, mut bad) = Initiator::start(sid, EPOCH, cert_der, &agent_key).unwrap();
        bad.client_eph[0] ^= 1;
        assert!(matches!(
            respond(
                sid,
                EPOCH,
                &bad.client_eph,
                &bad.sig,
                &agent_pub,
                cert_der,
                &ca_key
            ),
            Err(HsError::BadSignature)
        ));
    }

    #[test]
    fn a_forged_server_signature_is_rejected_by_the_agent() {
        let (agent_key, agent_pub) = identity_from(11);
        let (_ca_key, ca_pub) = identity_from(22);
        let (mitm_key, _) = identity_from(99); // not the CA
        let cert_der = b"agent-cert-der";
        let sid = b"session-1";

        let (initiator, hello) = Initiator::start(sid, EPOCH, cert_der, &agent_key).unwrap();
        // A MITM signs the ServerHello with a non-CA key.
        let resp = respond(
            sid,
            EPOCH,
            &hello.client_eph,
            &hello.sig,
            &agent_pub,
            cert_der,
            &mitm_key,
        )
        .unwrap();
        // The agent verifies against the *pinned CA* key → rejected.
        assert!(matches!(
            initiator.finish(&resp.server_eph, &resp.sig, &ca_pub),
            Err(HsError::BadSignature)
        ));
    }

    #[test]
    fn a_low_order_ephemeral_is_rejected_by_the_coordinator() {
        let (agent_key, agent_pub) = identity_from(11);
        let (ca_key, _) = identity_from(22);
        let cert_der = b"c";
        let sid = b"s";
        // Sign an all-zero (low-order) ephemeral with a valid key, so only the
        // X25519 contributory check can catch it.
        let zero = [0u8; 32];
        let sig = sign(&agent_key, &client_transcript(sid, EPOCH, &zero)).unwrap();
        assert!(matches!(
            respond(sid, EPOCH, &zero, &sig, &agent_pub, cert_der, &ca_key),
            Err(HsError::BadEphemeral(_))
        ));
    }

    #[test]
    fn a_low_order_ephemeral_is_rejected_by_the_agent() {
        // The symmetric agent-side path: the coordinator (here, a MITM holding the
        // CA key) sends a *validly signed* but low-order `server_eph`. Only the
        // X25519 contributory check in `finish` can catch it, and it must run
        // after the signature verifies.
        let (agent_key, _) = identity_from(11);
        let (ca_key, ca_pub) = identity_from(22);
        let cert_der = b"agent-cert-der";
        let sid = b"session-1";

        let (initiator, hello) = Initiator::start(sid, EPOCH, cert_der, &agent_key).unwrap();
        let zero = [0u8; 32];
        let server_sig = sign(&ca_key, &server_transcript(sid, &hello.client_eph, &zero)).unwrap();
        assert!(matches!(
            initiator.finish(&zero, &server_sig, &ca_pub),
            Err(HsError::BadEphemeral(_))
        ));
    }

    #[test]
    fn a_cert_der_mismatch_yields_non_matching_keys() {
        // The agent binds its *own* cert; the coordinator binds the cert it
        // received. If a MITM swaps the cert_der in transit the two bindings
        // diverge, the HKDF produces different keys, and the channel fails closed
        // — nothing decrypts, no silent acceptance.
        let (agent_key, agent_pub) = identity_from(11);
        let (ca_key, ca_pub) = identity_from(22);
        let sid = b"session-1";

        let (initiator, hello) =
            Initiator::start(sid, EPOCH, b"agent-cert-der", &agent_key).unwrap();
        // Coordinator binds a *different* cert than the agent did.
        let resp = respond(
            sid,
            EPOCH,
            &hello.client_eph,
            &hello.sig,
            &agent_pub,
            b"tampered-cert-der",
            &ca_key,
        )
        .unwrap();
        let agent_keys = initiator
            .finish(&resp.server_eph, &resp.sig, &ca_pub)
            .unwrap();

        let ct = resp.keys.seal(Direction::CoordToAgent, 0, b"hdr", b"x");
        assert!(
            agent_keys
                .open(Direction::CoordToAgent, 0, b"hdr", &ct)
                .is_err()
        );
    }

    #[test]
    fn malformed_inputs_are_rejected() {
        let (key, pubkey) = identity();
        let msg = b"transcript";
        let sig = sign(&key, msg).unwrap();

        // A non-PEM signing key.
        assert!(matches!(sign("not a pem", msg), Err(HsError::BadKey)));
        // A truncated / empty SEC1 public key.
        assert!(matches!(verify(b"", msg, &sig), Err(HsError::BadPeerKey)));
        assert!(matches!(
            verify(&pubkey[..8], msg, &sig),
            Err(HsError::BadPeerKey)
        ));
        // A wrong-length (here, 63-byte) signature is not a valid r‖s pair.
        assert!(matches!(
            verify(&pubkey, msg, &sig[..63]),
            Err(HsError::BadSignature)
        ));
    }

    #[test]
    fn transcripts_bind_their_fields() {
        // Different sids / ephemerals produce different transcripts (so a
        // signature can't be replayed across sessions).
        let a = client_transcript(b"s1", EPOCH, &[1u8; 32]);
        let b = client_transcript(b"s2", EPOCH, &[1u8; 32]);
        let c = client_transcript(b"s1", EPOCH, &[2u8; 32]);
        assert_ne!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn the_epoch_is_authenticated_and_cannot_be_downgraded() {
        // The agent signs its session epoch (4.3). A broker that rewrites the epoch
        // to a lower value (to replay/resurrect an old session) fails the signature;
        // only the epoch the agent actually signed verifies.
        let (agent_key, agent_pub) = identity_from(11);
        let (ca_key, _) = identity_from(22);
        let cert_der = b"agent-cert-der";
        let sid = b"session-1";
        let (_init, hello) = Initiator::start(sid, 5, cert_der, &agent_key).unwrap();
        assert!(matches!(
            respond(
                sid,
                4,
                &hello.client_eph,
                &hello.sig,
                &agent_pub,
                cert_der,
                &ca_key
            ),
            Err(HsError::BadSignature),
        ));
        assert!(
            respond(
                sid,
                5,
                &hello.client_eph,
                &hello.sig,
                &agent_pub,
                cert_der,
                &ca_key
            )
            .is_ok(),
            "the epoch the agent signed verifies"
        );
    }

    #[test]
    fn sign_and_verify_round_trip() {
        let (key, pubkey) = identity();
        let msg = b"transcript";
        let sig = sign(&key, msg).unwrap();
        assert!(verify(&pubkey, msg, &sig).is_ok());
        assert!(matches!(
            verify(&pubkey, b"other", &sig),
            Err(HsError::BadSignature)
        ));
    }
}
