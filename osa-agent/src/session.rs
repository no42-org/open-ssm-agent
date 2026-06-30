/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: MIT
 */

//! Agent side of the authenticated session handshake (AD-27, #20).
//!
//! The agent is the **initiator**: on each broker connection it mints a fresh
//! `sid`, signs an ephemeral X25519 key with its identity key ([`ClientHello`]),
//! and on the coordinator's [`ServerHello`] (verified against the **pinned CA**)
//! derives the per-session AES-256-GCM keys. The coordinator then sends a sealed
//! session-ready beacon; opening it proves both ends agree, and the agent replies
//! with a sealed ack.
//!
//! This module is the pure protocol logic (given the loaded identity and the
//! wire bytes); the MQTT publish/subscribe orchestration lives in
//! [`crate::control_channel`].

use std::path::Path;

use anyhow::Context;
use osa_core::handshake::Initiator;
use osa_core::seal::{Direction, SessionKeys};
use osa_core::wire;
use osa_proto::v1::envelope::Kind;
use osa_proto::v1::{ClientHello, Envelope, ServerHello};
use x509_parser::prelude::{FromDer, X509Certificate};

const KEY_FILE: &str = "host.key";
const CERT_FILE: &str = "host.crt";
const CA_FILE: &str = "ca.crt";
const HOST_ID_FILE: &str = "host_id";

/// The agent identity needed to run the handshake: its signing key, its cert (the
/// identity it presents), the pinned CA public key (to verify `ServerHello`), and
/// its `host_id` (the routing key for sealed envelopes).
pub struct AgentIdentity {
    pub host_id: String,
    signing_key_pem: String,
    cert_der: Vec<u8>,
    ca_pubkey_sec1: Vec<u8>,
}

impl AgentIdentity {
    /// Load the enrolled identity from `state_dir`. Re-read per connection so a
    /// cert renewed on disk is adopted on the next reconnect.
    pub fn load(state_dir: &Path) -> anyhow::Result<Self> {
        let host_id = std::fs::read_to_string(state_dir.join(HOST_ID_FILE))
            .with_context(|| format!("reading {HOST_ID_FILE} (is the host enrolled?)"))?
            .trim()
            .to_string();
        let signing_key_pem = std::fs::read_to_string(state_dir.join(KEY_FILE))
            .with_context(|| format!("reading {KEY_FILE}"))?;
        let cert_der =
            pem_to_der(&std::fs::read(state_dir.join(CERT_FILE))?).context("parsing host cert")?;
        let ca_der =
            pem_to_der(&std::fs::read(state_dir.join(CA_FILE))?).context("parsing pinned CA")?;
        let ca_pubkey_sec1 =
            subject_pubkey_sec1(&ca_der).context("reading pinned CA public key")?;
        Ok(Self {
            host_id,
            signing_key_pem,
            cert_der,
            ca_pubkey_sec1,
        })
    }
}

/// In-flight handshake: the consumed-on-finish initiator and the `sid` it bound.
pub struct Handshaking {
    initiator: Initiator,
    sid: String,
}

/// A live session: the per-direction keys and the `sid` they were bound to.
pub struct Established {
    keys: SessionKeys,
    sid: String,
}

/// Begin a session: mint a fresh `sid`, build and sign the `ClientHello`. Returns
/// the in-flight state plus the encoded message to publish on the handshake
/// uplink.
pub fn start_handshake(id: &AgentIdentity) -> anyhow::Result<(Handshaking, Vec<u8>)> {
    let sid = uuid::Uuid::new_v4().to_string();
    let (initiator, hello) = Initiator::start(sid.as_bytes(), &id.cert_der, &id.signing_key_pem)
        .context("building ClientHello")?;
    let msg = ClientHello {
        sid: sid.clone(),
        client_eph: hello.client_eph.to_vec(),
        cert_der: id.cert_der.clone(),
        sig: hello.sig,
    };
    Ok((Handshaking { initiator, sid }, wire::encode(&msg)))
}

/// Finish on the coordinator's `ServerHello`: verify it against the pinned CA and
/// derive the session keys.
pub fn finish_handshake(
    hs: Handshaking,
    id: &AgentIdentity,
    server_hello: &[u8],
) -> anyhow::Result<Established> {
    let sh: ServerHello = wire::decode(server_hello).context("decoding ServerHello")?;
    anyhow::ensure!(
        sh.sid == hs.sid,
        "ServerHello sid does not match this session"
    );
    let server_eph: [u8; 32] = sh
        .server_eph
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("ServerHello ephemeral is not 32 bytes"))?;
    let keys = hs
        .initiator
        .finish(&server_eph, &sh.sig, &id.ca_pubkey_sec1)
        .context("ServerHello did not verify against the pinned CA")?;
    Ok(Established { keys, sid: hs.sid })
}

/// Open the coordinator's sealed session-ready beacon and, if it is the expected
/// payload, return the encoded sealed ack to publish on the control uplink.
pub fn confirm_session(
    est: &Established,
    id: &AgentIdentity,
    beacon: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let env: Envelope = wire::decode(beacon).context("decoding session-ready beacon")?;
    anyhow::ensure!(env.sid == est.sid, "beacon sid does not match this session");
    let payload = wire::open_envelope(&est.keys, Direction::CoordToAgent, &env)
        .map_err(|_| anyhow::anyhow!("session-ready beacon failed to open — key mismatch"))?;
    anyhow::ensure!(
        payload == wire::CTRL_SESSION_READY,
        "unexpected sealed control payload"
    );
    let ack = wire::seal_envelope(
        &est.keys,
        Direction::AgentToCoord,
        &id.host_id,
        &est.sid,
        0,
        Kind::Control,
        wire::CTRL_SESSION_ACK,
    );
    Ok(wire::encode(&ack))
}

/// Decode PEM bytes into the wrapped DER content.
fn pem_to_der(pem_bytes: &[u8]) -> anyhow::Result<Vec<u8>> {
    Ok(pem::parse(pem_bytes)?.into_contents())
}

/// Extract a cert's SubjectPublicKey as SEC1 point bytes (for an EC key the BIT
/// STRING contents are exactly the SEC1 point `VerifyingKey::from_sec1_bytes`
/// wants).
fn subject_pubkey_sec1(cert_der: &[u8]) -> anyhow::Result<Vec<u8>> {
    let (_, cert) = X509Certificate::from_der(cert_der)
        .map_err(|_| anyhow::anyhow!("malformed certificate"))?;
    Ok(cert.public_key().subject_public_key.data.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An enrolled agent identity plus the coordinator CA signing-key PEM, so a
    /// test can play the coordinator via `osa_core::handshake::respond`. Built with
    /// rcgen (the agent's real P-256 key algorithm).
    fn enrolled() -> (AgentIdentity, String) {
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let ca_key_pem = ca_key.serialize_pem(); // capture before the Issuer takes it
        let mut ca_params = rcgen::CertificateParams::default();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

        let host_key = rcgen::KeyPair::generate().unwrap();
        let host_id = uuid::Uuid::new_v4();
        let mut host_params = rcgen::CertificateParams::default();
        host_params.subject_alt_names = vec![rcgen::SanType::URI(
            rcgen::string::Ia5String::try_from(format!("urn:osa:host:{host_id}")).unwrap(),
        )];
        let issuer = rcgen::Issuer::from_params(&ca_params, ca_key);
        let host_cert = host_params.signed_by(&host_key, &issuer).unwrap();

        let ca_der = pem::parse(ca_cert.pem()).unwrap().into_contents();
        let id = AgentIdentity {
            host_id: host_id.to_string(),
            signing_key_pem: host_key.serialize_pem(),
            cert_der: host_cert.der().to_vec(),
            ca_pubkey_sec1: subject_pubkey_sec1(&ca_der).unwrap(),
        };
        (id, ca_key_pem)
    }

    /// Play the coordinator: verify the ClientHello and produce the ServerHello +
    /// the session keys (exactly what the bridge does, via the same `respond`).
    fn coordinator_respond(
        id: &AgentIdentity,
        hello: &ClientHello,
        ca_key_pem: &str,
    ) -> osa_core::handshake::ServerResponse {
        let client_eph: [u8; 32] = hello.client_eph.as_slice().try_into().unwrap();
        let agent_pub = subject_pubkey_sec1(&id.cert_der).unwrap();
        osa_core::handshake::respond(
            hello.sid.as_bytes(),
            &client_eph,
            &hello.sig,
            &agent_pub,
            &hello.cert_der,
            ca_key_pem,
        )
        .unwrap()
    }

    #[test]
    fn start_handshake_builds_a_decodable_client_hello() {
        let (id, _) = enrolled();
        let (_hs, bytes) = start_handshake(&id).unwrap();
        let hello: ClientHello = wire::decode(&bytes).unwrap();
        assert_eq!(hello.client_eph.len(), 32);
        assert_eq!(hello.cert_der, id.cert_der);
        assert_eq!(hello.sig.len(), 64);
        assert!(
            uuid::Uuid::parse_str(&hello.sid).is_ok(),
            "sid is a fresh UUID"
        );
    }

    #[test]
    fn full_handshake_then_sealed_session_open_round_trips() {
        // The whole agent side against the real `respond`: start → finish →
        // open the coordinator's beacon → produce an ack the coordinator opens.
        let (id, ca_key_pem) = enrolled();
        let (hs, hello_bytes) = start_handshake(&id).unwrap();
        let hello: ClientHello = wire::decode(&hello_bytes).unwrap();
        let resp = coordinator_respond(&id, &hello, &ca_key_pem);

        let server_hello = ServerHello {
            sid: hello.sid.clone(),
            server_eph: resp.server_eph.to_vec(),
            sig: resp.sig.clone(),
        };
        let est = finish_handshake(hs, &id, &wire::encode(&server_hello)).unwrap();

        // Coordinator seals the ready beacon; the agent opens it and replies.
        let beacon = wire::seal_envelope(
            &resp.keys,
            Direction::CoordToAgent,
            &id.host_id,
            &hello.sid,
            0,
            Kind::Control,
            wire::CTRL_SESSION_READY,
        );
        let ack_bytes = confirm_session(&est, &id, &wire::encode(&beacon)).unwrap();

        // The coordinator opens the agent's ack with its own session keys.
        let ack: Envelope = wire::decode(&ack_bytes).unwrap();
        let pt = wire::open_envelope(&resp.keys, Direction::AgentToCoord, &ack).unwrap();
        assert_eq!(
            pt,
            wire::CTRL_SESSION_ACK,
            "coordinator must open the agent ack"
        );
    }

    #[test]
    fn finish_rejects_a_server_hello_not_signed_by_the_pinned_ca() {
        // A MITM signs the ServerHello with a non-CA key → the agent rejects it.
        let (id, _ca_key_pem) = enrolled();
        let (hs, hello_bytes) = start_handshake(&id).unwrap();
        let hello: ClientHello = wire::decode(&hello_bytes).unwrap();
        let mitm = rcgen::KeyPair::generate().unwrap().serialize_pem();
        let resp = coordinator_respond(&id, &hello, &mitm); // wrong signer
        let server_hello = ServerHello {
            sid: hello.sid.clone(),
            server_eph: resp.server_eph.to_vec(),
            sig: resp.sig.clone(),
        };
        assert!(finish_handshake(hs, &id, &wire::encode(&server_hello)).is_err());
    }

    #[test]
    fn confirm_rejects_a_beacon_for_a_different_sid() {
        let (id, ca_key_pem) = enrolled();
        let (hs, hello_bytes) = start_handshake(&id).unwrap();
        let hello: ClientHello = wire::decode(&hello_bytes).unwrap();
        let resp = coordinator_respond(&id, &hello, &ca_key_pem);
        let server_hello = ServerHello {
            sid: hello.sid.clone(),
            server_eph: resp.server_eph.to_vec(),
            sig: resp.sig.clone(),
        };
        let est = finish_handshake(hs, &id, &wire::encode(&server_hello)).unwrap();
        // A beacon bound to a different sid is refused (no cross-session splice).
        let beacon = wire::seal_envelope(
            &resp.keys,
            Direction::CoordToAgent,
            &id.host_id,
            "some-other-sid",
            0,
            Kind::Control,
            wire::CTRL_SESSION_READY,
        );
        assert!(confirm_session(&est, &id, &wire::encode(&beacon)).is_err());
    }
}
