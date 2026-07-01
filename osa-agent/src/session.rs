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
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

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

/// A live session: the per-direction keys, the `sid` they were bound to, the
/// monotonic uplink `seq` allocator, and the downlink replay guard.
///
/// `keys` and `send_seq` are shared (`Arc`) so concurrent job tasks can each seal
/// uplink envelopes with a **unique** `seq` (the AES-GCM nonce) — atomic
/// allocation is what keeps the per-direction nonce unique by construction.
pub struct Established {
    keys: Arc<SessionKeys>,
    sid: String,
    /// Next uplink (agent→coordinator) `seq`. The session-open ack takes 0; sealed
    /// results take 1, 2, … — allocated atomically across all job tasks.
    send_seq: Arc<AtomicU64>,
    /// Highest downlink (coordinator→agent) `seq` accepted, for replay rejection.
    /// `None` until the first downlink message (the beacon at seq 0).
    recv_high: Option<u64>,
}

impl Established {
    /// A cloneable handle to the session keys (for a spawned job task).
    pub fn keys(&self) -> Arc<SessionKeys> {
        Arc::clone(&self.keys)
    }

    /// A cloneable handle to the uplink `seq` allocator (for a spawned job task).
    pub fn send_seq(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.send_seq)
    }

    pub fn sid(&self) -> &str {
        &self.sid
    }

    /// Accept a downlink `seq` if it is newer than every one seen, updating the
    /// high-water mark. Rejects a replayed or out-of-order (≤ high) `seq`.
    fn accept_recv(&mut self, seq: u64) -> bool {
        if self.recv_high.is_some_and(|h| seq <= h) {
            return false;
        }
        self.recv_high = Some(seq);
        true
    }

    /// Open a sealed downlink envelope and enforce the replay guard, in the
    /// security-critical order: **authenticate first** (AEAD open, which also binds
    /// the cleartext `sid`/`seq` via the AAD), then advance the replay high-water
    /// mark. Returns the plaintext, or `None` if the tag fails OR the `seq` is a
    /// replay/stale. Authenticating first is what stops an untrusted broker from
    /// poisoning the high-water mark with a forged (unopenable) envelope to wedge
    /// the channel — a rejected forgery never touches `recv_high`.
    pub fn open_downlink(&mut self, env: &Envelope) -> Option<Vec<u8>> {
        let plaintext = wire::open_envelope(&self.keys, Direction::CoordToAgent, env).ok()?;
        self.accept_recv(env.seq).then_some(plaintext)
    }
}

/// Seal `payload` as the next uplink envelope and return its encoded bytes ready
/// to publish. Allocates the `seq` atomically from `send_seq` (unique nonce).
pub fn seal_uplink(
    keys: &SessionKeys,
    send_seq: &AtomicU64,
    host_id: &str,
    sid: &str,
    payload: &[u8],
) -> Vec<u8> {
    let seq = send_seq.fetch_add(1, Ordering::Relaxed);
    let env = wire::seal_envelope(
        keys,
        Direction::AgentToCoord,
        host_id,
        sid,
        seq,
        Kind::Control,
        payload,
    );
    wire::encode(&env)
}

/// Begin a session: mint a fresh `sid`, build and sign the `ClientHello` carrying
/// this session's monotonic `epoch` (4.3). Returns the in-flight state plus the
/// encoded message to publish on the handshake uplink.
pub fn start_handshake(id: &AgentIdentity, epoch: u64) -> anyhow::Result<(Handshaking, Vec<u8>)> {
    let sid = uuid::Uuid::new_v4().to_string();
    let (initiator, hello) =
        Initiator::start(sid.as_bytes(), epoch, &id.cert_der, &id.signing_key_pem)
            .context("building ClientHello")?;
    let msg = ClientHello {
        sid: sid.clone(),
        client_eph: hello.client_eph.to_vec(),
        cert_der: id.cert_der.clone(),
        sig: hello.sig,
        epoch,
    };
    Ok((Handshaking { initiator, sid }, wire::encode(&msg)))
}

/// File under `state_dir` holding the agent's last-used session epoch (4.3).
const EPOCH_FILE: &str = "session_epoch";

/// Read, increment, and **durably** persist the agent's monotonic session epoch
/// (4.3, reconnect-safe). The epoch advances on every session (per broker
/// connection) and survives an agent restart, so a reconnect never reuses or
/// regresses an epoch — that lets the coordinator reject a replayed old
/// session-open (anti-resurrection). A missing file starts from 0 (fresh agent);
/// a present-but-unparsable file fails **closed** — regressing to 0 would be the
/// very resurrection the epoch exists to prevent, so the caller declines to open
/// a session rather than silently reusing a stale epoch.
pub fn next_epoch(state_dir: &Path) -> anyhow::Result<u64> {
    let path = state_dir.join(EPOCH_FILE);
    let current: u64 = match std::fs::read_to_string(&path) {
        Ok(s) => s
            .trim()
            .parse()
            .context("session epoch file is corrupt; refusing to regress the epoch")?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => 0,
        Err(e) => return Err(e).context("reading the session epoch"),
    };
    let next = current
        .checked_add(1)
        .context("session epoch overflow (u64)")?;
    // Persist BEFORE returning: temp → fsync → rename → fsync(dir), so a crash
    // mid-write can neither corrupt the epoch nor let it regress on restart.
    let tmp = path.with_extension("tmp");
    {
        use std::io::Write;
        let mut f = std::fs::File::create(&tmp).context("creating epoch temp file")?;
        f.write_all(next.to_string().as_bytes())?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, &path).context("committing the epoch")?;
    if let Some(dir) = path.parent() {
        // fsync the directory so the rename itself is durable; propagate the error
        // (matching JobStore::write_durably) rather than advertising crash-safety
        // we didn't achieve — a lost dir-fsync could regress the epoch on restart.
        std::fs::File::open(dir)
            .and_then(|d| d.sync_all())
            .context("fsyncing the state dir after committing the epoch")?;
    }
    Ok(next)
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
    Ok(Established {
        keys: Arc::new(keys),
        sid: hs.sid,
        send_seq: Arc::new(AtomicU64::new(0)),
        recv_high: None,
    })
}

/// Open the coordinator's sealed session-ready beacon and, if it is the expected
/// payload, return the encoded sealed ack to publish on the control uplink. The
/// beacon's downlink `seq` (0) is recorded so a later dispatch must be newer.
pub fn confirm_session(
    est: &mut Established,
    id: &AgentIdentity,
    beacon: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let env: Envelope = wire::decode(beacon).context("decoding session-ready beacon")?;
    anyhow::ensure!(env.sid == est.sid, "beacon sid does not match this session");
    // Authenticate the beacon before advancing the replay guard (open_downlink),
    // so a forged beacon cannot poison the high-water mark.
    let payload = est
        .open_downlink(&env)
        .ok_or_else(|| anyhow::anyhow!("session-ready beacon failed to open or was replayed"))?;
    anyhow::ensure!(
        payload == wire::CTRL_SESSION_READY,
        "unexpected sealed control payload"
    );
    Ok(seal_uplink(
        &est.keys,
        &est.send_seq,
        &id.host_id,
        &est.sid,
        wire::CTRL_SESSION_ACK,
    ))
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
            hello.epoch,
            &client_eph,
            &hello.sig,
            &agent_pub,
            &hello.cert_der,
            ca_key_pem,
        )
        .unwrap()
    }

    #[test]
    fn next_epoch_is_monotonic_and_survives_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(next_epoch(dir.path()).unwrap(), 1, "starts from 1");
        assert_eq!(next_epoch(dir.path()).unwrap(), 2);
        assert_eq!(next_epoch(dir.path()).unwrap(), 3);
        // A "restart" is just a fresh read of the persisted file — the epoch
        // continues upward, never regressing (that would wedge the host out of new
        // sessions the coordinator has already seen).
        assert_eq!(
            next_epoch(dir.path()).unwrap(),
            4,
            "persisted across restart"
        );
    }

    #[test]
    fn next_epoch_fails_closed_on_a_corrupt_file() {
        let dir = tempfile::tempdir().unwrap();
        // Reach epoch 3, then corrupt the persisted file.
        assert_eq!(next_epoch(dir.path()).unwrap(), 1);
        assert_eq!(next_epoch(dir.path()).unwrap(), 2);
        assert_eq!(next_epoch(dir.path()).unwrap(), 3);
        std::fs::write(dir.path().join(EPOCH_FILE), b"not-a-number").unwrap();
        // A present-but-unparsable epoch must NOT reset to 0 (that regression is
        // the resurrection the epoch guards against) — it fails closed so the
        // caller declines to open a session.
        assert!(
            next_epoch(dir.path()).is_err(),
            "a corrupt epoch file must fail closed, not regress to 0"
        );
    }

    #[test]
    fn start_handshake_builds_a_decodable_client_hello() {
        let (id, _) = enrolled();
        let (_hs, bytes) = start_handshake(&id, 7).unwrap();
        let hello: ClientHello = wire::decode(&bytes).unwrap();
        assert_eq!(hello.client_eph.len(), 32);
        assert_eq!(hello.cert_der, id.cert_der);
        assert_eq!(hello.sig.len(), 64);
        assert_eq!(
            hello.epoch, 7,
            "the session epoch is carried in the ClientHello"
        );
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
        let (hs, hello_bytes) = start_handshake(&id, 7).unwrap();
        let hello: ClientHello = wire::decode(&hello_bytes).unwrap();
        let resp = coordinator_respond(&id, &hello, &ca_key_pem);

        let server_hello = ServerHello {
            sid: hello.sid.clone(),
            server_eph: resp.server_eph.to_vec(),
            sig: resp.sig.clone(),
        };
        let mut est = finish_handshake(hs, &id, &wire::encode(&server_hello)).unwrap();

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
        let ack_bytes = confirm_session(&mut est, &id, &wire::encode(&beacon)).unwrap();

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
        let (hs, hello_bytes) = start_handshake(&id, 7).unwrap();
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
        let (hs, hello_bytes) = start_handshake(&id, 7).unwrap();
        let hello: ClientHello = wire::decode(&hello_bytes).unwrap();
        let resp = coordinator_respond(&id, &hello, &ca_key_pem);
        let server_hello = ServerHello {
            sid: hello.sid.clone(),
            server_eph: resp.server_eph.to_vec(),
            sig: resp.sig.clone(),
        };
        let mut est = finish_handshake(hs, &id, &wire::encode(&server_hello)).unwrap();
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
        assert!(confirm_session(&mut est, &id, &wire::encode(&beacon)).is_err());
    }

    /// A session key pair (agent half, coordinator half) deriving identical keys.
    fn key_pair() -> (SessionKeys, SessionKeys) {
        use osa_core::seal::Handshake;
        let a = Handshake::new().unwrap();
        let b = Handshake::new().unwrap();
        let (apub, bpub) = (a.public, b.public);
        (
            a.derive(&bpub, b"bind").unwrap(),
            b.derive(&apub, b"bind").unwrap(),
        )
    }

    fn established(keys: SessionKeys) -> Established {
        Established {
            keys: Arc::new(keys),
            sid: "s".into(),
            send_seq: Arc::new(AtomicU64::new(0)),
            recv_high: None,
        }
    }

    #[test]
    fn accept_recv_rejects_replays_and_stale_seqs() {
        let (agent, _) = key_pair();
        let mut est = established(agent);
        assert!(est.accept_recv(0), "first (beacon) accepted");
        assert!(!est.accept_recv(0), "replay of 0 rejected");
        assert!(est.accept_recv(1), "next dispatch accepted");
        assert!(!est.accept_recv(1), "replay of 1 rejected");
        assert!(!est.accept_recv(0), "stale seq rejected");
        assert!(est.accept_recv(2), "newer accepted");
    }

    #[test]
    fn open_downlink_authenticates_before_advancing_the_replay_guard() {
        let (agent, coord) = key_pair();
        let (foreign, _) = key_pair(); // an unrelated session's keys
        let mut est = established(agent);

        // A forged high-seq envelope that does NOT open (sealed by a foreign key).
        // It must be rejected AND must not poison the replay high-water mark.
        let forged = wire::seal_envelope(
            &foreign,
            Direction::CoordToAgent,
            "s",
            "s",
            u64::MAX,
            Kind::Control,
            b"x",
        );
        assert!(
            est.open_downlink(&forged).is_none(),
            "forgery must not open"
        );

        // The guard was not poisoned: a legitimate beacon at seq 0 still opens.
        let real = wire::seal_envelope(
            &coord,
            Direction::CoordToAgent,
            "s",
            "s",
            0,
            Kind::Control,
            b"hi",
        );
        assert_eq!(est.open_downlink(&real).as_deref(), Some(&b"hi"[..]));
        // A replay of that (now-seen) seq is rejected.
        assert!(est.open_downlink(&real).is_none(), "replay rejected");
    }
}
