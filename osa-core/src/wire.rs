/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: MIT
 */

//! MQTT wire codec (AD-7, AD-27): the one place the coordinator and agent agree
//! on how messages are framed, so the two ends cannot drift.
//!
//! Two kinds of payload travel over the broker:
//!
//! - **Cleartext handshake messages** ([`osa_proto::v1::ClientHello`] /
//!   [`ServerHello`](osa_proto::v1::ServerHello)) on the `…/hs` topics. The
//!   handshake establishes the seal's keys, so its own messages are not sealed —
//!   they are authenticated by the ECDSA signatures (see [`crate::handshake`]).
//! - **Sealed [`Envelope`](osa_proto::v1::Envelope)s** for everything after: the
//!   cleartext routing header (`host_id, sid, seq, kind`) travels in the open so
//!   the untrusted broker can route, and is bound into the AEAD as **AAD** so the
//!   broker cannot splice a valid ciphertext onto different routing (AD-27).

use prost::Message;

use crate::seal::{Direction, OpenError, SessionKeys};
use osa_proto::v1::{Envelope, envelope::Kind};

/// The coordinator's sealed session-ready beacon (#20): the first sealed payload,
/// proving to the agent that both ends derived matching keys.
pub const CTRL_SESSION_READY: &[u8] = b"osa/v1 session-ready";

/// The agent's sealed reply to [`CTRL_SESSION_READY`] (#20): proves to the
/// coordinator that the agent derived matching keys, so the session is live.
pub const CTRL_SESSION_ACK: &[u8] = b"osa/v1 session-ack";

/// Encode a protobuf message to bytes for an MQTT payload.
pub fn encode<M: Message>(msg: &M) -> Vec<u8> {
    msg.encode_to_vec()
}

/// SHA-256 over the opaque capability params, for `ActionDescriptor.params_hash`
/// (AD-12). Binds the authorized action to the exact params sealed to the agent,
/// so a policy may constrain on it (the coordinator still never *parses* params).
pub fn params_hash(params: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    Sha256::digest(params).to_vec()
}

/// Lowercase-hex SHA-256 of `bytes` — e.g. to derive a safe, fixed-length
/// filename from an untrusted identifier (no path traversal regardless of input).
pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    use std::fmt::Write;
    Sha256::digest(bytes)
        .iter()
        .fold(String::new(), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

/// Decode a protobuf message from an MQTT payload.
pub fn decode<M: Message + Default>(bytes: &[u8]) -> Result<M, prost::DecodeError> {
    M::decode(bytes)
}

/// The AEAD additional data: a canonical, length-prefixed encoding of the
/// cleartext routing header. Both ends compute it identically from the envelope
/// fields, so any tampering with the routing (a broker re-route) fails the tag.
fn aad(host_id: &str, sid: &str, seq: u64, kind: i32) -> Vec<u8> {
    fn push(buf: &mut Vec<u8>, field: &[u8]) {
        buf.extend_from_slice(&(field.len() as u64).to_be_bytes());
        buf.extend_from_slice(field);
    }
    let mut a = Vec::with_capacity(host_id.len() + sid.len() + 32);
    push(&mut a, host_id.as_bytes());
    push(&mut a, sid.as_bytes());
    a.extend_from_slice(&seq.to_be_bytes());
    a.extend_from_slice(&kind.to_be_bytes());
    a
}

/// Build a sealed [`Envelope`]: seal `plaintext` under `keys`/`dir` with the
/// routing header as AAD. The caller owns `seq` (strictly monotonic per
/// direction — the seal's load-bearing contract).
pub fn seal_envelope(
    keys: &SessionKeys,
    dir: Direction,
    host_id: &str,
    sid: &str,
    seq: u64,
    kind: Kind,
    plaintext: &[u8],
) -> Envelope {
    let kind = kind as i32;
    let ciphertext = keys.seal(dir, seq, &aad(host_id, sid, seq, kind), plaintext);
    Envelope {
        host_id: host_id.to_string(),
        sid: sid.to_string(),
        seq,
        kind,
        ciphertext,
    }
}

/// Open a sealed [`Envelope`], recomputing the AAD from its own routing header.
/// Fails if the ciphertext or any routing field was tampered, or the wrong
/// `dir`/key/`seq` is used. A successful open is NOT proof of freshness — the
/// caller must still reject non-increasing `seq` per direction (AD-8).
pub fn open_envelope(
    keys: &SessionKeys,
    dir: Direction,
    env: &Envelope,
) -> Result<Vec<u8>, OpenError> {
    let aad = aad(&env.host_id, &env.sid, env.seq, env.kind);
    keys.open(dir, env.seq, &aad, &env.ciphertext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seal::Handshake;
    use osa_proto::v1::{ClientHello, ServerHello};

    /// Two ends of one session, deriving identical keys (as the live handshake
    /// would), so a payload sealed by one opens with the other.
    fn session_pair() -> (SessionKeys, SessionKeys) {
        let a = Handshake::new().unwrap();
        let b = Handshake::new().unwrap();
        let (apub, bpub) = (a.public, b.public);
        (
            a.derive(&bpub, b"bind").unwrap(),
            b.derive(&apub, b"bind").unwrap(),
        )
    }

    #[test]
    fn handshake_messages_round_trip() {
        let hello = ClientHello {
            sid: "session-1".into(),
            client_eph: vec![1; 32],
            cert_der: vec![2, 3, 4],
            sig: vec![5; 64],
            epoch: 1,
        };
        let back: ClientHello = decode(&encode(&hello)).unwrap();
        assert_eq!(back, hello);

        let sh = ServerHello {
            sid: "session-1".into(),
            server_eph: vec![9; 32],
            sig: vec![7; 64],
        };
        assert_eq!(decode::<ServerHello>(&encode(&sh)).unwrap(), sh);
    }

    #[test]
    fn sealed_envelope_round_trips_across_the_pair() {
        let (coord, agent) = session_pair();
        let env = seal_envelope(
            &coord,
            Direction::CoordToAgent,
            "host-1",
            "session-1",
            0,
            Kind::Control,
            b"dispatch",
        );
        assert!(env.ciphertext != b"dispatch", "payload must be sealed");
        let pt = open_envelope(&agent, Direction::CoordToAgent, &env).unwrap();
        assert_eq!(pt, b"dispatch");
    }

    #[test]
    fn rerouting_a_sealed_envelope_fails_the_tag() {
        let (coord, agent) = session_pair();
        let mut env = seal_envelope(
            &coord,
            Direction::AgentToCoord,
            "host-1",
            "session-1",
            3,
            Kind::Control,
            b"x",
        );
        // A broker swaps the cleartext routing host_id: the AAD no longer matches.
        env.host_id = "host-2".into();
        assert!(open_envelope(&agent, Direction::AgentToCoord, &env).is_err());
        // Tampering the sid likewise fails.
        let mut env2 = seal_envelope(
            &coord,
            Direction::AgentToCoord,
            "host-1",
            "session-1",
            4,
            Kind::Control,
            b"x",
        );
        env2.sid = "session-2".into();
        assert!(open_envelope(&agent, Direction::AgentToCoord, &env2).is_err());
    }

    #[test]
    fn aad_binds_every_routing_field() {
        // No two distinct headers share an AAD (length-prefixing prevents the
        // classic "host=ab,sid=c" vs "host=a,sid=bc" collision).
        let base = aad("ab", "c", 1, 1);
        assert_ne!(base, aad("a", "bc", 1, 1));
        assert_ne!(base, aad("ab", "c", 2, 1));
        assert_ne!(base, aad("ab", "c", 1, 2));
    }
}
