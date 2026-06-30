/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: MIT
 */

//! Per-host session registry (#20): the AES-256-GCM keys an authenticated
//! handshake establishes, keyed by host identity.
//!
//! A host can only establish a session under its own (cert-bound) identity, and
//! a reconnect *replaces* the prior entry, so the store is bounded by the size of
//! the enrolled fleet. A cap guards against pathological growth all the same.

use std::collections::HashMap;

use osa_core::HostId;
use osa_core::seal::{Direction, SessionKeys};
use osa_core::wire;
use osa_proto::v1::Envelope;
use osa_proto::v1::envelope::Kind;

/// Upper bound on tracked sessions (mirrors the broker's host cap). A host cannot
/// inflate this — it owns at most one entry, replaced on reconnect.
const MAX_SESSIONS: usize = 50_000;

/// One live session (coordinator side): the per-direction keys, the `sid` they
/// were bound to, the monotonic **downlink** (coordinator→agent) `seq` allocator,
/// and the **uplink** (agent→coordinator) replay guard. All sealing/opening for a
/// session happens in the single bridge task, so plain (non-atomic) state is safe.
pub struct Session {
    pub sid: String,
    keys: SessionKeys,
    /// Next downlink `seq`. The session-ready beacon takes 0; dispatches 1, 2, ….
    send_seq: u64,
    /// Highest uplink `seq` accepted (replay/dup rejection). `None` until the
    /// first uplink message (the session-open ack at seq 0).
    recv_high: Option<u64>,
}

impl Session {
    /// Seal `payload` as the next downlink envelope (coordinator→agent) and return
    /// its encoded bytes, allocating a fresh monotonic `seq` (the GCM nonce).
    pub fn seal_downlink(&mut self, host_id: &str, payload: &[u8]) -> Vec<u8> {
        let seq = self.send_seq;
        self.send_seq += 1;
        let env = wire::seal_envelope(
            &self.keys,
            Direction::CoordToAgent,
            host_id,
            &self.sid,
            seq,
            Kind::Control,
            payload,
        );
        wire::encode(&env)
    }

    /// Open a sealed uplink envelope (agent→coordinator), authenticating **before**
    /// advancing the replay guard (so a forged envelope can't poison it). Returns
    /// the plaintext, or `None` if the tag fails or the `seq` is a replay/stale.
    ///
    /// The guard is a strict high-water mark, not a reorder buffer: it assumes the
    /// uplink arrives in `seq` order. That holds today — one agent client, QoS1,
    /// and a single ordered stream per direction (the session-ack at seq 0 then
    /// results 1, 2, …, all sealed sequentially by one task). A `ReorderBuffer`
    /// (AD-8, [`osa_core::stream`]) would be needed only if the uplink ever spanned
    /// reordered sources.
    pub fn open_uplink(&mut self, env: &Envelope) -> Option<Vec<u8>> {
        let plaintext = wire::open_envelope(&self.keys, Direction::AgentToCoord, env).ok()?;
        if self.recv_high.is_some_and(|h| env.seq <= h) {
            return None;
        }
        self.recv_high = Some(env.seq);
        Some(plaintext)
    }
}

/// Sessions keyed by host. Single-owner (the bridge task), so no interior locking.
pub struct SessionStore {
    by_host: HashMap<HostId, Session>,
    cap: usize,
}

impl SessionStore {
    pub fn new() -> Self {
        Self {
            by_host: HashMap::new(),
            cap: MAX_SESSIONS,
        }
    }

    /// A store with a small cap, to exercise the at-capacity branch in tests.
    #[cfg(test)]
    fn with_cap(cap: usize) -> Self {
        Self {
            by_host: HashMap::new(),
            cap,
        }
    }

    /// Record (or replace, on reconnect) the session for `host`. Returns `false`
    /// without inserting if the store is at capacity with a *new* host (anti-DoS);
    /// replacing an existing host's session always succeeds.
    pub fn insert(&mut self, host: HostId, sid: String, keys: SessionKeys) -> bool {
        if !self.by_host.contains_key(&host) && self.by_host.len() >= self.cap {
            return false;
        }
        self.by_host.insert(
            host,
            Session {
                sid,
                keys,
                send_seq: 0,
                recv_high: None,
            },
        );
        true
    }

    pub fn get(&self, host: &HostId) -> Option<&Session> {
        self.by_host.get(host)
    }

    pub fn get_mut(&mut self, host: &HostId) -> Option<&mut Session> {
        self.by_host.get_mut(host)
    }

    /// Every host with a live session — the resolution of the `*` selector (the
    /// hosts the coordinator can actually reach right now) for fan-out (3.4).
    pub fn host_ids(&self) -> Vec<HostId> {
        self.by_host.keys().copied().collect()
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.by_host.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use osa_core::seal::{Direction, Handshake};

    fn keys() -> SessionKeys {
        let a = Handshake::new().unwrap();
        let b = Handshake::new().unwrap();
        let bpub = b.public;
        let _ = b.derive(&a.public, b"bind");
        a.derive(&bpub, b"bind").unwrap()
    }

    #[test]
    fn insert_then_get_returns_the_session() {
        let mut store = SessionStore::new();
        let host = HostId::new();
        assert!(store.insert(host, "sid-1".into(), keys()));
        let s = store.get(&host).unwrap();
        assert_eq!(s.sid, "sid-1");
        // The stored keys are usable.
        let ct = s.keys.seal(Direction::CoordToAgent, 0, b"h", b"x");
        assert_eq!(
            s.keys.open(Direction::CoordToAgent, 0, b"h", &ct).unwrap(),
            b"x"
        );
    }

    #[test]
    fn reconnect_replaces_the_session_in_place() {
        let mut store = SessionStore::new();
        let host = HostId::new();
        store.insert(host, "sid-1".into(), keys());
        store.insert(host, "sid-2".into(), keys());
        assert_eq!(store.len(), 1, "a host holds at most one session");
        assert_eq!(store.get(&host).unwrap().sid, "sid-2");
    }

    #[test]
    fn unknown_host_has_no_session() {
        let store = SessionStore::new();
        assert!(store.get(&HostId::new()).is_none());
    }

    #[test]
    fn seal_downlink_and_open_uplink_round_trip_with_dedup() {
        let a = Handshake::new().unwrap();
        let b = Handshake::new().unwrap();
        let (apub, bpub) = (a.public, b.public);
        let coord_keys = a.derive(&bpub, b"bind").unwrap();
        let agent_keys = b.derive(&apub, b"bind").unwrap();

        let mut store = SessionStore::new();
        let host = HostId::new();
        store.insert(host, "s".into(), coord_keys);
        let session = store.get_mut(&host).unwrap();

        // Downlink seqs are monotonic from 0; the agent opens them.
        let beacon = session.seal_downlink("h", b"beacon");
        let benv: Envelope = wire::decode(&beacon).unwrap();
        assert_eq!(benv.seq, 0);
        assert_eq!(
            wire::open_envelope(&agent_keys, Direction::CoordToAgent, &benv).unwrap(),
            b"beacon"
        );
        let dispatch = session.seal_downlink("h", b"dispatch");
        assert_eq!(wire::decode::<Envelope>(&dispatch).unwrap().seq, 1);

        // Uplink: the coordinator opens an agent-sealed envelope, then dedups a replay.
        let ack_env = wire::seal_envelope(
            &agent_keys,
            Direction::AgentToCoord,
            "h",
            "s",
            0,
            Kind::Control,
            b"ack",
        );
        assert_eq!(session.open_uplink(&ack_env).as_deref(), Some(&b"ack"[..]));
        assert!(session.open_uplink(&ack_env).is_none(), "replay rejected");
    }

    #[test]
    fn refuses_a_new_host_at_capacity_but_still_replaces_known_ones() {
        let mut store = SessionStore::with_cap(1);
        let a = HostId::new();
        let b = HostId::new();
        assert!(store.insert(a, "a-1".into(), keys()), "first host fits");
        // A *new* host at capacity is refused (anti-DoS).
        assert!(
            !store.insert(b, "b-1".into(), keys()),
            "second host refused"
        );
        assert!(store.get(&b).is_none());
        // Replacing the *existing* host always succeeds, even at capacity.
        assert!(
            store.insert(a, "a-2".into(), keys()),
            "reconnect still allowed"
        );
        assert_eq!(store.get(&a).unwrap().sid, "a-2");
    }
}
