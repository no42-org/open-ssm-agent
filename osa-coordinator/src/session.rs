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
use osa_core::seal::SessionKeys;

/// Upper bound on tracked sessions (mirrors the broker's host cap). A host cannot
/// inflate this — it owns at most one entry, replaced on reconnect.
const MAX_SESSIONS: usize = 50_000;

/// One live session: the per-direction keys plus the `sid` they were bound to.
pub struct Session {
    pub sid: String,
    pub keys: SessionKeys,
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
        self.by_host.insert(host, Session { sid, keys });
        true
    }

    pub fn get(&self, host: &HostId) -> Option<&Session> {
        self.by_host.get(host)
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
