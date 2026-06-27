/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: MIT
 */

//! Coordinator-side certificate revocation (AD-28).
//!
//! A revoked `host_id` can no longer renew its certificate, so its short-lived
//! cert lapses within its TTL — a kill switch bounded by the cert lifetime.
//! Immediate rejection at the broker connect is not yet possible (`rumqttd`
//! exposes no per-cert revocation hook — issue #16); renewal-refusal + a short
//! TTL is the v1 mitigation.
//!
//! Known v1 limitations (all resolved by the enforcement spine, Epic 2):
//!
//! - **Not durable.** The set is in-memory, so a coordinator restart clears it
//!   and the kill switch fails *open*: a revoked host whose cert is still within
//!   TTL can renew again until it is re-revoked. The Postgres-backed set
//!   (AD-24) makes revocation survive restarts.
//! - **Identity-scoped, not machine-scoped.** Revocation blocks one `host_id`.
//!   Re-enrollment mints a *new* identity, so it is not blocked here — but it
//!   requires a fresh single-use, short-TTL join token that only an operator can
//!   mint (AD-25), so a revoked host cannot re-enroll on its own.
//! - **Unauthenticated caller.** Like the rest of the `Operator` surface, the
//!   `Revoke` RPC has no operator authn/authz yet (Epic 2, AD-18/AD-19); until
//!   then any caller that can reach the port can revoke (or flood) arbitrary
//!   host ids. The set is insert-only and never evicted.

use std::collections::HashSet;
use std::sync::Mutex;

use osa_core::HostId;

/// The set of revoked host identities.
#[derive(Default)]
pub struct RevocationRegistry {
    revoked: Mutex<HashSet<HostId>>,
}

impl RevocationRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Revoke `host_id`. Idempotent.
    pub fn revoke(&self, host_id: HostId) {
        self.revoked
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(host_id);
    }

    /// Whether `host_id` has been revoked.
    pub fn is_revoked(&self, host_id: HostId) -> bool {
        self.revoked
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains(&host_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn revoke_is_idempotent_and_scoped_to_the_host() {
        let r = RevocationRegistry::new();
        let h = HostId::new();
        assert!(!r.is_revoked(h));
        r.revoke(h);
        r.revoke(h); // idempotent
        assert!(r.is_revoked(h));
        assert!(!r.is_revoked(HostId::new())); // a different host is unaffected
    }
}
