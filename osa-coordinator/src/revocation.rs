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
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use osa_core::HostId;
use osa_core::ports::PortError;
use sqlx::PgPool;

/// Record and query revoked identities. The in-memory adapter
/// ([`RevocationRegistry`]) is single-node; the Postgres adapter
/// ([`PgRevocations`]) shares the set across replicas (AD-24).
#[async_trait]
pub trait Revocations: Send + Sync {
    /// Revoke `host_id`. Idempotent.
    async fn revoke(&self, host_id: HostId) -> Result<(), PortError>;
    /// Whether `host_id` has been revoked.
    async fn is_revoked(&self, host_id: HostId) -> Result<bool, PortError>;
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

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

/// The in-memory registry as a [`Revocations`] adapter (no-DB / dev mode).
#[async_trait]
impl Revocations for RevocationRegistry {
    async fn revoke(&self, host_id: HostId) -> Result<(), PortError> {
        RevocationRegistry::revoke(self, host_id);
        Ok(())
    }
    async fn is_revoked(&self, host_id: HostId) -> Result<bool, PortError> {
        Ok(RevocationRegistry::is_revoked(self, host_id))
    }
}

/// Durable, cross-replica revocation set in Postgres (AD-24, AD-28): a revoke on
/// one coordinator is seen by every other's renewal check.
pub struct PgRevocations {
    pool: PgPool,
}

impl PgRevocations {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl Revocations for PgRevocations {
    async fn revoke(&self, host_id: HostId) -> Result<(), PortError> {
        sqlx::query(
            "INSERT INTO revoked_identity (host_id, revoked_at_unix) VALUES ($1, $2) \
             ON CONFLICT (host_id) DO NOTHING",
        )
        .bind(host_id.0)
        .bind(now_unix())
        .execute(&self.pool)
        .await
        .map_err(|e| PortError::Backend(e.to_string()))?;
        Ok(())
    }

    async fn is_revoked(&self, host_id: HostId) -> Result<bool, PortError> {
        let revoked: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM revoked_identity WHERE host_id = $1)")
                .bind(host_id.0)
                .fetch_one(&self.pool)
                .await
                .map_err(|e| PortError::Backend(e.to_string()))?;
        Ok(revoked)
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

    // --- Postgres adapter (testcontainers; needs Docker) ---

    use testcontainers_modules::postgres::Postgres;
    use testcontainers_modules::testcontainers::ImageExt;
    use testcontainers_modules::testcontainers::runners::AsyncRunner;

    async fn pg_revocations() -> (
        testcontainers_modules::testcontainers::ContainerAsync<Postgres>,
        PgRevocations,
    ) {
        let node = Postgres::default()
            .with_tag("17-alpine")
            .start()
            .await
            .unwrap();
        let port = node.get_host_port_ipv4(5432).await.unwrap();
        let url = format!("postgres://postgres:postgres@127.0.0.1:{port}/postgres");
        let pool = crate::db::connect(&url).await.unwrap();
        crate::db::migrate(&pool).await.unwrap();
        (node, PgRevocations::new(pool))
    }

    #[tokio::test]
    async fn pg_revoke_is_idempotent_and_durable() {
        let (_node, r) = pg_revocations().await;
        let h = HostId::new();
        assert!(!r.is_revoked(h).await.unwrap());
        r.revoke(h).await.unwrap();
        r.revoke(h).await.unwrap(); // idempotent (ON CONFLICT DO NOTHING)
        assert!(r.is_revoked(h).await.unwrap());
        assert!(!r.is_revoked(HostId::new()).await.unwrap());
    }

    #[tokio::test]
    async fn pg_revocation_is_visible_to_a_separate_adapter() {
        // A revoke through one adapter is seen by another over the same database
        // — i.e. a revoke on replica A is honored by replica B's renewal check.
        let (_node, a) = pg_revocations().await;
        let b = PgRevocations::new(a.pool.clone());
        let h = HostId::new();
        a.revoke(h).await.unwrap();
        assert!(b.is_revoked(h).await.unwrap());
    }
}
