/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: MIT
 */

//! Coordinator-side session-epoch high-water store (AD-24, AD-27; story 4.3).
//!
//! Each host carries a monotonic session epoch, signed into its handshake
//! ([`crate::broker`]). The coordinator admits a `ClientHello` only if its epoch
//! is strictly greater than the highest it has already accepted for that host —
//! so a replayed or stale session-open (even one captured by the untrusted
//! broker) cannot resurrect a session (anti-resurrection).
//!
//! That high-water must survive a coordinator restart or failover, or the guard
//! fails **open**: a fresh replica starts with an empty map and would re-accept a
//! captured old hello. The in-memory adapter ([`EpochRegistry`]) is single-node
//! (4.3a); the Postgres adapter ([`PgEpochs`]) shares the high-water across
//! replicas so the guard holds across failover (4.3b).

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use osa_core::HostId;
use osa_core::ports::PortError;
use sqlx::PgPool;

/// Admit or reject a session epoch against a host's durable high-water mark.
#[async_trait]
pub trait Epochs: Send + Sync {
    /// **Atomically** admit `epoch` for `host_id` iff it is strictly greater than
    /// the highest previously admitted, recording it as the new high-water in the
    /// same step. Returns whether it was admitted.
    ///
    /// Check-and-set in one operation is load-bearing: splitting it into a read
    /// then a write would let two coordinators (or two concurrent hellos) both pass
    /// the read for the same fresh epoch and both admit it. A single conditional
    /// UPSERT closes that race, so a replayed/stale epoch is always rejected and a
    /// fresh epoch is admitted at most once — even across replicas.
    async fn admit(&self, host_id: HostId, epoch: u64) -> Result<bool, PortError>;
}

/// In-memory high-water map (no-DB / dev mode); single-node, lost on restart.
#[derive(Default)]
pub struct EpochRegistry {
    marks: Mutex<HashMap<HostId, u64>>,
}

impl EpochRegistry {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl Epochs for EpochRegistry {
    async fn admit(&self, host_id: HostId, epoch: u64) -> Result<bool, PortError> {
        let mut marks = self.marks.lock().unwrap_or_else(|e| e.into_inner());
        match marks.get(&host_id) {
            Some(&high) if epoch <= high => Ok(false),
            _ => {
                marks.insert(host_id, epoch);
                Ok(true)
            }
        }
    }
}

/// Durable, cross-replica high-water store in Postgres (AD-24): the epoch a host
/// reaches on one coordinator is honored by every other's admission check, so a
/// restart or failover does not reopen the resurrection window.
pub struct PgEpochs {
    pool: PgPool,
}

impl PgEpochs {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

/// The epoch is a `u64` on the wire but Postgres `BIGINT` is signed. A session
/// epoch is a small monotonic reconnect counter, so it never approaches
/// `i64::MAX`; a value that does not fit is malformed and fails **closed**.
fn to_bigint(epoch: u64) -> Result<i64, PortError> {
    i64::try_from(epoch).map_err(|_| PortError::Backend("session epoch out of range".into()))
}

#[async_trait]
impl Epochs for PgEpochs {
    async fn admit(&self, host_id: HostId, epoch: u64) -> Result<bool, PortError> {
        // One atomic conditional UPSERT does check-and-set: insert the row if the
        // host is unseen, or update it only when the new epoch strictly exceeds the
        // stored one. Postgres row-locks the conflicting row, so concurrent admits
        // serialize. `rows_affected` is 1 exactly when THIS call inserted or
        // advanced the high-water (i.e. admitted), and 0 when the WHERE guard
        // rejected a stale/equal epoch — no read-then-write race (mirrors the
        // atomic join-token redeem).
        let result = sqlx::query(
            "INSERT INTO session_epoch (host_id, epoch) VALUES ($1, $2) \
             ON CONFLICT (host_id) DO UPDATE SET epoch = EXCLUDED.epoch \
             WHERE EXCLUDED.epoch > session_epoch.epoch",
        )
        .bind(host_id.0)
        .bind(to_bigint(epoch)?)
        .execute(&self.pool)
        .await
        .map_err(|e| PortError::Backend(e.to_string()))?;
        Ok(result.rows_affected() == 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn in_memory_admits_only_strictly_increasing_epochs() {
        let e = EpochRegistry::new();
        let h = HostId::new();
        assert!(
            e.admit(h, 5).await.unwrap(),
            "first epoch for an unseen host"
        );
        assert!(!e.admit(h, 5).await.unwrap(), "equal epoch is a replay");
        assert!(!e.admit(h, 3).await.unwrap(), "stale epoch is rejected");
        assert!(e.admit(h, 9).await.unwrap(), "a higher epoch advances");
        assert!(!e.admit(h, 9).await.unwrap(), "and is then itself a replay");
        assert!(
            e.admit(HostId::new(), 1).await.unwrap(),
            "a different host has its own high-water"
        );
    }

    // --- Postgres adapter (testcontainers; needs Docker) ---

    use testcontainers_modules::postgres::Postgres;
    use testcontainers_modules::testcontainers::ImageExt;
    use testcontainers_modules::testcontainers::runners::AsyncRunner;

    async fn pg_epochs() -> (
        testcontainers_modules::testcontainers::ContainerAsync<Postgres>,
        PgEpochs,
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
        (node, PgEpochs::new(pool))
    }

    #[tokio::test]
    async fn pg_admits_only_strictly_increasing_epochs_and_is_durable() {
        let (_node, e) = pg_epochs().await;
        let h = HostId::new();
        assert!(e.admit(h, 5).await.unwrap(), "first epoch admitted");
        assert!(!e.admit(h, 5).await.unwrap(), "equal epoch is a replay");
        assert!(
            !e.admit(h, 3).await.unwrap(),
            "stale UPSERT is rejected (WHERE guard)"
        );
        assert!(e.admit(h, 9).await.unwrap(), "a higher epoch advances");
    }

    #[tokio::test]
    async fn pg_high_water_survives_a_fresh_adapter_over_the_same_store() {
        // A high-water set through one adapter is honored by a NEW adapter over the
        // same database — i.e. after a coordinator restart/failover a replayed old
        // epoch is still rejected: the anti-resurrection window stays closed.
        let (_node, a) = pg_epochs().await;
        let h = HostId::new();
        assert!(a.admit(h, 7).await.unwrap());
        let b = PgEpochs::new(a.pool.clone()); // the "restarted" coordinator
        assert!(
            !b.admit(h, 7).await.unwrap(),
            "replay after restart is rejected"
        );
        assert!(!b.admit(h, 4).await.unwrap(), "an older epoch too");
        assert!(
            b.admit(h, 8).await.unwrap(),
            "the host still advances normally"
        );
    }
}
