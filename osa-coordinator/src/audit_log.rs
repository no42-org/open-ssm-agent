/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: MIT
 */

//! In-memory audit-log adapter (AD-21).
//!
//! Holds the hash chain behind a `Mutex`, which serializes appends so two
//! concurrent dispatches cannot read the same head and fork the chain
//! (single-writer). The chain hashing/verification lives in
//! [`osa_core::audit`]; this adapter only owns storage + serialization.
//!
//! In-memory for v1: the chain is lost on restart. The Postgres-backed store
//! that makes it durable and serializes appends across stateless replicas
//! (AD-24) lands with story 2.3b.

use std::sync::Mutex;

use async_trait::async_trait;
use osa_core::audit::{AuditEntry, AuditRecord, Decision, GENESIS_PREV, Hash};
use osa_core::ports::{AuditLog, PortError};
use sqlx::{PgPool, Row};

/// Advisory-lock key serializing all appends to the (single) audit chain across
/// replicas. Arbitrary but fixed (`0x05A_AD21` ≈ "OSA AD-21"). It shares
/// Postgres's advisory-lock namespace with sqlx's migrator (which locks on a
/// db-name hash); a collision would only serialize a migration against an append
/// — no corruption — and migrations run at boot before traffic.
const CHAIN_LOCK_KEY: i64 = 0x05A_AD21;

/// An append-only hash chain kept in memory.
#[derive(Default)]
pub struct MemoryAuditLog {
    entries: Mutex<Vec<AuditEntry>>,
}

impl MemoryAuditLog {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl AuditLog for MemoryAuditLog {
    async fn append(&self, record: AuditRecord) -> Result<(), PortError> {
        // The lock makes seal-and-append atomic: the seq and prev_hash are read
        // and the entry pushed under one hold, so concurrent appends serialize
        // and the chain cannot fork.
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let seq = entries.len() as u64;
        let prev = entries.last().map_or(GENESIS_PREV, |e| e.hash);
        entries.push(AuditEntry::seal(seq, record, prev));
        Ok(())
    }

    async fn export(&self) -> Result<Vec<AuditEntry>, PortError> {
        Ok(self
            .entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone())
    }
}

/// A durable, hash-chained audit log in Postgres (AD-21, AD-24).
///
/// Appends are serialized across replicas by a transaction-scoped advisory lock,
/// so two coordinators sharing one database cannot read the same head and fork
/// the chain — the database is the single writer per chain. **Operational
/// invariant:** every replica must point at the *same* database; the lock is
/// per-database, so replicas on different databases would each keep their own
/// (forked) chain with no error.
pub struct PgAuditLog {
    pool: PgPool,
    /// Serializes appends *within* this replica so only one append holds a
    /// pooled connection at a time — the rest of the pool stays free for
    /// `export` and the other Postgres adapters. Cross-replica serialization is
    /// the database advisory lock; this just avoids parking the whole pool on it.
    append_lock: tokio::sync::Mutex<()>,
}

impl PgAuditLog {
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            append_lock: tokio::sync::Mutex::new(()),
        }
    }
}

/// Decode a stored 32-byte hash, treating a wrong length as a corrupt row.
fn hash_from_row(bytes: Vec<u8>) -> Result<Hash, PortError> {
    <Hash>::try_from(bytes.as_slice())
        .map_err(|_| PortError::Backend("audit row has a malformed hash".into()))
}

fn backend(e: sqlx::Error) -> PortError {
    PortError::Backend(e.to_string())
}

#[async_trait]
impl AuditLog for PgAuditLog {
    async fn append(&self, record: AuditRecord) -> Result<(), PortError> {
        // Hold the per-replica append lock for the whole transaction so this
        // replica only ever uses one connection for appends (no pool parking).
        let _local = self.append_lock.lock().await;
        let mut tx = self.pool.begin().await.map_err(backend)?;
        // Pin READ COMMITTED (the first statement in the txn) so the head read
        // below takes a fresh snapshot *after* the advisory lock. Under a stricter
        // cluster default the snapshot would be fixed at the lock acquire and a
        // concurrent committer's row could be missed → fork.
        sqlx::query("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
            .execute(&mut *tx)
            .await
            .map_err(backend)?;
        // Serialize appends to this chain across all replicas. The lock is held
        // until the transaction commits, so the read-head → seal → insert is
        // atomic system-wide and the chain cannot fork.
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(CHAIN_LOCK_KEY)
            .execute(&mut *tx)
            .await
            .map_err(backend)?;

        let head = sqlx::query("SELECT seq, hash FROM audit_log ORDER BY seq DESC LIMIT 1")
            .fetch_optional(&mut *tx)
            .await
            .map_err(backend)?;
        let (seq, prev) = match head {
            Some(row) => {
                let seq: i64 = row.try_get("seq").map_err(backend)?;
                let hash: Vec<u8> = row.try_get("hash").map_err(backend)?;
                (seq as u64 + 1, hash_from_row(hash)?)
            }
            None => (0, GENESIS_PREV),
        };

        let entry = AuditEntry::seal(seq, record, prev);
        sqlx::query(
            "INSERT INTO audit_log \
             (seq, ts_unix, subject, kind, target, run_as, decision, prev_hash, hash) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind(entry.seq as i64)
        .bind(entry.record.ts_unix)
        .bind(&entry.record.subject)
        .bind(&entry.record.kind)
        .bind(&entry.record.target)
        .bind(&entry.record.run_as)
        .bind(entry.record.decision.as_str())
        .bind(&entry.prev_hash[..])
        .bind(&entry.hash[..])
        .execute(&mut *tx)
        .await
        .map_err(backend)?;

        tx.commit().await.map_err(backend)?;
        Ok(())
    }

    async fn export(&self) -> Result<Vec<AuditEntry>, PortError> {
        let rows = sqlx::query(
            "SELECT seq, ts_unix, subject, kind, target, run_as, decision, prev_hash, hash \
             FROM audit_log ORDER BY seq ASC",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(backend)?;

        rows.into_iter()
            .map(|row| {
                let seq: i64 = row.try_get("seq").map_err(backend)?;
                let decision_str: String = row.try_get("decision").map_err(backend)?;
                let decision = Decision::parse(&decision_str).ok_or_else(|| {
                    PortError::Backend("audit row has an unknown decision".into())
                })?;
                let prev_hash: Vec<u8> = row.try_get("prev_hash").map_err(backend)?;
                let hash: Vec<u8> = row.try_get("hash").map_err(backend)?;
                Ok(AuditEntry {
                    seq: seq as u64,
                    record: AuditRecord {
                        ts_unix: row.try_get("ts_unix").map_err(backend)?,
                        subject: row.try_get("subject").map_err(backend)?,
                        kind: row.try_get("kind").map_err(backend)?,
                        target: row.try_get("target").map_err(backend)?,
                        run_as: row.try_get("run_as").map_err(backend)?,
                        decision,
                    },
                    prev_hash: hash_from_row(prev_hash)?,
                    hash: hash_from_row(hash)?,
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use osa_core::audit::verify;

    fn record(subject: &str, decision: Decision) -> AuditRecord {
        AuditRecord {
            ts_unix: 1_700_000_000,
            subject: subject.into(),
            kind: "exec".into(),
            target: "11111111-1111-4111-8111-111111111111".into(),
            run_as: String::new(),
            decision,
        }
    }

    #[tokio::test]
    async fn appends_form_a_verifiable_chain() {
        let log = MemoryAuditLog::new();
        log.append(record("alice", Decision::Allow)).await.unwrap();
        log.append(record("bob", Decision::Deny)).await.unwrap();
        log.append(record("alice", Decision::Allow)).await.unwrap();

        let entries = log.export().await.unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].seq, 0);
        assert_eq!(entries[0].prev_hash, GENESIS_PREV);
        assert_eq!(entries[1].prev_hash, entries[0].hash);
        verify(&entries, None).expect("the appended chain must verify");
    }

    #[tokio::test]
    async fn concurrent_appends_do_not_fork_the_chain() {
        use std::sync::Arc;
        let log = Arc::new(MemoryAuditLog::new());
        let mut tasks = Vec::new();
        for i in 0..50 {
            let log = Arc::clone(&log);
            tasks.push(tokio::spawn(async move {
                log.append(record(&format!("op{i}"), Decision::Allow))
                    .await
                    .unwrap();
            }));
        }
        for t in tasks {
            t.await.unwrap();
        }
        let entries = log.export().await.unwrap();
        assert_eq!(entries.len(), 50);
        // Every seq 0..50 appears exactly once and the chain links cleanly.
        verify(&entries, None).expect("concurrent appends must not fork the chain");
    }

    // --- Postgres-backed durable store (testcontainers; needs Docker) ---

    use std::sync::Arc;
    use testcontainers_modules::postgres::Postgres;
    use testcontainers_modules::testcontainers::ImageExt;
    use testcontainers_modules::testcontainers::runners::AsyncRunner;

    /// Spin up an ephemeral Postgres, migrate it, and return (container, pool).
    /// The container is returned so the caller keeps it alive for the test.
    async fn pg() -> (
        testcontainers_modules::testcontainers::ContainerAsync<Postgres>,
        sqlx::PgPool,
    ) {
        let node = Postgres::default()
            .with_tag("17-alpine")
            .start()
            .await
            .expect("start postgres container");
        let port = node.get_host_port_ipv4(5432).await.unwrap();
        let url = format!("postgres://postgres:postgres@127.0.0.1:{port}/postgres");
        let pool = crate::db::connect(&url).await.unwrap();
        crate::db::migrate(&pool).await.unwrap();
        (node, pool)
    }

    #[tokio::test]
    async fn pg_appends_form_a_verifiable_chain() {
        let (_node, pool) = pg().await;
        let log = PgAuditLog::new(pool);
        log.append(record("alice", Decision::Allow)).await.unwrap();
        log.append(record("bob", Decision::Deny)).await.unwrap();

        let entries = log.export().await.unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].seq, 0);
        assert_eq!(entries[0].prev_hash, GENESIS_PREV);
        assert_eq!(entries[1].record.decision, Decision::Deny);
        verify(&entries, None).expect("the Postgres chain must verify");
    }

    #[tokio::test]
    async fn pg_chain_survives_a_reconnect() {
        let (_node, pool) = pg().await;
        {
            let log = PgAuditLog::new(pool.clone());
            log.append(record("alice", Decision::Allow)).await.unwrap();
        }
        // A fresh adapter over the same database (i.e. a coordinator restart)
        // sees the persisted chain and continues it.
        let log = PgAuditLog::new(pool);
        log.append(record("bob", Decision::Deny)).await.unwrap();
        let entries = log.export().await.unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[1].seq, 1);
        verify(&entries, None).unwrap();
    }

    #[tokio::test]
    async fn pg_concurrent_appends_do_not_fork_the_chain() {
        let (_node, pool) = pg().await;
        // Many concurrent appends over the shared pool stand in for concurrent
        // dispatches across replicas: the advisory lock must serialize them.
        let log = Arc::new(PgAuditLog::new(pool));
        let mut tasks = Vec::new();
        for i in 0..40 {
            let log = Arc::clone(&log);
            tasks.push(tokio::spawn(async move {
                log.append(record(&format!("op{i}"), Decision::Allow))
                    .await
                    .unwrap();
            }));
        }
        for t in tasks {
            t.await.unwrap();
        }
        let entries = log.export().await.unwrap();
        assert_eq!(entries.len(), 40);
        verify(&entries, None).expect("concurrent Postgres appends must not fork");
    }

    #[tokio::test]
    async fn pg_empty_export_is_an_empty_chain() {
        let (_node, pool) = pg().await;
        let log = PgAuditLog::new(pool);
        let entries = log.export().await.unwrap();
        assert!(entries.is_empty());
        verify(&entries, None).expect("an empty chain verifies vacuously");
    }

    #[tokio::test]
    async fn pg_a_corrupt_row_is_a_backend_error_not_a_panic() {
        let (_node, pool) = pg().await;
        // Insert a row whose stored hash is the wrong length, directly.
        sqlx::query(
            "INSERT INTO audit_log \
             (seq, ts_unix, subject, kind, target, run_as, decision, prev_hash, hash) \
             VALUES (0, 1, 'a', 'exec', 'h', '', 'allow', $1, $2)",
        )
        .bind(vec![0u8; 32])
        .bind(vec![0u8; 31]) // not 32 bytes
        .execute(&pool)
        .await
        .unwrap();
        let log = PgAuditLog::new(pool);
        assert!(
            log.export().await.is_err(),
            "a malformed hash must surface as an error, never a panic"
        );
    }
}
