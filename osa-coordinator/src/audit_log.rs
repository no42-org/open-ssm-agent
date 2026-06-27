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
use osa_core::audit::{AuditEntry, AuditRecord, GENESIS_PREV};
use osa_core::ports::{AuditLog, PortError};

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

#[cfg(test)]
mod tests {
    use super::*;
    use osa_core::audit::{Decision, verify};

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
}
