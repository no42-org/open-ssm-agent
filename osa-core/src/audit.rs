/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: MIT
 */

//! Append-only, hash-chained audit log (AD-21).
//!
//! Every dispatch decision — allowed **or** denied — is recorded as an entry
//! chained to its predecessor: `hash = H(seq ‖ record ‖ prev_hash)`. Recomputing
//! the chain (see [`verify`]) detects any altered entry and any removed *interior*
//! entry.
//!
//! **Scope of the guarantee.** The chain proves *internal consistency*: that the
//! entries handed to a verifier have not been individually altered or interiorly
//! removed. On its own it is not tamper-proof against the writer — a party that
//! can rewrite the whole store can re-chain a doctored history from genesis. Two
//! things close that gap: an `expected_head` anchor the verifier holds
//! independently (detects tail truncation / rewrite — see [`verify`]), and a
//! signed head / external anchor (issue #24, lands with the durable store 2.3b).
//!
//! This module is the pure chain logic (encoding + hashing + verification). The
//! storage and the single-writer serialization that stops two appends forking
//! the chain are an adapter concern (the [`AuditLog`](crate::ports::AuditLog)
//! port), wired in the coordinator bin.

use sha2::{Digest, Sha256};

/// A 32-byte SHA-256 chain hash.
pub type Hash = [u8; 32];

/// The chain's anchor: the `prev_hash` of the first (seq 0) entry.
pub const GENESIS_PREV: Hash = [0u8; 32];

/// The authorization outcome recorded for a dispatch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny,
}

impl Decision {
    /// The stable wire/encoding token. Load-bearing: it is hashed into the chain,
    /// so it must never change for an existing decision.
    pub fn as_str(&self) -> &'static str {
        match self {
            Decision::Allow => "allow",
            Decision::Deny => "deny",
        }
    }

    /// Parse a decision token (for reconstructing an exported entry).
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "allow" => Some(Decision::Allow),
            "deny" => Some(Decision::Deny),
            _ => None,
        }
    }
}

/// The content of one audit record — everything except the chain fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditRecord {
    /// Decision time, unix seconds.
    pub ts_unix: i64,
    /// The authenticated operator (`anonymous` if the API runs without auth).
    pub subject: String,
    /// The action kind (`exec`, `shell`, …).
    pub kind: String,
    /// The target host_id.
    pub target: String,
    /// The requested `run_as` (empty when unspecified).
    pub run_as: String,
    /// Allowed or denied.
    pub decision: Decision,
}

/// A sealed entry: a record plus its position and chain hashes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditEntry {
    pub seq: u64,
    pub record: AuditRecord,
    pub prev_hash: Hash,
    pub hash: Hash,
}

impl AuditEntry {
    /// Seal `record` at `seq` onto `prev_hash`, computing the chained hash.
    pub fn seal(seq: u64, record: AuditRecord, prev_hash: Hash) -> Self {
        let hash = compute_hash(seq, &record, &prev_hash);
        Self {
            seq,
            record,
            prev_hash,
            hash,
        }
    }
}

/// Canonical, unambiguous encoding then hash: fixed field order, each string
/// length-prefixed so no field boundary can be shifted, finished with the
/// `prev_hash` that chains this entry to its predecessor.
fn compute_hash(seq: u64, r: &AuditRecord, prev_hash: &Hash) -> Hash {
    let mut h = Sha256::new();
    h.update(seq.to_be_bytes());
    h.update(r.ts_unix.to_be_bytes());
    for field in [
        r.subject.as_str(),
        r.kind.as_str(),
        r.target.as_str(),
        r.run_as.as_str(),
        r.decision.as_str(),
    ] {
        h.update((field.len() as u64).to_be_bytes());
        h.update(field.as_bytes());
    }
    h.update(prev_hash);
    h.finalize().into()
}

/// Why a chain failed verification.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AuditError {
    #[error("entry at index {index} has seq {seq}, expected {expected}")]
    OutOfOrder {
        index: usize,
        seq: u64,
        expected: u64,
    },
    #[error("entry {seq} breaks the chain: its prev_hash does not match the previous entry")]
    BrokenLink { seq: u64 },
    #[error("entry {seq} was altered: its hash does not match its content")]
    Altered { seq: u64 },
    #[error("the chain is shorter than the expected head: it has been truncated")]
    Truncated,
    #[error("the chain head does not match the expected head")]
    UnexpectedHead,
}

/// Recompute the chain and verify integrity: seq is contiguous from 0, each
/// `prev_hash` links to the prior entry's `hash`, and each `hash` matches its
/// content. Detects any altered entry and any removed *interior* entry.
///
/// Tail truncation (dropping the most recent entries) leaves a still-valid
/// prefix, so it is only detectable against an external anchor: pass
/// `expected_head = Some(last_known_hash)` to require the chain to still end
/// there. With `None`, an empty chain verifies vacuously.
pub fn verify(entries: &[AuditEntry], expected_head: Option<Hash>) -> Result<(), AuditError> {
    let mut prev = GENESIS_PREV;
    for (index, e) in entries.iter().enumerate() {
        let expected = index as u64;
        if e.seq != expected {
            return Err(AuditError::OutOfOrder {
                index,
                seq: e.seq,
                expected,
            });
        }
        if e.prev_hash != prev {
            return Err(AuditError::BrokenLink { seq: e.seq });
        }
        if compute_hash(e.seq, &e.record, &e.prev_hash) != e.hash {
            return Err(AuditError::Altered { seq: e.seq });
        }
        prev = e.hash;
    }
    if let Some(head) = expected_head {
        match entries.last() {
            Some(last) if last.hash == head => {}
            Some(_) => return Err(AuditError::UnexpectedHead),
            // Anchor known but chain empty (or shorter) → truncated away.
            None => return Err(AuditError::Truncated),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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

    /// Build a valid chain of `n` entries.
    fn chain(n: u64) -> Vec<AuditEntry> {
        let mut out = Vec::new();
        let mut prev = GENESIS_PREV;
        for seq in 0..n {
            let dec = if seq % 2 == 0 {
                Decision::Allow
            } else {
                Decision::Deny
            };
            let e = AuditEntry::seal(seq, record(&format!("op{seq}"), dec), prev);
            prev = e.hash;
            out.push(e);
        }
        out
    }

    #[test]
    fn seal_is_deterministic() {
        let r = record("alice", Decision::Allow);
        let a = AuditEntry::seal(0, r.clone(), GENESIS_PREV);
        let b = AuditEntry::seal(0, r, GENESIS_PREV);
        assert_eq!(a.hash, b.hash);
    }

    #[test]
    fn a_well_formed_chain_verifies() {
        assert_eq!(verify(&chain(5), None), Ok(()));
    }

    #[test]
    fn an_empty_chain_verifies() {
        assert_eq!(verify(&[], None), Ok(()));
    }

    #[test]
    fn detects_an_altered_record() {
        let mut c = chain(5);
        // Tamper the content of entry 2 without recomputing its hash.
        c[2].record.decision = Decision::Allow;
        c[2].record.subject = "mallory".into();
        assert_eq!(verify(&c, None), Err(AuditError::Altered { seq: 2 }));
    }

    #[test]
    fn detects_an_altered_record_even_if_its_hash_is_recomputed() {
        let mut c = chain(5);
        // Recompute entry 2's own hash after tampering — the *next* entry's
        // prev_hash no longer links, so the chain still breaks.
        c[2].record.subject = "mallory".into();
        c[2].hash = compute_hash(c[2].seq, &c[2].record, &c[2].prev_hash);
        assert_eq!(verify(&c, None), Err(AuditError::BrokenLink { seq: 3 }));
    }

    #[test]
    fn detects_a_removed_interior_entry() {
        let mut c = chain(5);
        c.remove(2); // seq jumps 1 -> 3
        assert!(matches!(
            verify(&c, None),
            Err(AuditError::OutOfOrder { .. })
        ));
    }

    #[test]
    fn tail_truncation_is_detected_only_against_an_anchor() {
        let full = chain(5);
        let head = full.last().unwrap().hash;
        let mut truncated = full.clone();
        truncated.pop(); // drop the most recent entry

        // Without an anchor the prefix still verifies (the known limitation)...
        assert_eq!(verify(&truncated, None), Ok(()));
        // ...but against the last-known head, truncation is caught.
        assert_eq!(
            verify(&truncated, Some(head)),
            Err(AuditError::UnexpectedHead)
        );
        // The full chain still matches its head.
        assert_eq!(verify(&full, Some(head)), Ok(()));
    }

    #[test]
    fn decision_round_trips() {
        assert_eq!(
            Decision::parse(Decision::Allow.as_str()),
            Some(Decision::Allow)
        );
        assert_eq!(
            Decision::parse(Decision::Deny.as_str()),
            Some(Decision::Deny)
        );
        assert_eq!(Decision::parse("maybe"), None);
    }

    #[test]
    fn a_first_entry_not_anchored_to_genesis_is_a_broken_link() {
        // An entry sealed onto a non-genesis prev_hash, presented as seq 0.
        let bogus = AuditEntry::seal(0, record("alice", Decision::Allow), [9u8; 32]);
        assert_eq!(
            verify(&[bogus], None),
            Err(AuditError::BrokenLink { seq: 0 })
        );
    }

    #[test]
    fn an_empty_chain_against_an_anchor_is_truncated() {
        assert_eq!(verify(&[], Some([1u8; 32])), Err(AuditError::Truncated));
    }

    #[test]
    fn a_duplicated_seq_is_out_of_order() {
        let mut c = chain(3);
        // Replay entry 1 in place of entry 2: seq 1 appears where 2 is expected.
        c[2] = c[1].clone();
        assert!(matches!(
            verify(&c, None),
            Err(AuditError::OutOfOrder { expected: 2, .. })
        ));
    }
}
