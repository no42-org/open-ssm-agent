/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: MIT
 */

//! Crash-recoverable, idempotent job state (AD-22, story 3.3).
//!
//! Dispatch is at-least-once: an untrusted broker or a coordinator retry can
//! redeliver the same `job_id`. The within-session `seq` replay guard dedups a
//! same-session redelivery, but a redelivery **across a reconnect or an agent
//! restart** needs durable, `job_id`-keyed state — that is this store.
//!
//! For each job the agent records, on disk:
//! 1. a **started** marker, fsynced *before* the process is spawned, and
//! 2. the **terminal outcome**, after the process exits.
//!
//! On a redelivery the runner consults the store:
//! - **Done** → replay the recorded outcome; do not re-run.
//! - **Started** with no terminal → the job was interrupted (a crash mid-run);
//!   **do not re-execute** (at-most-once for a side-effecting exec) — report it
//!   interrupted.
//!
//! The store survives a restart (it is just files); recovery is the lookup on the
//! next delivery. The coordinator-supplied `job_id` is **hashed** to the filename,
//! so a hostile id can never escape the jobs directory.

use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use osa_core::wire;
use osa_proto::v1::JobOutcome;

/// First byte of a job record: the state discriminator.
const TAG_STARTED: u8 = 0;
const TAG_DONE: u8 = 1;
/// Records older than this are pruned at startup, bounding `jobs/` growth across
/// agent restarts. Far longer than any redelivery window (the coordinator forgets
/// a pending job within minutes), so a live job is never pruned out from under us.
const RETENTION: Duration = Duration::from_secs(7 * 24 * 3600);

/// The recorded state of a `job_id`.
pub enum JobState {
    /// A start marker exists but no terminal outcome — the job was interrupted.
    Started,
    /// The job ran to completion with this terminal outcome.
    Done(JobOutcome),
}

/// On-disk, per-`job_id` job state under `<state_dir>/jobs/`.
pub struct JobStore {
    dir: PathBuf,
}

impl JobStore {
    /// Open (creating if needed) the job store under `state_dir`, pruning stale
    /// records and orphaned temp files left by an earlier crash.
    pub fn new(state_dir: &Path) -> io::Result<Self> {
        let dir = state_dir.join("jobs");
        std::fs::create_dir_all(&dir)?;
        let store = Self { dir };
        store.prune();
        Ok(store)
    }

    /// Best-effort retention: drop records older than [`RETENTION`] and any
    /// leftover `*.tmp` files (an interrupted write). Bounds `jobs/` growth across
    /// restarts. (Periodic pruning during a long uptime is a future refinement.)
    fn prune(&self) {
        let cutoff = SystemTime::now().checked_sub(RETENTION);
        let Ok(entries) = std::fs::read_dir(&self.dir) else {
            return;
        };
        for entry in entries.flatten() {
            // A record filename is pure SHA-256 hex (no dot); a temp file is
            // `<hex>.tmp.<pid>` — so any name with a dot is an orphaned write.
            let is_tmp = entry.file_name().to_string_lossy().contains('.');
            let stale = cutoff.is_some_and(|c| {
                entry
                    .metadata()
                    .and_then(|m| m.modified())
                    .is_ok_and(|t| t < c)
            });
            if is_tmp || stale {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }

    /// The record path for `job_id` — a SHA-256 of the id, so a coordinator-
    /// supplied id (even one containing `/` or `..`) cannot traverse out.
    fn path(&self, job_id: &str) -> PathBuf {
        self.dir.join(wire::sha256_hex(job_id.as_bytes()))
    }

    /// The recorded state of `job_id`, or `None` if it has never been seen.
    pub fn lookup(&self, job_id: &str) -> io::Result<Option<JobState>> {
        let bytes = match std::fs::read(self.path(job_id)) {
            Ok(b) => b,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        match bytes.split_first() {
            // A well-formed Done record (decodes AND carries a terminal status).
            Some((&TAG_DONE, rest)) => match wire::decode::<JobOutcome>(rest) {
                Ok(outcome) if outcome.terminal.is_some() => Ok(Some(JobState::Done(outcome))),
                // A start marker, or any corrupt/partial/terminal-less record, is
                // treated as "interrupted" — fail closed (never re-execute), and
                // never wedge the job on a decode error.
                _ => Ok(Some(JobState::Started)),
            },
            _ => Ok(Some(JobState::Started)),
        }
    }

    /// Durably record that `job_id` has started — call BEFORE spawning the
    /// process, so a crash mid-run leaves a recoverable "interrupted" marker.
    pub fn mark_started(&self, job_id: &str) -> io::Result<()> {
        write_durably(&self.path(job_id), &[TAG_STARTED])
    }

    /// Durably record the terminal `outcome` for `job_id`.
    pub fn record_done(&self, job_id: &str, outcome: &JobOutcome) -> io::Result<()> {
        let mut buf = Vec::with_capacity(64);
        buf.push(TAG_DONE);
        buf.extend_from_slice(&wire::encode(outcome));
        write_durably(&self.path(job_id), &buf)
    }
}

/// Write `bytes` to `path` atomically and durably: temp file → fsync(file) →
/// rename → **fsync(dir)**. The directory fsync is load-bearing: without it the
/// new dir entry can be lost on a crash even though `rename` is atomic, so a
/// "started" marker could vanish and a side-effecting job would re-run.
fn write_durably(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write;
    let dir = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "record path has no parent"))?;
    // Per-process temp name, so concurrent writers never collide on one temp file.
    let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
    let mut f = std::fs::File::create(&tmp)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    std::fs::rename(&tmp, path)?;
    // Make the new directory entry durable, not just the file contents.
    std::fs::File::open(dir)?.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;
    use osa_proto::v1::job_outcome::Terminal;

    fn outcome(code: i32) -> JobOutcome {
        JobOutcome {
            terminal: Some(Terminal::ExitCode(code)),
            output_truncated: false,
            timed_out: false,
        }
    }

    #[test]
    fn unseen_job_is_none() {
        let dir = tempfile::tempdir().unwrap();
        let store = JobStore::new(dir.path()).unwrap();
        assert!(store.lookup("job-1").unwrap().is_none());
    }

    #[test]
    fn started_then_done_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let store = JobStore::new(dir.path()).unwrap();
        store.mark_started("job-1").unwrap();
        assert!(matches!(
            store.lookup("job-1").unwrap(),
            Some(JobState::Started)
        ));
        store.record_done("job-1", &outcome(7)).unwrap();
        let Some(JobState::Done(o)) = store.lookup("job-1").unwrap() else {
            panic!("expected Done");
        };
        assert_eq!(o.terminal, Some(Terminal::ExitCode(7)));
    }

    #[test]
    fn state_survives_a_restart() {
        // A fresh JobStore over the same dir (an agent restart) sees prior state.
        let dir = tempfile::tempdir().unwrap();
        JobStore::new(dir.path())
            .unwrap()
            .record_done("job-1", &outcome(0))
            .unwrap();
        let reopened = JobStore::new(dir.path()).unwrap();
        assert!(matches!(
            reopened.lookup("job-1").unwrap(),
            Some(JobState::Done(_))
        ));
    }

    #[test]
    fn a_corrupt_done_record_is_treated_as_interrupted_not_replayed() {
        let dir = tempfile::tempdir().unwrap();
        let store = JobStore::new(dir.path()).unwrap();
        // A "done" tag with an empty/garbage body must NOT replay a bogus outcome
        // and must NOT wedge the job — it degrades to interrupted (fail closed).
        std::fs::write(store.path("job-1"), [TAG_DONE]).unwrap();
        assert!(matches!(
            store.lookup("job-1").unwrap(),
            Some(JobState::Started)
        ));
        std::fs::write(store.path("job-2"), [TAG_DONE, 0xff, 0xff, 0xff]).unwrap();
        assert!(matches!(
            store.lookup("job-2").unwrap(),
            Some(JobState::Started)
        ));
    }

    #[test]
    fn opening_the_store_prunes_orphan_temp_files() {
        let dir = tempfile::tempdir().unwrap();
        let jobs_dir = dir.path().join("jobs");
        std::fs::create_dir_all(&jobs_dir).unwrap();
        // An interrupted write left a temp file behind.
        std::fs::write(jobs_dir.join("abcd.tmp.123"), b"junk").unwrap();
        // Opening the store prunes it.
        let _store = JobStore::new(dir.path()).unwrap();
        assert!(
            !jobs_dir.join("abcd.tmp.123").exists(),
            "orphan temp pruned"
        );
    }

    #[test]
    fn a_hostile_job_id_cannot_traverse_out_of_the_jobs_dir() {
        let dir = tempfile::tempdir().unwrap();
        let store = JobStore::new(dir.path()).unwrap();
        store.mark_started("../../etc/passwd").unwrap();
        // The record lives under jobs/, named by hash — nothing escaped.
        assert!(matches!(
            store.lookup("../../etc/passwd").unwrap(),
            Some(JobState::Started)
        ));
        let escaped = dir.path().join("etc/passwd");
        assert!(!escaped.exists(), "no traversal outside the jobs dir");
        let entries: Vec<_> = std::fs::read_dir(dir.path().join("jobs"))
            .unwrap()
            .collect();
        assert_eq!(entries.len(), 1, "exactly one hashed record file");
    }
}
