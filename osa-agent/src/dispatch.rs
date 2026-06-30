/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: MIT
 */

//! Running a dispatched job and streaming its sealed results (Epic 3, #20b·2).
//!
//! A [`Dispatch`] that the agent opened off the sealed downlink lands here. The
//! job is checked against the host-local backstop (AD-20), the capability is
//! selected by `kind`, and the exec engine streams output [`OutputChunk`]s
//! followed by exactly one terminal [`JobOutcome`] — each sealed as a
//! [`JobResult`] on the session uplink. Runs in a spawned task so a long command
//! never blocks the control-channel event loop.

use std::collections::HashSet;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use osa_core::allowlist::LocalAllowlist;
use osa_core::seal::SessionKeys;
use osa_core::wire;
use osa_proto::v1::job_outcome::Terminal;
use osa_proto::v1::job_result::Body;
use osa_proto::v1::output_chunk::Stream;
use osa_proto::v1::{ActionDescriptor, Dispatch, ExecParams, JobOutcome, JobResult, OutputChunk};
use tokio::sync::mpsc;

use crate::exec::{self, Chunk, ExecLimits};
use crate::jobstore::{JobState, JobStore};
use crate::session::seal_uplink;

/// Combined stdout+stderr byte cap for one dispatched job (anti-OOM, AD-22).
const MAX_JOB_OUTPUT: usize = 8 * 1024 * 1024;
/// Wall-clock deadline for one dispatched job.
const JOB_TIMEOUT: Duration = Duration::from_secs(300);
/// Reject an absurd `job_id` before hashing/using it (the coordinator mints a
/// UUID; this just bounds a hostile value).
const MAX_JOB_ID_LEN: usize = 256;

/// The set of `job_id`s currently executing in this agent process — the in-memory
/// guard that makes "look up persisted state, then mark started" atomic against
/// concurrent (cross-session) redeliveries, so a job is never run twice nor
/// falsely reported interrupted while it is still running.
pub type InFlight = Arc<Mutex<HashSet<String>>>;

/// A fresh, empty in-flight set, shared across all of an agent's job tasks.
pub fn new_inflight() -> InFlight {
    Arc::new(Mutex::new(HashSet::new()))
}

/// Holds a `job_id`'s in-flight claim; releases it on drop (any `run_job` exit).
struct Claim {
    set: InFlight,
    job_id: String,
}

impl Drop for Claim {
    fn drop(&mut self) {
        if let Ok(mut g) = self.set.lock() {
            g.remove(&self.job_id);
        }
    }
}

/// Claim `job_id` as in-flight, or `None` if another task already holds it.
fn try_claim(set: &InFlight, job_id: &str) -> Option<Claim> {
    let mut g = set.lock().ok()?;
    if !g.insert(job_id.to_string()) {
        return None;
    }
    Some(Claim {
        set: Arc::clone(set),
        job_id: job_id.to_string(),
    })
}

/// Run a blocking job-store operation off the async runtime (fsync can stall a
/// worker thread), returning its result.
async fn store_op<T, F>(jobs: &Arc<JobStore>, f: F) -> T
where
    F: FnOnce(&JobStore) -> T + Send + 'static,
    T: Send + 'static,
{
    let jobs = Arc::clone(jobs);
    tokio::task::spawn_blocking(move || f(&jobs))
        .await
        .expect("job store task panicked")
}

/// Seals a job's results and hands the **sealed bytes** to a publisher task (over
/// `results`) rather than touching MQTT directly — so the job runner is decoupled
/// from the transport (and unit-testable), and `send().await` backpressures the
/// job rather than dropping output when the link is busy.
pub struct JobChannel {
    pub results: mpsc::Sender<Vec<u8>>,
    pub keys: Arc<SessionKeys>,
    pub send_seq: Arc<AtomicU64>,
    pub host_id: String,
    pub sid: String,
}

impl JobChannel {
    /// Seal one `JobResult` and hand it to the publisher.
    async fn send(&self, result: &JobResult) {
        let bytes = seal_uplink(
            &self.keys,
            &self.send_seq,
            &self.host_id,
            &self.sid,
            &wire::encode(result),
        );
        if self.results.send(bytes).await.is_err() {
            tracing::warn!("result channel closed — job results will not be delivered");
        }
    }

    async fn chunk(&self, job_id: &str, stream: Stream, data: Vec<u8>) {
        self.send(&JobResult {
            job_id: job_id.to_string(),
            body: Some(Body::Chunk(OutputChunk {
                stream: stream as i32,
                data,
            })),
        })
        .await;
    }

    async fn outcome(&self, job_id: &str, outcome: JobOutcome) {
        self.send(&JobResult {
            job_id: job_id.to_string(),
            body: Some(Body::Outcome(outcome)),
        })
        .await;
    }
}

/// Run a dispatched job to completion, streaming sealed results over `ch`.
///
/// Idempotent under redelivery (AD-22, 3.3): persisted `job_id` state is consulted
/// first — a completed job replays its recorded outcome (no re-run), and an
/// interrupted job (a "started" marker with no terminal, i.e. a crash mid-run) is
/// **not** re-executed (at-most-once for a side-effecting exec).
pub async fn run_job(
    dispatch: Dispatch,
    backstop: Arc<LocalAllowlist>,
    jobs: Arc<JobStore>,
    inflight: InFlight,
    ch: JobChannel,
) {
    let job_id = dispatch.job_id.clone();
    if job_id.is_empty() || job_id.len() > MAX_JOB_ID_LEN {
        ch.outcome(&job_id, failed("invalid job_id".into())).await;
        return;
    }

    // Claim the job in-flight: if another task already holds it, this is a
    // concurrent redelivery of a still-running job — ignore it (no double-run, no
    // false "interrupted"; the running task reports the result). The disk store
    // (below) handles the cross-restart/reconnect case.
    let _claim = match try_claim(&inflight, &job_id) {
        Some(c) => c,
        None => {
            tracing::info!(%job_id, "duplicate dispatch while the job is running — ignoring");
            return;
        }
    };

    // Crash-recoverable, idempotent redelivery (3.3) — before any side effect.
    match store_op(&jobs, {
        let job_id = job_id.clone();
        move |j| j.lookup(&job_id)
    })
    .await
    {
        Ok(Some(JobState::Done(outcome))) => {
            tracing::info!(%job_id, "duplicate dispatch — replaying recorded outcome (not re-run)");
            ch.outcome(&job_id, outcome).await;
            return;
        }
        Ok(Some(JobState::Started)) => {
            tracing::warn!(%job_id, "redelivered interrupted job — not re-executed (at-most-once)");
            ch.outcome(
                &job_id,
                failed("job was interrupted before completing; not re-executed".into()),
            )
            .await;
            return;
        }
        Ok(None) => {}
        Err(e) => {
            // Fail closed: if we cannot determine prior state, do not risk a
            // re-execution.
            tracing::error!(error = %e, %job_id, "job store lookup failed — refusing to run");
            ch.outcome(&job_id, failed("agent job store unavailable".into()))
                .await;
            return;
        }
    }

    // Host-local backstop (AD-20): the allowlist must permit this kind + run_as,
    // even if the coordinator authorized it — the agent is the last line.
    let action = ActionDescriptor {
        kind: dispatch.kind.clone(),
        target: ch.host_id.clone(),
        run_as: dispatch.run_as.clone(),
        params_hash: Vec::new(),
    };
    if let Err(denial) = backstop.permits(&action) {
        tracing::warn!(%job_id, %denial, "dispatch refused by host backstop");
        ch.outcome(
            &job_id,
            failed(format!("denied by host backstop: {denial}")),
        )
        .await;
        return;
    }
    if dispatch.kind != exec::KIND {
        ch.outcome(
            &job_id,
            failed(format!("unsupported capability {:?}", dispatch.kind)),
        )
        .await;
        return;
    }
    let params: ExecParams = match wire::decode(&dispatch.params) {
        Ok(p) => p,
        Err(e) => {
            ch.outcome(&job_id, failed(format!("malformed exec params: {e}")))
                .await;
            return;
        }
    };

    // Durably mark the job started BEFORE spawning, so a crash mid-run is
    // recoverable as "interrupted" (and never silently re-run). Fail closed.
    if let Err(e) = store_op(&jobs, {
        let job_id = job_id.clone();
        move |j| j.mark_started(&job_id)
    })
    .await
    {
        tracing::error!(error = %e, %job_id, "failed to persist job start — refusing to run");
        ch.outcome(&job_id, failed("agent job store unavailable".into()))
            .await;
        return;
    }

    let limits = ExecLimits {
        max_output_bytes: MAX_JOB_OUTPUT,
        timeout: Some(JOB_TIMEOUT),
    };
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Chunk>(64);
    let drain = async {
        while let Some(chunk) = rx.recv().await {
            match chunk {
                Chunk::Stdout(d) => ch.chunk(&job_id, Stream::Stdout, d).await,
                Chunk::Stderr(d) => ch.chunk(&job_id, Stream::Stderr, d).await,
            }
        }
    };
    let (exec_result, ()) = tokio::join!(
        exec::stream(&params.argv, &dispatch.run_as, limits, tx),
        drain
    );

    let outcome = match exec_result {
        Ok(so) => {
            let terminal = match (so.exit_code, so.signal) {
                (Some(code), _) => Terminal::ExitCode(code),
                (None, Some(sig)) => Terminal::Signal(sig),
                (None, None) => Terminal::Error("no terminal status".into()),
            };
            JobOutcome {
                terminal: Some(terminal),
                output_truncated: so.truncated,
                timed_out: so.timed_out,
            }
        }
        Err(e) => failed(e.to_string()),
    };
    // Record the terminal outcome durably before reporting it, so a redelivery
    // replays it instead of re-running. A persist failure still reports the
    // outcome (the result is not lost; a later redelivery would see the lingering
    // "started" marker and report it interrupted rather than re-run it).
    if let Err(e) = store_op(&jobs, {
        let job_id = job_id.clone();
        let outcome = outcome.clone();
        move |j| j.record_done(&job_id, &outcome)
    })
    .await
    {
        tracing::warn!(error = %e, %job_id, "failed to persist job outcome");
    }
    ch.outcome(&job_id, outcome).await;
}

fn failed(msg: String) -> JobOutcome {
    JobOutcome {
        terminal: Some(Terminal::Error(msg)),
        output_truncated: false,
        timed_out: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use osa_core::seal::{Direction, Handshake, SessionKeys};
    use osa_proto::v1::Envelope;

    /// Two ends of one session: the agent seals, the coordinator opens.
    fn session_pair() -> (SessionKeys, SessionKeys) {
        let a = Handshake::new().unwrap();
        let b = Handshake::new().unwrap();
        let (apub, bpub) = (a.public, b.public);
        (
            a.derive(&bpub, b"bind").unwrap(),
            b.derive(&apub, b"bind").unwrap(),
        )
    }

    fn exec_dispatch(job_id: &str, run_as: &str, script: &str) -> Dispatch {
        Dispatch {
            job_id: job_id.into(),
            kind: exec::KIND.into(),
            run_as: run_as.into(),
            params: wire::encode(&ExecParams {
                argv: vec!["/bin/sh".into(), "-c".into(), script.into()],
            }),
        }
    }

    /// Run a job (with a fresh, isolated job store) and return its JobResults.
    async fn run_and_collect(dispatch: Dispatch, backstop: Arc<LocalAllowlist>) -> Vec<JobResult> {
        let dir = tempfile::tempdir().unwrap();
        let jobs = Arc::new(JobStore::new(dir.path()).unwrap());
        run_and_collect_with(dispatch, backstop, jobs).await
    }

    /// Run a job against a given (possibly shared) job store, returning the
    /// (opened, decoded) JobResults the coordinator would see.
    async fn run_and_collect_with(
        dispatch: Dispatch,
        backstop: Arc<LocalAllowlist>,
        jobs: Arc<JobStore>,
    ) -> Vec<JobResult> {
        let (agent_keys, coord_keys) = session_pair();
        let (tx, mut rx) = mpsc::channel(64);
        let ch = JobChannel {
            results: tx,
            keys: Arc::new(agent_keys),
            send_seq: Arc::new(AtomicU64::new(1)),
            host_id: "h".into(),
            sid: "s".into(),
        };
        run_job(dispatch, backstop, jobs, new_inflight(), ch).await; // drops ch → tx → rx ends
        let mut out = Vec::new();
        while let Some(bytes) = rx.recv().await {
            let env: Envelope = wire::decode(&bytes).unwrap();
            let pt = wire::open_envelope(&coord_keys, Direction::AgentToCoord, &env)
                .expect("the coordinator must open the agent-sealed result");
            out.push(wire::decode::<JobResult>(&pt).unwrap());
        }
        out
    }

    fn allow_exec() -> Arc<LocalAllowlist> {
        Arc::new(LocalAllowlist::new(vec!["exec".into()], vec!["".into()]))
    }

    #[tokio::test]
    async fn exec_dispatch_streams_sealed_output_then_a_terminal_outcome() {
        let results = run_and_collect(
            exec_dispatch("j1", "", "printf hi; printf oops 1>&2; exit 7"),
            allow_exec(),
        )
        .await;

        // Reassemble the streams from the ordered chunks; the last result is the
        // terminal outcome.
        let (mut stdout, mut stderr): (Vec<u8>, Vec<u8>) = (Vec::new(), Vec::new());
        let mut outcome = None;
        for r in &results {
            assert_eq!(r.job_id, "j1");
            match r.body.as_ref().unwrap() {
                Body::Chunk(c) if c.stream == Stream::Stdout as i32 => stdout.extend(&c.data),
                Body::Chunk(c) if c.stream == Stream::Stderr as i32 => stderr.extend(&c.data),
                Body::Chunk(_) => panic!("unspecified stream"),
                Body::Outcome(o) => outcome = Some(o.clone()),
            }
        }
        assert_eq!(stdout, b"hi");
        assert_eq!(stderr, b"oops");
        assert_eq!(outcome.unwrap().terminal, Some(Terminal::ExitCode(7)));
    }

    #[tokio::test]
    async fn a_dispatch_denied_by_the_backstop_reports_an_error_and_runs_nothing() {
        let results = run_and_collect(
            exec_dispatch("j2", "root", "touch /tmp/should-not-happen"),
            Arc::new(LocalAllowlist::deny_all()),
        )
        .await;
        // Exactly one result: a failure outcome — no output chunks, nothing ran.
        assert_eq!(results.len(), 1);
        match results[0].body.as_ref().unwrap() {
            Body::Outcome(o) => match o.terminal.as_ref().unwrap() {
                Terminal::Error(msg) => assert!(msg.contains("backstop"), "got: {msg}"),
                other => panic!("expected an error outcome, got {other:?}"),
            },
            other => panic!("expected an outcome, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn an_unsupported_capability_reports_an_error() {
        let mut d = exec_dispatch("j3", "", "true");
        d.kind = "shell".into(); // not exec
        let backstop = Arc::new(LocalAllowlist::new(vec!["shell".into()], vec!["".into()]));
        let results = run_and_collect(d, backstop).await;
        assert_eq!(results.len(), 1);
        let Body::Outcome(o) = results[0].body.as_ref().unwrap() else {
            panic!("expected an outcome");
        };
        assert!(
            matches!(o.terminal.as_ref().unwrap(), Terminal::Error(m) if m.contains("unsupported"))
        );
    }

    /// The single terminal outcome among a job's results.
    fn terminal_of(results: &[JobResult]) -> &JobOutcome {
        results
            .iter()
            .find_map(|r| match r.body.as_ref() {
                Some(Body::Outcome(o)) => Some(o),
                _ => None,
            })
            .expect("a terminal outcome")
    }

    #[tokio::test]
    async fn a_redelivered_completed_job_replays_its_outcome_and_does_not_re_run() {
        let dir = tempfile::tempdir().unwrap();
        let jobs = Arc::new(JobStore::new(dir.path()).unwrap());
        let marker = dir.path().join("ran");
        // The command appends a byte to a side-effect file each time it runs.
        let script = format!("printf x >> {}; printf out", marker.display());

        let first = run_and_collect_with(
            exec_dispatch("dup", "", &script),
            allow_exec(),
            jobs.clone(),
        )
        .await;
        // First run: streamed output + the recorded exit 0; the command ran once.
        assert_eq!(terminal_of(&first).terminal, Some(Terminal::ExitCode(0)));
        assert_eq!(std::fs::read(&marker).unwrap(), b"x");

        let second = run_and_collect_with(
            exec_dispatch("dup", "", &script),
            allow_exec(),
            jobs.clone(),
        )
        .await;
        // Redelivery: ONLY the recorded outcome replays (no output chunk)...
        assert_eq!(second.len(), 1, "redelivery replays just the outcome");
        assert_eq!(terminal_of(&second).terminal, Some(Terminal::ExitCode(0)));
        // ...and the side effect did NOT happen again (no re-execution).
        assert_eq!(
            std::fs::read(&marker).unwrap(),
            b"x",
            "command must not re-run"
        );
    }

    #[tokio::test]
    async fn a_redelivered_interrupted_job_is_not_re_executed() {
        let dir = tempfile::tempdir().unwrap();
        let jobs = Arc::new(JobStore::new(dir.path()).unwrap());
        // Simulate a crash mid-run: a "started" marker with no terminal outcome.
        jobs.mark_started("intr").unwrap();
        let marker = dir.path().join("side-effect");
        let script = format!("printf x >> {}", marker.display());

        let results = run_and_collect_with(
            exec_dispatch("intr", "", &script),
            allow_exec(),
            jobs.clone(),
        )
        .await;

        // Reported interrupted (at-most-once), and the command did NOT run.
        assert_eq!(results.len(), 1);
        assert!(matches!(
            terminal_of(&results).terminal.as_ref().unwrap(),
            Terminal::Error(m) if m.contains("interrupted")
        ));
        assert!(
            !marker.exists(),
            "an interrupted job must not be re-executed"
        );
    }

    #[tokio::test]
    async fn a_concurrent_redelivery_of_a_running_job_does_not_double_execute() {
        let dir = tempfile::tempdir().unwrap();
        let jobs = Arc::new(JobStore::new(dir.path()).unwrap());
        let inflight = new_inflight();
        let marker = dir.path().join("ran");
        // Sleeps so the two deliveries overlap; appends a byte only when it runs.
        let script = format!("sleep 0.3; printf x >> {}", marker.display());

        async fn one(jobs: Arc<JobStore>, inflight: InFlight, script: String) {
            let (agent, _coord) = session_pair();
            let (tx, mut rx) = mpsc::channel(64);
            let ch = JobChannel {
                results: tx,
                keys: Arc::new(agent),
                send_seq: Arc::new(AtomicU64::new(1)),
                host_id: "h".into(),
                sid: "s".into(),
            };
            run_job(
                exec_dispatch("same", "", &script),
                allow_exec(),
                jobs,
                inflight,
                ch,
            )
            .await;
            while rx.recv().await.is_some() {}
        }

        let a = tokio::spawn(one(jobs.clone(), inflight.clone(), script.clone()));
        let b = tokio::spawn(one(jobs.clone(), inflight.clone(), script.clone()));
        let _ = tokio::join!(a, b);
        // Despite two concurrent deliveries of one job_id, the command ran once.
        assert_eq!(
            std::fs::read(&marker).unwrap(),
            b"x",
            "command ran exactly once"
        );
    }

    #[tokio::test]
    async fn a_denied_job_is_not_persisted_and_can_run_on_a_later_allow() {
        let dir = tempfile::tempdir().unwrap();
        let jobs = Arc::new(JobStore::new(dir.path()).unwrap());
        let marker = dir.path().join("ran");
        let script = format!("printf x >> {}", marker.display());

        // First delivery is denied by the backstop → not run, not persisted.
        run_and_collect_with(
            exec_dispatch("j", "root", &script),
            Arc::new(LocalAllowlist::deny_all()),
            jobs.clone(),
        )
        .await;
        assert!(!marker.exists(), "denied job did not run");

        // A later allowed delivery of the same job_id runs (no stale marker stuck).
        run_and_collect_with(exec_dispatch("j", "", &script), allow_exec(), jobs.clone()).await;
        assert_eq!(std::fs::read(&marker).unwrap(), b"x", "allowed retry ran");
    }
}
