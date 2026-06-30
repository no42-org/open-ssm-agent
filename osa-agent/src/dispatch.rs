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

use std::sync::Arc;
use std::sync::atomic::AtomicU64;
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
use crate::session::seal_uplink;

/// Combined stdout+stderr byte cap for one dispatched job (anti-OOM, AD-22).
const MAX_JOB_OUTPUT: usize = 8 * 1024 * 1024;
/// Wall-clock deadline for one dispatched job.
const JOB_TIMEOUT: Duration = Duration::from_secs(300);

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
pub async fn run_job(dispatch: Dispatch, backstop: Arc<LocalAllowlist>, ch: JobChannel) {
    let job_id = dispatch.job_id.clone();

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

    /// Run a job and return the (opened, decoded) JobResults the coordinator sees.
    async fn run_and_collect(dispatch: Dispatch, backstop: Arc<LocalAllowlist>) -> Vec<JobResult> {
        let (agent_keys, coord_keys) = session_pair();
        let (tx, mut rx) = mpsc::channel(64);
        let ch = JobChannel {
            results: tx,
            keys: Arc::new(agent_keys),
            send_seq: Arc::new(AtomicU64::new(1)),
            host_id: "h".into(),
            sid: "s".into(),
        };
        run_job(dispatch, backstop, ch).await; // drops ch → tx → rx ends after draining
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
}
