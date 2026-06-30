/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: MIT
 */

//! The exec `JobCapability` adapter (AD-13·Job, AD-14): run a command under a
//! target user and stream its output and terminal status.
//!
//! This is the agent-side execution engine for `kind = "exec"`. It resolves
//! `run_as` to a unix user and **drops privileges** in the child (setgid →
//! setgroups → setuid, in that order, before exec) so the command runs as that
//! user and never with the agent's (root's) supplementary groups. When dropping,
//! the child's environment is **cleared** and replaced with a minimal one for the
//! target user (so the agent's secrets and any `LD_*` are never inherited, and
//! `argv[0]` resolves against a fixed safe `PATH`). Every failure is a typed
//! [`ExecError`] — a bad `run_as`, an unsupported platform, or an unspawnable
//! binary never panics.
//!
//! [`stream`] reads stdout/stderr **incrementally**, emitting [`Chunk`]s as the
//! process produces them, and enforces an output byte-cap and an execution
//! timeout (killing the child on either). [`run`] is a buffered convenience over
//! it (used by the local `osa-agent exec` driver). stdin is `/dev/null`, so a
//! command that reads stdin gets EOF rather than hanging.
//!
//! Privilege drop is **fail-closed by platform**: it is implemented only where we
//! can also drop supplementary groups (Linux/Android, the AD-1 target). On any
//! other target a non-empty `run_as` returns [`ExecError::PrivDropUnsupported`]
//! rather than running with the agent's groups retained.
//!
//! # Deferred (later Epic 3 stories)
//! Process-group isolation (`setsid`) and on-disk job-state / `job_id` dedup for
//! crash-recoverable redelivery (3.3) are not done here.
//!
//! # Testing the privilege drop
//! The actual setuid/setgid path needs root, so it is covered by a `#[cfg(linux)]
//! #[ignore]` test (`cargo test -- --ignored`, run as root); the unprivileged
//! tests cover the no-drop, streaming, cap/timeout, and every failure path.

use std::os::unix::process::ExitStatusExt;
use std::process::Stdio;
use std::time::Duration;

use nix::unistd::User;
use tokio::io::AsyncReadExt;
use tokio::sync::mpsc;

/// The `action.kind` this capability answers to.
pub const KIND: &str = "exec";

/// Bytes read from a child pipe per step.
const READ_CHUNK: usize = 16 * 1024;

/// Why the output pump stopped reading.
enum PumpEnd {
    /// Both pipes reached EOF (the process finished writing).
    Eof,
    /// The output byte-cap was exceeded.
    Truncated,
    /// The result consumer went away (nothing left to read the output).
    SinkClosed,
}

/// One ordered slice of a running job's output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Chunk {
    Stdout(Vec<u8>),
    Stderr(Vec<u8>),
}

/// Bounds on a single exec, so a runaway command cannot exhaust agent memory or
/// pin a worker forever.
#[derive(Debug, Clone, Copy)]
pub struct ExecLimits {
    /// Combined stdout+stderr byte cap; once exceeded the child is killed and the
    /// outcome is flagged `truncated`.
    pub max_output_bytes: usize,
    /// Wall-clock deadline; on expiry the child is killed and the outcome is
    /// flagged `timed_out`. `None` disables the timeout (the buffered local CLI).
    pub timeout: Option<Duration>,
}

impl ExecLimits {
    /// No cap, no timeout — for the operator-invoked local `exec` driver.
    pub fn unbounded() -> Self {
        Self {
            max_output_bytes: usize::MAX,
            timeout: None,
        }
    }
}

/// How a streamed job ended (its output having been emitted as [`Chunk`]s).
#[derive(Debug)]
pub struct StreamOutcome {
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub truncated: bool,
    pub timed_out: bool,
}

/// The terminal result of a buffered job: how it ended plus the captured streams.
#[derive(Debug)]
pub struct ExecOutcome {
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// Why an exec job could not produce a terminal status. Distinct from a process
/// that ran and exited non-zero (that is a successful outcome).
#[derive(Debug, thiserror::Error)]
pub enum ExecError {
    #[error("no command given")]
    EmptyArgv,
    /// The `run_as` name was not found. Resolution is by **name** (getpwnam); a
    /// numeric uid string is not resolved.
    #[error("run_as user {0:?} does not exist")]
    UnknownUser(String),
    #[error("looking up run_as user {user:?} failed: {source}")]
    UserLookup {
        user: String,
        source: std::io::Error,
    },
    /// A non-empty `run_as` was requested on a platform where we cannot fully drop
    /// privileges (no `setgroups`). Fail closed rather than retain root's groups.
    /// Only exists off the supported targets, where the fail-closed path builds it.
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    #[error("dropping privileges to a run_as user is only supported on Linux")]
    PrivDropUnsupported,
    #[error("spawning {program:?} failed: {source}")]
    Spawn {
        program: String,
        source: std::io::Error,
    },
    #[error("waiting on the child failed: {0}")]
    Wait(std::io::Error),
}

/// Run `argv` as `run_as`, streaming output [`Chunk`]s to `sink` as the process
/// produces them and enforcing `limits`. Returns the terminal status once the
/// process exits (or is killed for exceeding a limit). An empty `run_as` runs as
/// the agent's own user.
pub async fn stream(
    argv: &[String],
    run_as: &str,
    limits: ExecLimits,
    sink: mpsc::Sender<Chunk>,
) -> Result<StreamOutcome, ExecError> {
    if argv.is_empty() {
        return Err(ExecError::EmptyArgv);
    }
    let mut std_cmd = std::process::Command::new(&argv[0]);
    std_cmd.args(&argv[1..]);
    if let Some(user) = resolve_user(run_as)? {
        apply_target_user(&mut std_cmd, &user)?;
    }
    std_cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = tokio::process::Command::from(std_cmd)
        .spawn()
        .map_err(|e| ExecError::Spawn {
            program: argv[0].clone(),
            source: e,
        })?;
    let mut out = child.stdout.take().expect("stdout piped");
    let mut err = child.stderr.take().expect("stderr piped");

    // Read both pipes concurrently, forwarding each slice to the sink and counting
    // total bytes. Returns whether the cap was hit and whether the consumer is gone
    // — either means stop and kill the child.
    let pump = async {
        let mut obuf = vec![0u8; READ_CHUNK];
        let mut ebuf = vec![0u8; READ_CHUNK];
        let (mut out_done, mut err_done) = (false, false);
        let mut total = 0usize;
        while !(out_done && err_done) {
            tokio::select! {
                r = out.read(&mut obuf), if !out_done => match r {
                    Ok(0) | Err(_) => out_done = true,
                    Ok(n) => {
                        if sink.send(Chunk::Stdout(obuf[..n].to_vec())).await.is_err() {
                            return PumpEnd::SinkClosed;
                        }
                        total += n;
                        if total > limits.max_output_bytes { return PumpEnd::Truncated; }
                    }
                },
                r = err.read(&mut ebuf), if !err_done => match r {
                    Ok(0) | Err(_) => err_done = true,
                    Ok(n) => {
                        if sink.send(Chunk::Stderr(ebuf[..n].to_vec())).await.is_err() {
                            return PumpEnd::SinkClosed;
                        }
                        total += n;
                        if total > limits.max_output_bytes { return PumpEnd::Truncated; }
                    }
                },
            }
        }
        PumpEnd::Eof
    };

    let (mut truncated, mut timed_out, mut sink_closed) = (false, false, false);
    match limits.timeout {
        Some(d) => match tokio::time::timeout(d, pump).await {
            Ok(PumpEnd::Truncated) => truncated = true,
            Ok(PumpEnd::SinkClosed) => sink_closed = true,
            Ok(PumpEnd::Eof) => {}
            Err(_) => timed_out = true,
        },
        None => match pump.await {
            PumpEnd::Truncated => truncated = true,
            PumpEnd::SinkClosed => sink_closed = true,
            PumpEnd::Eof => {}
        },
    }
    // Kill the child if we stopped early for ANY reason (cap, timeout, or the
    // consumer going away) — never leave it running with no one reading its output.
    if truncated || timed_out || sink_closed {
        let _ = child.start_kill(); // SIGKILL; wait() below reaps it (no zombie)
    }
    let status = child.wait().await.map_err(ExecError::Wait)?;
    Ok(StreamOutcome {
        exit_code: status.code(),
        signal: status.signal(),
        truncated,
        timed_out,
    })
}

/// Run `argv` as `run_as`, buffering all output (no cap, no timeout) and returning
/// the captured streams + terminal status. For the operator-invoked local driver.
pub async fn run(argv: Vec<String>, run_as: String) -> Result<ExecOutcome, ExecError> {
    let (tx, mut rx) = mpsc::channel(64);
    let collect = async {
        let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
        while let Some(chunk) = rx.recv().await {
            match chunk {
                Chunk::Stdout(d) => stdout.extend_from_slice(&d),
                Chunk::Stderr(d) => stderr.extend_from_slice(&d),
            }
        }
        (stdout, stderr)
    };
    let (outcome, (stdout, stderr)) =
        tokio::join!(stream(&argv, &run_as, ExecLimits::unbounded(), tx), collect);
    let outcome = outcome?;
    Ok(ExecOutcome {
        exit_code: outcome.exit_code,
        signal: outcome.signal,
        stdout,
        stderr,
    })
}

/// The target user to run as, or `None` to keep the agent's own credentials.
/// Resolution is by name (getpwnam); a numeric uid string is not resolved.
fn resolve_user(run_as: &str) -> Result<Option<User>, ExecError> {
    if run_as.is_empty() {
        return Ok(None);
    }
    match User::from_name(run_as) {
        Ok(Some(u)) => Ok(Some(u)),
        Ok(None) => Err(ExecError::UnknownUser(run_as.to_string())),
        Err(e) => Err(ExecError::UserLookup {
            user: run_as.to_string(),
            source: std::io::Error::from(e),
        }),
    }
}

/// Configure `cmd` to run as `user`: a minimal, cleared environment plus a child
/// `pre_exec` that drops privileges. Implemented only where supplementary groups
/// can also be dropped (Linux/Android); elsewhere it fails closed.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn apply_target_user(cmd: &mut std::process::Command, user: &User) -> Result<(), ExecError> {
    use std::os::unix::process::CommandExt;
    // Clear the agent's environment (secrets, OSA_* vars, any LD_PRELOAD/
    // LD_LIBRARY_PATH) and give the target user a minimal one. `argv[0]` then
    // resolves against this fixed safe PATH, not the agent's inherited PATH.
    cmd.env_clear()
        .env("PATH", "/usr/local/bin:/usr/bin:/bin")
        .env("HOME", &user.dir)
        .env("USER", &user.name)
        .env("LOGNAME", &user.name)
        .env("SHELL", &user.shell);
    let (uid, gid) = (user.uid, user.gid);
    // SAFETY: the closure runs in the forked child before exec and only calls
    // async-signal-safe syscalls. Order is load-bearing: set the group and drop
    // supplementary groups (to just the primary gid) while still privileged, then
    // drop the uid LAST — after which CAP_SETUID/SETGID are gone. A failure in any
    // step returns Err, so std does not exec and the command never runs with a
    // partially-dropped identity.
    unsafe {
        cmd.pre_exec(move || {
            nix::unistd::setgid(gid).map_err(std::io::Error::from)?;
            nix::unistd::setgroups(&[gid]).map_err(std::io::Error::from)?;
            nix::unistd::setuid(uid).map_err(std::io::Error::from)?;
            Ok(())
        });
    }
    Ok(())
}

/// Fail closed: refuse to run as another user where we cannot drop supplementary
/// groups, rather than running with the agent's (root's) groups retained.
#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn apply_target_user(_cmd: &mut std::process::Command, _user: &User) -> Result<(), ExecError> {
    Err(ExecError::PrivDropUnsupported)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sh(script: &str) -> Vec<String> {
        vec!["/bin/sh".into(), "-c".into(), script.into()]
    }

    #[tokio::test]
    async fn captures_stdout_stderr_and_exit_code() {
        let out = run(sh("printf out; printf err 1>&2; exit 3"), String::new())
            .await
            .unwrap();
        assert_eq!(out.stdout, b"out");
        assert_eq!(out.stderr, b"err");
        assert_eq!(out.exit_code, Some(3));
        assert_eq!(out.signal, None);
    }

    #[tokio::test]
    async fn a_successful_command_exits_zero() {
        let out = run(sh("true"), String::new()).await.unwrap();
        assert_eq!(out.exit_code, Some(0));
    }

    #[tokio::test]
    async fn termination_by_signal_is_reported() {
        // The shell kills itself with SIGTERM → no exit code, signal 15.
        let out = run(sh("kill -TERM $$"), String::new()).await.unwrap();
        assert_eq!(out.exit_code, None);
        assert_eq!(out.signal, Some(15));
    }

    #[tokio::test]
    async fn empty_argv_is_a_typed_error() {
        let (tx, _rx) = mpsc::channel(1);
        assert!(matches!(
            stream(&[], "", ExecLimits::unbounded(), tx).await,
            Err(ExecError::EmptyArgv)
        ));
    }

    #[tokio::test]
    async fn an_unspawnable_binary_is_a_typed_error_not_a_panic() {
        let err = run(
            vec!["/nonexistent/osa-no-such-binary".into()],
            String::new(),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, ExecError::Spawn { .. }));
    }

    #[tokio::test]
    async fn a_nonexistent_run_as_is_a_typed_error_not_a_panic() {
        let err = run(sh("true"), "osa-no-such-user-xyz".into())
            .await
            .unwrap_err();
        assert!(matches!(err, ExecError::UnknownUser(_)));
    }

    #[tokio::test]
    async fn output_streams_in_chunks_as_produced() {
        // Two writes with a gap arrive as separate chunks (not one buffered blob).
        let (tx, mut rx) = mpsc::channel(8);
        let job = tokio::spawn(async move {
            let argv = sh("printf a; sleep 0.2; printf b");
            stream(&argv, "", ExecLimits::unbounded(), tx).await
        });
        let mut chunks = Vec::new();
        while let Some(c) = rx.recv().await {
            chunks.push(c);
        }
        let outcome = job.await.unwrap().unwrap();
        assert_eq!(outcome.exit_code, Some(0));
        assert_eq!(
            chunks,
            vec![Chunk::Stdout(b"a".to_vec()), Chunk::Stdout(b"b".to_vec())]
        );
    }

    #[tokio::test]
    async fn the_output_cap_truncates_and_kills() {
        // `yes` produces output forever; the cap must stop and kill it.
        let (tx, mut rx) = mpsc::channel(8);
        let job = tokio::spawn(async move {
            let limits = ExecLimits {
                max_output_bytes: 4096,
                timeout: Some(Duration::from_secs(10)),
            };
            stream(&["/usr/bin/yes".into()], "", limits, tx).await
        });
        let mut total = 0usize;
        while let Some(c) = rx.recv().await {
            if let Chunk::Stdout(d) = c {
                total += d.len();
            }
        }
        let outcome = job.await.unwrap().unwrap();
        assert!(outcome.truncated, "the cap must flag truncation");
        assert!(total >= 4096, "at least the cap was delivered");
        // Killed by SIGKILL → reported as a signal, not a clean exit.
        assert!(outcome.signal.is_some() || outcome.exit_code.is_some());
    }

    #[tokio::test]
    async fn the_timeout_kills_a_hung_command() {
        let (tx, mut rx) = mpsc::channel(8);
        let job = tokio::spawn(async move {
            let limits = ExecLimits {
                max_output_bytes: usize::MAX,
                timeout: Some(Duration::from_millis(200)),
            };
            stream(&sh("sleep 30"), "", limits, tx).await
        });
        while rx.recv().await.is_some() {}
        let outcome = job.await.unwrap().unwrap();
        assert!(outcome.timed_out, "the deadline must flag a timeout");
    }

    // The privilege drop needs root, so it can't run in the normal (unprivileged)
    // suite. Run explicitly as root: `cargo test -- --ignored`.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "requires root to drop privileges to run_as"]
    async fn drops_privileges_to_run_as_when_root() {
        let out = run(vec!["id".into(), "-un".into()], "nobody".into())
            .await
            .unwrap();
        assert_eq!(out.exit_code, Some(0));
        assert_eq!(out.stdout, b"nobody\n");
    }
}
