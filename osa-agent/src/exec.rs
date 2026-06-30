/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: MIT
 */

//! The exec `JobCapability` adapter (AD-13·Job, AD-14): run a command under a
//! target user and capture its output and terminal status.
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
//! Privilege drop is **fail-closed by platform**: it is implemented only where we
//! can also drop supplementary groups (Linux/Android, the AD-1 target). On any
//! other target a non-empty `run_as` returns [`ExecError::PrivDropUnsupported`]
//! rather than running with the agent's groups retained.
//!
//! # Deferred to the dispatch story (3.2)
//! Output is captured **buffered with no size cap** and there is **no execution
//! timeout** — a runaway command can grow agent memory or pin a blocking thread.
//! Incremental streaming over the sealed channel, an output byte-cap, a job
//! timeout/cancel, and process-group isolation (`setsid`) are designed together
//! in 3.2; this engine intentionally does none of them yet. The local
//! `osa-agent exec` driver is operator-invoked, so the uncapped path is not
//! attacker-reachable until dispatch wiring (3.2) lands with those bounds.
//!
//! # Testing the privilege drop
//! The actual setuid/setgid path needs root, so it is covered by a `#[cfg(linux)]
//! #[ignore]` test (`cargo test -- --ignored`, run as root); the unprivileged
//! tests cover the no-drop and every failure path.

use std::os::unix::process::ExitStatusExt;

use nix::unistd::User;

/// The `action.kind` this capability answers to.
pub const KIND: &str = "exec";

/// The terminal result of an exec job: how it ended plus the captured streams.
#[derive(Debug)]
pub struct ExecOutcome {
    /// Process exit code, or `None` if it was terminated by a signal.
    pub exit_code: Option<i32>,
    /// Terminating signal number, if any.
    pub signal: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// Why an exec job could not produce a terminal status. Distinct from a process
/// that ran and exited non-zero (that is a successful [`ExecOutcome`]).
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
    #[error("dropping privileges to a run_as user is only supported on Linux")]
    PrivDropUnsupported,
    #[error("spawning {program:?} failed: {source}")]
    Spawn {
        program: String,
        source: std::io::Error,
    },
    #[error("exec task did not complete: {0}")]
    Join(String),
}

/// Run `argv` (program + args) as `run_as`, capturing stdout/stderr and the
/// terminal status. An empty `run_as` runs as the agent's own user (no privilege
/// change). The blocking spawn/wait runs on a blocking thread so it never stalls
/// the async runtime.
pub async fn run(argv: Vec<String>, run_as: String) -> Result<ExecOutcome, ExecError> {
    if argv.is_empty() {
        return Err(ExecError::EmptyArgv);
    }
    tokio::task::spawn_blocking(move || run_blocking(&argv, &run_as))
        .await
        .map_err(|e| ExecError::Join(e.to_string()))?
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

fn run_blocking(argv: &[String], run_as: &str) -> Result<ExecOutcome, ExecError> {
    let mut cmd = std::process::Command::new(&argv[0]);
    cmd.args(&argv[1..]);
    if let Some(user) = resolve_user(run_as)? {
        apply_target_user(&mut cmd, &user)?;
    }
    // `output()` spawns, captures both streams, and waits. A missing binary or a
    // failed privilege drop surfaces here as an Err — never a panic.
    let output = cmd.output().map_err(|e| ExecError::Spawn {
        program: argv[0].clone(),
        source: e,
    })?;
    Ok(ExecOutcome {
        exit_code: output.status.code(),
        signal: output.status.signal(),
        stdout: output.stdout,
        stderr: output.stderr,
    })
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

    #[tokio::test]
    async fn captures_stdout_stderr_and_exit_code() {
        let out = run(
            vec![
                "/bin/sh".into(),
                "-c".into(),
                "printf out; printf err 1>&2; exit 3".into(),
            ],
            String::new(),
        )
        .await
        .unwrap();
        assert_eq!(out.stdout, b"out");
        assert_eq!(out.stderr, b"err");
        assert_eq!(out.exit_code, Some(3));
        assert_eq!(out.signal, None);
    }

    #[tokio::test]
    async fn a_successful_command_exits_zero() {
        let out = run(
            vec!["/bin/sh".into(), "-c".into(), "true".into()],
            String::new(),
        )
        .await
        .unwrap();
        assert_eq!(out.exit_code, Some(0));
    }

    #[tokio::test]
    async fn termination_by_signal_is_reported() {
        // The shell kills itself with SIGTERM → no exit code, signal 15.
        let out = run(
            vec!["/bin/sh".into(), "-c".into(), "kill -TERM $$".into()],
            String::new(),
        )
        .await
        .unwrap();
        assert_eq!(out.exit_code, None);
        assert_eq!(out.signal, Some(15));
    }

    #[tokio::test]
    async fn empty_argv_is_a_typed_error() {
        assert!(matches!(
            run(vec![], String::new()).await,
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
        let err = run(
            vec!["/bin/sh".into(), "-c".into(), "true".into()],
            "osa-no-such-user-xyz".into(),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, ExecError::UnknownUser(_)));
    }

    // The privilege drop needs root, so it can't run in the normal (unprivileged)
    // suite. Run explicitly as root: `cargo test -- --ignored`.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "requires root to drop privileges to run_as"]
    async fn drops_privileges_to_run_as_when_root() {
        // `id -un` run as `nobody` must report `nobody` — proving the setuid drop
        // actually took effect (not just that the command ran).
        let out = run(vec!["id".into(), "-un".into()], "nobody".into())
            .await
            .unwrap();
        assert_eq!(out.exit_code, Some(0));
        assert_eq!(out.stdout, b"nobody\n");
    }
}
