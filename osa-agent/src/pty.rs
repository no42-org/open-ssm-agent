/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: MIT
 */

//! The interactive-shell `StreamCapability` (AD-13·Stream, FR3): spawn a
//! PTY-backed shell under a target user, **isolated** from the agent, and stream
//! its terminal I/O.
//!
//! This is the agent-side engine for `kind = "shell"`. It opens a pseudo-terminal,
//! spawns the target user's login shell attached to the PTY slave, and hands back
//! the PTY master as an async byte stream ([`PtyMaster`]: `AsyncRead` +
//! `AsyncWrite`). Wiring it to the operator over the sealed stream channel — plus
//! window-resize and Ctrl-C handling — is story 4.2; this module is the local
//! engine + a local driver (`osa-agent shell`), as the exec engine landed before
//! its dispatch.
//!
//! **Isolation.** The child runs in its own session ([`setsid`]) with the PTY slave
//! as its controlling terminal (`TIOCSCTTY`), so it is detached from the agent's
//! process group and a signal to the shell (or its job-control children) never
//! reaches the agent. Privileges are dropped exactly as in [`crate::exec`]
//! (setgid → setgroups → setuid, before exec, env cleared), fail-closed by
//! platform: a non-empty `run_as` off Linux/Android returns
//! [`PtyError::Unsupported`] rather than running with the agent's groups.
//!
//! **Reaping.** The child is spawned `kill_on_drop`, and [`PtySession::shutdown`]
//! kills the shell's process group and reaps it, so a gracefully closed session
//! leaves no orphaned foreground child and no zombie. (A `SIGKILL`ed agent runs no
//! teardown; the PTY hangup is then the only reaper — see [`PtySession::shutdown`].)
//! Reading the master after the shell exits surfaces as a clean EOF (the kernel
//! reports `EIO` on a hung-up PTY master; we map it to end-of-stream).
//!
//! # Testing the privilege drop
//! The setuid/setgid path needs root, so it is a `#[cfg(linux)] #[ignore]` test
//! (`cargo test -- --ignored`, run as root); the unprivileged tests cover the
//! no-drop spawn, the echo round-trip, EOF, reaping, and the typed errors.

use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::pin::Pin;
use std::process::Stdio;
use std::task::{Context, Poll};

use nix::pty::{OpenptyResult, Winsize, openpty};
use nix::unistd::User;
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// The `action.kind` this capability answers to.
pub const KIND: &str = "shell";

/// Why an interactive shell could not be started (distinct from a shell that ran
/// and exited — that is a normal outcome). Never a panic.
#[derive(Debug, thiserror::Error)]
pub enum PtyError {
    /// The `run_as` name was not found. Resolution is by **name** (getpwnam).
    #[error("run_as user {0:?} does not exist")]
    UnknownUser(String),
    #[error("looking up run_as user {user:?} failed: {source}")]
    UserLookup { user: String, source: io::Error },
    /// A non-empty `run_as` was requested on a platform where we cannot fully drop
    /// privileges (no `setgroups`). Fail closed rather than retain root's groups.
    /// Only exists off the supported targets, where the fail-closed path builds it.
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    #[error("a PTY shell under a run_as user is only supported on Linux")]
    Unsupported,
    #[error("opening a pty failed: {0}")]
    OpenPty(io::Error),
    #[error("preparing the pty master failed: {0}")]
    Master(io::Error),
    #[error("spawning the shell {program:?} failed: {source}")]
    Spawn { program: String, source: io::Error },
}

/// A running PTY-backed shell: the async master stream plus the child handle.
pub struct PtySession {
    /// `take`-n by the driver to split into read/write halves; always `Some` until
    /// then.
    master: Option<PtyMaster>,
    child: tokio::process::Child,
}

impl PtySession {
    /// Open a PTY of `rows`×`cols` and spawn `run_as`'s login shell attached to it
    /// (the agent's own shell when `run_as` is empty). The child is isolated
    /// (`setsid` + controlling-tty) and privilege-dropped to `run_as`.
    pub fn spawn(run_as: &str, rows: u16, cols: u16) -> Result<Self, PtyError> {
        let user = resolve_user(run_as)?;
        // Resolve the privilege-drop target first so an unsupported platform fails
        // BEFORE we open a PTY or fork.
        let drop_to = target_drop(&user)?;

        let size = Winsize {
            ws_row: rows,
            ws_col: cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        let OpenptyResult { master, slave } =
            openpty(Some(&size), None).map_err(|e| PtyError::OpenPty(e.into()))?;
        // The master must NOT leak across exec into the (unprivileged) shell: it is
        // the agent's sole handle to the terminal, and a stray inherited copy would
        // also defeat EOF detection (a backgrounded grandchild holding it open keeps
        // the master readable forever). `openpty` does not set close-on-exec.
        nix::fcntl::fcntl(
            master.as_raw_fd(),
            nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::FD_CLOEXEC),
        )
        .map_err(|e| PtyError::OpenPty(e.into()))?;

        let shell = user
            .as_ref()
            .map(|u| u.shell.clone())
            .unwrap_or_else(|| std::path::PathBuf::from("/bin/sh"));
        let program = shell.to_string_lossy().into_owned();

        let mut cmd = std::process::Command::new(&shell);
        // The slave is the child's stdin/stdout/stderr (three independent dups; the
        // child owns them, the agent keeps only the master).
        let dup = |label| {
            slave
                .try_clone()
                .map_err(|e| PtyError::Spawn {
                    program: program.clone(),
                    source: io::Error::new(e.kind(), format!("dup pty slave for {label}: {e}")),
                })
                .map(Stdio::from)
        };
        cmd.stdin(dup("stdin")?)
            .stdout(dup("stdout")?)
            .stderr(dup("stderr")?);

        // A minimal, cleared environment for a dropped user (no agent secrets /
        // `LD_*`); keep `TERM` so the shell behaves as a terminal either way.
        match &user {
            Some(u) => {
                cmd.env_clear()
                    .env("PATH", "/usr/local/bin:/usr/bin:/bin")
                    .env("HOME", &u.dir)
                    .env("USER", &u.name)
                    .env("LOGNAME", &u.name)
                    .env("SHELL", &u.shell)
                    .env("TERM", "xterm");
            }
            None => {
                cmd.env("TERM", "xterm");
            }
        }

        // Drop the agent's own slave handle before spawning: the child receives the
        // slave only through the three stdio dups (which std sets up across exec), so
        // the shell never inherits a stray extra slave fd. Once only the child holds
        // the slave, the master reads EOF when the shell exits.
        drop(slave);

        // SAFETY: the closure runs in the forked child before exec and calls only
        // async-signal-safe syscalls. Order is load-bearing: detach into a new
        // session, claim the slave (now fd 0) as the controlling terminal, THEN
        // drop privileges (setgid → setgroups → setuid) while still privileged
        // enough to do so. Any error aborts the exec, so the shell never runs
        // half-isolated or half-dropped.
        unsafe {
            cmd.pre_exec(move || {
                nix::unistd::setsid().map_err(io::Error::from)?;
                // fd 0 is the slave; arg 0 = don't steal another session's tty.
                if libc::ioctl(0, libc::TIOCSCTTY as _, 0 as libc::c_int) < 0 {
                    return Err(io::Error::last_os_error());
                }
                if let Some((uid, gid)) = drop_to {
                    drop_privileges_in_child(uid, gid)?;
                }
                Ok(())
            });
        }

        let child = tokio::process::Command::from(cmd)
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| PtyError::Spawn {
                program: program.clone(),
                source: e,
            })?;

        let master = PtyMaster::new(master).map_err(PtyError::Master)?;
        Ok(Self {
            master: Some(master),
            child,
        })
    }

    /// Take the master stream to split into read/write halves (the driver does this
    /// once). Panics if already taken.
    pub fn take_master(&mut self) -> PtyMaster {
        self.master.take().expect("master already taken")
    }

    /// The child's pid, if it has not been reaped.
    pub fn id(&self) -> Option<u32> {
        self.child.id()
    }

    /// Wait for the shell to exit (reaping it).
    pub async fn wait(&mut self) -> io::Result<std::process::ExitStatus> {
        self.child.wait().await
    }

    /// Kill the shell's **process group** and reap it — deterministic teardown that
    /// tears down the shell's foreground children too, not just the shell, leaving no
    /// orphaned foreground process and no zombie. Best-effort signal (the child may
    /// have already exited), then reap. `kill_on_drop` is the backstop for a session
    /// dropped without calling this.
    ///
    /// A `SIGKILL`ed agent runs no teardown at all; the PTY hangup (`SIGHUP` when the
    /// master closes) is then the only reaper, so a child that re-`setsid`s or traps
    /// `SIGHUP` can still escape — inherent to a deliberately detached PTY session.
    pub async fn shutdown(mut self) -> io::Result<()> {
        if let Some(pid) = self.child.id() {
            // The shell is its own process-group leader (`setsid`), so signalling the
            // group (`-pid`) also kills its foreground children.
            // SAFETY: a plain kill(2) with a negative pid (the group) and SIGKILL.
            unsafe {
                libc::kill(-(pid as i32), libc::SIGKILL);
            }
        }
        let _ = self.child.start_kill(); // backstop for the shell process itself
        self.child.wait().await?;
        Ok(())
    }
}

/// The PTY master end, async over tokio's [`AsyncFd`]. `AsyncRead` + `AsyncWrite`,
/// so it composes with [`tokio::io::split`] / [`tokio::io::copy`]; a read returns
/// `Ok(0)` (clean EOF) once the shell has closed the slave.
pub struct PtyMaster {
    fd: AsyncFd<OwnedFd>,
}

impl PtyMaster {
    fn new(master: OwnedFd) -> io::Result<Self> {
        // Non-blocking, so AsyncFd drives readiness rather than blocking the runtime.
        use nix::fcntl::{FcntlArg, OFlag, fcntl};
        let flags = OFlag::from_bits_truncate(fcntl(master.as_raw_fd(), FcntlArg::F_GETFL)?);
        fcntl(
            master.as_raw_fd(),
            FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK),
        )?;
        Ok(Self {
            fd: AsyncFd::new(master)?,
        })
    }
}

impl AsyncRead for PtyMaster {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            let mut guard = match this.fd.poll_read_ready(cx) {
                Poll::Ready(Ok(g)) => g,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            };
            let unfilled = buf.initialize_unfilled();
            let res = guard.try_io(|inner| {
                // SAFETY: `unfilled` is a valid writable buffer of `len` bytes.
                let n = unsafe {
                    libc::read(
                        inner.get_ref().as_raw_fd(),
                        unfilled.as_mut_ptr().cast(),
                        unfilled.len(),
                    )
                };
                if n >= 0 {
                    Ok(n as usize)
                } else {
                    let e = io::Error::last_os_error();
                    // A hung-up PTY master reports EIO once the slave (the shell) is
                    // gone — treat it as a clean end-of-stream, not an error.
                    if e.raw_os_error() == Some(libc::EIO) {
                        Ok(0)
                    } else {
                        Err(e)
                    }
                }
            });
            match res {
                Ok(Ok(n)) => {
                    buf.advance(n);
                    return Poll::Ready(Ok(()));
                }
                Ok(Err(e)) => return Poll::Ready(Err(e)),
                Err(_would_block) => continue,
            }
        }
    }
}

impl AsyncWrite for PtyMaster {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        loop {
            let mut guard = match this.fd.poll_write_ready(cx) {
                Poll::Ready(Ok(g)) => g,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            };
            let res = guard.try_io(|inner| {
                // SAFETY: `buf` is a valid readable buffer of `len` bytes.
                let n = unsafe {
                    libc::write(inner.get_ref().as_raw_fd(), buf.as_ptr().cast(), buf.len())
                };
                if n >= 0 {
                    Ok(n as usize)
                } else {
                    Err(io::Error::last_os_error())
                }
            });
            match res {
                Ok(result) => return Poll::Ready(result),
                Err(_would_block) => continue,
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(())) // a PTY write is delivered to the line discipline directly
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// The target user to run as, or `None` to keep the agent's own credentials.
/// Resolution is by name (getpwnam); a numeric uid string is not resolved.
fn resolve_user(run_as: &str) -> Result<Option<User>, PtyError> {
    if run_as.is_empty() {
        return Ok(None);
    }
    match User::from_name(run_as) {
        Ok(Some(u)) => Ok(Some(u)),
        Ok(None) => Err(PtyError::UnknownUser(run_as.to_string())),
        Err(e) => Err(PtyError::UserLookup {
            user: run_as.to_string(),
            source: io::Error::from(e),
        }),
    }
}

/// The (uid, gid) to drop to, or `None` for the agent's own identity. Implemented
/// only where supplementary groups can also be dropped (Linux/Android); elsewhere
/// a non-empty `run_as` fails closed.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn target_drop(
    user: &Option<User>,
) -> Result<Option<(nix::unistd::Uid, nix::unistd::Gid)>, PtyError> {
    Ok(user.as_ref().map(|u| (u.uid, u.gid)))
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn target_drop(
    user: &Option<User>,
) -> Result<Option<(nix::unistd::Uid, nix::unistd::Gid)>, PtyError> {
    if user.is_some() {
        Err(PtyError::Unsupported)
    } else {
        Ok(None)
    }
}

/// Drop to `(uid, gid)` in the forked child: setgid → setgroups → setuid, in that
/// order — drop the group and supplementary groups while still privileged, then the
/// uid last. Async-signal-safe. Only reachable where [`target_drop`] yields `Some`
/// (Linux/Android), since `setgroups` (the supplementary-group drop) is gated off
/// other targets.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn drop_privileges_in_child(uid: nix::unistd::Uid, gid: nix::unistd::Gid) -> io::Result<()> {
    nix::unistd::setgid(gid)?;
    nix::unistd::setgroups(&[gid])?;
    nix::unistd::setuid(uid)?;
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn drop_privileges_in_child(_uid: nix::unistd::Uid, _gid: nix::unistd::Gid) -> io::Result<()> {
    // Unreachable: off Linux/Android `target_drop` returns `None` for the default
    // identity and `Err(Unsupported)` for a real user, so no `Some` reaches here.
    unreachable!("privilege drop is unsupported on this platform")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Drain the master to EOF, returning all bytes. Draining (rather than stopping
    /// at a marker) keeps the slave's output buffer from filling — otherwise the
    /// shell would block on write and never reach its `exit`, deadlocking the test.
    /// A timeout converts a genuine hang into a fast failure rather than blocking CI.
    async fn read_to_eof(master: &mut PtyMaster) -> Vec<u8> {
        let mut buf = Vec::new();
        let mut tmp = [0u8; 1024];
        loop {
            let n = tokio::time::timeout(std::time::Duration::from_secs(10), master.read(&mut tmp))
                .await
                .expect("pty read timed out")
                .expect("pty read");
            if n == 0 {
                break; // EOF: the shell exited and closed the slave
            }
            buf.extend_from_slice(&tmp[..n]);
        }
        buf
    }

    /// Read until a `prefix<digits>\n` line appears, returning the parsed pid. The
    /// shell blocks on its next *read* after emitting this small line (it is not
    /// blocked writing), so pausing here does not deadlock the PTY. Bounded by a
    /// timeout so a failure is fast, not a hang. Only the Linux process-group test
    /// uses it.
    #[cfg(target_os = "linux")]
    async fn read_marked_pid(master: &mut PtyMaster, prefix: &str) -> Option<i32> {
        let mut buf = Vec::new();
        let mut tmp = [0u8; 256];
        loop {
            let n = tokio::time::timeout(std::time::Duration::from_secs(5), master.read(&mut tmp))
                .await
                .ok()?
                .ok()?;
            if n == 0 {
                return None;
            }
            buf.extend_from_slice(&tmp[..n]);
            let s = String::from_utf8_lossy(&buf);
            // Scan every `prefix` occurrence, not just the first: the line discipline
            // echoes our input (`CHILD=$!`) back before the command's output
            // (`CHILD=<pid>`) arrives, and only the latter parses to a number.
            for (idx, _) in s.match_indices(prefix) {
                let rest = &s[idx + prefix.len()..];
                if let Some(nl) = rest.find('\n')
                    && let Ok(pid) = rest[..nl].trim().parse::<i32>()
                {
                    return Some(pid);
                }
            }
        }
    }

    #[tokio::test]
    async fn a_pty_shell_runs_a_command_and_streams_output() {
        let mut session = PtySession::spawn("", 24, 80).expect("spawn pty shell");
        let mut master = session.take_master();
        // One line: run a command, then exit — so the shell terminates
        // deterministically and the master reaches EOF.
        master
            .write_all(b"printf 'hello-pty\\n'; exit\n")
            .await
            .unwrap();
        let out = read_to_eof(&mut master).await;
        assert!(
            String::from_utf8_lossy(&out).contains("hello-pty"),
            "pty output did not contain the marker: {:?}",
            String::from_utf8_lossy(&out)
        );
        let status = session.wait().await.unwrap();
        assert_eq!(status.code(), Some(0));
    }

    #[tokio::test]
    async fn reading_the_master_returns_eof_after_the_shell_exits() {
        let mut session = PtySession::spawn("", 24, 80).unwrap();
        let mut master = session.take_master();
        master.write_all(b"exit 0\n").await.unwrap();
        // Drain to EOF — the hung-up master (EIO) must surface as Ok(0), not an error.
        let mut sink = [0u8; 1024];
        loop {
            let n = master
                .read(&mut sink)
                .await
                .expect("read must not error on hangup");
            if n == 0 {
                break;
            }
        }
        let status = session.wait().await.unwrap();
        assert_eq!(status.code(), Some(0));
    }

    #[tokio::test]
    async fn shutdown_reaps_the_child_with_no_orphan() {
        let session = PtySession::spawn("", 24, 80).unwrap();
        let pid = session.id().expect("a spawned child has a pid") as i32;
        session.shutdown().await.unwrap();
        // A reaped pid is fully gone: kill(pid, 0) fails ESRCH. A *zombie* (not
        // reaped) would still return 0 here, so this proves no orphan/zombie.
        let rc = unsafe { libc::kill(pid, 0) };
        assert_eq!(rc, -1);
        assert_eq!(
            io::Error::last_os_error().raw_os_error(),
            Some(libc::ESRCH),
            "the shell child must be reaped, not left as an orphan or zombie"
        );
    }

    // The shell's background job shares the shell's process group only where job
    // control is off for a non-interactive shell (Linux/AD-1 target); macOS's
    // `/bin/sh` puts it in its own group, so the group-kill assertion is
    // Linux-specific. CI (ubuntu) exercises it; it needs no root.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn shutdown_kills_the_shells_child_processes() {
        let mut session = PtySession::spawn("", 24, 80).unwrap();
        let mut master = session.take_master();
        // Start a long-lived child in the shell's (job-control-off) process group and
        // report its pid.
        master
            .write_all(b"sleep 300 & echo CHILD=$!\n")
            .await
            .unwrap();
        let child_pid = read_marked_pid(&mut master, "CHILD=")
            .await
            .expect("the shell must report the background child's pid");
        // Tearing the session down signals the whole process group, so the child dies
        // with the shell rather than being orphaned.
        session.shutdown().await.unwrap();
        // Give the group signal a moment to be delivered/reaped by init.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let rc = unsafe { libc::kill(child_pid, 0) };
        assert_eq!(rc, -1);
        assert_eq!(
            io::Error::last_os_error().raw_os_error(),
            Some(libc::ESRCH),
            "the shell's child must be killed with the process group, not orphaned"
        );
    }

    #[tokio::test]
    async fn an_unknown_run_as_is_a_typed_error_not_a_panic() {
        // Name resolution runs on every platform before the privilege-drop gate, so
        // an unknown user is always a typed `UnknownUser` (never a panic).
        assert!(matches!(
            PtySession::spawn("osa-no-such-user-xyz", 24, 80),
            Err(PtyError::UnknownUser(_))
        ));
    }

    // The privilege drop needs root, so it can't run in the normal (unprivileged)
    // suite. Run explicitly as root: `cargo test -- --ignored`.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "requires root to drop privileges to run_as"]
    async fn drops_privileges_in_the_pty_shell_when_root() {
        let mut session = PtySession::spawn("nobody", 24, 80).unwrap();
        let mut master = session.take_master();
        master.write_all(b"id -un; id -Gn; exit\n").await.unwrap();
        let out = read_to_eof(&mut master).await;
        let s = String::from_utf8_lossy(&out);
        assert!(s.contains("nobody"), "shell did not run as nobody: {s:?}");
        // setgroups(&[gid]) dropped the agent's (root's) supplementary groups — a
        // retained one would show root's group in `id -Gn`. This is what proves the
        // supplementary-group drop, which the uid alone does not.
        assert!(
            !s.contains("root"),
            "supplementary groups were not dropped (root still present): {s:?}"
        );
        let _ = session.wait().await;
    }
}
