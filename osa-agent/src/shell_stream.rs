/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: MIT
 */

//! Agent side of an interactive shell stream (Epic 4, CAP-3): bridge a PTY
//! ([`crate::pty`]) to the operator over the **sealed `KIND_STREAM` transport**.
//!
//! A `kind = "shell"` dispatch opens one of these. The `Dispatch.job_id` is the
//! **stream_id**: from the live session keys we derive an independent per-stream
//! subkey ([`SessionKeys::derive_stream`]), so the stream owns its own
//! `(key, seq)` nonce space from 0, disjoint from the control channel — the
//! coordinator mints a fresh, never-recycled stream_id per shell, so a subkey is
//! never reused (which would be catastrophic AEAD nonce reuse).
//!
//! Two independent pumps move bytes, each sealing/opening under the stream subkey:
//! - **uplink** (`PtyMaster` read half → sealed `StreamFrame` → `…/up/stream`):
//!   allocates the uplink `seq` monotonically from a single task, and sends one
//!   terminal `eof` frame when the shell exits.
//! - **downlink** (`…/down/stream` → decoded `StreamFrame` → `PtyMaster` write
//!   half): [`route_downlink`] authenticates + replay-guards each frame on the
//!   event loop, then hands the bytes to the write pump.
//!
//! Dropping the `ShellStream` tears the session down **deterministically**: it
//! SIGKILLs the shell's process group (so a backgrounded child cannot keep the PTY
//! slave open) and aborts both pump tasks, then the `PtySession` reaps the direct
//! shell (`kill_on_drop`) — so a disconnect (which drops it) leaves no orphaned
//! foreground shell and no leaked pump task or fd. (A child that re-`setsid`s
//! escapes the group kill — inherent to a detached PTY, as in [`crate::pty`].)
//!
//! The downlink replay guard is a strict monotonic high-water mark, not a reorder
//! buffer: it assumes the single QoS-1 stream topic preserves order (it does), and
//! a full downlink queue drops keystrokes rather than block the event loop.
//!
//! [`route_downlink`]: ShellStream::route_downlink

use std::sync::Arc;

use osa_core::seal::{Direction, SessionKeys};
use osa_core::wire;
use osa_proto::v1::envelope::Kind;
use osa_proto::v1::{Envelope, StreamFrame};
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::pty::{PtyError, PtyMaster, PtySession};

/// Bytes read from the PTY master per uplink frame.
const READ_CHUNK: usize = 8 * 1024;
/// Bound on decoded downlink (keystroke) bytes queued for the PTY write pump.
const DOWNLINK_QUEUE: usize = 256;

/// A live interactive shell stream (agent side): the PTY child (held for reaping)
/// plus the per-stream subkey, downlink replay guard, and the channel feeding the
/// PTY write pump.
pub struct ShellStream {
    /// Held so dropping the stream reaps the shell (`kill_on_drop`); the master was
    /// split out to the pumps.
    pty: PtySession,
    stream_keys: Arc<SessionKeys>,
    /// Highest downlink `seq` accepted (per-stream replay guard); `None` until the
    /// first frame.
    recv_high: Option<u64>,
    /// Decoded operator keystrokes → the PTY write pump.
    downlink_tx: mpsc::Sender<Vec<u8>>,
    /// Pump task handles, aborted on drop so teardown never depends on the PTY
    /// reaching EOF (a backgrounded child could otherwise wedge the uplink read).
    uplink_task: JoinHandle<()>,
    downlink_task: JoinHandle<()>,
}

impl Drop for ShellStream {
    fn drop(&mut self) {
        // Kill the shell's process group so a foreground child cannot keep the PTY
        // slave open, then abort both pumps so they end regardless of any surviving
        // descendant (the `pty` field then reaps the direct shell via kill_on_drop).
        if let Some(pid) = self.pty.id() {
            // SAFETY: kill(2) with a negative pid signals the process group; the
            // shell is its own group leader (setsid).
            unsafe {
                libc::kill(-(pid as i32), libc::SIGKILL);
            }
        }
        self.uplink_task.abort();
        self.downlink_task.abort();
    }
}

impl ShellStream {
    /// Open a shell stream: derive the per-stream subkey from `session_keys` and
    /// `stream_id`, spawn the PTY under `run_as`, and start both pumps. `stream_up`
    /// receives sealed uplink envelope bytes to publish on `…/up/stream`.
    #[allow(clippy::too_many_arguments)]
    pub fn open(
        session_keys: &SessionKeys,
        stream_id: &str,
        run_as: &str,
        rows: u16,
        cols: u16,
        host_id: &str,
        sid: &str,
        stream_up: mpsc::Sender<Vec<u8>>,
    ) -> Result<Self, PtyError> {
        let stream_keys = Arc::new(session_keys.derive_stream(stream_id.as_bytes()));
        let mut pty = PtySession::spawn(run_as, rows, cols)?;
        let (read_half, write_half) = tokio::io::split(pty.take_master());

        let (downlink_tx, downlink_rx) = mpsc::channel::<Vec<u8>>(DOWNLINK_QUEUE);
        let uplink_task = tokio::spawn(uplink_pump(
            read_half,
            Arc::clone(&stream_keys),
            host_id.to_string(),
            sid.to_string(),
            stream_up,
        ));
        let downlink_task = tokio::spawn(downlink_pump(write_half, downlink_rx));

        Ok(Self {
            pty,
            stream_keys,
            recv_high: None,
            downlink_tx,
            uplink_task,
            downlink_task,
        })
    }

    /// Route a sealed downlink `KIND_STREAM` envelope to the PTY. Authenticates and
    /// replay-guards under the stream subkey (a forged/replayed frame is dropped and
    /// never poisons the guard), decodes the [`StreamFrame`], and forwards its bytes
    /// to the PTY. Returns `false` when the stream should be torn down — the
    /// operator sent the terminal `eof` frame.
    pub fn route_downlink(&mut self, env: &Envelope) -> bool {
        let Some(plaintext) = self.open_downlink(env) else {
            // Bad tag or replay/stale seq: drop this frame, keep the stream.
            return true;
        };
        let frame: StreamFrame = match wire::decode(&plaintext) {
            Ok(f) => f,
            Err(_) => return true, // undecodable frame — drop, keep the stream
        };
        if frame.eof {
            return false; // operator closed the stream
        }
        if let Err(e) = self.downlink_tx.try_send(frame.data) {
            // A full queue means the operator is typing faster than the PTY drains;
            // dropping a keystroke burst is far better than blocking the event loop.
            tracing::warn!(error = %e, "shell stream: downlink queue full — dropping input");
        }
        true
    }

    /// Open a sealed downlink envelope under the stream subkey, then advance the
    /// per-stream replay guard — authenticate-before-advance, so a forgery cannot
    /// poison the high-water mark.
    fn open_downlink(&mut self, env: &Envelope) -> Option<Vec<u8>> {
        let plaintext =
            wire::open_envelope(&self.stream_keys, Direction::CoordToAgent, env).ok()?;
        if self.recv_high.is_some_and(|h| env.seq <= h) {
            return None;
        }
        self.recv_high = Some(env.seq);
        Some(plaintext)
    }
}

/// Pump PTY output to the sealed stream uplink: read the master, seal each slice as
/// a `StreamFrame`, and send the encoded envelope bytes to the publisher. Ends on
/// PTY EOF (the shell exited) or when the publisher goes away — emitting a final
/// `eof` frame so the operator sees the shell close. The `seq` is allocated from a
/// single task, so the per-direction nonce is unique by construction.
async fn uplink_pump(
    mut read: ReadHalf<PtyMaster>,
    keys: Arc<SessionKeys>,
    host_id: String,
    sid: String,
    out: mpsc::Sender<Vec<u8>>,
) {
    let mut seq = 0u64;
    let mut buf = vec![0u8; READ_CHUNK];
    loop {
        let n = match read.read(&mut buf).await {
            Ok(0) | Err(_) => break, // EOF (shell exited) or a read error
            Ok(n) => n,
        };
        let bytes = seal_frame(&keys, &host_id, &sid, seq, &buf[..n], false);
        seq += 1;
        if out.send(bytes).await.is_err() {
            return; // publisher gone — no point sending the eof
        }
    }
    // Terminal frame: tell the operator the shell has closed.
    let eof = seal_frame(&keys, &host_id, &sid, seq, &[], true);
    let _ = out.send(eof).await;
}

/// Pump decoded operator keystrokes into the PTY. Ends when the stream is torn down
/// (the sender drops) or the PTY write fails (the shell is gone).
async fn downlink_pump(mut write: WriteHalf<PtyMaster>, mut rx: mpsc::Receiver<Vec<u8>>) {
    while let Some(data) = rx.recv().await {
        if write.write_all(&data).await.is_err() {
            break;
        }
    }
}

/// Seal a `StreamFrame` as a `KIND_STREAM` uplink envelope and encode it for
/// publishing.
fn seal_frame(
    keys: &SessionKeys,
    host_id: &str,
    sid: &str,
    seq: u64,
    data: &[u8],
    eof: bool,
) -> Vec<u8> {
    let frame = StreamFrame {
        data: data.to_vec(),
        eof,
    };
    let env = wire::seal_envelope(
        keys,
        Direction::AgentToCoord,
        host_id,
        sid,
        seq,
        Kind::Stream,
        &wire::encode(&frame),
    );
    wire::encode(&env)
}

#[cfg(test)]
mod tests {
    use super::*;
    use osa_core::seal::Handshake;

    /// A session key pair (agent half, coordinator half) deriving identical keys.
    fn session_pair() -> (SessionKeys, SessionKeys) {
        let a = Handshake::new().unwrap();
        let b = Handshake::new().unwrap();
        let (apub, bpub) = (a.public, b.public);
        (
            a.derive(&bpub, b"bind").unwrap(),
            b.derive(&apub, b"bind").unwrap(),
        )
    }

    /// Seal a downlink `StreamFrame` the way the coordinator would, under the same
    /// per-stream subkey.
    fn coord_downlink(
        coord_stream: &SessionKeys,
        host_id: &str,
        sid: &str,
        seq: u64,
        data: &[u8],
        eof: bool,
    ) -> Envelope {
        let frame = StreamFrame {
            data: data.to_vec(),
            eof,
        };
        wire::seal_envelope(
            coord_stream,
            Direction::CoordToAgent,
            host_id,
            sid,
            seq,
            Kind::Stream,
            &wire::encode(&frame),
        )
    }

    #[tokio::test]
    async fn keystrokes_downlink_reach_the_shell_and_output_comes_back_uplink() {
        let (agent_keys, coord_keys) = session_pair();
        let stream_id = "job-1";
        let (host, sid) = ("h", "s");
        let coord_stream = coord_keys.derive_stream(stream_id.as_bytes());

        let (up_tx, mut up_rx) = mpsc::channel::<Vec<u8>>(64);
        let mut stream =
            ShellStream::open(&agent_keys, stream_id, "", 24, 80, host, sid, up_tx).unwrap();

        // Send a command (and exit) as sealed downlink keystrokes.
        let env = coord_downlink(
            &coord_stream,
            host,
            sid,
            0,
            b"printf 'hello-stream\\n'; exit\n",
            false,
        );
        assert!(stream.route_downlink(&env), "a data frame keeps the stream");

        // Collect uplink frames until the terminal eof, opening each under the
        // coordinator's matching stream subkey.
        let mut output = Vec::new();
        let mut saw_eof = false;
        while let Ok(Some(bytes)) =
            tokio::time::timeout(std::time::Duration::from_secs(10), up_rx.recv()).await
        {
            let env: Envelope = wire::decode(&bytes).unwrap();
            let pt = wire::open_envelope(&coord_stream, Direction::AgentToCoord, &env).unwrap();
            let frame: StreamFrame = wire::decode(&pt).unwrap();
            output.extend_from_slice(&frame.data);
            if frame.eof {
                saw_eof = true;
                break;
            }
        }
        assert!(
            saw_eof,
            "the shell's exit must produce a terminal eof frame"
        );
        assert!(
            String::from_utf8_lossy(&output).contains("hello-stream"),
            "the command output must return over the uplink: {:?}",
            String::from_utf8_lossy(&output)
        );
    }

    #[tokio::test]
    async fn an_eof_downlink_frame_tears_the_stream_down() {
        let (agent_keys, coord_keys) = session_pair();
        let stream_id = "job-2";
        let coord_stream = coord_keys.derive_stream(stream_id.as_bytes());
        let (up_tx, _up_rx) = mpsc::channel::<Vec<u8>>(64);
        let mut stream =
            ShellStream::open(&agent_keys, stream_id, "", 24, 80, "h", "s", up_tx).unwrap();
        let eof = coord_downlink(&coord_stream, "h", "s", 0, &[], true);
        assert!(
            !stream.route_downlink(&eof),
            "an eof frame signals teardown"
        );
    }

    #[tokio::test]
    async fn a_replayed_downlink_seq_is_dropped() {
        let (agent_keys, coord_keys) = session_pair();
        let stream_id = "job-3";
        let coord_stream = coord_keys.derive_stream(stream_id.as_bytes());
        let (up_tx, _up_rx) = mpsc::channel::<Vec<u8>>(64);
        let mut stream =
            ShellStream::open(&agent_keys, stream_id, "", 24, 80, "h", "s", up_tx).unwrap();
        let f = coord_downlink(&coord_stream, "h", "s", 5, b"x", false);
        assert!(stream.route_downlink(&f), "first frame accepted");
        // Same seq again: replay-guarded (dropped), stream stays alive.
        assert!(stream.route_downlink(&f), "replay is dropped, not fatal");
        // A stale (lower) seq is likewise dropped.
        let stale = coord_downlink(&coord_stream, "h", "s", 4, b"y", false);
        assert!(stream.route_downlink(&stale), "stale seq dropped");
    }

    #[tokio::test]
    async fn dropping_the_stream_ends_the_uplink_pump_deterministically() {
        // Even with no PTY EOF (an idle shell blocked on read), dropping the stream
        // must abort the uplink pump — so its sender closes and the receiver sees
        // end-of-stream. This is the leak guard: teardown never waits on the PTY.
        let (agent_keys, _coord) = session_pair();
        let (up_tx, mut up_rx) = mpsc::channel::<Vec<u8>>(64);
        let stream = ShellStream::open(&agent_keys, "job-x", "", 24, 80, "h", "s", up_tx).unwrap();
        drop(stream);
        let ended = tokio::time::timeout(std::time::Duration::from_secs(5), async move {
            while up_rx.recv().await.is_some() {} // drain any buffered frames to close
        })
        .await;
        assert!(
            ended.is_ok(),
            "dropping the stream must end the uplink pump (its sender closes)"
        );
    }

    #[tokio::test]
    async fn a_frame_under_the_wrong_stream_key_does_not_open() {
        let (agent_keys, coord_keys) = session_pair();
        let (up_tx, _up_rx) = mpsc::channel::<Vec<u8>>(64);
        let mut stream =
            ShellStream::open(&agent_keys, "job-4", "", 24, 80, "h", "s", up_tx).unwrap();
        // A frame sealed under a DIFFERENT stream_id's subkey must not open — its
        // bytes never reach the PTY (and the guard is untouched).
        let wrong = coord_keys.derive_stream(b"a-different-stream");
        let env = coord_downlink(&wrong, "h", "s", 0, b"x", false);
        assert!(
            stream.route_downlink(&env),
            "a foreign-key frame is dropped, not fatal"
        );
    }
}
