# Pre-review edge checklist

A first implementation almost always nails the happy path. Across Epics 2–4 the
3-layer adversarial review then caught a **durability, concurrency, or security
edge** in essentially every substantive story — the same class of miss, three
epics running (see the epic retros). This checklist exists to move those catches
**earlier**: run it against your own diff *before* the review, so the review
finds less and what it finds is rarer.

**How to use:** walk every item that touches your change. Each is phrased as a
question with the real, merged regression that motivates it. If the answer is
"not sure," that's a finding — fix it or write the test that proves it. This is
not a substitute for the review; it is the floor beneath it.

---

## 1. Fail closed, never fail open

On a missing / corrupt / unparsable input, does the code **deny** rather than
proceed with a permissive default? Audit every `unwrap_or`, `.ok()`,
`unwrap_or_default`, and silent fallback on the security or correctness path.

- *4.3a:* `next_epoch` used `unwrap_or(0)` on a corrupt epoch file — regressing
  the monotonic high-water to 0, the **exact resurrection the feature prevents**,
  plus a multi-reconnect self-DoS. A present-but-unparsable value must error, not
  reset. (A *missing* file legitimately starting from 0 is different from a
  *corrupt* one — distinguish `NotFound` from parse failure.)
- *JobStore:* a corrupt "done" record is treated as *interrupted* (re-run guard
  stays armed), never as "already done."

## 2. Durable writes (fsync discipline)

A durable write is `temp → write → fsync(file) → rename → fsync(parent dir)`. Is
the **parent directory** fsynced (not just the file)? Is the read side fail-closed
on a partial/corrupt file (§1)?

- *3.3:* `write_durably` missed the parent-dir fsync — a lost "started" marker
  after a crash re-executes a side-effecting command, defeating the at-most-once
  guarantee the story exists to provide.
- *4.3a:* the dir-fsync error was swallowed with `let _` — advertising crash
  safety we hadn't achieved. Propagate it.
- There are now three copies of this dance (`jobstore::write_durably`,
  `enroll::write_atomic`, `session::next_epoch`) — prefer the shared helper so a
  fix lands once.

## 3. Atomicity / TOCTOU

Any **read → decide → write** sequence: is it atomic against a concurrent task,
and against another replica? Prefer a single atomic operation (conditional
`UPDATE`/`UPSERT ... WHERE`, compare-and-swap, an in-flight claim guard) over a
separate check and set.

- *4.3b:* the first design read `highest()` then `record()` — two coordinators
  could both pass the read for the same fresh epoch and both admit it. Fixed with
  one conditional-UPSERT `admit` (mirrors the atomic join-token redeem).
- *3.3:* a `lookup → mark_started` TOCTOU let a job double-run; fixed with an
  in-flight `Claim` guard.
- "It's safe because the loop is single-task" is only true until the work moves
  off that task — say so in a comment if you rely on it.

## 4. AEAD nonce uniqueness

Is every `(key, nonce/seq)` pair used **at most once**? A recycled id under a
per-key subkey is catastrophic nonce reuse, not a cosmetic bug.

- *4.2:* a recycled `stream_id` under the per-stream HKDF subkey would reuse the
  AES-GCM nonce space — the coordinator mints a **fresh, never-recycled** UUID per
  stream. Per-direction `seq` is strictly monotonic, allocated atomically.

## 5. Bounded channels & back-pressure

Does a bounded-channel send distinguish **Full** (shed / abort the producer) from
**Closed** (peer gone)? Can a blocking send **deadlock** when the consumer is gone
or lagging? Are queues **capped and swept** so they can't grow without bound?

- *3.2b:* `try_send` conflated `Full` with `Closed` → silent output truncation;
  plus an unbounded `PendingJobs` leak. Fixed with distinct match arms,
  abort-on-Full, and a TTL sweep + cap + reconnect purge.
- *3.4:* the fan-out loop did a blocking send into a bounded channel with no
  consumer past N denied hosts → **deadlock**, invisible to a happy-path smoke.

## 6. Resource lifecycle (FDs, children, teardown)

Are file descriptors that must not survive `exec`/`fork` marked `FD_CLOEXEC`? Is
every child process / PTY **reaped on session end AND on peer disconnect** (no
orphan)? Are pumps/streams torn down when the far side closes?

- *4.1 (High):* the PTY master FD leaked across `exec` into the **unprivileged**
  child — a privilege-separation hole. Fixed with `FD_CLOEXEC` on the master.
- *4.2:* an operator disconnect left a pump/fd/orphan leak; the eof-both-ways
  teardown + `ShellClose` reaps it. (A SIGKILL'd agent runs no teardown — an
  inherent detached-PTY caveat, documented, not silently ignored.)

## 7. Partial-failure isolation (fan-out / loops)

In a fan-out or batch loop, does one item's error abort the **whole** operation?
Prefer per-item error events; the batch continues and reports per item.

- *3.4:* a per-host `?` aborted the entire RPC after partial execution. Fixed by
  spawning the loop and emitting per-host error events.

## 8. Replay & ordering (authenticate before advancing state)

Do you **authenticate first, then advance** any replay high-water / sequence
guard? A forged or unopenable message must not be able to poison shared state.
Is a non-increasing `seq` per direction rejected?

- *Epic 3 handshake/session:* the AEAD open (authentication) runs **before** the
  replay high-water is advanced — a forged envelope a broker injects can't wedge
  the channel by poisoning the mark.

## 9. Blocking in async

Is there a blocking read / syscall in an async task that can stall shutdown or the
event loop? Does the PTY / pipe drain to **EOF** rather than a bounded read?

- *4.2c:* a blocking stdin read hung process exit → raw-mode-first + explicit
  `std::process::exit`.
- *4.1:* a PTY read/drain deadlock — must drain to EOF, not `read_until`.

## 10. Cross-target / platform

Does `cfg(target_os = "...")` code compile **and lint** on the target, not just
the host? Are platform-specific syscalls guarded?

- Recurred twice (4.1 `cfg(linux)` clippy; earlier a dead `cfg` variant): host
  clippy on macOS skips Linux-gated code. Run **`make lint-linux`** (or
  `make verify-ci`) before pushing — it clippy-checks the Linux code in a
  container.
