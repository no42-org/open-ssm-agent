/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: MIT
 */

//! MQTT `ControlChannel` connect loop (AD-3).
//!
//! The agent dials the broker **outbound only** over mTLS, presenting the cert
//! it was issued at enrollment and pinning the CA root it was given. It never
//! listens — the host exposes no inbound port. On disconnect it reconnects with
//! bounded exponential backoff plus per-host jitter (so a fleet does not
//! reconnect in lockstep). On connect it publishes heartbeats (AD-9), opens the
//! authenticated session (#20), and runs sealed `Dispatch`es as spawned jobs that
//! stream sealed results back (Epic 3).

use std::hash::{Hash, Hasher};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context;
use osa_core::allowlist::LocalAllowlist;
use osa_proto::v1::{Dispatch, Envelope};
use rumqttc::{AsyncClient, Event, MqttOptions, Packet, QoS, Transport};
use tokio::sync::{Semaphore, mpsc};
use tokio::time::sleep;

use crate::dispatch::{self, JobChannel};
use crate::jobstore::JobStore;
use crate::session::{AgentIdentity, Established, Handshaking};

/// Bound on undelivered sealed job-result bytes queued for the publisher; the job
/// runner backpressures on `send().await` rather than dropping output.
const RESULT_QUEUE: usize = 256;
/// Cap on concurrently-running dispatched jobs (and thus child processes) per
/// agent. A compromised coordinator could otherwise stream distinct-seq dispatches
/// to fork-bomb the host; the backstop gates kind/run_as, this gates count (AD-20).
const MAX_CONCURRENT_JOBS: usize = 16;

const BACKOFF_BASE: Duration = Duration::from_millis(500);
const BACKOFF_MAX: Duration = Duration::from_secs(30);
const KEEP_ALIVE: Duration = Duration::from_secs(30);
/// How often the agent publishes a liveness heartbeat (AD-9).
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(15);
/// A session must stay up at least this long before its disconnect resets the
/// backoff — otherwise a connection that flaps right after connecting would
/// reconnect in a tight loop.
const STABLE_RESET: Duration = Duration::from_secs(30);

/// Enrolled identity material (PEM) for the mTLS handshake.
struct TlsIdentity {
    ca_pem: Vec<u8>,
    cert_pem: Vec<u8>,
    key_pem: Vec<u8>,
}

fn load_identity(state_dir: &Path) -> anyhow::Result<TlsIdentity> {
    let read = |name: &str| -> anyhow::Result<Vec<u8>> {
        std::fs::read(state_dir.join(name)).with_context(|| {
            format!(
                "reading {name} from {} (is the host enrolled?)",
                state_dir.display()
            )
        })
    };
    Ok(TlsIdentity {
        ca_pem: read("ca.crt")?,
        cert_pem: read("host.crt")?,
        key_pem: read("host.key")?,
    })
}

fn read_host_id(state_dir: &Path) -> anyhow::Result<String> {
    Ok(std::fs::read_to_string(state_dir.join("host_id"))?
        .trim()
        .to_string())
}

fn stable_seed(host_id: &str) -> u64 {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    host_id.hash(&mut h);
    h.finish()
}

/// Reconnect delay: exponential from `BACKOFF_BASE` capped at `BACKOFF_MAX`, then
/// jittered into `[50%, 100%)` of that value using a stable per-host seed.
fn backoff(attempt: u32, seed: u64) -> Duration {
    let base_ms = BACKOFF_BASE.as_millis() as u64;
    let max_ms = BACKOFF_MAX.as_millis() as u64;
    let factor = 1u64.checked_shl(attempt.min(20)).unwrap_or(u64::MAX);
    let capped = base_ms.saturating_mul(factor).min(max_ms).max(base_ms);
    let mut h = std::collections::hash_map::DefaultHasher::new();
    (seed, attempt).hash(&mut h);
    let frac = h.finish() % 1000; // 0..=999
    Duration::from_millis(capped / 2 + (capped / 2) * frac / 1000)
}

/// Run the control channel forever: connect over mTLS, drive the event loop, and
/// reconnect with backoff on any failure. Returns only on an unrecoverable setup
/// error (e.g. missing identity).
pub async fn run(
    state_dir: &Path,
    broker_host: &str,
    broker_port: u16,
    backstop: Arc<LocalAllowlist>,
) -> anyhow::Result<()> {
    // Fail fast if the host is not enrolled; the host_id is stable.
    let host_id = read_host_id(state_dir)?;
    load_identity(state_dir)?;
    let seed = stable_seed(&host_id);
    let heartbeat_topic = osa_core::topics::heartbeat(&host_id);
    // Caps concurrent jobs across the agent's whole lifetime (survives reconnects).
    let job_permits = Arc::new(Semaphore::new(MAX_CONCURRENT_JOBS));
    // Durable, job_id-keyed state for crash-recoverable idempotent redelivery (3.3),
    // plus the in-memory in-flight guard against concurrent redelivery.
    let jobs = Arc::new(JobStore::new(state_dir).context("opening the job store")?);
    let inflight = dispatch::new_inflight();
    tracing::info!(%host_id, broker = %format!("{broker_host}:{broker_port}"), "control channel: dialing broker (mTLS, outbound-only)");

    let mut attempt = 0u32;
    let mut ever_connected = false;
    loop {
        // Re-read the identity each reconnect so a cert renewed on disk
        // (renewal_loop) is adopted on the next connection.
        let identity = load_identity(state_dir)?;
        let mut opts = MqttOptions::new(host_id.clone(), broker_host, broker_port);
        opts.set_keep_alive(KEEP_ALIVE);
        opts.set_transport(Transport::tls(
            identity.ca_pem,
            Some((identity.cert_pem, identity.key_pem)),
            None,
        ));
        let (client, mut eventloop) = AsyncClient::new(opts, 16);
        let mut heartbeat = tokio::time::interval(HEARTBEAT_INTERVAL);
        // Liveness semantics: after a stall, send one heartbeat, not a catch-up burst.
        heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        // Re-load the identity for the session handshake each connection so a cert
        // renewed on disk is adopted (#20). A load failure here is unexpected (the
        // mTLS identity above already loaded), so back off and retry.
        let agent_id = match AgentIdentity::load(state_dir) {
            Ok(id) => id,
            Err(e) => {
                tracing::error!(error = %e, "control channel: cannot load identity for handshake");
                let wait = backoff(attempt, seed);
                attempt = attempt.saturating_add(1);
                sleep(wait).await;
                continue;
            }
        };
        let topics = SessionTopics::for_host(&host_id);
        let mut handshaking: Option<Handshaking> = None;
        let mut session: Option<Established> = None;
        // Job tasks seal results and hand the bytes to a dedicated publisher task,
        // so a long/high-output job never blocks the event loop and backpressures
        // instead of dropping output. The publisher ends when this connection's
        // sender and all job clones drop.
        let (results_tx, results_rx) = mpsc::channel::<Vec<u8>>(RESULT_QUEUE);
        tokio::spawn(publish_results(
            client.clone(),
            results_rx,
            topics.result_up.clone(),
        ));

        let mut connected_at: Option<Instant> = None;
        loop {
            tokio::select! {
                // Drain the network first; a heartbeat tick only fires when the
                // eventloop is otherwise idle. `EventLoop::poll` retains its state
                // across calls, so dropping a pending poll here is safe.
                biased;
                event = eventloop.poll() => match event {
                    Ok(Event::Incoming(Packet::ConnAck(_))) => {
                        connected_at = Some(Instant::now());
                        ever_connected = true;
                        tracing::info!(%host_id, "control channel: connected");
                        publish_heartbeat(&client, &heartbeat_topic);
                        // Open an authenticated session as soon as we connect (#20).
                        handshaking = begin_handshake(&client, &agent_id, &topics);
                    }
                    Ok(Event::Incoming(Packet::Publish(p))) => {
                        on_publish(
                            &p.topic,
                            &p.payload,
                            &client,
                            &agent_id,
                            &backstop,
                            &jobs,
                            &inflight,
                            &job_permits,
                            &results_tx,
                            &topics,
                            &mut handshaking,
                            &mut session,
                        );
                    }
                    Ok(_) => {}
                    Err(e) => {
                        tracing::warn!(error = %e, "control channel: disconnected");
                        break;
                    }
                },
                _ = heartbeat.tick() => {
                    if connected_at.is_some() {
                        publish_heartbeat(&client, &heartbeat_topic);
                    }
                }
            }
        }

        // Reset backoff only after a *stable* session, so a connection that flaps
        // right after ConnAck still backs off instead of reconnecting in a storm.
        if connected_at.is_some_and(|t| t.elapsed() >= STABLE_RESET) {
            attempt = 0;
        }
        let wait = backoff(attempt, seed);
        attempt = attempt.saturating_add(1);
        if !ever_connected && attempt >= 5 {
            tracing::error!(
                attempt,
                "control channel: still not connected — check enrollment, broker reachability, and the host cert"
            );
        }
        tracing::info!(
            ?wait,
            attempt,
            "control channel: reconnecting after backoff"
        );
        sleep(wait).await;
    }
}

/// Publish a liveness heartbeat. The payload is empty — presence is the signal;
/// the AD-27 AEAD seal lands in a later story.
///
/// Non-blocking on purpose: `publish().await` would stall the eventloop if the
/// request channel filled (only `poll()` drains it), so a full channel could
/// deadlock the connection. A dropped heartbeat is harmless — the next one is
/// 15 s away.
fn publish_heartbeat(client: &AsyncClient, topic: &str) {
    if let Err(e) = client.try_publish(topic, QoS::AtMostOnce, false, Vec::new()) {
        tracing::warn!(error = %e, "heartbeat publish skipped");
    }
}

/// The per-host session topics (#20), computed once per connection.
struct SessionTopics {
    hs_up: String,
    hs_down: String,
    ctrl_up: String,
    ctrl_down: String,
    dispatch_down: String,
    result_up: String,
}

impl SessionTopics {
    fn for_host(host_id: &str) -> Self {
        Self {
            hs_up: osa_core::topics::hs_up(host_id),
            hs_down: osa_core::topics::hs_down(host_id),
            ctrl_up: osa_core::topics::ctrl_up(host_id),
            ctrl_down: osa_core::topics::ctrl_down(host_id),
            dispatch_down: osa_core::topics::dispatch_down(host_id),
            result_up: osa_core::topics::result_up(host_id),
        }
    }
}

/// Subscribe to the downlinks and publish a fresh `ClientHello` to start an
/// authenticated session (#20). Subscribes *before* publishing so the
/// `ServerHello`/beacon cannot be missed. Returns the in-flight state, or `None`
/// if it could not be started (logged). Non-blocking (`try_*`) so the eventloop
/// never stalls; a dropped start is retried on the next reconnect.
fn begin_handshake(
    client: &AsyncClient,
    id: &AgentIdentity,
    topics: &SessionTopics,
) -> Option<Handshaking> {
    if let Err(e) = client.try_subscribe(topics.hs_down.clone(), QoS::AtLeastOnce) {
        tracing::warn!(error = %e, "control channel: subscribing handshake downlink failed");
        return None;
    }
    if let Err(e) = client.try_subscribe(topics.ctrl_down.clone(), QoS::AtLeastOnce) {
        tracing::warn!(error = %e, "control channel: subscribing control downlink failed");
        return None;
    }
    if let Err(e) = client.try_subscribe(topics.dispatch_down.clone(), QoS::AtLeastOnce) {
        tracing::warn!(error = %e, "control channel: subscribing dispatch downlink failed");
        return None;
    }
    let (hs, hello) = match crate::session::start_handshake(id) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(error = %e, "control channel: building ClientHello failed");
            return None;
        }
    };
    if let Err(e) = client.try_publish(topics.hs_up.clone(), QoS::AtLeastOnce, false, hello) {
        tracing::warn!(error = %e, "control channel: publishing ClientHello failed");
        return None;
    }
    tracing::info!("control channel: session handshake started (#20)");
    Some(hs)
}

/// Route an incoming Publish: a `ServerHello` finishes the handshake; the sealed
/// session-ready beacon is opened and acked (#20); a sealed `Dispatch` is opened
/// and run as a spawned job streaming sealed results (Epic 3).
#[allow(clippy::too_many_arguments)]
fn on_publish(
    topic: &str,
    payload: &[u8],
    client: &AsyncClient,
    id: &AgentIdentity,
    backstop: &Arc<LocalAllowlist>,
    jobs: &Arc<JobStore>,
    inflight: &dispatch::InFlight,
    job_permits: &Arc<Semaphore>,
    results: &mpsc::Sender<Vec<u8>>,
    topics: &SessionTopics,
    handshaking: &mut Option<Handshaking>,
    session: &mut Option<Established>,
) {
    if topic == topics.hs_down {
        let Some(hs) = handshaking.take() else {
            tracing::warn!("control channel: ServerHello with no handshake in flight — ignoring");
            return;
        };
        match crate::session::finish_handshake(hs, id, payload) {
            Ok(est) => {
                *session = Some(est);
                tracing::info!("control channel: session established (#20)");
            }
            Err(e) => tracing::warn!(error = %e, "control channel: ServerHello rejected"),
        }
    } else if topic == topics.ctrl_down {
        let Some(est) = session.as_mut() else {
            tracing::warn!("control channel: sealed control before a session — ignoring");
            return;
        };
        match crate::session::confirm_session(est, id, payload) {
            Ok(ack) => {
                if let Err(e) =
                    client.try_publish(topics.ctrl_up.clone(), QoS::AtLeastOnce, false, ack)
                {
                    tracing::warn!(error = %e, "control channel: publishing session ack failed");
                } else {
                    tracing::info!(
                        "control channel: session-open confirmed (E2E sealed channel live, #20)"
                    );
                }
            }
            Err(e) => tracing::warn!(error = %e, "control channel: session beacon rejected"),
        }
    } else if topic == topics.dispatch_down {
        let Some(est) = session.as_mut() else {
            tracing::warn!("control channel: dispatch before a session — ignoring");
            return;
        };
        handle_dispatch(
            est,
            id,
            backstop,
            jobs,
            inflight,
            job_permits,
            results,
            payload,
        );
    }
}

/// Drain sealed job-result bytes and publish them on the result uplink with
/// backpressure (`publish().await`), so output is delivered rather than dropped.
/// Ends when the connection's sender and all job clones drop, or on a publish
/// error (e.g. the link went away).
async fn publish_results(client: AsyncClient, mut rx: mpsc::Receiver<Vec<u8>>, topic: String) {
    while let Some(bytes) = rx.recv().await {
        if let Err(e) = client
            .publish(topic.clone(), QoS::AtLeastOnce, false, bytes)
            .await
        {
            tracing::warn!(error = %e, "control channel: result publish failed — stopping publisher");
            break;
        }
    }
}

/// Open a sealed `Dispatch` against the live session and spawn it as a job that
/// streams sealed results. Rejects a replayed/stale downlink `seq` (anti
/// double-execution) before opening. Spawned so a long command never blocks the
/// event loop.
#[allow(clippy::too_many_arguments)]
fn handle_dispatch(
    est: &mut Established,
    id: &AgentIdentity,
    backstop: &Arc<LocalAllowlist>,
    jobs: &Arc<JobStore>,
    inflight: &dispatch::InFlight,
    job_permits: &Arc<Semaphore>,
    results: &mpsc::Sender<Vec<u8>>,
    payload: &[u8],
) {
    let env: Envelope = match osa_core::wire::decode(payload) {
        Ok(e) => e,
        Err(e) => {
            tracing::warn!(error = %e, "control channel: malformed dispatch envelope — dropping");
            return;
        }
    };
    // Authenticate first, then enforce the replay guard (open_downlink): a forged
    // envelope can neither be acted on nor poison the replay high-water mark.
    let Some(plaintext) = est.open_downlink(&env) else {
        tracing::warn!(
            seq = env.seq,
            "control channel: dispatch did not open or was replayed — dropping"
        );
        return;
    };
    let dispatch: Dispatch = match osa_core::wire::decode(&plaintext) {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!(error = %e, "control channel: undecodable dispatch — dropping");
            return;
        }
    };
    // Bound concurrent jobs/children. Shed (don't queue) at capacity so a
    // compromised coordinator cannot fork-bomb the host; a legitimate operator
    // sees a timeout and can retry.
    let Ok(permit) = Arc::clone(job_permits).try_acquire_owned() else {
        tracing::warn!(job_id = %dispatch.job_id, "control channel: at job capacity — shedding dispatch");
        return;
    };
    tracing::info!(job_id = %dispatch.job_id, kind = %dispatch.kind, "control channel: dispatch received");
    let channel = JobChannel {
        results: results.clone(),
        keys: est.keys(),
        send_seq: est.send_seq(),
        host_id: id.host_id.clone(),
        sid: est.sid().to_string(),
    };
    let backstop = Arc::clone(backstop);
    let jobs = Arc::clone(jobs);
    let inflight = Arc::clone(inflight);
    tokio::spawn(async move {
        let _permit = permit; // held for the job's life; frees a slot on completion
        dispatch::run_job(dispatch, backstop, jobs, inflight, channel).await;
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_is_bounded_and_grows() {
        let seed = stable_seed("a-host");
        for attempt in 0..25 {
            let b = backoff(attempt, seed);
            assert!(b <= BACKOFF_MAX, "never exceeds max");
            assert!(b >= BACKOFF_BASE / 2, "at least half the base");
        }
        // Large attempts saturate near the cap.
        assert!(backoff(20, seed) >= BACKOFF_MAX / 2);
    }

    #[test]
    fn jitter_decorrelates_hosts() {
        // Two different hosts get different delays for the same attempt.
        let a = backoff(8, stable_seed("host-a"));
        let b = backoff(8, stable_seed("host-b"));
        assert_ne!(a, b);
    }
}
