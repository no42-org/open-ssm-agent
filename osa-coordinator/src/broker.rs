/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: MIT
 */

//! Embedded MQTT broker (`rumqttd`) with mTLS (AD-3, AD-27).
//!
//! For v1 (tens of hosts) the broker embeds in the coordinator. It requires
//! client certificates (mTLS): an agent presents the cert it was issued at
//! enrollment, and the broker's own server cert is signed by the same embedded
//! CA so an agent that pinned the CA root trusts it.
//!
//! Per-host topic isolation (AD-31, issue #16) **is enforced**: the
//! `validate-tenant-prefix` feature confines each client to the `/tenants/<O>/…`
//! subtree derived from its cert's Organization field (= the host_id), so a
//! compromised host cert can neither publish nor subscribe to another host's
//! topics. The coordinator's in-process bridge link presents no cert and is
//! exempt, so it can still observe `/tenants/+/…` across hosts.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context;
use osa_core::HostId;
use osa_core::topics::{
    CTRL_UP_FILTER, HEARTBEAT_FILTER, HS_UP_FILTER, RESULT_UP_FILTER, tenant_from_ctrl_up,
    tenant_from_heartbeat, tenant_from_hs_up, tenant_from_result_up,
};
use osa_proto::v1::job_outcome::Terminal;
use osa_proto::v1::job_result::Body;
use osa_proto::v1::{ClientHello, Dispatch, Envelope, JobOutcome, JobResult, ServerHello};
use rumqttd::local::{LinkRx, LinkTx};
use rumqttd::{
    Broker, Config, ConnectionSettings, Notification, RouterConfig, ServerSettings, TlsConfig,
};
use tokio::sync::mpsc::{self, Sender, channel, error::TrySendError};
use uuid::Uuid;

use crate::ca::EmbeddedCa;
use crate::revocation::Revocations;
use crate::session::SessionStore;

/// A result destined for an operator's stream, tagged with the host it came from
/// (so a fan-out across a selector can interleave per-host results, 3.4).
pub type HostResult = (HostId, JobResult);

/// A command to the bridge from the operator-facing gRPC service. The service
/// never touches the broker or session keys directly.
pub enum BridgeCommand {
    /// Seal `dispatch` to `host_id`'s live session and stream its `JobResult`s
    /// (output chunks, then one terminal outcome) back over `events`, tagged with
    /// `host_id`. The bridge reports a terminal error outcome if the host has no
    /// live session. Many `Dispatch`es may share one `events` channel (fan-out).
    Dispatch {
        host_id: HostId,
        dispatch: Dispatch,
        events: mpsc::Sender<HostResult>,
    },
    /// Reply with the hosts that currently have a live session — the resolution of
    /// the `*` selector for fan-out (3.4).
    OnlineHosts {
        reply: tokio::sync::oneshot::Sender<Vec<HostId>>,
    },
}

/// One in-flight dispatched job: the operator's (tagged) result-stream sender plus
/// a deadline after which it is reaped (so an agent that dies mid-job, or a job
/// that never sends a terminal outcome, cannot leak the entry forever).
struct PendingJob {
    events: mpsc::Sender<HostResult>,
    deadline: Instant,
}

/// In-flight dispatched jobs, keyed by (host, job_id). An entry is removed on the
/// job's terminal outcome, when its operator stream goes away, on a host reconnect
/// (the old session's jobs can never complete), or by the stale-job sweep.
type PendingJobs = HashMap<(HostId, String), PendingJob>;

/// Cap on concurrently-pending dispatched jobs, so a flood of dispatches (or dead
/// hosts) cannot grow the map without bound.
const MAX_PENDING_JOBS: usize = 4096;
/// A pending job with no terminal outcome by this age is reaped (with an error to
/// the operator). Comfortably exceeds the agent's per-job timeout (300 s).
const PENDING_TTL: Duration = Duration::from_secs(600);
/// How often the bridge sweeps for stale pending jobs.
const PENDING_SWEEP: Duration = Duration::from_secs(60);

/// A host is considered to have come back online if its previous heartbeat was
/// older than this (so transient gaps do not spam "online" logs).
const ONLINE_AFTER_GAP: Duration = Duration::from_secs(90);
/// Cap on tracked hosts, so the last-seen map cannot grow without bound from host
/// churn. A host can only publish under its own tenant now (#16), so a single
/// cert can no longer inflate the map with foreign host_ids.
const MAX_TRACKED_HOSTS: usize = 50_000;
/// Bound on the bridge's in-flight message queue. The blocking receive thread
/// sheds load (drops messages) when the async bridge falls behind, so a host
/// flooding its own `…/up/hs` cannot grow the queue without bound (memory DoS).
/// Shed messages are recoverable: agents re-handshake on the next reconnect.
const BRIDGE_QUEUE: usize = 1024;

/// File names the broker reads its TLS material from, written under the cert dir.
pub const BROKER_CERT: &str = "broker.crt";
pub const BROKER_KEY: &str = "broker.key";
pub const CA_CERT: &str = "ca.crt";

/// Spawn the embedded broker listening on `addr` with mTLS, plus the coordinator
/// **bridge**: an in-process, tenant-exempt link that observes heartbeats and
/// drives the authenticated session handshake (#20). The cert/key/CA PEM files
/// must already exist in `cert_dir`.
///
/// The broker run loop and the blocking link receive both run on dedicated OS
/// threads; received messages are forwarded to an async bridge task (spawned on
/// the current Tokio runtime) that can `await` the revocation store and publish
/// `ServerHello`s. Returns once the threads/task are spawned.
pub fn spawn(
    addr: SocketAddr,
    cert_dir: &Path,
    ca: Arc<EmbeddedCa>,
    revocations: Arc<dyn Revocations>,
    commands: mpsc::Receiver<BridgeCommand>,
) -> anyhow::Result<()> {
    let path = |name: &str| cert_dir.join(name).to_string_lossy().into_owned();

    let server = ServerSettings {
        name: "osa-mqtts".to_string(),
        listen: addr,
        tls: Some(TlsConfig::Rustls {
            // `capath` set ⇒ the broker requires and verifies client certs (mTLS).
            capath: Some(path(CA_CERT)),
            certpath: path(BROKER_CERT),
            keypath: path(BROKER_KEY),
        }),
        next_connection_delay_ms: 10,
        connections: ConnectionSettings {
            connection_timeout_ms: 60_000,
            max_payload_size: 1_048_576,
            max_inflight_count: 500,
            auth: None,
            external_auth: None,
            dynamic_filters: false,
        },
    };

    let config = Config {
        id: 0,
        router: RouterConfig {
            max_connections: 10_010,
            max_outgoing_packet_count: 200,
            max_segment_size: 104_857_600,
            max_segment_count: 10,
            custom_segment: None,
            initialized_filters: None,
            shared_subscriptions_strategy: Default::default(),
        },
        v4: Some(HashMap::from([("v4-1".to_string(), server)])),
        ..Default::default()
    };

    // `Broker::new` spawns the router immediately, so the in-process bridge link
    // can be created now (before `start()`). It presents no cert and is therefore
    // tenant-exempt: it observes `/tenants/+/…` across hosts and publishes into
    // any host's downlink — no second TLS client or bridge cert needed.
    let mut broker = Broker::new(config);
    let (mut link_tx, link_rx) = broker
        .link("osa-coordinator-bridge")
        .context("creating broker bridge link")?;
    for filter in [
        HEARTBEAT_FILTER,
        HS_UP_FILTER,
        CTRL_UP_FILTER,
        RESULT_UP_FILTER,
    ] {
        link_tx
            .subscribe(filter)
            .with_context(|| format!("subscribing bridge to {filter}"))?;
    }

    std::thread::Builder::new()
        .name("osa-broker".to_string())
        .spawn(move || {
            if let Err(e) = broker.start() {
                tracing::error!(error = %e, "embedded broker exited");
            }
        })
        .context("spawning broker thread")?;

    // The link receive is blocking, so it runs on its own thread and forwards each
    // message to the async bridge task (which can await the revocation store) over
    // a BOUNDED channel — the thread sheds load rather than letting a flood grow
    // memory without bound.
    let (evt_tx, evt_rx) = channel::<(String, Vec<u8>)>(BRIDGE_QUEUE);
    std::thread::Builder::new()
        .name("osa-bridge-recv".to_string())
        .spawn(move || forward_events(link_rx, evt_tx))
        .context("spawning bridge receive thread")?;
    tokio::spawn(run_bridge(evt_rx, commands, link_tx, ca, revocations));
    Ok(())
}

/// Blocking receive loop: forward every published message `(topic, payload)` to
/// the async bridge over a bounded channel. When the bridge falls behind, the
/// queue fills and messages are **dropped** (load-shed, logged periodically)
/// rather than buffered without bound. Stops if the broker link errors or the
/// bridge task is gone.
fn forward_events(mut rx: LinkRx, tx: Sender<(String, Vec<u8>)>) {
    let mut shed: u64 = 0;
    loop {
        match rx.recv() {
            Ok(Some(Notification::Forward(fwd))) => {
                let topic = String::from_utf8_lossy(&fwd.publish.topic).into_owned();
                let payload = fwd.publish.payload.to_vec();
                match tx.try_send((topic, payload)) {
                    Ok(()) => {}
                    Err(TrySendError::Full(_)) => {
                        shed += 1;
                        if shed.is_power_of_two() {
                            tracing::warn!(
                                shed,
                                "broker bridge overloaded — shedding messages (agents will re-handshake)"
                            );
                        }
                    }
                    Err(TrySendError::Closed(_)) => break, // bridge task gone
                }
            }
            Ok(_) => {}
            Err(e) => {
                tracing::error!(error = %e, "broker bridge receive stopped");
                break;
            }
        }
    }
}

/// The async bridge: route each forwarded message by topic — heartbeats (AD-9),
/// `ClientHello`s (start a session, #20), and sealed control acks (confirm a
/// session is live). Owns `link_tx` (to publish `ServerHello`s + the sealed
/// beacon) and the per-host [`SessionStore`].
///
/// Messages are processed serially. With the in-memory revocation store the
/// per-`ClientHello` `await` is instant; once revocation is Postgres-backed a
/// slow lookup would stall this single loop, so the per-hello verify+revocation
/// work should move off the loop (a task per hello, sharing `link_tx`) when the
/// dispatch path lands (slice 2 / Epic 3).
async fn run_bridge(
    mut rx: mpsc::Receiver<(String, Vec<u8>)>,
    mut commands: mpsc::Receiver<BridgeCommand>,
    mut link_tx: LinkTx,
    ca: Arc<EmbeddedCa>,
    revocations: Arc<dyn Revocations>,
) {
    let mut sessions = SessionStore::new();
    let mut last_seen: HashMap<String, Instant> = HashMap::new();
    let mut pending: PendingJobs = HashMap::new();
    let mut commands_open = true;
    let mut sweep = tokio::time::interval(PENDING_SWEEP);
    sweep.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            msg = rx.recv() => {
                let Some((topic, payload)) = msg else { break };
                // The broker confines each host to its own tenant subtree, so a
                // message on `/tenants/<t>/…` can only have come from the host whose
                // cert O = <t> — the publisher is broker-authenticated (issue #16).
                if let Some(tenant) = tenant_from_heartbeat(&topic) {
                    if record_heartbeat(&mut last_seen, tenant, Instant::now(), MAX_TRACKED_HOSTS) {
                        tracing::info!(%tenant, "host online (heartbeat)");
                    }
                } else if let Some(tenant) = tenant_from_hs_up(&topic) {
                    if let Some(host) = handle_client_hello(
                        tenant, &payload, &ca, revocations.as_ref(), &mut sessions, &mut link_tx,
                    )
                    .await
                    {
                        // A (re)established session means any prior jobs for this
                        // host belong to a dead session — fail them, don't leak.
                        purge_host_jobs(&mut pending, host);
                    }
                } else if tenant_from_ctrl_up(&topic).is_some() {
                    handle_ctrl_ack(&payload, &mut sessions);
                } else if let Some(tenant) = tenant_from_result_up(&topic) {
                    handle_result(tenant, &payload, &mut sessions, &mut pending);
                }
            }
            cmd = commands.recv(), if commands_open => match cmd {
                Some(cmd) => handle_command(cmd, &mut sessions, &mut pending, &mut link_tx),
                None => commands_open = false, // service gone; keep serving the broker
            },
            _ = sweep.tick() => reap_stale_jobs(&mut pending),
        }
    }
    tracing::warn!("coordinator bridge stopped");
}

/// Handle a `ClientHello` (#20): verify the agent cert (chain + validity +
/// tenant-binding + revocation), run the authenticated handshake, publish the
/// `ServerHello`, seal the session-ready beacon, and record the session. Returns
/// the established `HostId` on success (so the caller can purge that host's stale
/// jobs), or `None` if the handshake was dropped (an untrusted broker can feed
/// garbage — every failure drops silently).
async fn handle_client_hello(
    tenant: &str,
    payload: &[u8],
    ca: &EmbeddedCa,
    revocations: &dyn Revocations,
    sessions: &mut SessionStore,
    link_tx: &mut LinkTx,
) -> Option<HostId> {
    let hello: ClientHello = match osa_core::wire::decode(payload) {
        Ok(h) => h,
        Err(e) => {
            tracing::warn!(error = %e, "dropping malformed ClientHello");
            return None;
        }
    };
    let client_eph: [u8; 32] = match <[u8; 32]>::try_from(hello.client_eph.as_slice()) {
        Ok(a) => a,
        Err(_) => {
            tracing::warn!("ClientHello ephemeral is not 32 bytes — dropping");
            return None;
        }
    };
    // Sanity-bound the agent-chosen sid (it becomes the cleartext envelope sid and
    // an AAD field). The agent owns sid freshness; the coordinator only guards
    // against an empty or absurdly large value.
    if hello.sid.is_empty() || hello.sid.len() > 128 {
        tracing::warn!("ClientHello sid is empty or too long — dropping");
        return None;
    }
    // Chain + validity. The cert is the agent's claimed identity.
    let verified = match ca.verify_host_cert(&hello.cert_der) {
        Ok(v) => v,
        Err(e) => {
            tracing::info!(error = %e, "rejecting ClientHello: cert did not verify");
            return None;
        }
    };
    // Tenant binding: the broker-authenticated tenant (the topic) MUST equal the
    // cert identity, so a host cannot present another host's cert in its hello.
    let host_str = verified.host_id.0.to_string();
    if osa_core::topics::tenant(&host_str) != tenant {
        tracing::warn!(%tenant, host = %host_str, "ClientHello cert/tenant mismatch — dropping");
        return None;
    }
    // Replay guard: a ClientHello whose sid already matches this host's live
    // session is a replay (a genuine reconnect mints a fresh sid). Drop it before
    // doing key agreement, so an untrusted broker cannot replay a captured hello
    // to overwrite — and desync — an established session.
    if sessions
        .get(&verified.host_id)
        .is_some_and(|s| s.sid == hello.sid)
    {
        tracing::warn!(host = %host_str, "duplicate ClientHello sid — replay, dropping");
        return None;
    }
    // Revocation (defense in depth, AD-28). Fail closed: no session on store error.
    match revocations.is_revoked(verified.host_id).await {
        Ok(false) => {}
        Ok(true) => {
            tracing::info!(host = %host_str, "rejecting ClientHello: identity revoked");
            return None;
        }
        Err(e) => {
            tracing::error!(error = %e, "revocation check failed — refusing session");
            return None;
        }
    }
    let resp = match ca.respond_handshake(
        hello.sid.as_bytes(),
        &client_eph,
        &hello.sig,
        &verified.public_key_sec1,
        &hello.cert_der,
    ) {
        Ok(r) => r,
        Err(e) => {
            tracing::info!(error = %e, host = %host_str, "rejecting ClientHello: handshake failed");
            return None;
        }
    };
    // Reserve (store) the session BEFORE emitting anything the agent treats as
    // established, so a store-at-capacity refusal cannot leave the agent with a
    // live session the coordinator never tracked.
    if !sessions.insert(verified.host_id, hello.sid.clone(), resp.keys) {
        tracing::warn!(host = %host_str, "session store at capacity — refusing session");
        return None;
    }
    // ServerHello (cleartext, signature-authenticated) on the handshake downlink.
    let server_hello = ServerHello {
        sid: hello.sid.clone(),
        server_eph: resp.server_eph.to_vec(),
        sig: resp.sig,
    };
    if let Err(e) = link_tx.publish(
        osa_core::topics::hs_down(&host_str),
        osa_core::wire::encode(&server_hello),
    ) {
        tracing::warn!(error = %e, host = %host_str, "publishing ServerHello failed");
        return None;
    }
    // The first sealed payload: a session-ready beacon on the control downlink
    // (seq 0 from the session's downlink allocator), proving key agreement.
    let session = sessions
        .get_mut(&verified.host_id)
        .expect("session was just inserted");
    let beacon = session.seal_downlink(&host_str, osa_core::wire::CTRL_SESSION_READY);
    if let Err(e) = link_tx.publish(osa_core::topics::ctrl_down(&host_str), beacon) {
        tracing::warn!(error = %e, host = %host_str, "publishing session-ready beacon failed");
    }
    tracing::info!(host = %host_str, "session established (authenticated handshake, #20)");
    Some(verified.host_id)
}

/// Handle a sealed control ack on the uplink (#20): open it against the host's
/// session keys (authenticating before advancing the replay guard). A successful
/// open with the expected payload proves the agent derived matching keys.
fn handle_ctrl_ack(payload: &[u8], sessions: &mut SessionStore) {
    let env: Envelope = match osa_core::wire::decode(payload) {
        Ok(e) => e,
        Err(e) => {
            tracing::warn!(error = %e, "dropping malformed control envelope");
            return;
        }
    };
    let host_id = match env.host_id.parse::<Uuid>().map(HostId) {
        Ok(h) => h,
        Err(_) => {
            tracing::warn!("control envelope host_id is not a UUID — dropping");
            return;
        }
    };
    let Some(session) = sessions.get_mut(&host_id) else {
        tracing::warn!(host = %host_id.0, "control ack for an unknown session — dropping");
        return;
    };
    if session.sid != env.sid {
        tracing::warn!(host = %host_id.0, "control ack sid mismatch — dropping");
        return;
    }
    match session.open_uplink(&env) {
        Some(pt) if pt == osa_core::wire::CTRL_SESSION_ACK => {
            tracing::info!(host = %host_id.0, "session-open confirmed by agent (E2E sealed channel live, #20)");
        }
        Some(_) => tracing::warn!(host = %host_id.0, "unexpected sealed control payload"),
        None => {
            tracing::warn!(host = %host_id.0, "session-open ack failed to open or was replayed")
        }
    }
}

/// Handle a `BridgeCommand` (Epic 3): seal a dispatch to a host's live session and
/// register the operator's result stream. Reports a terminal error outcome if the
/// host is offline or the publish fails — the operator is never left hanging.
fn handle_command(
    cmd: BridgeCommand,
    sessions: &mut SessionStore,
    pending: &mut PendingJobs,
    link_tx: &mut LinkTx,
) {
    let (host_id, dispatch, events) = match cmd {
        BridgeCommand::Dispatch {
            host_id,
            dispatch,
            events,
        } => (host_id, dispatch, events),
        BridgeCommand::OnlineHosts { reply } => {
            let _ = reply.send(sessions.host_ids());
            return;
        }
    };
    let job_id = dispatch.job_id.clone();
    let key = (host_id, job_id.clone());
    // A job_id collision would orphan the first operator's stream; refuse it.
    if pending.contains_key(&key) {
        let _ = events.try_send((host_id, error_result(&job_id, "duplicate job_id")));
        return;
    }
    if pending.len() >= MAX_PENDING_JOBS {
        let _ = events.try_send((
            host_id,
            error_result(&job_id, "coordinator at job capacity"),
        ));
        return;
    }
    let host_str = host_id.0.to_string();
    let Some(session) = sessions.get_mut(&host_id) else {
        let _ = events.try_send((host_id, error_result(&job_id, "host is not connected")));
        return;
    };
    let sealed = session.seal_downlink(&host_str, &osa_core::wire::encode(&dispatch));
    if let Err(e) = link_tx.publish(osa_core::topics::dispatch_down(&host_str), sealed) {
        tracing::warn!(error = %e, host = %host_str, %job_id, "publishing dispatch failed");
        let _ = events.try_send((host_id, error_result(&job_id, "failed to reach the host")));
        return;
    }
    pending.insert(
        key,
        PendingJob {
            events,
            deadline: Instant::now() + PENDING_TTL,
        },
    );
    tracing::info!(host = %host_str, %job_id, kind = %dispatch.kind, "dispatched to agent");
}

/// Handle a sealed `JobResult` on the result uplink (Epic 3): open it against the
/// host's session keys and route it to the waiting operator's stream by job_id. On
/// the terminal outcome, the job is forgotten (which closes the operator stream).
fn handle_result(
    tenant: &str,
    payload: &[u8],
    sessions: &mut SessionStore,
    pending: &mut PendingJobs,
) {
    let Ok(host_id) = Uuid::parse_str(tenant).map(HostId) else {
        tracing::warn!(%tenant, "result tenant is not a UUID — dropping");
        return;
    };
    let env: Envelope = match osa_core::wire::decode(payload) {
        Ok(e) => e,
        Err(e) => {
            tracing::warn!(error = %e, "dropping malformed result envelope");
            return;
        }
    };
    let Some(session) = sessions.get_mut(&host_id) else {
        return; // a result for a host with no live session
    };
    let Some(plaintext) = session.open_uplink(&env) else {
        return; // bad tag or replay/stale seq
    };
    let result: JobResult = match osa_core::wire::decode(&plaintext) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, host = %host_id.0, "dropping undecodable JobResult");
            return;
        }
    };
    let key = (host_id, result.job_id.clone());
    let Some(job) = pending.get(&key) else {
        tracing::debug!(host = %host_id.0, job_id = %key.1, "result for an unknown/finished job — dropping");
        return;
    };
    let terminal = matches!(result.body, Some(Body::Outcome(_)));
    match job.events.try_send((host_id, result)) {
        Ok(()) => {
            if terminal {
                pending.remove(&key); // closes the operator stream
            }
        }
        Err(TrySendError::Closed(_)) => {
            pending.remove(&key); // operator disconnected; forget the job
        }
        Err(TrySendError::Full(_)) => {
            // The operator cannot keep up. Rather than silently corrupt its output
            // (a missing chunk) or buffer without bound, abort the job: drop it so
            // its stream ends, and the operator reports an incomplete run.
            tracing::warn!(host = %host_id.0, job_id = %key.1, "operator result stream full — aborting job");
            pending.remove(&key);
        }
    }
}

/// Fail and forget every pending job for `host` — used when the host reconnects
/// (its old session's jobs can never produce a result against the new keys).
fn purge_host_jobs(pending: &mut PendingJobs, host: HostId) {
    pending.retain(|(h, job_id), job| {
        if *h == host {
            let _ = job.events.try_send((
                host,
                error_result(job_id, "host reconnected; job interrupted"),
            ));
            false
        } else {
            true
        }
    });
}

/// Reap pending jobs past their deadline (an agent that died or never sent a
/// terminal outcome), failing each so the operator is not left hanging.
fn reap_stale_jobs(pending: &mut PendingJobs) {
    let now = Instant::now();
    pending.retain(|(host, job_id), job| {
        if now >= job.deadline {
            let _ = job.events.try_send((
                *host,
                error_result(job_id, "no result from host (timed out)"),
            ));
            false
        } else {
            true
        }
    });
}

/// A terminal `JobResult` carrying a capability/transport error for the operator.
fn error_result(job_id: &str, msg: &str) -> JobResult {
    JobResult {
        job_id: job_id.to_string(),
        body: Some(Body::Outcome(JobOutcome {
            terminal: Some(Terminal::Error(msg.to_string())),
            output_truncated: false,
            timed_out: false,
        })),
    }
}

/// Record a heartbeat and return whether it is a new "online" transition (first
/// sight, or returning after `ONLINE_AFTER_GAP`). Prunes stale entries and caps
/// the map at `cap` so it cannot grow without bound.
fn record_heartbeat(
    last_seen: &mut HashMap<String, Instant>,
    host_id: &str,
    now: Instant,
    cap: usize,
) -> bool {
    // Forget hosts not seen within the online window — they are offline, and
    // pruning them bounds the map to roughly the active fleet.
    last_seen.retain(|_, t| now.saturating_duration_since(*t) <= ONLINE_AFTER_GAP);
    if last_seen.contains_key(host_id) {
        last_seen.insert(host_id.to_string(), now);
        false
    } else if last_seen.len() >= cap {
        false // at capacity with fresh entries: refuse new host_ids (anti-DoS)
    } else {
        last_seen.insert(host_id.to_string(), now);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_heartbeat_is_online_then_quiet() {
        let mut m = HashMap::new();
        let t0 = Instant::now();
        assert!(record_heartbeat(&mut m, "a", t0, 10));
        assert!(!record_heartbeat(
            &mut m,
            "a",
            t0 + Duration::from_secs(1),
            10
        ));
    }

    #[test]
    fn returns_online_after_a_gap() {
        let mut m = HashMap::new();
        let t0 = Instant::now();
        assert!(record_heartbeat(&mut m, "a", t0, 10));
        let later = t0 + ONLINE_AFTER_GAP + Duration::from_secs(1);
        assert!(record_heartbeat(&mut m, "a", later, 10));
    }

    #[test]
    fn map_is_capped() {
        let mut m = HashMap::new();
        let t0 = Instant::now();
        assert!(record_heartbeat(&mut m, "a", t0, 2));
        assert!(record_heartbeat(&mut m, "b", t0, 2));
        assert!(!record_heartbeat(&mut m, "c", t0, 2));
        assert_eq!(m.len(), 2);
    }

    // --- Per-host topic isolation over real mTLS (issue #16) ---

    use crate::ca::EmbeddedCa;
    use osa_core::HostId;
    use osa_core::ports::CertIssuer;
    use rumqttc::{AsyncClient, Event, MqttOptions, Packet, QoS, Transport};
    use std::time::Duration as StdDuration;

    /// A client identity (CA root, leaf cert, key) as PEM byte vectors, issued by
    /// `ca` for `host` — so its cert carries `O = <host_id hex>` (the tenant).
    async fn client_identity(ca: &EmbeddedCa, host: HostId) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let key = rcgen::KeyPair::generate().unwrap();
        let csr = rcgen::CertificateParams::default()
            .serialize_request(&key)
            .unwrap()
            .der()
            .to_vec();
        let cert_der = ca.sign(host, &csr).await.unwrap();
        let cert_pem = pem::encode(&pem::Pem::new("CERTIFICATE", cert_der));
        (
            ca.ca_root_pem().into_bytes(),
            cert_pem.into_bytes(),
            key.serialize_pem().into_bytes(),
        )
    }

    fn free_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    /// Connect over mTLS with `identity`, subscribe to `topic`, and return whether
    /// a Publish arrives within `within` (false on rejection/disconnect/timeout).
    async fn receives_after_subscribing(
        identity: (Vec<u8>, Vec<u8>, Vec<u8>),
        port: u16,
        topic: &str,
        within: StdDuration,
    ) -> bool {
        let (ca, cert, key) = identity;
        let mut opts = MqttOptions::new("probe", "localhost", port);
        opts.set_keep_alive(StdDuration::from_secs(30));
        opts.set_transport(Transport::tls(ca, Some((cert, key)), None));
        let (client, mut eventloop) = AsyncClient::new(opts, 10);
        let deadline = std::time::Instant::now() + within;
        loop {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                return false;
            }
            match tokio::time::timeout(remaining, eventloop.poll()).await {
                Ok(Ok(Event::Incoming(Packet::ConnAck(_)))) => {
                    client.subscribe(topic, QoS::AtLeastOnce).await.ok();
                }
                Ok(Ok(Event::Incoming(Packet::Publish(_)))) => return true,
                Ok(Ok(_)) => {}
                Ok(Err(_)) => return false, // disconnected (e.g. foreign subscribe rejected)
                Err(_) => return false,     // timed out with no delivery
            }
        }
    }

    /// Publish a retained message to `topic` over mTLS with `identity`.
    async fn publish_retained(identity: (Vec<u8>, Vec<u8>, Vec<u8>), port: u16, topic: &str) {
        let (ca, cert, key) = identity;
        let mut opts = MqttOptions::new("producer", "localhost", port);
        opts.set_keep_alive(StdDuration::from_secs(30));
        opts.set_transport(Transport::tls(ca, Some((cert, key)), None));
        let (client, mut eventloop) = AsyncClient::new(opts, 10);
        // Drive the loop until connected, then publish retained and let it flush.
        let deadline = std::time::Instant::now() + StdDuration::from_secs(5);
        let mut published = false;
        while std::time::Instant::now() < deadline {
            match tokio::time::timeout(StdDuration::from_millis(500), eventloop.poll()).await {
                Ok(Ok(Event::Incoming(Packet::ConnAck(_)))) => {
                    client
                        .publish(topic, QoS::AtLeastOnce, true, b"probe".to_vec())
                        .await
                        .ok();
                }
                Ok(Ok(Event::Incoming(Packet::PubAck(_)))) => {
                    published = true;
                    break;
                }
                _ => {}
            }
        }
        assert!(
            published,
            "producer must publish to its own tenant: {topic}"
        );
    }

    /// Connect over mTLS with `identity`, publish to `topic`, and return whether
    /// the broker acknowledges it (false on rejection/disconnect/timeout).
    async fn publish_is_accepted(
        identity: (Vec<u8>, Vec<u8>, Vec<u8>),
        port: u16,
        topic: &str,
    ) -> bool {
        let (ca, cert, key) = identity;
        let mut opts = MqttOptions::new("pub-probe", "localhost", port);
        opts.set_keep_alive(StdDuration::from_secs(30));
        opts.set_transport(Transport::tls(ca, Some((cert, key)), None));
        let (client, mut eventloop) = AsyncClient::new(opts, 10);
        let deadline = std::time::Instant::now() + StdDuration::from_secs(3);
        loop {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                return false;
            }
            match tokio::time::timeout(remaining, eventloop.poll()).await {
                Ok(Ok(Event::Incoming(Packet::ConnAck(_)))) => {
                    client
                        .publish(topic, QoS::AtLeastOnce, false, b"x".to_vec())
                        .await
                        .ok();
                }
                Ok(Ok(Event::Incoming(Packet::PubAck(_)))) => return true,
                Ok(Ok(_)) => {}
                Ok(Err(_)) => return false, // rejected (BadTenant) → disconnected
                Err(_) => return false,     // no ack within the window
            }
        }
    }

    #[tokio::test]
    async fn broker_confines_a_cert_to_its_own_tenant() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let ca = EmbeddedCa::new(time::Duration::hours(24)).unwrap();
        let server = ca.issue_server_cert(&["localhost"]).unwrap();

        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(dir.path().join(BROKER_CERT), &server.cert_pem).unwrap();
        std::fs::write(dir.path().join(BROKER_KEY), &server.key_pem).unwrap();
        std::fs::write(dir.path().join(CA_CERT), ca.ca_root_pem()).unwrap();
        let port = free_port();
        // This test exercises tenant isolation, not the handshake, so the bridge's
        // CA/revocation deps are throwaway (no ClientHello is ever sent).
        let (_cmd_tx, cmd_rx) = mpsc::channel(1);
        spawn(
            format!("127.0.0.1:{port}").parse().unwrap(),
            dir.path(),
            Arc::new(EmbeddedCa::new(time::Duration::hours(24)).unwrap()),
            Arc::new(crate::revocation::RevocationRegistry::new()),
            cmd_rx,
        )
        .unwrap();
        tokio::time::sleep(StdDuration::from_millis(400)).await;

        let host_a = HostId::new();
        let host_b = HostId::new();
        let topic_a = osa_core::topics::heartbeat(&host_a.0.to_string());
        let topic_b = osa_core::topics::heartbeat(&host_b.0.to_string());

        // Each host publishes a retained probe to its OWN tenant (allowed).
        publish_retained(client_identity(&ca, host_a).await, port, &topic_a).await;
        publish_retained(client_identity(&ca, host_b).await, port, &topic_b).await;

        // Positive: host A reads its OWN tenant topic.
        assert!(
            receives_after_subscribing(
                client_identity(&ca, host_a).await,
                port,
                &topic_a,
                StdDuration::from_secs(3),
            )
            .await,
            "a cert must reach its own tenant"
        );

        // Isolation (#16), subscribe: host A's cert must NOT read host B's tenant.
        assert!(
            !receives_after_subscribing(
                client_identity(&ca, host_a).await,
                port,
                &topic_b,
                StdDuration::from_secs(3),
            )
            .await,
            "a cert must NOT subscribe to another host's tenant (#16)"
        );

        // Isolation (#16), publish: host A's cert must NOT publish INTO host B's
        // tenant (the higher-severity attack — forging under another identity).
        assert!(
            !publish_is_accepted(client_identity(&ca, host_a).await, port, &topic_b).await,
            "a cert must NOT publish into another host's tenant (#16)"
        );
        // Positive control for publish: host A CAN publish into its own tenant.
        assert!(
            publish_is_accepted(client_identity(&ca, host_a).await, port, &topic_a).await,
            "a cert must be able to publish into its own tenant"
        );
    }

    // --- Authenticated session handshake over the real broker (#20) ---

    /// An agent (driven here via the osa-core primitives over real mTLS) completes
    /// the authenticated handshake against the live coordinator bridge: it sends a
    /// ClientHello, receives a CA-signed ServerHello it can finish, and opens the
    /// coordinator's sealed session-ready beacon — proving end-to-end key
    /// agreement through the untrusted broker.
    #[tokio::test]
    async fn an_agent_completes_an_authenticated_session_over_the_broker() {
        use osa_core::handshake::Initiator;
        use osa_core::seal::{Direction, SessionKeys};
        use osa_proto::v1::{ClientHello, Envelope, ServerHello};
        use x509_parser::prelude::FromDer;

        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let ca = Arc::new(EmbeddedCa::new(time::Duration::hours(24)).unwrap());
        let server = ca.issue_server_cert(&["localhost"]).unwrap();

        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(dir.path().join(BROKER_CERT), &server.cert_pem).unwrap();
        std::fs::write(dir.path().join(BROKER_KEY), &server.key_pem).unwrap();
        std::fs::write(dir.path().join(CA_CERT), ca.ca_root_pem()).unwrap();
        let port = free_port();
        let (_cmd_tx, cmd_rx) = mpsc::channel(1);
        spawn(
            format!("127.0.0.1:{port}").parse().unwrap(),
            dir.path(),
            ca.clone(),
            Arc::new(crate::revocation::RevocationRegistry::new()),
            cmd_rx,
        )
        .unwrap();
        tokio::time::sleep(StdDuration::from_millis(400)).await;

        // Enroll an agent identity from the same CA (host_id, key, cert).
        let host = HostId::new();
        let host_key = rcgen::KeyPair::generate().unwrap();
        let csr = rcgen::CertificateParams::default()
            .serialize_request(&host_key)
            .unwrap()
            .der()
            .to_vec();
        let cert_der = ca.sign(host, &csr).await.unwrap();
        let host_str = host.0.to_string();

        // Connect over mTLS as that host.
        let cert_pem = pem::encode(&pem::Pem::new("CERTIFICATE", cert_der.clone())).into_bytes();
        let mut opts = MqttOptions::new(host_str.clone(), "localhost", port);
        opts.set_keep_alive(StdDuration::from_secs(30));
        opts.set_transport(Transport::tls(
            ca.ca_root_pem().into_bytes(),
            Some((cert_pem, host_key.serialize_pem().into_bytes())),
            None,
        ));
        let (client, mut eventloop) = AsyncClient::new(opts, 10);

        // Build the ClientHello with the agent's identity (as osa-agent does).
        let sid = "itest-session";
        let ca_pub_sec1 = {
            let der = ca.ca_root_der();
            let (_, root) = x509_parser::prelude::X509Certificate::from_der(&der).unwrap();
            root.public_key().subject_public_key.data.to_vec()
        };
        let (mut initiator, hello) =
            Initiator::start(sid.as_bytes(), &cert_der, &host_key.serialize_pem())
                .map(|(i, h)| (Some(i), h))
                .unwrap();
        let client_hello = ClientHello {
            sid: sid.into(),
            client_eph: hello.client_eph.to_vec(),
            cert_der: cert_der.clone(),
            sig: hello.sig,
        };

        let mut keys: Option<SessionKeys> = None;
        let mut beacon_opened = false;
        let deadline = std::time::Instant::now() + StdDuration::from_secs(8);
        while std::time::Instant::now() < deadline && !beacon_opened {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            match tokio::time::timeout(remaining, eventloop.poll()).await {
                Ok(Ok(Event::Incoming(Packet::ConnAck(_)))) => {
                    client
                        .subscribe(osa_core::topics::hs_down(&host_str), QoS::AtLeastOnce)
                        .await
                        .unwrap();
                    client
                        .subscribe(osa_core::topics::ctrl_down(&host_str), QoS::AtLeastOnce)
                        .await
                        .unwrap();
                    client
                        .publish(
                            osa_core::topics::hs_up(&host_str),
                            QoS::AtLeastOnce,
                            false,
                            osa_core::wire::encode(&client_hello),
                        )
                        .await
                        .unwrap();
                }
                Ok(Ok(Event::Incoming(Packet::Publish(p)))) => {
                    if p.topic == osa_core::topics::hs_down(&host_str) {
                        let sh: ServerHello = osa_core::wire::decode(&p.payload).unwrap();
                        let server_eph: [u8; 32] = sh.server_eph.as_slice().try_into().unwrap();
                        let session_keys = initiator
                            .take()
                            .unwrap()
                            .finish(&server_eph, &sh.sig, &ca_pub_sec1)
                            .expect("ServerHello must verify against the pinned CA");
                        keys = Some(session_keys);
                    } else if p.topic == osa_core::topics::ctrl_down(&host_str) {
                        let env: Envelope = osa_core::wire::decode(&p.payload).unwrap();
                        let pt = osa_core::wire::open_envelope(
                            keys.as_ref().expect("session keys before beacon"),
                            Direction::CoordToAgent,
                            &env,
                        )
                        .expect("the coordinator-sealed beacon must open with the agent's keys");
                        assert_eq!(pt, osa_core::wire::CTRL_SESSION_READY);
                        beacon_opened = true;
                    }
                }
                Ok(Ok(_)) => {}
                Ok(Err(e)) => panic!("agent mqtt loop errored: {e}"),
                Err(_) => break,
            }
        }
        assert!(
            beacon_opened,
            "the agent must complete the handshake and open the sealed session beacon (#20)"
        );
    }

    /// Enroll a host from `ca`, returning its cert DER and keypair.
    async fn enroll_host(ca: &EmbeddedCa, host: HostId) -> (Vec<u8>, rcgen::KeyPair) {
        let key = rcgen::KeyPair::generate().unwrap();
        let csr = rcgen::CertificateParams::default()
            .serialize_request(&key)
            .unwrap()
            .der()
            .to_vec();
        let cert_der = ca.sign(host, &csr).await.unwrap();
        (cert_der, key)
    }

    /// Build an encoded `ClientHello` for `sid` with the host's identity.
    fn client_hello_bytes(sid: &str, cert_der: &[u8], key: &rcgen::KeyPair) -> Vec<u8> {
        use osa_core::handshake::Initiator;
        let (_init, hello) =
            Initiator::start(sid.as_bytes(), cert_der, &key.serialize_pem()).unwrap();
        osa_core::wire::encode(&osa_proto::v1::ClientHello {
            sid: sid.into(),
            client_eph: hello.client_eph.to_vec(),
            cert_der: cert_der.to_vec(),
            sig: hello.sig,
        })
    }

    /// Connect as `host_str` over mTLS, publish `payload` to its handshake uplink,
    /// and return whether a `ServerHello` arrives on its downlink within `within`.
    async fn server_hello_within(
        ca: &EmbeddedCa,
        cert_der: &[u8],
        key: &rcgen::KeyPair,
        host_str: &str,
        port: u16,
        payload: Vec<u8>,
        within: StdDuration,
    ) -> bool {
        let cert_pem = pem::encode(&pem::Pem::new("CERTIFICATE", cert_der.to_vec())).into_bytes();
        let mut opts = MqttOptions::new(host_str.to_string(), "localhost", port);
        opts.set_keep_alive(StdDuration::from_secs(30));
        opts.set_transport(Transport::tls(
            ca.ca_root_pem().into_bytes(),
            Some((cert_pem, key.serialize_pem().into_bytes())),
            None,
        ));
        let (client, mut eventloop) = AsyncClient::new(opts, 10);
        let deadline = std::time::Instant::now() + within;
        loop {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                return false;
            }
            match tokio::time::timeout(remaining, eventloop.poll()).await {
                Ok(Ok(Event::Incoming(Packet::ConnAck(_)))) => {
                    client
                        .subscribe(osa_core::topics::hs_down(host_str), QoS::AtLeastOnce)
                        .await
                        .ok();
                    client
                        .publish(
                            osa_core::topics::hs_up(host_str),
                            QoS::AtLeastOnce,
                            false,
                            payload.clone(),
                        )
                        .await
                        .ok();
                }
                Ok(Ok(Event::Incoming(Packet::Publish(p))))
                    if p.topic == osa_core::topics::hs_down(host_str) =>
                {
                    return true;
                }
                Ok(Ok(_)) => {}
                Ok(Err(_)) => return false,
                Err(_) => return false,
            }
        }
    }

    /// The bridge drops a revoked host's ClientHello and a malformed ClientHello,
    /// survives both, and still serves a legitimate host afterward (#20).
    #[tokio::test]
    async fn the_bridge_rejects_bad_handshakes_and_keeps_serving() {
        use crate::revocation::RevocationRegistry;

        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let ca = Arc::new(EmbeddedCa::new(time::Duration::hours(24)).unwrap());
        let server = ca.issue_server_cert(&["localhost"]).unwrap();
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(dir.path().join(BROKER_CERT), &server.cert_pem).unwrap();
        std::fs::write(dir.path().join(BROKER_KEY), &server.key_pem).unwrap();
        std::fs::write(dir.path().join(CA_CERT), ca.ca_root_pem()).unwrap();
        let port = free_port();
        let revocations = Arc::new(RevocationRegistry::new());
        let (_cmd_tx, cmd_rx) = mpsc::channel(1);
        spawn(
            format!("127.0.0.1:{port}").parse().unwrap(),
            dir.path(),
            ca.clone(),
            revocations.clone(),
            cmd_rx,
        )
        .unwrap();
        tokio::time::sleep(StdDuration::from_millis(400)).await;

        // A revoked host: a well-formed, validly-signed ClientHello is dropped.
        let revoked = HostId::new();
        let (rev_cert, rev_key) = enroll_host(&ca, revoked).await;
        revocations.revoke(revoked);
        let rev_hello = client_hello_bytes("revoked-sid", &rev_cert, &rev_key);
        assert!(
            !server_hello_within(
                &ca,
                &rev_cert,
                &rev_key,
                &revoked.0.to_string(),
                port,
                rev_hello,
                StdDuration::from_millis(1500),
            )
            .await,
            "a revoked host must NOT receive a ServerHello"
        );

        // A malformed ClientHello is dropped without killing the bridge loop.
        let live = HostId::new();
        let (live_cert, live_key) = enroll_host(&ca, live).await;
        assert!(
            !server_hello_within(
                &ca,
                &live_cert,
                &live_key,
                &live.0.to_string(),
                port,
                b"not a protobuf".to_vec(),
                StdDuration::from_millis(1200),
            )
            .await,
            "a malformed ClientHello must not produce a ServerHello"
        );

        // The bridge survived: a legitimate ClientHello from the same host now
        // completes (proving the loop kept serving after the bad inputs).
        let good_hello = client_hello_bytes("live-sid", &live_cert, &live_key);
        assert!(
            server_hello_within(
                &ca,
                &live_cert,
                &live_key,
                &live.0.to_string(),
                port,
                good_hello,
                StdDuration::from_secs(5),
            )
            .await,
            "the bridge must keep serving legitimate hosts after rejecting bad input"
        );
    }

    // --- Dispatch + result routing (Epic 3, slice 3.2b) ---

    /// A coordinator/agent session key pair deriving identical keys.
    fn session_keys_pair() -> (osa_core::seal::SessionKeys, osa_core::seal::SessionKeys) {
        use osa_core::seal::Handshake;
        let a = Handshake::new().unwrap();
        let b = Handshake::new().unwrap();
        let (apub, bpub) = (a.public, b.public);
        (
            a.derive(&bpub, b"bind").unwrap(),
            b.derive(&apub, b"bind").unwrap(),
        )
    }

    #[test]
    fn handle_result_opens_and_routes_to_the_waiting_operator_then_forgets_on_terminal() {
        use osa_core::seal::Direction;
        use osa_proto::v1::job_outcome::Terminal;
        use osa_proto::v1::job_result::Body;
        use osa_proto::v1::output_chunk::Stream;
        use osa_proto::v1::{JobResult, OutputChunk};

        let (coord_keys, agent_keys) = session_keys_pair();
        let host = HostId::new();
        let mut sessions = SessionStore::new();
        sessions.insert(host, "s".into(), coord_keys);
        let tenant = osa_core::topics::tenant(&host.0.to_string());

        let (events_tx, mut events_rx) = mpsc::channel(8);
        let mut pending: PendingJobs = HashMap::new();
        pending.insert(
            (host, "j1".into()),
            PendingJob {
                events: events_tx,
                deadline: Instant::now() + Duration::from_secs(60),
            },
        );

        // The agent seals an OutputChunk (seq 0) then a terminal JobOutcome (seq 1).
        let seal = |seq: u64, body: Body| {
            let result = JobResult {
                job_id: "j1".into(),
                body: Some(body),
            };
            let env = osa_core::wire::seal_envelope(
                &agent_keys,
                Direction::AgentToCoord,
                &host.0.to_string(),
                "s",
                seq,
                osa_proto::v1::envelope::Kind::Control,
                &osa_core::wire::encode(&result),
            );
            osa_core::wire::encode(&env)
        };
        let chunk = seal(
            0,
            Body::Chunk(OutputChunk {
                stream: Stream::Stdout as i32,
                data: b"hi".to_vec(),
            }),
        );
        let outcome = seal(
            1,
            Body::Outcome(osa_proto::v1::JobOutcome {
                terminal: Some(Terminal::ExitCode(0)),
                output_truncated: false,
                timed_out: false,
            }),
        );

        handle_result(&tenant, &chunk, &mut sessions, &mut pending);
        assert!(!pending.is_empty(), "job still open after a chunk");
        handle_result(&tenant, &outcome, &mut sessions, &mut pending);
        assert!(pending.is_empty(), "job forgotten on the terminal outcome");

        // The operator received the chunk then the outcome, in order, each tagged
        // with the source host.
        let (h1, r1) = events_rx.try_recv().unwrap();
        assert_eq!(h1, host);
        assert!(matches!(r1.body, Some(Body::Chunk(c)) if c.data == b"hi"));
        let (h2, r2) = events_rx.try_recv().unwrap();
        assert_eq!(h2, host);
        assert!(
            matches!(r2.body, Some(Body::Outcome(o)) if o.terminal == Some(Terminal::ExitCode(0)))
        );
    }

    fn pending_with(
        host: HostId,
        job_id: &str,
        deadline: Instant,
    ) -> (PendingJobs, mpsc::Receiver<HostResult>) {
        let (tx, rx) = mpsc::channel(8);
        let mut pending: PendingJobs = HashMap::new();
        pending.insert(
            (host, job_id.into()),
            PendingJob {
                events: tx,
                deadline,
            },
        );
        (pending, rx)
    }

    #[test]
    fn reap_stale_jobs_fails_expired_jobs_and_leaves_fresh_ones() {
        use osa_proto::v1::job_outcome::Terminal;
        use osa_proto::v1::job_result::Body;

        let stale_host = HostId::new();
        let (mut pending, mut rx) =
            pending_with(stale_host, "old", Instant::now() - Duration::from_secs(1));
        // A fresh job that must survive the sweep.
        let (fresh_tx, _fresh_rx) = mpsc::channel(8);
        let fresh_host = HostId::new();
        pending.insert(
            (fresh_host, "new".into()),
            PendingJob {
                events: fresh_tx,
                deadline: Instant::now() + Duration::from_secs(60),
            },
        );

        reap_stale_jobs(&mut pending);

        assert!(
            pending.contains_key(&(fresh_host, "new".into())),
            "fresh job kept"
        );
        assert!(
            !pending.contains_key(&(stale_host, "old".into())),
            "stale job reaped"
        );
        // The reaped job's operator got a terminal error, tagged with its host.
        let (rhost, r) = rx.try_recv().unwrap();
        assert_eq!(rhost, stale_host);
        assert!(
            matches!(r.body, Some(Body::Outcome(o)) if matches!(o.terminal, Some(Terminal::Error(_))))
        );
    }

    #[test]
    fn purge_host_jobs_fails_only_the_reconnecting_hosts_jobs() {
        use osa_proto::v1::job_result::Body;

        let host_a = HostId::new();
        let host_b = HostId::new();
        let deadline = Instant::now() + Duration::from_secs(60);
        let (mut pending, mut rx_a) = pending_with(host_a, "ja", deadline);
        let (tx_b, _rx_b) = mpsc::channel(8);
        pending.insert(
            (host_b, "jb".into()),
            PendingJob {
                events: tx_b,
                deadline,
            },
        );

        purge_host_jobs(&mut pending, host_a);

        assert!(
            !pending.contains_key(&(host_a, "ja".into())),
            "reconnecting host's job purged"
        );
        assert!(
            pending.contains_key(&(host_b, "jb".into())),
            "other host's job kept"
        );
        let (rhost, r) = rx_a.try_recv().unwrap();
        assert_eq!(rhost, host_a);
        assert!(
            matches!(r.body, Some(Body::Outcome(_))),
            "purged operator got a terminal event"
        );
    }

    /// Play a real agent over the broker: handshake, ack, then on a sealed dispatch
    /// echo `argv` joined as stdout + a clean exit, all sealed on the uplink.
    async fn play_agent_exec(
        ca: Arc<EmbeddedCa>,
        cert_der: Vec<u8>,
        key: rcgen::KeyPair,
        host_str: String,
        port: u16,
        ready: tokio::sync::oneshot::Sender<()>,
    ) {
        use osa_core::handshake::Initiator;
        use osa_core::seal::{Direction, SessionKeys};
        use osa_core::topics;
        use osa_core::wire;
        use osa_proto::v1::envelope::Kind;
        use osa_proto::v1::job_outcome::Terminal;
        use osa_proto::v1::job_result::Body;
        use osa_proto::v1::output_chunk::Stream as OutStream;
        use osa_proto::v1::{
            ClientHello, Dispatch, Envelope, ExecParams, JobOutcome, JobResult, OutputChunk,
            ServerHello,
        };
        use x509_parser::prelude::FromDer;

        let cert_pem = pem::encode(&pem::Pem::new("CERTIFICATE", cert_der.clone())).into_bytes();
        let mut opts = MqttOptions::new(host_str.clone(), "localhost", port);
        opts.set_keep_alive(StdDuration::from_secs(30));
        opts.set_transport(Transport::tls(
            ca.ca_root_pem().into_bytes(),
            Some((cert_pem, key.serialize_pem().into_bytes())),
            None,
        ));
        let (client, mut eventloop) = AsyncClient::new(opts, 16);

        let ca_pub = {
            let der = ca.ca_root_der();
            let (_, root) = x509_parser::prelude::X509Certificate::from_der(&der).unwrap();
            root.public_key().subject_public_key.data.to_vec()
        };
        let sid = "exec-itest";
        let (mut initiator, hello) =
            Initiator::start(sid.as_bytes(), &cert_der, &key.serialize_pem())
                .map(|(i, h)| (Some(i), h))
                .unwrap();
        let client_hello = ClientHello {
            sid: sid.into(),
            client_eph: hello.client_eph.to_vec(),
            cert_der: cert_der.clone(),
            sig: hello.sig,
        };

        let mut keys: Option<SessionKeys> = None;
        let mut send_seq = 0u64;
        let mut ready = Some(ready);
        let seal_uplink = |keys: &SessionKeys, seq: &mut u64, payload: &[u8]| {
            let env = wire::seal_envelope(
                keys,
                Direction::AgentToCoord,
                &host_str,
                sid,
                *seq,
                Kind::Control,
                payload,
            );
            *seq += 1;
            wire::encode(&env)
        };
        loop {
            match eventloop.poll().await {
                Ok(Event::Incoming(Packet::ConnAck(_))) => {
                    for t in [
                        topics::hs_down(&host_str),
                        topics::ctrl_down(&host_str),
                        topics::dispatch_down(&host_str),
                    ] {
                        client.subscribe(t, QoS::AtLeastOnce).await.unwrap();
                    }
                    client
                        .publish(
                            topics::hs_up(&host_str),
                            QoS::AtLeastOnce,
                            false,
                            wire::encode(&client_hello),
                        )
                        .await
                        .unwrap();
                }
                Ok(Event::Incoming(Packet::Publish(p))) => {
                    if p.topic == topics::hs_down(&host_str) {
                        let sh: ServerHello = wire::decode(&p.payload).unwrap();
                        let server_eph: [u8; 32] = sh.server_eph.as_slice().try_into().unwrap();
                        keys = Some(
                            initiator
                                .take()
                                .unwrap()
                                .finish(&server_eph, &sh.sig, &ca_pub)
                                .unwrap(),
                        );
                    } else if p.topic == topics::ctrl_down(&host_str) {
                        let env: Envelope = wire::decode(&p.payload).unwrap();
                        let k = keys.as_ref().unwrap();
                        wire::open_envelope(k, Direction::CoordToAgent, &env).unwrap();
                        let ack = seal_uplink(k, &mut send_seq, wire::CTRL_SESSION_ACK);
                        client
                            .publish(topics::ctrl_up(&host_str), QoS::AtLeastOnce, false, ack)
                            .await
                            .unwrap();
                        if let Some(r) = ready.take() {
                            let _ = r.send(());
                        }
                    } else if p.topic == topics::dispatch_down(&host_str) {
                        let env: Envelope = wire::decode(&p.payload).unwrap();
                        let k = keys.as_ref().unwrap();
                        let pt = wire::open_envelope(k, Direction::CoordToAgent, &env).unwrap();
                        let dispatch: Dispatch = wire::decode(&pt).unwrap();
                        let params: ExecParams = wire::decode(&dispatch.params).unwrap();
                        let out = params.argv.join(" ").into_bytes();
                        let chunk = JobResult {
                            job_id: dispatch.job_id.clone(),
                            body: Some(Body::Chunk(OutputChunk {
                                stream: OutStream::Stdout as i32,
                                data: out,
                            })),
                        };
                        let b = seal_uplink(k, &mut send_seq, &wire::encode(&chunk));
                        client
                            .publish(topics::result_up(&host_str), QoS::AtLeastOnce, false, b)
                            .await
                            .unwrap();
                        let outcome = JobResult {
                            job_id: dispatch.job_id.clone(),
                            body: Some(Body::Outcome(JobOutcome {
                                terminal: Some(Terminal::ExitCode(0)),
                                output_truncated: false,
                                timed_out: false,
                            })),
                        };
                        let b = seal_uplink(k, &mut send_seq, &wire::encode(&outcome));
                        client
                            .publish(topics::result_up(&host_str), QoS::AtLeastOnce, false, b)
                            .await
                            .unwrap();
                    }
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }
    }

    /// End-to-end over the real broker: an operator dispatch flows through the
    /// bridge to a live agent and its sealed output + exit code stream back.
    #[tokio::test]
    async fn an_operator_exec_streams_output_end_to_end() {
        use osa_proto::v1::job_outcome::Terminal;
        use osa_proto::v1::job_result::Body;
        use osa_proto::v1::{Dispatch, ExecParams};

        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let ca = Arc::new(EmbeddedCa::new(time::Duration::hours(24)).unwrap());
        let server = ca.issue_server_cert(&["localhost"]).unwrap();
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(dir.path().join(BROKER_CERT), &server.cert_pem).unwrap();
        std::fs::write(dir.path().join(BROKER_KEY), &server.key_pem).unwrap();
        std::fs::write(dir.path().join(CA_CERT), ca.ca_root_pem()).unwrap();
        let port = free_port();
        let (cmd_tx, cmd_rx) = mpsc::channel(8);
        spawn(
            format!("127.0.0.1:{port}").parse().unwrap(),
            dir.path(),
            ca.clone(),
            Arc::new(crate::revocation::RevocationRegistry::new()),
            cmd_rx,
        )
        .unwrap();
        tokio::time::sleep(StdDuration::from_millis(400)).await;

        let host = HostId::new();
        let (cert_der, key) = enroll_host(&ca, host).await;
        let host_str = host.0.to_string();

        // Bring a real agent online (handshake + ack) and wait until it is ready.
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let agent = tokio::spawn(play_agent_exec(
            ca.clone(),
            cert_der,
            key,
            host_str,
            port,
            ready_tx,
        ));
        tokio::time::timeout(StdDuration::from_secs(8), ready_rx)
            .await
            .expect("agent should establish a session")
            .unwrap();

        // The operator dispatches an exec; the bridge seals it and streams results.
        let (events_tx, mut events_rx) = mpsc::channel(8);
        let params = osa_core::wire::encode(&ExecParams {
            argv: vec!["echo".into(), "hi".into()],
        });
        cmd_tx
            .send(BridgeCommand::Dispatch {
                host_id: host,
                dispatch: Dispatch {
                    job_id: "job-1".into(),
                    kind: "exec".into(),
                    run_as: String::new(),
                    params,
                },
                events: events_tx,
            })
            .await
            .unwrap();

        let mut stdout = Vec::new();
        let mut terminal = None;
        while let Ok(Some((rhost, r))) =
            tokio::time::timeout(StdDuration::from_secs(8), events_rx.recv()).await
        {
            assert_eq!(rhost, host, "every result is tagged with its host");
            match r.body.unwrap() {
                Body::Chunk(c) => stdout.extend(c.data),
                Body::Outcome(o) => {
                    terminal = o.terminal;
                    break;
                }
            }
        }
        assert_eq!(
            stdout, b"echo hi",
            "the agent's sealed stdout streamed back"
        );
        assert_eq!(
            terminal,
            Some(Terminal::ExitCode(0)),
            "the exit code streamed back"
        );
        agent.abort();
    }

    /// Fan-out over the real broker: two agents come online, `OnlineHosts` returns
    /// both, and a dispatch to each streams back results tagged with their host_id.
    #[tokio::test]
    async fn fan_out_dispatches_to_each_online_host_with_tagged_results() {
        use osa_proto::v1::job_result::Body;
        use osa_proto::v1::{Dispatch, ExecParams};

        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let ca = Arc::new(EmbeddedCa::new(time::Duration::hours(24)).unwrap());
        let server = ca.issue_server_cert(&["localhost"]).unwrap();
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(dir.path().join(BROKER_CERT), &server.cert_pem).unwrap();
        std::fs::write(dir.path().join(BROKER_KEY), &server.key_pem).unwrap();
        std::fs::write(dir.path().join(CA_CERT), ca.ca_root_pem()).unwrap();
        let port = free_port();
        let (cmd_tx, cmd_rx) = mpsc::channel(8);
        spawn(
            format!("127.0.0.1:{port}").parse().unwrap(),
            dir.path(),
            ca.clone(),
            Arc::new(crate::revocation::RevocationRegistry::new()),
            cmd_rx,
        )
        .unwrap();
        tokio::time::sleep(StdDuration::from_millis(400)).await;

        // Bring two agents online.
        let host1 = HostId::new();
        let host2 = HostId::new();
        let mut agents = Vec::new();
        for host in [host1, host2] {
            let (cert, key) = enroll_host(&ca, host).await;
            let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
            agents.push(tokio::spawn(play_agent_exec(
                ca.clone(),
                cert,
                key,
                host.0.to_string(),
                port,
                ready_tx,
            )));
            tokio::time::timeout(StdDuration::from_secs(8), ready_rx)
                .await
                .expect("agent online")
                .unwrap();
        }

        // `*` resolution: the bridge reports both online hosts.
        let (otx, orx) = tokio::sync::oneshot::channel();
        cmd_tx
            .send(BridgeCommand::OnlineHosts { reply: otx })
            .await
            .unwrap();
        let online = orx.await.unwrap();
        assert_eq!(online.len(), 2);
        assert!(online.contains(&host1) && online.contains(&host2));

        // Fan out to the two online hosts AND one OFFLINE host (never connected),
        // over one shared, tagged result stream.
        let offline = HostId::new();
        let (events_tx, mut events_rx) = mpsc::channel::<HostResult>(16);
        for host in [host1, host2, offline] {
            let params = osa_core::wire::encode(&ExecParams {
                argv: vec!["echo".into(), "hi".into()],
            });
            cmd_tx
                .send(BridgeCommand::Dispatch {
                    host_id: host,
                    dispatch: Dispatch {
                        job_id: format!("job-{}", host.0),
                        kind: "exec".into(),
                        run_as: String::new(),
                        params,
                    },
                    events: events_tx.clone(),
                })
                .await
                .unwrap();
        }
        drop(events_tx);

        // Each host reports a terminal outcome tagged with its host: the two online
        // hosts exit 0; the offline host is reported "not connected" — without
        // blocking the others.
        let mut outcomes: std::collections::HashMap<HostId, Terminal> =
            std::collections::HashMap::new();
        while let Ok(Some((host, r))) =
            tokio::time::timeout(StdDuration::from_secs(8), events_rx.recv()).await
        {
            if let Some(Body::Outcome(o)) = r.body
                && let Some(t) = o.terminal
            {
                outcomes.insert(host, t);
            }
        }
        assert_eq!(outcomes.get(&host1), Some(&Terminal::ExitCode(0)));
        assert_eq!(outcomes.get(&host2), Some(&Terminal::ExitCode(0)));
        assert!(
            matches!(outcomes.get(&offline), Some(Terminal::Error(m)) if m.contains("not connected")),
            "the offline host is reported as such: {:?}",
            outcomes.get(&offline)
        );
        for a in agents {
            a.abort();
        }
    }
}
