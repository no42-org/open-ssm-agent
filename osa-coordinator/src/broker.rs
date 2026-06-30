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
use osa_core::seal::Direction;
use osa_core::topics::{
    CTRL_UP_FILTER, HEARTBEAT_FILTER, HS_UP_FILTER, tenant_from_ctrl_up, tenant_from_heartbeat,
    tenant_from_hs_up,
};
use osa_proto::v1::{ClientHello, Envelope, ServerHello, envelope::Kind};
use rumqttd::local::{LinkRx, LinkTx};
use rumqttd::{
    Broker, Config, ConnectionSettings, Notification, RouterConfig, ServerSettings, TlsConfig,
};
use tokio::sync::mpsc::{Sender, channel, error::TrySendError};

use crate::ca::EmbeddedCa;
use crate::revocation::Revocations;
use crate::session::SessionStore;

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
    for filter in [HEARTBEAT_FILTER, HS_UP_FILTER, CTRL_UP_FILTER] {
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
    tokio::spawn(run_bridge(evt_rx, link_tx, ca, revocations));
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
    mut rx: tokio::sync::mpsc::Receiver<(String, Vec<u8>)>,
    mut link_tx: LinkTx,
    ca: Arc<EmbeddedCa>,
    revocations: Arc<dyn Revocations>,
) {
    let mut sessions = SessionStore::new();
    let mut last_seen: HashMap<String, Instant> = HashMap::new();
    while let Some((topic, payload)) = rx.recv().await {
        // The broker confines each host to its own tenant subtree, so a message on
        // `/tenants/<t>/…` can only have come from the host whose cert O = <t> —
        // the publisher's identity is authenticated by the broker (issue #16).
        if let Some(tenant) = tenant_from_heartbeat(&topic) {
            if record_heartbeat(&mut last_seen, tenant, Instant::now(), MAX_TRACKED_HOSTS) {
                tracing::info!(%tenant, "host online (heartbeat)");
            }
        } else if let Some(tenant) = tenant_from_hs_up(&topic) {
            handle_client_hello(
                tenant,
                &payload,
                &ca,
                revocations.as_ref(),
                &mut sessions,
                &mut link_tx,
            )
            .await;
        } else if tenant_from_ctrl_up(&topic).is_some() {
            handle_ctrl_ack(&payload, &sessions);
        }
    }
    tracing::warn!("coordinator bridge stopped");
}

/// Handle a `ClientHello` (#20): verify the agent cert (chain + validity +
/// tenant-binding + revocation), run the authenticated handshake, publish the
/// `ServerHello`, seal the session-ready beacon, and record the session. Any
/// failure drops the handshake silently (an untrusted broker can feed garbage).
async fn handle_client_hello(
    tenant: &str,
    payload: &[u8],
    ca: &EmbeddedCa,
    revocations: &dyn Revocations,
    sessions: &mut SessionStore,
    link_tx: &mut LinkTx,
) {
    let hello: ClientHello = match osa_core::wire::decode(payload) {
        Ok(h) => h,
        Err(e) => {
            tracing::warn!(error = %e, "dropping malformed ClientHello");
            return;
        }
    };
    let client_eph: [u8; 32] = match <[u8; 32]>::try_from(hello.client_eph.as_slice()) {
        Ok(a) => a,
        Err(_) => {
            tracing::warn!("ClientHello ephemeral is not 32 bytes — dropping");
            return;
        }
    };
    // Sanity-bound the agent-chosen sid (it becomes the cleartext envelope sid and
    // an AAD field). The agent owns sid freshness; the coordinator only guards
    // against an empty or absurdly large value.
    if hello.sid.is_empty() || hello.sid.len() > 128 {
        tracing::warn!("ClientHello sid is empty or too long — dropping");
        return;
    }
    // Chain + validity. The cert is the agent's claimed identity.
    let verified = match ca.verify_host_cert(&hello.cert_der) {
        Ok(v) => v,
        Err(e) => {
            tracing::info!(error = %e, "rejecting ClientHello: cert did not verify");
            return;
        }
    };
    // Tenant binding: the broker-authenticated tenant (the topic) MUST equal the
    // cert identity, so a host cannot present another host's cert in its hello.
    let host_str = verified.host_id.0.to_string();
    if osa_core::topics::tenant(&host_str) != tenant {
        tracing::warn!(%tenant, host = %host_str, "ClientHello cert/tenant mismatch — dropping");
        return;
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
        return;
    }
    // Revocation (defense in depth, AD-28). Fail closed: no session on store error.
    match revocations.is_revoked(verified.host_id).await {
        Ok(false) => {}
        Ok(true) => {
            tracing::info!(host = %host_str, "rejecting ClientHello: identity revoked");
            return;
        }
        Err(e) => {
            tracing::error!(error = %e, "revocation check failed — refusing session");
            return;
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
            return;
        }
    };
    // Reserve (store) the session BEFORE emitting anything the agent treats as
    // established, so a store-at-capacity refusal cannot leave the agent with a
    // live session the coordinator never tracked.
    if !sessions.insert(verified.host_id, hello.sid.clone(), resp.keys) {
        tracing::warn!(host = %host_str, "session store at capacity — refusing session");
        return;
    }
    let session = sessions
        .get(&verified.host_id)
        .expect("session was just inserted");
    // ServerHello on the handshake downlink.
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
        return;
    }
    // The first sealed payload: a session-ready beacon on the control downlink,
    // proving key agreement to the agent (seq 0, coordinator→agent direction).
    let beacon = osa_core::wire::seal_envelope(
        &session.keys,
        Direction::CoordToAgent,
        &host_str,
        &hello.sid,
        0,
        Kind::Control,
        osa_core::wire::CTRL_SESSION_READY,
    );
    if let Err(e) = link_tx.publish(
        osa_core::topics::ctrl_down(&host_str),
        osa_core::wire::encode(&beacon),
    ) {
        tracing::warn!(error = %e, host = %host_str, "publishing session-ready beacon failed");
    }
    tracing::info!(host = %host_str, "session established (authenticated handshake, #20)");
}

/// Handle a sealed control ack on the uplink (#20): open it against the host's
/// session keys. A successful open with the expected payload proves the agent
/// derived matching keys — the end-to-end sealed channel is live.
fn handle_ctrl_ack(payload: &[u8], sessions: &SessionStore) {
    let env: Envelope = match osa_core::wire::decode(payload) {
        Ok(e) => e,
        Err(e) => {
            tracing::warn!(error = %e, "dropping malformed control envelope");
            return;
        }
    };
    let host_id = match env.host_id.parse::<uuid::Uuid>().map(HostId) {
        Ok(h) => h,
        Err(_) => {
            tracing::warn!("control envelope host_id is not a UUID — dropping");
            return;
        }
    };
    let Some(session) = sessions.get(&host_id) else {
        tracing::warn!(host = %host_id.0, "control ack for an unknown session — dropping");
        return;
    };
    if session.sid != env.sid {
        tracing::warn!(host = %host_id.0, "control ack sid mismatch — dropping");
        return;
    }
    match osa_core::wire::open_envelope(&session.keys, Direction::AgentToCoord, &env) {
        Ok(pt) if pt == osa_core::wire::CTRL_SESSION_ACK => {
            tracing::info!(host = %host_id.0, "session-open confirmed by agent (E2E sealed channel live, #20)");
        }
        Ok(_) => tracing::warn!(host = %host_id.0, "unexpected sealed control payload"),
        Err(_) => {
            tracing::warn!(host = %host_id.0, "session-open ack failed to open — key mismatch?")
        }
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
        spawn(
            format!("127.0.0.1:{port}").parse().unwrap(),
            dir.path(),
            Arc::new(EmbeddedCa::new(time::Duration::hours(24)).unwrap()),
            Arc::new(crate::revocation::RevocationRegistry::new()),
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
        spawn(
            format!("127.0.0.1:{port}").parse().unwrap(),
            dir.path(),
            ca.clone(),
            Arc::new(crate::revocation::RevocationRegistry::new()),
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
        spawn(
            format!("127.0.0.1:{port}").parse().unwrap(),
            dir.path(),
            ca.clone(),
            revocations.clone(),
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
}
