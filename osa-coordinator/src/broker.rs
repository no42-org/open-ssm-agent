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
use std::time::{Duration, Instant};

use anyhow::Context;
use rumqttd::local::LinkRx;
use rumqttd::{
    Broker, Config, ConnectionSettings, Notification, RouterConfig, ServerSettings, TlsConfig,
};

/// A host is considered to have come back online if its previous heartbeat was
/// older than this (so transient gaps do not spam "online" logs).
const ONLINE_AFTER_GAP: Duration = Duration::from_secs(90);
/// Cap on tracked hosts, so the last-seen map cannot grow without bound from host
/// churn. A host can only publish under its own tenant now (#16), so a single
/// cert can no longer inflate the map with foreign host_ids.
const MAX_TRACKED_HOSTS: usize = 50_000;

/// File names the broker reads its TLS material from, written under the cert dir.
pub const BROKER_CERT: &str = "broker.crt";
pub const BROKER_KEY: &str = "broker.key";
pub const CA_CERT: &str = "ca.crt";

/// Spawn the embedded broker listening on `addr` with mTLS. The cert/key/CA PEM
/// files must already exist in `cert_dir`. Runs on a dedicated OS thread (the
/// broker's run loop is blocking); returns once the thread is spawned.
pub fn spawn(addr: SocketAddr, cert_dir: &Path) -> anyhow::Result<()> {
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

    // `Broker::new` spawns the router immediately, so an in-process link can be
    // created now (before `start()`) to observe host heartbeats — no second TLS
    // client or bridge cert needed.
    let mut broker = Broker::new(config);
    let (mut link_tx, link_rx) = broker
        .link("osa-coordinator-observer")
        .context("creating broker observer link")?;
    link_tx
        .subscribe(osa_core::topics::HEARTBEAT_FILTER)
        .context("subscribing to host heartbeats")?;

    std::thread::Builder::new()
        .name("osa-broker".to_string())
        .spawn(move || {
            if let Err(e) = broker.start() {
                tracing::error!(error = %e, "embedded broker exited");
            }
        })
        .context("spawning broker thread")?;

    std::thread::Builder::new()
        .name("osa-observer".to_string())
        .spawn(move || {
            // Hold `link_tx` for the thread's life so the link stays registered.
            let _link_tx = link_tx;
            observe_heartbeats(link_rx);
        })
        .context("spawning heartbeat observer thread")?;
    Ok(())
}

/// Receive forwarded heartbeats and log each host's online transition (AD-9).
/// The bounded last-seen map only dedups transitions; a queryable registry +
/// offline detection land with the Postgres registry (Epic 2).
fn observe_heartbeats(mut rx: LinkRx) {
    let mut last_seen: HashMap<String, Instant> = HashMap::new();
    loop {
        match rx.recv() {
            Ok(Some(Notification::Forward(fwd))) => {
                let topic = String::from_utf8_lossy(&fwd.publish.topic);
                // The broker confines each host to its own tenant subtree, so a
                // heartbeat on `/tenants/<t>/…` can only have come from the host
                // whose cert O = <t> — this liveness signal is now authenticated
                // to the publisher's identity (issue #16).
                if let Some(tenant) = osa_core::topics::tenant_from_heartbeat(&topic)
                    && record_heartbeat(&mut last_seen, tenant, Instant::now(), MAX_TRACKED_HOSTS)
                {
                    tracing::info!(%tenant, "host online (heartbeat)");
                }
            }
            Ok(_) => {}
            Err(e) => {
                tracing::error!(error = %e, "heartbeat observer stopped");
                break;
            }
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
        spawn(format!("127.0.0.1:{port}").parse().unwrap(), dir.path()).unwrap();
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
}
