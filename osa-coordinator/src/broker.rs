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
//! Per-cert topic ACLs (AD-31) are **not enforced**: `rumqttd 0.20` has no
//! per-SAN topic authorization, so any cert signed by the CA may publish or
//! subscribe to any topic (deferred — issue #16). The substantive attack
//! (forging another host's content) is already blocked by the per-host AES-256
//! GCM seal (AD-27, `osa-core::seal`); only spoofing of unsealed liveness
//! remains, and that is low-severity.

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
/// churn or spoofed host_ids (before topic ACLs, story 1.7).
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
                // NOTE: the broker enforces no per-cert topic ACL (issue #16), so
                // this liveness signal is not authenticated against the publisher's
                // identity. A host could spoof another's empty heartbeat; sealed
                // payloads (AD-27) cannot be forged this way.
                if let Some(host_id) = osa_core::topics::host_id_from_heartbeat(&topic)
                    && record_heartbeat(&mut last_seen, host_id, Instant::now(), MAX_TRACKED_HOSTS)
                {
                    tracing::info!(%host_id, "host online (heartbeat)");
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
}
