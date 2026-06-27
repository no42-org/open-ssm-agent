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
//! reconnect in lockstep). Publishing / heartbeat land in the next slice.

use std::hash::{Hash, Hasher};
use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::Context;
use rumqttc::{AsyncClient, Event, MqttOptions, Packet, Transport};
use tokio::time::sleep;

const BACKOFF_BASE: Duration = Duration::from_millis(500);
const BACKOFF_MAX: Duration = Duration::from_secs(30);
const KEEP_ALIVE: Duration = Duration::from_secs(30);
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
pub async fn run(state_dir: &Path, broker_host: &str, broker_port: u16) -> anyhow::Result<()> {
    let identity = load_identity(state_dir)?;
    let host_id = read_host_id(state_dir)?;
    let seed = stable_seed(&host_id);
    tracing::info!(%host_id, broker = %format!("{broker_host}:{broker_port}"), "control channel: dialing broker (mTLS, outbound-only)");

    let mut attempt = 0u32;
    let mut ever_connected = false;
    loop {
        let mut opts = MqttOptions::new(host_id.clone(), broker_host, broker_port);
        opts.set_keep_alive(KEEP_ALIVE);
        opts.set_transport(Transport::tls(
            identity.ca_pem.clone(),
            Some((identity.cert_pem.clone(), identity.key_pem.clone())),
            None,
        ));
        // Keep the client bound so the connection stays open while the loop runs.
        let (_client, mut eventloop) = AsyncClient::new(opts, 16);

        let mut connected_at: Option<Instant> = None;
        loop {
            match eventloop.poll().await {
                Ok(Event::Incoming(Packet::ConnAck(_))) => {
                    connected_at = Some(Instant::now());
                    ever_connected = true;
                    tracing::info!(%host_id, "control channel: connected");
                }
                Ok(_) => {}
                Err(e) => {
                    tracing::warn!(error = %e, "control channel: disconnected");
                    break;
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
