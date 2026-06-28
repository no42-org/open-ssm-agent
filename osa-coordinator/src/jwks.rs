/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: MIT
 */

//! Live JWKS fetch + key-rotation refresh (AD-18, story 2.1b).
//!
//! When the coordinator is configured with a JWKS **URL** (rather than a static
//! file), it fetches the issuer's signing keys at startup and then re-fetches
//! them on an interval. A successful refresh swaps a freshly-built validator into
//! the [`JwtAuth`](crate::auth::JwtAuth) cell, so an issuer key rotation is picked
//! up within one interval without dropping connections. A failed fetch or a
//! malformed document is logged and the **current** keys are kept — a transient
//! issuer outage must not take operator auth down.
//!
//! The JWKS endpoint is the root of operator-auth trust: keys fetched over an
//! attacker-controllable channel would let anyone forge operator tokens. So the
//! URL must be `https` (plaintext is permitted only to a loopback host, which
//! cannot be MITM'd — local dev/tests), redirects are refused (no downgrade),
//! proxies are bypassed, and the body is size-capped.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use osa_core::auth::{JwtValidator, ValidationPolicy};

use crate::auth::ValidatorCell;

/// Total time budget for one JWKS fetch (connect + body).
const FETCH_TIMEOUT: Duration = Duration::from_secs(10);
/// Hard cap on the JWKS body — a real key set is a few KB; anything near this is
/// hostile. Bounds memory against a compromised/misbehaving endpoint.
const MAX_JWKS_BYTES: usize = 1 << 20; // 1 MiB

/// How the validator's keys are sourced.
pub struct OidcConfig {
    pub issuer: String,
    pub audience: String,
    pub leeway_secs: u64,
}

impl OidcConfig {
    pub fn policy(&self) -> ValidationPolicy {
        ValidationPolicy {
            issuer: self.issuer.clone(),
            audience: self.audience.clone(),
            leeway_secs: self.leeway_secs,
        }
    }
}

/// Validate and normalize a JWKS URL. Requires `https`, except `http` to a
/// loopback host (local dev/tests, not MITM-able). Returns the normalized URL.
pub fn validate_url(raw: &str) -> anyhow::Result<String> {
    let raw = raw.trim();
    anyhow::ensure!(!raw.is_empty(), "--oidc-jwks-url must not be empty");
    let url = reqwest::Url::parse(raw)
        .with_context(|| format!("--oidc-jwks-url {raw:?} is not a valid URL"))?;
    match url.scheme() {
        "https" => Ok(url.to_string()),
        "http" if host_is_loopback(&url) => Ok(url.to_string()),
        "http" => anyhow::bail!(
            "--oidc-jwks-url must use https — refusing to fetch operator signing keys over plaintext http to a non-loopback host"
        ),
        other => {
            anyhow::bail!("--oidc-jwks-url scheme {other:?} is not supported (use https)")
        }
    }
}

fn host_is_loopback(url: &reqwest::Url) -> bool {
    match url.host_str() {
        Some("localhost") => true,
        Some(host) => host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<std::net::IpAddr>()
            .map(|ip| ip.is_loopback())
            .unwrap_or(false),
        None => false,
    }
}

/// Fetch the JWKS document from `url` and build a validator from it.
pub async fn fetch_validator(config: &OidcConfig, url: &str) -> anyhow::Result<JwtValidator> {
    let bytes = fetch_bytes(url).await?;
    JwtValidator::from_jwks_json(config.policy(), &bytes)
        .map_err(|e| anyhow::anyhow!("JWKS from {url} is unusable: {e}"))
}

async fn fetch_bytes(url: &str) -> anyhow::Result<Vec<u8>> {
    let client = reqwest::Client::builder()
        .timeout(FETCH_TIMEOUT)
        // A JWKS endpoint does not legitimately redirect; following one could
        // downgrade https->http or jump to an attacker origin.
        .redirect(reqwest::redirect::Policy::none())
        // Never route the key fetch through an ambient proxy.
        .no_proxy()
        .build()
        .context("building HTTP client")?;
    let mut resp = client
        .get(url)
        .send()
        .await
        .with_context(|| format!("fetching JWKS from {url}"))?
        .error_for_status()
        .with_context(|| format!("JWKS endpoint {url} returned an error"))?;
    // Stream with a hard ceiling rather than buffering an unbounded body.
    let mut body = Vec::new();
    while let Some(chunk) = resp.chunk().await.context("reading JWKS body")? {
        anyhow::ensure!(
            body.len() + chunk.len() <= MAX_JWKS_BYTES,
            "JWKS body exceeds {MAX_JWKS_BYTES} bytes"
        );
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// Spawn the background refresher: every `interval`, re-fetch the JWKS and, on
/// success, swap a fresh validator into `cell`. Errors keep the current keys.
pub fn spawn_refresh(cell: ValidatorCell, config: OidcConfig, url: String, interval: Duration) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(interval).await;
            match fetch_validator(&config, &url).await {
                Ok(validator) => {
                    *cell.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(validator);
                    tracing::debug!(%url, "refreshed operator JWKS");
                }
                Err(e) => {
                    tracing::warn!(%url, error = %e, "JWKS refresh failed; keeping current keys");
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn https_is_accepted() {
        assert!(validate_url("https://issuer.example/jwks").is_ok());
    }

    #[test]
    fn remote_http_is_refused() {
        assert!(validate_url("http://issuer.example/jwks").is_err());
    }

    #[test]
    fn loopback_http_is_allowed_for_dev() {
        assert!(validate_url("http://127.0.0.1:8200/jwks").is_ok());
        assert!(validate_url("http://localhost/jwks").is_ok());
        assert!(validate_url("http://[::1]:9000/jwks").is_ok());
    }

    #[test]
    fn empty_and_nonsense_are_refused() {
        assert!(validate_url("   ").is_err());
        assert!(validate_url("ftp://issuer.example/jwks").is_err());
        assert!(validate_url("not a url").is_err());
    }
}
