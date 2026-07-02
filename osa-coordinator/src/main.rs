/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: MIT
 */

//! open-ssm-agent coordinator (AD-4, AD-24).
//!
//! The self-hosted control point: owns the operator-facing gRPC API (AD-5), the
//! host registry / audit / policy in Postgres (AD-15, AD-21, AD-24), the
//! embedded `CertIssuer` CA (AD-23), the NetBox `InventorySink` (AD-17), and the
//! bridge to the untrusted broker (AD-27). For v1 (tens of hosts) `rumqttd` may
//! embed here rather than run standalone (AD-3). It currently serves the
//! operator-facing `Operator` gRPC API (mint join tokens, enroll hosts); the
//! broker bridge and other ports land in later stories.
//!
//! The join-token registry is in-memory and **single-node** for v1. The
//! Postgres-backed registry that makes the coordinator stateless across N
//! replicas (AD-24) lands with the enforcement spine (Epic 2).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use clap::Parser;
use osa_proto::v1::enrollment_server::EnrollmentServer;
use osa_proto::v1::operator_server::OperatorServer;

mod audit_log;
mod auth;
mod broker;
mod ca;
mod db;
mod epoch;
mod jwks;
mod netbox;
mod policy;
mod revocation;
mod service;
mod session;
mod token;

/// Validity of issued host certificates — short-lived; renewed per AD-11/AD-28.
const HOST_CERT_TTL: time::Duration = time::Duration::hours(24);
/// Upper bound on a join token's TTL.
const MAX_TOKEN_TTL: Duration = Duration::from_secs(3600);
/// Default join-token TTL when the operator does not request one.
const DEFAULT_TOKEN_TTL: Duration = Duration::from_secs(900);
/// Bound on dispatch commands queued from the operator service to the bridge.
const BRIDGE_COMMAND_QUEUE: usize = 256;

#[derive(Parser)]
#[command(
    name = "osa-coordinator",
    version,
    about = "open-ssm-agent coordinator (control plane)"
)]
struct Cli {
    /// Path to the coordinator config file.
    #[arg(
        long,
        env = "OSA_COORDINATOR_CONFIG",
        default_value = "/etc/osa/coordinator.toml"
    )]
    config: String,

    /// gRPC operator API bind address.
    #[arg(long, env = "OSA_GRPC_BIND", default_value = "0.0.0.0:8443")]
    grpc_bind: String,

    /// Embedded MQTT broker (mTLS) bind address.
    #[arg(long, env = "OSA_MQTT_BIND", default_value = "0.0.0.0:8883")]
    mqtt_bind: String,

    /// DNS name(s) the broker's TLS certificate is valid for. Agents must reach
    /// the broker by one of these names. Comma-separated.
    #[arg(
        long,
        env = "OSA_BROKER_DNS",
        default_value = "localhost",
        value_delimiter = ','
    )]
    broker_dns: Vec<String>,

    /// OIDC issuer (`iss`) operator JWTs must carry (AD-18). Enables operator
    /// authentication; requires `--oidc-audience` and `--oidc-jwks` too.
    #[arg(long, env = "OSA_OIDC_ISSUER")]
    oidc_issuer: Option<String>,

    /// OIDC audience (`aud`) operator JWTs must carry.
    #[arg(long, env = "OSA_OIDC_AUDIENCE")]
    oidc_audience: Option<String>,

    /// Path to a static JWKS document (the issuer's public signing keys), read
    /// from disk at startup. Mutually exclusive with `--oidc-jwks-url`.
    #[arg(long, env = "OSA_OIDC_JWKS")]
    oidc_jwks: Option<String>,

    /// URL of the issuer's JWKS endpoint. Keys are fetched live at startup and
    /// re-fetched on an interval to pick up rotation. Mutually exclusive with
    /// `--oidc-jwks`.
    #[arg(long, env = "OSA_OIDC_JWKS_URL")]
    oidc_jwks_url: Option<String>,

    /// How often (seconds) to re-fetch a live JWKS for key rotation.
    #[arg(long, env = "OSA_OIDC_REFRESH_SECS", default_value_t = 300)]
    oidc_refresh_secs: u64,

    /// Clock-skew leeway, in seconds, applied to JWT `exp`/`nbf`.
    #[arg(long, env = "OSA_OIDC_LEEWAY_SECS", default_value_t = 60)]
    oidc_leeway_secs: u64,

    /// Path to the RBAC policy document (TOML, AD-19). Without it the coordinator
    /// denies every dispatch (deny-by-default).
    #[arg(long, env = "OSA_RBAC_POLICY")]
    rbac_policy: Option<String>,

    /// Postgres connection URL (AD-24). When set, durable state (the audit log
    /// now; tokens/revocation/CA with story 2.5) lives in Postgres and the
    /// coordinator is stateless across replicas. Absent → in-memory single-node.
    #[arg(long, env = "OSA_DATABASE_URL")]
    database_url: Option<String>,

    /// NetBox base URL for the inventory sink (AD-16/AD-17). When set (with
    /// `--netbox-token`), agent-reported inventory is reconciled into NetBox;
    /// absent → inventory is ignored. The coordinator holds the ONLY write
    /// credential — no host ever does.
    #[arg(long, env = "OSA_NETBOX_URL")]
    netbox_url: Option<String>,

    /// NetBox API token for the inventory sink. Required with `--netbox-url`.
    #[arg(long, env = "OSA_NETBOX_TOKEN")]
    netbox_token: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(tracing_subscriber::filter::LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .init();

    // Install the process-wide rustls crypto provider used by the broker's TLS.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let cli = Cli::parse();
    let addr: SocketAddr = cli
        .grpc_bind
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid --grpc-bind {:?}: {e}", cli.grpc_bind))?;
    let mqtt_addr: SocketAddr = cli
        .mqtt_bind
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid --mqtt-bind {:?}: {e}", cli.mqtt_bind))?;

    // Shared coordinator state (AD-24): durable in Postgres when --database-url
    // is set (stateless across replicas), otherwise in-memory single-node.
    let pool = match &cli.database_url {
        Some(url) => {
            let pool = db::connect(url).await?;
            db::migrate(&pool).await?;
            tracing::info!("state: Postgres (durable, stateless-ready)");
            Some(pool)
        }
        None => {
            tracing::warn!(
                "no --database-url — CA/token/revocation/audit state is in-memory (single-node; lost on restart)"
            );
            None
        }
    };

    // The embedded CA (AD-23). With Postgres it is generated once and shared by
    // every replica (closes #7); without, it is in-memory and regenerated on
    // restart. The CA must exist before the broker (its server cert is CA-signed).
    let ca = Arc::new(match &pool {
        Some(pool) => ca::load_or_generate(pool, HOST_CERT_TTL).await?,
        None => ca::EmbeddedCa::new(HOST_CERT_TTL)?,
    });

    let (tokens, revocations, audit, epochs) = match &pool {
        Some(pool) => (
            Arc::new(token::PgJoinTokens::new(pool.clone(), MAX_TOKEN_TTL))
                as Arc<dyn token::JoinTokens>,
            Arc::new(revocation::PgRevocations::new(pool.clone()))
                as Arc<dyn revocation::Revocations>,
            Arc::new(audit_log::PgAuditLog::new(pool.clone()))
                as Arc<dyn osa_core::ports::AuditLog>,
            Arc::new(epoch::PgEpochs::new(pool.clone())) as Arc<dyn epoch::Epochs>,
        ),
        None => (
            Arc::new(token::JoinTokenRegistry::new(MAX_TOKEN_TTL)) as Arc<dyn token::JoinTokens>,
            Arc::new(revocation::RevocationRegistry::new()) as Arc<dyn revocation::Revocations>,
            Arc::new(audit_log::MemoryAuditLog::new()) as Arc<dyn osa_core::ports::AuditLog>,
            Arc::new(epoch::EpochRegistry::new()) as Arc<dyn epoch::Epochs>,
        ),
    };

    // Stand up the embedded mTLS broker + coordinator bridge (#20): issue the
    // broker's server cert from the CA (so an agent that pinned the CA root trusts
    // it) and write the TLS material to a private temp dir the broker reads. The
    // bridge verifies host certs and drives the session handshake, so it needs the
    // CA and the revocation store. `cert_dir` is held for the process life.
    let cert_dir = tempfile::TempDir::new().context("creating broker cert dir")?;
    let dns: Vec<&str> = cli.broker_dns.iter().map(String::as_str).collect();
    let server_cert = ca.issue_server_cert(&dns)?;
    std::fs::write(
        cert_dir.path().join(broker::BROKER_CERT),
        &server_cert.cert_pem,
    )?;
    write_secret(
        &cert_dir.path().join(broker::BROKER_KEY),
        &server_cert.key_pem,
    )?;
    std::fs::write(cert_dir.path().join(broker::CA_CERT), ca.ca_root_pem())?;
    // The NetBox inventory sink (AD-16/AD-17): the coordinator holds the single
    // write credential. Configured → agent-reported inventory is reconciled into
    // NetBox; absent → inventory is ignored. The bridge upserts through it.
    let inventory_sink = build_inventory_sink(&cli).await?;

    // The operator service hands dispatches to the bridge over this channel; the
    // bridge seals them to host sessions and streams results back (Epic 3).
    let (bridge_tx, bridge_rx) = tokio::sync::mpsc::channel(BRIDGE_COMMAND_QUEUE);
    broker::spawn(
        mqtt_addr,
        cert_dir.path(),
        ca.clone(),
        revocations.clone(),
        epochs,
        inventory_sink,
        bridge_rx,
    )?;
    wait_until_listening(mqtt_addr).await?;
    tracing::info!(%mqtt_addr, broker_dns = ?cli.broker_dns, "coordinator: embedded MQTT broker (mTLS) + session bridge listening");

    let policy = build_policy_engine(&cli)?;
    let operator = service::OperatorService::new(
        ca,
        tokens,
        revocations,
        policy,
        audit,
        bridge_tx,
        DEFAULT_TOKEN_TTL,
    );

    let jwt_auth = build_operator_auth(&cli).await?;

    tracing::info!(config = %cli.config, %addr, "coordinator: serving Operator + Enrollment gRPC (plaintext)");
    if jwt_auth.is_some() {
        tracing::info!("operator authentication: OIDC/JWT required (AD-18)");
    } else {
        tracing::warn!(
            "operator API is UNAUTHENTICATED — set --oidc-issuer/--oidc-audience/--oidc-jwks to require operator JWTs"
        );
    }
    build_router(operator, jwt_auth).serve(addr).await?;
    Ok(())
}

/// Assemble the gRPC router: the operator-facing `Operator` service behind the
/// optional operator JWT interceptor (AD-18), and the agent-facing `Enrollment`
/// service (Enroll/Renew), which is **never** interceptor-gated — it carries its
/// own authentication (single-use join token / cert proof-of-possession, AD-25).
///
/// Extracted from `main` so the auth boundary is exercised by a wire-level test
/// (see `tests` below) rather than only assembled inline. A regression that
/// re-wrapped Enrollment in the operator gate — the exact shape of #31 — would
/// break agent enroll/renew while every in-process handler unit test still
/// passed, because those bypass the gRPC server + interceptor entirely.
fn build_router(
    operator: service::OperatorService,
    jwt_auth: Option<auth::JwtAuth>,
) -> tonic::transport::server::Router {
    let enrollment = EnrollmentServer::new(operator.clone());
    // Bound per-request time and per-connection concurrency to blunt abuse of the
    // enrollment surface.
    let mut server = tonic::transport::Server::builder()
        .timeout(Duration::from_secs(30))
        .concurrency_limit_per_connection(64);
    match jwt_auth {
        Some(jwt_auth) => server
            .add_service(OperatorServer::with_interceptor(operator, jwt_auth))
            .add_service(enrollment),
        None => server
            .add_service(OperatorServer::new(operator))
            .add_service(enrollment),
    }
}

/// Build the NetBox inventory sink (AD-16/AD-17) if configured. `--netbox-url` +
/// `--netbox-token` must be set together; neither → no sink (inventory ignored),
/// one without the other is a hard misconfiguration, never a silent fallback.
async fn build_inventory_sink(
    cli: &Cli,
) -> anyhow::Result<Option<Arc<dyn osa_core::ports::InventorySink>>> {
    match (&cli.netbox_url, &cli.netbox_token) {
        (Some(url), Some(token)) => {
            anyhow::ensure!(
                !url.trim().is_empty() && !token.trim().is_empty(),
                "--netbox-url and --netbox-token must be non-empty"
            );
            let config = netbox::NetboxConfig {
                url: url.clone(),
                token: token.clone(),
            };
            let client = netbox::NetboxClient::new(&config)?;
            // Warn early if the osa_host_id custom field is missing (else every
            // stamp 400s); non-blocking so the coordinator still serves the rest.
            client.preflight().await;
            tracing::info!(%url, "NetBox inventory sink configured (AD-17)");
            Ok(Some(Arc::new(netbox::NetboxInventorySink::new(client))))
        }
        (None, None) => {
            tracing::info!(
                "no --netbox-url — agent-reported inventory is ignored (no NetBox sink)"
            );
            Ok(None)
        }
        _ => anyhow::bail!("--netbox-url and --netbox-token must be set together"),
    }
}

/// Build the deny-by-default RBAC PDP (AD-19) from the policy file, or an
/// empty (deny-all) engine if none is configured.
fn build_policy_engine(cli: &Cli) -> anyhow::Result<Arc<dyn osa_core::ports::PolicyEngine>> {
    match &cli.rbac_policy {
        Some(path) => {
            let doc = std::fs::read_to_string(path)
                .with_context(|| format!("reading RBAC policy {path}"))?;
            let engine = policy::RbacPolicyEngine::from_toml(&doc)?;
            if engine.is_empty() {
                tracing::warn!(
                    %path,
                    "RBAC policy has no bindings — every dispatch is denied (deny-by-default)"
                );
            }
            Ok(Arc::new(engine))
        }
        None => {
            tracing::warn!(
                "no --rbac-policy configured — every dispatch is denied (deny-by-default)"
            );
            Ok(Arc::new(policy::RbacPolicyEngine::empty()))
        }
    }
}

/// Build the operator JWT interceptor from config, if OIDC is configured.
///
/// `--oidc-issuer` + `--oidc-audience` enable auth and require exactly one key
/// source — `--oidc-jwks <file>` (static) or `--oidc-jwks-url <url>` (live,
/// auto-refreshed). Anything partial is a hard misconfiguration, never a silent
/// fallback to no auth.
async fn build_operator_auth(cli: &Cli) -> anyhow::Result<Option<auth::JwtAuth>> {
    // A leeway large enough to swallow a token's whole lifetime would silently
    // defeat `exp`/`nbf`; keep the clock-skew allowance small.
    const MAX_LEEWAY_SECS: u64 = 300;
    match (&cli.oidc_issuer, &cli.oidc_audience) {
        (Some(issuer), Some(audience)) => {
            anyhow::ensure!(
                !issuer.trim().is_empty() && !audience.trim().is_empty(),
                "--oidc-issuer and --oidc-audience must be non-empty"
            );
            anyhow::ensure!(
                cli.oidc_leeway_secs <= MAX_LEEWAY_SECS,
                "--oidc-leeway-secs must be <= {MAX_LEEWAY_SECS}"
            );
            let config = jwks::OidcConfig {
                issuer: issuer.clone(),
                audience: audience.clone(),
                leeway_secs: cli.oidc_leeway_secs,
            };
            match (&cli.oidc_jwks, &cli.oidc_jwks_url) {
                (Some(path), None) => {
                    anyhow::ensure!(!path.trim().is_empty(), "--oidc-jwks must not be empty");
                    let bytes = std::fs::read(path)
                        .with_context(|| format!("reading OIDC JWKS from {path}"))?;
                    let validator =
                        osa_core::auth::JwtValidator::from_jwks_json(config.policy(), &bytes)
                            .map_err(|e| anyhow::anyhow!("invalid OIDC JWKS: {e}"))?;
                    tracing::info!(%path, "operator JWKS loaded from file (static)");
                    Ok(Some(auth::JwtAuth::new(Arc::new(validator))))
                }
                (None, Some(url)) => {
                    anyhow::ensure!(
                        cli.oidc_refresh_secs >= 1,
                        "--oidc-refresh-secs must be >= 1"
                    );
                    // Enforce https (or loopback http) before the first fetch and
                    // for every refresh — the key endpoint is the auth trust root.
                    let url = jwks::validate_url(url)?;
                    let validator = jwks::fetch_validator(&config, &url).await?;
                    let jwt_auth = auth::JwtAuth::new(Arc::new(validator));
                    jwks::spawn_refresh(
                        jwt_auth.cell(),
                        config,
                        url.clone(),
                        Duration::from_secs(cli.oidc_refresh_secs),
                    );
                    tracing::info!(%url, refresh_secs = cli.oidc_refresh_secs, "operator JWKS fetched live; key-rotation refresh enabled");
                    Ok(Some(jwt_auth))
                }
                (None, None) => anyhow::bail!(
                    "operator OIDC auth requires --oidc-jwks <file> or --oidc-jwks-url <url>"
                ),
                (Some(_), Some(_)) => {
                    anyhow::bail!("--oidc-jwks and --oidc-jwks-url are mutually exclusive")
                }
            }
        }
        (None, None) => {
            anyhow::ensure!(
                cli.oidc_jwks.is_none() && cli.oidc_jwks_url.is_none(),
                "--oidc-jwks/--oidc-jwks-url require --oidc-issuer and --oidc-audience"
            );
            Ok(None)
        }
        _ => anyhow::bail!("--oidc-issuer and --oidc-audience must be set together"),
    }
}

/// Write a secret file owner-only (0600) on Unix, created with that mode so the
/// bytes never touch disk world-readable.
fn write_secret(path: &std::path::Path, contents: &str) -> anyhow::Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    f.write_all(contents.as_bytes())?;
    Ok(())
}

/// Probe until the embedded broker accepts a TCP connection, so a bind failure
/// surfaces at startup instead of as a silently dead control plane.
async fn wait_until_listening(addr: SocketAddr) -> anyhow::Result<()> {
    let probe = if addr.ip().is_unspecified() {
        SocketAddr::new(std::net::Ipv4Addr::LOCALHOST.into(), addr.port())
    } else {
        addr
    };
    for _ in 0..50 {
        if tokio::net::TcpStream::connect(probe).await.is_ok() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    anyhow::bail!("embedded broker did not start listening on {addr}")
}

/// The operator/enrollment **auth boundary**, exercised over a real gRPC
/// connection through `build_router` (#33). This is the gap that hid #31: the
/// operator JWT interceptor once wrapped the whole service, breaking agent
/// enroll/renew — yet every handler unit test passed, because they call handlers
/// in-process and never traverse the server + interceptor. These tests connect a
/// real client to a real server and assert the boundary at the wire:
///
/// - operator RPCs (e.g. `MintToken`) REQUIRE a valid operator JWT, and
/// - the agent `Enrollment` surface is reachable WITHOUT one (it runs its own
///   token / proof-of-possession auth instead).
#[cfg(test)]
mod auth_boundary_tests {
    use super::*;
    use std::time::Duration as StdDuration;

    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    use osa_core::auth::{JwtValidator, ValidationPolicy};
    use osa_proto::v1::enrollment_client::EnrollmentClient;
    use osa_proto::v1::operator_client::OperatorClient;
    use osa_proto::v1::{EnrollRequest, MintTokenRequest};
    use serde::Serialize;
    use tokio::net::TcpListener;
    use tokio_stream::wrappers::TcpListenerStream;
    use tonic::transport::{Channel, Endpoint};

    const ISSUER: &str = "https://issuer.example/";
    const AUDIENCE: &str = "osa-coordinator";

    // Hermetic RS256 test material (same throwaway key the osa-core/auth tests
    // use): the private PEM mints tokens here; the validator parses the matching
    // public JWKS. Generated offline; never used outside tests.
    const TEST_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCfE4eSObMn1QZq
7aeBKXKo3K0mvMS+iZo9aQMbX7MrpQLfeMOxUiXPcdsIxputElzjQCazgkv3MxWF
e61qx6EGOuk+4CL46RG4Wq+SppaUoLCGlOdY3aFhX5t7d/ZsL1e4q/8lOSKLPTM6
0oQ4oTKvMhBuRjED7DLq6V4MmISoNNBF8ZPWuXgnMEqDwJmbrmMPPpP3F/SK0QcW
8LFBAMQfOO1pKQzcj1ayujE8afRwo7u1N64BM7ojf1XhzTwfn0SX0CiwOf4dcGBo
rcoHZe8GQxNKScz/1R42bHP7ItjbvvraFEyz9U/AQp2Vp6sdBakT5LQXk4IUH3J1
wEtLynatAgMBAAECggEAJP213CE6QbQ1/JX8ilrAzLcaNaSWTKdzXD3n6MzpfWfv
AdfTi8+qNrHHaSREDaw0OO0RQtN1BkwVAFgI9Mhsr6Xx2LrmrwKFqhy+cKf34qJ2
QilsnbvV++5vWbgE79XXfHxUhcuiNoY5/D75W7DSeC54Zyg/3CVoFrvDMMMjr/hQ
JzJsdmAJ7dG9358eQXdoTJiMrhNmxuIQHy9DqOcEVpsBp1uKrvEaRDb6phj5HHIz
TtoOPRTFC79dkZ9fyeYV/Ku5qPVT3wJrv+pWUylSaBGwrmP7rsgVumauqCR8Yx/p
dwSGsMYSKj4RDPJqdprVj8LP0u4b+KWDo+lsmp8qOQKBgQDO7DpCeDz7mOZbDAJz
4VlvaQt7YT3++wQ3eJSjBu2DzOdVdbaV4j6TIRS4zz45YV/WgvlP3cYCnXvdSX3P
6sPx+g0Eb9F7bwfyXNMSX1fyF1SagHuZ2NMDNu8xnh1HGVFpc/gIDvkKrVZojaXf
gtdUCOlmi3orGn6sBAz0ycjvRQKBgQDEzjKSYJClzDd0RbBEB8TJDIpzR+KwN+B7
SZ+D9VE6cKz2f2GMXckH+4m2tnncFhFD+ZK0pY41+LI5v72f2Q6K0qXT0rMWvj5j
WT8NlmoB3YxJVyryDQEdPJGnyy+dXXuUkQaVGCQUDTQF2FA4F8rxaDjYhvBZgvQP
Vj0XUhsMSQKBgQC4AoqsoZBZjVcMkFl+A2AtGxUC2y7umPre+XP0piyBkK4H6W49
S7ypyjlLP8Dt9hHsCPz8cROtL67+0mP3iaZGgT8iOu3m/o3qkXGCXRcwSl8KJkfE
QHUl3qxHS3xtxa4IQQDI6ce+HvdAcvaXFRu3t1UXw+EYg68x+UgsR2VQoQKBgAM2
kqDNLs9mLCmb0arqrY3SxJfpPow9/U5F/3K6GJ9po4lKvx75kQSuWKtBA3BSc+m2
M2z7nvzGmLJUrRXlB1XA5rA0qnPem0on9N2V7RkmstmnsK3PBIujp4Ujzh01n4Tn
cUIR6NTi+kx2IakoyklyuCrg2R+9AZsWf1zYHFTxAoGAR3I7LujdzIRNXPtZEmyl
hdSa21dZ/yguvJEGuXkEEA6uDbWZ8NJBQWgSO7er6526z+nEPMT3CxLHwan6bqAO
lC0IHFk6GDyzSxlPRKbLMCRIO+rU8vfX7PwolHxYzVqxX3MlrOD3sJdURsVp+Qh9
ycpRumeHZKJHtUrce7hTefI=
-----END PRIVATE KEY-----";

    const TEST_JWKS: &str = r#"{"keys":[{"kty":"RSA","kid":"test-key-1","use":"sig","alg":"RS256","n":"nxOHkjmzJ9UGau2ngSlyqNytJrzEvomaPWkDG1-zK6UC33jDsVIlz3HbCMabrRJc40Ams4JL9zMVhXutasehBjrpPuAi-OkRuFqvkqaWlKCwhpTnWN2hYV-be3f2bC9XuKv_JTkiiz0zOtKEOKEyrzIQbkYxA-wy6uleDJiEqDTQRfGT1rl4JzBKg8CZm65jDz6T9xf0itEHFvCxQQDEHzjtaSkM3I9WsroxPGn0cKO7tTeuATO6I39V4c08H59El9AosDn-HXBgaK3KB2XvBkMTSknM_9UeNmxz-yLY27762hRMs_VPwEKdlaerHQWpE-S0F5OCFB9ydcBLS8p2rQ","e":"AQAB"}]}"#;

    #[derive(Serialize)]
    struct Claims {
        sub: String,
        iss: String,
        aud: String,
        exp: i64,
    }

    /// A valid operator JWT signed by the test key.
    fn valid_token() -> String {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let claims = Claims {
            sub: "alice@example".into(),
            iss: ISSUER.into(),
            aud: AUDIENCE.into(),
            exp: now + 3600,
        };
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("test-key-1".into());
        encode(
            &header,
            &claims,
            &EncodingKey::from_rsa_pem(TEST_KEY_PEM.as_bytes()).unwrap(),
        )
        .unwrap()
    }

    /// Wrap a message with the operator `authorization: Bearer <token>` metadata.
    fn authed<T>(msg: T, token: &str) -> tonic::Request<T> {
        let mut req = tonic::Request::new(msg);
        req.metadata_mut().insert(
            "authorization",
            tonic::metadata::MetadataValue::try_from(format!("Bearer {token}")).unwrap(),
        );
        req
    }

    fn jwt_auth() -> auth::JwtAuth {
        let policy = ValidationPolicy {
            issuer: ISSUER.into(),
            audience: AUDIENCE.into(),
            leeway_secs: 60,
        };
        let v = JwtValidator::from_jwks_json(policy, TEST_JWKS.as_bytes()).unwrap();
        auth::JwtAuth::new(Arc::new(v))
    }

    fn operator_service() -> service::OperatorService {
        let ca = Arc::new(ca::EmbeddedCa::new(time::Duration::hours(24)).unwrap());
        let tokens = Arc::new(token::JoinTokenRegistry::new(StdDuration::from_secs(3600)));
        let revocations = Arc::new(revocation::RevocationRegistry::new());
        let policy = Arc::new(policy::RbacPolicyEngine::empty());
        let audit = Arc::new(audit_log::MemoryAuditLog::new());
        // No dispatch is issued in these tests, so a closed bridge channel is fine.
        let (bridge_tx, _bridge_rx) = tokio::sync::mpsc::channel(8);
        service::OperatorService::new(
            ca,
            tokens,
            revocations,
            policy,
            audit,
            bridge_tx,
            StdDuration::from_secs(900),
        )
    }

    fn csr() -> Vec<u8> {
        let key = rcgen::KeyPair::generate().unwrap();
        rcgen::CertificateParams::default()
            .serialize_request(&key)
            .unwrap()
            .der()
            .to_vec()
    }

    /// Serve the real router (OIDC required) on an ephemeral port; return its URL.
    /// The listener is bound (and thus accepting) before we return, so a client
    /// can connect immediately without racing the spawned server task.
    async fn serve() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let router = build_router(operator_service(), Some(jwt_auth()));
        tokio::spawn(async move {
            router
                .serve_with_incoming(TcpListenerStream::new(listener))
                .await
                .unwrap();
        });
        format!("http://{addr}")
    }

    async fn channel(url: &str) -> Channel {
        Endpoint::from_shared(url.to_string())
            .unwrap()
            .connect()
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn operator_rpc_without_a_token_is_unauthenticated() {
        let url = serve().await;
        let mut client = OperatorClient::new(channel(&url).await);
        let err = client
            .mint_token(MintTokenRequest { ttl_seconds: 0 })
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }

    #[tokio::test]
    async fn operator_rpc_with_a_bad_token_is_unauthenticated() {
        let url = serve().await;
        let mut client = OperatorClient::new(channel(&url).await);
        let err = client
            .mint_token(authed(MintTokenRequest { ttl_seconds: 0 }, "not.a.jwt"))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }

    #[tokio::test]
    async fn operator_rpc_with_a_valid_token_succeeds() {
        let url = serve().await;
        let mut client = OperatorClient::new(channel(&url).await);
        let resp = client
            .mint_token(authed(MintTokenRequest { ttl_seconds: 0 }, &valid_token()))
            .await
            .unwrap()
            .into_inner();
        assert!(!resp.join_token.is_empty());
    }

    /// The #31 regression guard: with OIDC required on the operator surface, an
    /// agent still enrolls with NO operator token. An operator mints a join token
    /// (authenticated); the agent redeems it over the ungated Enrollment service
    /// and gets a real identity back. Under the #31 bug this `enroll` would return
    /// `Unauthenticated` and the unwrap would panic.
    #[tokio::test]
    async fn enrollment_is_reachable_without_an_operator_token() {
        let url = serve().await;

        let mut operator = OperatorClient::new(channel(&url).await);
        let join_token = operator
            .mint_token(authed(MintTokenRequest { ttl_seconds: 0 }, &valid_token()))
            .await
            .unwrap()
            .into_inner()
            .join_token;

        let mut agent = EnrollmentClient::new(channel(&url).await);
        let resp = agent
            .enroll(EnrollRequest {
                join_token,
                csr: csr(),
            })
            .await
            .expect("enroll must NOT be behind the operator JWT gate (#31)")
            .into_inner();
        assert_eq!(
            uuid::Uuid::parse_str(&resp.host_id)
                .unwrap()
                .get_version_num(),
            4,
            "a successful enroll returns a UUIDv4 host_id"
        );
    }

    /// Enrollment runs its OWN auth, not the operator gate: a bogus join token is
    /// `PermissionDenied` by the handler — proof the request reached it — rather
    /// than `Unauthenticated` from an interceptor that never should have run.
    #[tokio::test]
    async fn enrollment_runs_its_own_auth_not_the_operator_gate() {
        let url = serve().await;
        let mut agent = EnrollmentClient::new(channel(&url).await);
        let err = agent
            .enroll(EnrollRequest {
                join_token: "nope".into(),
                csr: csr(),
            })
            .await
            .unwrap_err();
        // PermissionDenied — the Enrollment handler's OWN token check ran and
        // denied — NOT Unauthenticated, which would mean the operator interceptor
        // (which must never gate Enrollment) ran instead (#31).
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }
}
