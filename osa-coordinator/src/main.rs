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
use osa_proto::v1::operator_server::OperatorServer;

mod auth;
mod broker;
mod ca;
mod revocation;
mod service;
mod token;

/// Validity of issued host certificates — short-lived; renewed per AD-11/AD-28.
const HOST_CERT_TTL: time::Duration = time::Duration::hours(24);
/// Upper bound on a join token's TTL.
const MAX_TOKEN_TTL: Duration = Duration::from_secs(3600);
/// Default join-token TTL when the operator does not request one.
const DEFAULT_TOKEN_TTL: Duration = Duration::from_secs(900);

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

    /// Path to the issuer's JWKS document (its public signing keys). v1 reads it
    /// from disk; live fetch/refresh over HTTP lands in a later story.
    #[arg(long, env = "OSA_OIDC_JWKS")]
    oidc_jwks: Option<String>,

    /// Clock-skew leeway, in seconds, applied to JWT `exp`/`nbf`.
    #[arg(long, env = "OSA_OIDC_LEEWAY_SECS", default_value_t = 60)]
    oidc_leeway_secs: u64,
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

    // Initialize the embedded CA (AD-23). For now it is generated in-memory at
    // startup; persistence lands in a later story (#7).
    let ca = Arc::new(ca::EmbeddedCa::new(HOST_CERT_TTL)?);

    // Stand up the embedded mTLS broker: issue its server cert from the CA (so an
    // agent that pinned the CA root trusts it) and write the TLS material to a
    // private temp dir the broker reads. `cert_dir` is held for the process life.
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
    broker::spawn(mqtt_addr, cert_dir.path())?;
    wait_until_listening(mqtt_addr).await?;
    tracing::info!(%mqtt_addr, broker_dns = ?cli.broker_dns, "coordinator: embedded MQTT broker (mTLS) listening");

    let tokens = Arc::new(token::JoinTokenRegistry::new(MAX_TOKEN_TTL));
    let revocations = Arc::new(revocation::RevocationRegistry::new());
    let operator = service::OperatorService::new(ca, tokens, revocations, DEFAULT_TOKEN_TTL);

    let jwt_auth = build_operator_auth(&cli)?;

    // Bound per-request time and per-connection concurrency to blunt abuse of the
    // enrollment surface.
    let mut server = tonic::transport::Server::builder()
        .timeout(Duration::from_secs(30))
        .concurrency_limit_per_connection(64);

    tracing::info!(config = %cli.config, %addr, "coordinator: serving Operator gRPC (plaintext)");
    match jwt_auth {
        Some(jwt_auth) => {
            tracing::info!("operator authentication: OIDC/JWT required (AD-18)");
            server
                .add_service(OperatorServer::with_interceptor(operator, jwt_auth))
                .serve(addr)
                .await?;
        }
        None => {
            tracing::warn!(
                "operator API is UNAUTHENTICATED — set --oidc-issuer/--oidc-audience/--oidc-jwks to require operator JWTs"
            );
            server
                .add_service(OperatorServer::new(operator))
                .serve(addr)
                .await?;
        }
    }
    Ok(())
}

/// Build the operator JWT interceptor from config, if OIDC is configured. The
/// three OIDC flags are all-or-nothing: providing some but not all is a hard
/// misconfiguration rather than a silent fallback to no auth.
fn build_operator_auth(cli: &Cli) -> anyhow::Result<Option<auth::JwtAuth>> {
    // A leeway large enough to swallow a token's whole lifetime would silently
    // defeat `exp`/`nbf`; keep the clock-skew allowance small.
    const MAX_LEEWAY_SECS: u64 = 300;
    match (&cli.oidc_issuer, &cli.oidc_audience, &cli.oidc_jwks) {
        (Some(issuer), Some(audience), Some(jwks_path)) => {
            if issuer.trim().is_empty() || audience.trim().is_empty() {
                anyhow::bail!("--oidc-issuer and --oidc-audience must be non-empty");
            }
            if cli.oidc_leeway_secs > MAX_LEEWAY_SECS {
                anyhow::bail!("--oidc-leeway-secs must be <= {MAX_LEEWAY_SECS}");
            }
            let jwks = std::fs::read(jwks_path)
                .with_context(|| format!("reading OIDC JWKS from {jwks_path}"))?;
            let policy = osa_core::auth::ValidationPolicy {
                issuer: issuer.clone(),
                audience: audience.clone(),
                leeway_secs: cli.oidc_leeway_secs,
            };
            let validator = osa_core::auth::JwtValidator::from_jwks_json(policy, &jwks)
                .map_err(|e| anyhow::anyhow!("invalid OIDC JWKS: {e}"))?;
            Ok(Some(auth::JwtAuth::new(Arc::new(validator))))
        }
        (None, None, None) => Ok(None),
        _ => anyhow::bail!(
            "operator OIDC auth requires --oidc-issuer, --oidc-audience, and --oidc-jwks together"
        ),
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
