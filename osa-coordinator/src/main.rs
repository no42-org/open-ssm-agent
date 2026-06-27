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

use clap::Parser;
use osa_proto::v1::operator_server::OperatorServer;

mod ca;
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

    let cli = Cli::parse();
    let addr: SocketAddr = cli
        .grpc_bind
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid --grpc-bind {:?}: {e}", cli.grpc_bind))?;

    // Initialize the embedded CA (AD-23). For now it is generated in-memory at
    // startup; persistence lands in a later story (#7).
    let ca = Arc::new(ca::EmbeddedCa::new(HOST_CERT_TTL)?);
    let tokens = Arc::new(token::JoinTokenRegistry::new(MAX_TOKEN_TTL));
    let operator = service::OperatorService::new(ca, tokens, DEFAULT_TOKEN_TTL);

    tracing::info!(config = %cli.config, %addr, "coordinator: serving Operator gRPC (plaintext)");
    tonic::transport::Server::builder()
        // Bound per-request time and per-connection concurrency to blunt abuse of
        // the (currently unauthenticated) enrollment surface until Epic 2.
        .timeout(Duration::from_secs(30))
        .concurrency_limit_per_connection(64)
        .add_service(OperatorServer::new(operator))
        .serve(addr)
        .await?;
    Ok(())
}
