/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: MIT
 */

//! open-ssm-agent coordinator (AD-4, AD-24).
//!
//! The self-hosted control point: owns the operator-facing gRPC API (AD-5), the
//! host registry / audit / policy in Postgres (AD-15, AD-21, AD-24), the
//! embedded `CertIssuer` CA (AD-23), the NetBox `InventorySink` (AD-17), and the
//! bridge to the untrusted broker (AD-27). Stateless across N replicas. For v1
//! (tens of hosts) `rumqttd` may embed here rather than run standalone (AD-3).
//! This entrypoint is a scaffold: it wires config + logging and parks.

use clap::Parser;

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
    tracing::info!(config = %cli.config, grpc_bind = %cli.grpc_bind, "coordinator: scaffold — not yet implemented");
    Ok(())
}
