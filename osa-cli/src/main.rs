/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: MIT
 */

//! `osa` — the operator CLI (AD-5).
//!
//! The sole v1 client surface: talks gRPC to the coordinator (OIDC/JWT operator
//! auth, AD-18). Operators never reach agents directly (AD-2). This entrypoint
//! is a scaffold: it defines the command surface; calls land in later stories.

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "osa", version, about = "open-ssm-agent operator CLI")]
struct Cli {
    /// Coordinator gRPC endpoint. Plaintext (`http://`) for now; switches to
    /// `https://` once the coordinator's TLS is wired (a later channel story).
    #[arg(long, env = "OSA_COORDINATOR", default_value = "http://localhost:8443")]
    coordinator: String,

    /// Operator OIDC bearer token (JWT). Sent as `authorization: Bearer <token>`
    /// when the coordinator requires operator auth (AD-18). Obtain it from your
    /// OIDC provider; typically exported as `OSA_OPERATOR_TOKEN`.
    #[arg(long, env = "OSA_OPERATOR_TOKEN")]
    operator_token: Option<String>,

    #[command(subcommand)]
    command: Command,
}

/// Wrap a request message, attaching the operator bearer token (if set) as
/// gRPC `authorization` metadata.
fn authed<T>(msg: T, token: &Option<String>) -> anyhow::Result<tonic::Request<T>> {
    let mut req = tonic::Request::new(msg);
    if let Some(token) = token {
        let value = tonic::metadata::MetadataValue::try_from(format!("Bearer {token}"))
            .map_err(|_| anyhow::anyhow!("operator token is not valid ASCII"))?;
        req.metadata_mut().insert("authorization", value);
    }
    Ok(req)
}

#[derive(Subcommand)]
enum Command {
    /// Mint a short-TTL single-use join token for a new host (AD-25).
    Token,
    /// Run a command on one or more hosts and collect the result (CAP-2).
    Exec {
        /// Host selector (host_id or tag/group, AD-19).
        host: String,
        /// Command line to execute on the target.
        #[arg(last = true)]
        argv: Vec<String>,
    },
    /// Open an interactive shell on a host (CAP-3).
    Shell {
        /// Target host_id.
        host: String,
    },
    /// Revoke a host identity so it can no longer renew (AD-28).
    Revoke {
        /// Target host_id (UUID).
        host: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Token => {
            let mut client =
                osa_proto::v1::operator_client::OperatorClient::connect(cli.coordinator.clone())
                    .await?;
            let resp = client
                .mint_token(authed(
                    osa_proto::v1::MintTokenRequest { ttl_seconds: 0 },
                    &cli.operator_token,
                )?)
                .await?
                .into_inner();
            println!("join token:     {}", resp.join_token);
            println!("expires (unix): {}", resp.expires_at_unix);
        }
        Command::Revoke { host } => {
            let mut client =
                osa_proto::v1::operator_client::OperatorClient::connect(cli.coordinator.clone())
                    .await?;
            client
                .revoke(authed(
                    osa_proto::v1::RevokeRequest {
                        host_id: host.clone(),
                    },
                    &cli.operator_token,
                )?)
                .await?;
            println!("revoked {host}");
        }
        Command::Exec { host, .. } => println!("exec on {host}: scaffold — not yet implemented"),
        Command::Shell { host } => println!("shell on {host}: scaffold — not yet implemented"),
    }
    Ok(())
}
