/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: MIT
 */

//! open-ssm-agent host agent (AD-2, AD-32).
//!
//! Single-process `tokio` core that dials **outbound only** to the broker
//! (never listens), wires the `ControlChannel` and capability adapters, and
//! enforces the host-local backstop (AD-20). Interactive sessions run as
//! isolated child processes (AD-14). The `enroll` subcommand mints the host's
//! identity (AD-11/AD-25); the `run` adapters land in later stories.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

mod enroll;

#[derive(Parser)]
#[command(
    name = "osa-agent",
    version,
    about = "open-ssm-agent host agent (outbound-only)"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Join the fleet with a short-TTL single-use token (AD-25).
    Enroll {
        /// Coordinator enrollment endpoint.
        #[arg(long, env = "OSA_COORDINATOR")]
        coordinator: String,
        /// Short-TTL single-use join token.
        #[arg(long, env = "OSA_JOIN_TOKEN")]
        token: String,
        /// Directory the minted identity is persisted to.
        #[arg(long, env = "OSA_STATE_DIR", default_value = "/var/lib/osa")]
        state_dir: PathBuf,
        /// Re-enroll even if an identity already exists.
        #[arg(long)]
        force: bool,
    },
    /// Run the agent: dial the broker and serve dispatched actions.
    Run {
        /// Path to the agent config file.
        #[arg(long, env = "OSA_AGENT_CONFIG", default_value = "/etc/osa/agent.toml")]
        config: String,
    },
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
    match cli.command {
        Command::Enroll {
            coordinator,
            token,
            state_dir,
            force,
        } => {
            let host_id = enroll::run(coordinator, token, &state_dir, force).await?;
            tracing::info!(%host_id, state_dir = %state_dir.display(), "enrolled");
        }
        Command::Run { config } => {
            tracing::info!(%config, "run: scaffold — not yet implemented");
        }
    }
    Ok(())
}
