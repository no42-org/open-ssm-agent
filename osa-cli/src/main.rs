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
    /// Coordinator gRPC endpoint.
    #[arg(
        long,
        env = "OSA_COORDINATOR",
        default_value = "https://localhost:8443"
    )]
    coordinator: String,

    #[command(subcommand)]
    command: Command,
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
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Token => println!(
            "token: scaffold — not yet implemented ({})",
            cli.coordinator
        ),
        Command::Exec { host, .. } => println!("exec on {host}: scaffold — not yet implemented"),
        Command::Shell { host } => println!("shell on {host}: scaffold — not yet implemented"),
    }
    Ok(())
}
