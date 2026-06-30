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

mod backstop;
mod control_channel;
mod dispatch;
mod enroll;
mod exec;
mod session;

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
    /// Run the agent: dial the broker outbound over mTLS and serve actions.
    Run {
        /// Directory holding the enrolled identity.
        #[arg(long, env = "OSA_STATE_DIR", default_value = "/var/lib/osa")]
        state_dir: PathBuf,
        /// Coordinator gRPC endpoint (used for background cert renewal).
        #[arg(long, env = "OSA_COORDINATOR", default_value = "http://localhost:8443")]
        coordinator: String,
        /// Broker host (must match the broker certificate name).
        #[arg(long, env = "OSA_BROKER_HOST", default_value = "localhost")]
        broker_host: String,
        /// Broker mTLS port.
        #[arg(long, env = "OSA_BROKER_PORT", default_value_t = 8883)]
        broker_port: u16,
        /// Path to the host-local allowlist (TOML, AD-20). Without it the agent
        /// refuses every dispatched action (deny-by-default).
        #[arg(long, env = "OSA_ALLOWLIST")]
        allowlist: Option<PathBuf>,
    },
    /// Evaluate an action against the host-local allowlist (AD-20) without
    /// running it — to validate an allowlist before deploying it.
    Check {
        /// Path to the host-local allowlist (TOML).
        #[arg(long, env = "OSA_ALLOWLIST")]
        allowlist: Option<PathBuf>,
        /// Action kind / verb (e.g. `exec`).
        #[arg(long)]
        kind: String,
        /// Target unix user; empty means the agent's default user.
        #[arg(long, default_value = "")]
        run_as: String,
    },
    /// Renew the host certificate before it expires (AD-11/AD-28).
    Renew {
        /// Coordinator gRPC endpoint.
        #[arg(long, env = "OSA_COORDINATOR", default_value = "http://localhost:8443")]
        coordinator: String,
        /// Directory holding the enrolled identity.
        #[arg(long, env = "OSA_STATE_DIR", default_value = "/var/lib/osa")]
        state_dir: PathBuf,
    },
    /// Run a command locally under `run_as` and report its output + exit status —
    /// validate the exec capability and privilege drop on this host before relying
    /// on dispatched execution (parallels `check`). The agent must be able to drop
    /// to `run_as` (typically run as root) for a non-empty `--run-as`.
    Exec {
        /// Target unix user; empty runs as the agent's own user.
        #[arg(long, default_value = "")]
        run_as: String,
        /// The command and its arguments, after `--`.
        #[arg(last = true, required = true)]
        argv: Vec<String>,
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

    // Process-wide rustls crypto provider used by the mTLS control channel.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

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
        Command::Renew {
            coordinator,
            state_dir,
        } => {
            enroll::renew(coordinator, &state_dir).await?;
            tracing::info!(state_dir = %state_dir.display(), "certificate renewed");
        }
        Command::Run {
            state_dir,
            coordinator,
            broker_host,
            broker_port,
            allowlist,
        } => {
            // Load the host backstop (AD-20) and announce it. The dispatch job
            // runner (Epic 3) evaluates every dispatched action through it before
            // any side effect.
            let backstop = std::sync::Arc::new(backstop::load(allowlist.as_deref())?);
            backstop::log_active(&backstop);
            // Renew the cert in the background as it nears expiry.
            tokio::spawn(enroll::renewal_loop(coordinator, state_dir.clone()));
            control_channel::run(&state_dir, &broker_host, broker_port, backstop).await?;
        }
        Command::Exec { run_as, argv } => {
            use std::io::Write;
            let outcome = exec::run(argv, run_as).await?;
            tracing::info!(kind = exec::KIND, "exec finished");
            // Mirror the captured streams, then exit with the child's status. Write
            // errors (e.g. a closed pipe) must not replace the real exit code, and
            // stdout (a line-buffered LineWriter) must be flushed before the
            // `process::exit` below skips destructors.
            let mut stdout = std::io::stdout();
            let _ = stdout.write_all(&outcome.stdout);
            let _ = stdout.flush();
            let _ = std::io::stderr().write_all(&outcome.stderr);
            match (outcome.exit_code, outcome.signal) {
                (Some(code), _) => std::process::exit(code),
                (None, Some(sig)) => {
                    eprintln!("terminated by signal {sig}");
                    std::process::exit(128 + sig);
                }
                (None, None) => std::process::exit(1),
            }
        }
        Command::Check {
            allowlist,
            kind,
            run_as,
        } => {
            let backstop = backstop::load(allowlist.as_deref())?;
            let action = osa_proto::v1::ActionDescriptor {
                kind: kind.clone(),
                target: String::new(),
                run_as: run_as.clone(),
                params_hash: Vec::new(),
            };
            match backstop.permits(&action) {
                Ok(()) => println!("PERMITTED: kind={kind} run_as={run_as:?}"),
                Err(denial) => {
                    eprintln!("REFUSED: {denial}");
                    std::process::exit(1);
                }
            }
        }
    }
    Ok(())
}
