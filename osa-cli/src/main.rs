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
    /// Run a command across a host selector and stream per-host output (CAP-2).
    Exec {
        /// Host selector: a host_id, a comma-separated list, or `*` (all online).
        host: String,
        /// Target unix user; empty runs as the agent's own user.
        #[arg(long, default_value = "")]
        run_as: String,
        /// Command line to execute on the target, after `--`.
        #[arg(last = true)]
        argv: Vec<String>,
    },
    /// Open an interactive shell on a host (CAP-3).
    Shell {
        /// Target host_id (UUID).
        host: String,
        /// Target unix user; empty runs the agent's own shell.
        #[arg(long, default_value = "")]
        run_as: String,
    },
    /// Revoke a host identity so it can no longer renew (AD-28).
    Revoke {
        /// Target host_id (UUID).
        host: String,
    },
    /// Inspect the coordinator's tamper-evident audit log (AD-21).
    Audit {
        #[command(subcommand)]
        command: AuditCommand,
    },
}

#[derive(Subcommand)]
enum AuditCommand {
    /// Export the audit chain and verify its integrity client-side.
    Verify {
        /// Hex-encoded last-known chain head (the `head:` line from a previous
        /// run). If given, the chain must still end there — this is what detects
        /// tail truncation or a rewrite of recent history (AD-21).
        #[arg(long)]
        expect_head: Option<String>,
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
        Command::Exec { host, run_as, argv } => {
            use osa_proto::v1::{exec_event::Event, job_outcome::Terminal, output_chunk::Stream};
            use std::io::Write;

            if argv.is_empty() {
                anyhow::bail!("no command given — use: osa exec <selector> -- <cmd> [args...]");
            }
            let mut client =
                osa_proto::v1::operator_client::OperatorClient::connect(cli.coordinator.clone())
                    .await?;
            // The capability params are opaque to the coordinator (AD-12): the CLI
            // encodes ExecParams and the coordinator seals the bytes unparsed. The
            // params_hash binds the authorized action to exactly these params.
            let params = osa_core::wire::encode(&osa_proto::v1::ExecParams { argv });
            let params_hash = osa_core::wire::params_hash(&params);
            let req = authed(
                osa_proto::v1::DispatchRequest {
                    action: Some(osa_proto::v1::ActionDescriptor {
                        kind: "exec".into(),
                        target: host.clone(), // a selector: a host_id, a comma-list, or "*"
                        run_as,
                        params_hash,
                    }),
                    params,
                },
                &cli.operator_token,
            )?;
            let mut stream = client.exec(req).await?.into_inner();
            // Per-host streaming: tag output (to stderr) when the producing host
            // changes, and collect a per-host terminal status; exit non-zero if any
            // host failed. NOTE: for a multi-host fan-out, redirecting stdout
            // concatenates all hosts' output without in-band markers (the host
            // headers go to stderr) — a structured `--json` mode is a follow-up.
            let mut last_host: Option<String> = None;
            let mut hosts_reported = 0usize;
            let mut failures = 0usize;
            while let Some(event) = stream.message().await? {
                let host = event.host_id;
                match event.event {
                    Some(Event::Chunk(chunk)) => {
                        if last_host.as_deref() != Some(host.as_str()) {
                            eprintln!("==> {host} <==");
                            last_host = Some(host);
                        }
                        if chunk.stream() == Stream::Stderr {
                            std::io::stderr().write_all(&chunk.data)?;
                        } else {
                            let mut out = std::io::stdout();
                            out.write_all(&chunk.data)?;
                            out.flush()?;
                        }
                    }
                    Some(Event::Outcome(outcome)) => {
                        hosts_reported += 1;
                        let mut flags = String::new();
                        if outcome.output_truncated {
                            flags.push_str(" [output truncated]");
                        }
                        if outcome.timed_out {
                            flags.push_str(" [timed out]");
                        }
                        let status = match outcome.terminal {
                            Some(Terminal::ExitCode(0)) => "exit 0".to_string(),
                            Some(Terminal::ExitCode(code)) => {
                                failures += 1;
                                format!("exit {code}")
                            }
                            Some(Terminal::Signal(sig)) => {
                                failures += 1;
                                format!("signal {sig}")
                            }
                            Some(Terminal::Error(msg)) => {
                                failures += 1;
                                format!("error: {msg}")
                            }
                            None => {
                                failures += 1;
                                "no status".to_string()
                            }
                        };
                        eprintln!("[osa] {host}: {status}{flags}");
                    }
                    None => {}
                }
            }
            eprintln!("[osa] {hosts_reported} host(s) reported, {failures} failed");
            std::process::exit(if failures == 0 && hosts_reported > 0 {
                0
            } else {
                1
            });
        }
        Command::Shell { host, run_as } => {
            // Enter raw mode BEFORE the session (so even the first keystrokes are raw)
            // and restore it explicitly below — `process::exit` skips destructors.
            let raw = RawMode::enable();
            let result =
                run_shell_session(cli.coordinator.clone(), cli.operator_token, host, run_as).await;
            drop(raw); // restore the local terminal

            // Exit the process directly rather than returning: the spawned stdin
            // reader is parked in a blocking `read(2)` that runtime teardown would
            // otherwise wait on (hanging the command until the next keypress).
            match result {
                Ok(()) => std::process::exit(0),
                Err(e) => {
                    eprintln!("osa shell: {e:#}");
                    std::process::exit(1);
                }
            }
        }
        Command::Audit {
            command: AuditCommand::Verify { expect_head },
        } => {
            let anchor = expect_head.as_deref().map(parse_head).transpose()?;
            let mut client =
                osa_proto::v1::operator_client::OperatorClient::connect(cli.coordinator.clone())
                    .await?;
            let resp = client
                .export_audit(authed(
                    osa_proto::v1::ExportAuditRequest {},
                    &cli.operator_token,
                )?)
                .await?
                .into_inner();

            // Recompute the chain locally rather than trusting a server verdict.
            // NOTE: recomputing an unsigned chain proves only internal
            // consistency. Detecting truncation/rewrite of recent history needs
            // `--expect-head <hash>` (a head the operator recorded earlier);
            // detecting a wholesale re-chain by a compromised coordinator needs a
            // signed head (issue #24, lands with the durable store 2.3b).
            let entries = resp
                .entries
                .iter()
                .map(to_audit_entry)
                .collect::<anyhow::Result<Vec<_>>>()?;
            let count = entries.len();
            match osa_core::audit::verify(&entries, anchor) {
                Ok(()) => {
                    if count == 0 {
                        println!("audit chain is EMPTY (0 entries)");
                    } else {
                        let head = to_hex(&entries[count - 1].hash);
                        let anchored = if anchor.is_some() { ", anchored" } else { "" };
                        println!("audit chain OK — {count} entries verified{anchored}");
                        println!("head: {head}");
                    }
                }
                Err(e) => {
                    eprintln!("audit verification FAILED: {e}");
                    std::process::exit(1);
                }
            }
        }
    }
    Ok(())
}

/// Default terminal size for `osa shell` when the local size can't be queried
/// (e.g. stdout is not a terminal).
const DEFAULT_ROWS: u16 = 24;
const DEFAULT_COLS: u16 = 80;

/// Run one interactive shell session: open the bidirectional `Shell` stream (with a
/// `ShellOpen` sized to the local terminal), pump local stdin → `input` frames, and
/// write `output` frames to stdout until the remote shell closes. The caller owns
/// raw-mode setup/restore and process exit.
async fn run_shell_session(
    coordinator: String,
    token: Option<String>,
    host: String,
    run_as: String,
) -> anyhow::Result<()> {
    use osa_proto::v1::shell_client_msg::Msg as ClientMsg;
    use osa_proto::v1::shell_server_msg::Msg as ServerMsg;
    use osa_proto::v1::{ShellClientMsg, ShellOpen};
    use std::io::Write;
    use tokio::io::AsyncReadExt;

    let mut client = osa_proto::v1::operator_client::OperatorClient::connect(coordinator).await?;

    // Outbound stream: `ShellOpen` first (sized to the local terminal), then raw
    // keystrokes (Ctrl-C flows through as a byte, not a local signal).
    let (rows, cols) = terminal_size().unwrap_or((DEFAULT_ROWS, DEFAULT_COLS));
    let (tx, rx) = tokio::sync::mpsc::channel::<ShellClientMsg>(64);
    tx.send(ShellClientMsg {
        msg: Some(ClientMsg::Open(ShellOpen {
            host_id: host,
            run_as,
            rows: rows as u32,
            cols: cols as u32,
        })),
    })
    .await
    .ok();
    // Pump local stdin → input frames; a clean stdin EOF (or pipe close) sends
    // `close`, ending the session on the agent. (This task is abandoned when the
    // session ends; the caller's `process::exit` reaps its blocking read.)
    let stdin_tx = tx.clone();
    tokio::spawn(async move {
        let mut stdin = tokio::io::stdin();
        let mut buf = [0u8; 4096];
        loop {
            match stdin.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let frame = ShellClientMsg {
                        msg: Some(ClientMsg::Input(buf[..n].to_vec())),
                    };
                    if stdin_tx.send(frame).await.is_err() {
                        break;
                    }
                }
            }
        }
        let _ = stdin_tx
            .send(ShellClientMsg {
                msg: Some(ClientMsg::Close(true)),
            })
            .await;
    });
    drop(tx); // only the stdin task holds a sender now

    let req = authed(tokio_stream::wrappers::ReceiverStream::new(rx), &token)?;
    let mut resp = client.shell(req).await?.into_inner();
    let mut stdout = std::io::stdout();
    while let Some(msg) = resp.message().await? {
        match msg.msg {
            Some(ServerMsg::Output(data)) => {
                stdout.write_all(&data)?;
                stdout.flush()?;
            }
            Some(ServerMsg::Closed(_)) => break, // the remote shell exited
            None => {}
        }
    }
    Ok(())
}

/// Query the local terminal size (rows, cols) via `TIOCGWINSZ` on stdout, or `None`
/// if stdout is not a terminal.
fn terminal_size() -> Option<(u16, u16)> {
    // SAFETY: `winsize` is a plain-old-data struct; zeroing it is valid.
    let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
    // SAFETY: a valid fd (stdout) and a pointer to a live `winsize`.
    let rc = unsafe { libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, &mut ws) };
    if rc == 0 && ws.ws_row > 0 && ws.ws_col > 0 {
        Some((ws.ws_row, ws.ws_col))
    } else {
        None
    }
}

/// Puts the local terminal (stdin) into raw mode for its lifetime, restoring the
/// original settings on drop — so a normal exit, an error, or a panic all leave the
/// terminal usable. A no-op when stdin is not a TTY (piped/redirected input).
struct RawMode {
    original: Option<nix::sys::termios::Termios>,
}

impl RawMode {
    fn enable() -> Self {
        use nix::sys::termios::{SetArg, cfmakeraw, tcgetattr, tcsetattr};
        let stdin = std::io::stdin();
        // `tcgetattr` fails when stdin is not a terminal — then run line-buffered.
        let Ok(original) = tcgetattr(&stdin) else {
            return Self { original: None };
        };
        let mut raw = original.clone();
        cfmakeraw(&mut raw);
        if tcsetattr(&stdin, SetArg::TCSANOW, &raw).is_err() {
            return Self { original: None };
        }
        Self {
            original: Some(original),
        }
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        if let Some(original) = &self.original {
            use nix::sys::termios::{SetArg, tcsetattr};
            let _ = tcsetattr(std::io::stdin(), SetArg::TCSANOW, original);
        }
    }
}

/// Lowercase-hex encode bytes.
fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// Parse a 64-char hex string into a 32-byte chain head.
fn parse_head(s: &str) -> anyhow::Result<[u8; 32]> {
    let s = s.trim();
    anyhow::ensure!(
        s.len() == 64,
        "--expect-head must be 64 hex chars (32 bytes)"
    );
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[2 * i..2 * i + 2], 16)
            .map_err(|_| anyhow::anyhow!("--expect-head is not valid hex"))?;
    }
    Ok(out)
}

/// Convert one exported proto entry into the core type the verifier checks,
/// validating the fixed-width hashes and the decision token.
fn to_audit_entry(e: &osa_proto::v1::AuditEntry) -> anyhow::Result<osa_core::audit::AuditEntry> {
    let hash32 = |b: &[u8], field: &str| -> anyhow::Result<[u8; 32]> {
        <[u8; 32]>::try_from(b)
            .map_err(|_| anyhow::anyhow!("audit entry {} has a malformed {field} hash", e.seq))
    };
    let decision = osa_core::audit::Decision::parse(&e.decision)
        .ok_or_else(|| anyhow::anyhow!("audit entry {} has an unknown decision", e.seq))?;
    Ok(osa_core::audit::AuditEntry {
        seq: e.seq,
        record: osa_core::audit::AuditRecord {
            ts_unix: e.ts_unix,
            subject: e.subject.clone(),
            kind: e.kind.clone(),
            target: e.target.clone(),
            run_as: e.run_as.clone(),
            decision,
        },
        prev_hash: hash32(&e.prev_hash, "prev_hash")?,
        hash: hash32(&e.hash, "hash")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proto_entry() -> osa_proto::v1::AuditEntry {
        osa_proto::v1::AuditEntry {
            seq: 0,
            ts_unix: 1_700_000_000,
            subject: "alice".into(),
            kind: "exec".into(),
            target: "host".into(),
            run_as: String::new(),
            decision: "allow".into(),
            prev_hash: vec![0u8; 32],
            hash: vec![1u8; 32],
        }
    }

    #[test]
    fn to_audit_entry_accepts_a_well_formed_entry() {
        assert!(to_audit_entry(&proto_entry()).is_ok());
    }

    #[test]
    fn to_audit_entry_rejects_a_wrong_length_hash() {
        let mut e = proto_entry();
        e.hash = vec![1u8; 31]; // not 32 bytes
        assert!(to_audit_entry(&e).is_err());
    }

    #[test]
    fn to_audit_entry_rejects_an_unknown_decision() {
        let mut e = proto_entry();
        e.decision = "maybe".into();
        assert!(to_audit_entry(&e).is_err());
    }

    #[test]
    fn parse_head_round_trips_with_to_hex() {
        let h = [0xabu8; 32];
        assert_eq!(parse_head(&to_hex(&h)).unwrap(), h);
    }

    #[test]
    fn parse_head_rejects_bad_input() {
        assert!(parse_head("xyz").is_err()); // too short
        assert!(parse_head(&"g".repeat(64)).is_err()); // not hex
    }
}
