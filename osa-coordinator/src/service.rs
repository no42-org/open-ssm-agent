/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: MIT
 */

//! The operator-facing `Operator` gRPC service (AD-5): mint join tokens and
//! enroll hosts.
//!
//! v1 leaves this surface unauthenticated; operator authn/authz lands in the
//! enforcement spine (Epic 2, AD-18/AD-19). The transport is plaintext for now —
//! mTLS/TLS wiring is a later channel story.

use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use osa_core::HostId;
use osa_core::audit::{AuditRecord, Decision};
use osa_core::auth::Subject;
use osa_core::ports::{AuditLog, CertIssuer, PolicyEngine, PortError};
use osa_proto::v1::enrollment_server::Enrollment;
use osa_proto::v1::operator_server::Operator;
use osa_proto::v1::{
    ActionDescriptor, Dispatch, DispatchRequest, DispatchResponse, EnrollRequest, EnrollResponse,
    ExecEvent, ExportAuditRequest, ExportAuditResponse, JobResult, MintTokenRequest,
    MintTokenResponse, RenewRequest, RenewResponse, RevokeRequest, RevokeResponse, ShellClientMsg,
    ShellOpen, ShellServerMsg, StreamFrame,
};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::{Stream, StreamExt};
use tonic::{Request, Response, Status, Streaming};

use crate::broker::{BridgeCommand, HostResult};
use crate::ca::EmbeddedCa;
use crate::revocation::Revocations;
use crate::token::{JoinTokens, MintError};

/// Bound on undelivered streamed result events buffered per `Exec` call (absorbs
/// output bursts a slow operator hasn't drained yet; on sustained overrun the
/// bridge aborts the job rather than corrupting output silently).
const EXEC_EVENT_QUEUE: usize = 256;
/// Cap on how many hosts one selector may fan out to, so a single request cannot
/// drive an unbounded number of authz/audit writes + dispatches.
const MAX_FANOUT: usize = 1024;

/// Backs both gRPC services: the agent-facing `Enrollment` (self-authenticating)
/// and the operator-facing `Operator` (OIDC/JWT-gated). Cloning is cheap — every
/// field is an `Arc` or a `Copy` config value, and the clone shares the same
/// CA/token/revocation/audit/policy state.
#[derive(Clone)]
pub struct OperatorService {
    ca: Arc<EmbeddedCa>,
    tokens: Arc<dyn JoinTokens>,
    revocations: Arc<dyn Revocations>,
    policy: Arc<dyn PolicyEngine>,
    audit: Arc<dyn AuditLog>,
    /// Hands dispatches to the broker bridge, which seals them to a host's session
    /// and streams results back (Epic 3). Cheap to clone (an mpsc sender).
    bridge: mpsc::Sender<BridgeCommand>,
    default_ttl: Duration,
}

impl OperatorService {
    pub fn new(
        ca: Arc<EmbeddedCa>,
        tokens: Arc<dyn JoinTokens>,
        revocations: Arc<dyn Revocations>,
        policy: Arc<dyn PolicyEngine>,
        audit: Arc<dyn AuditLog>,
        bridge: mpsc::Sender<BridgeCommand>,
        default_ttl: Duration,
    ) -> Self {
        Self {
            ca,
            tokens,
            revocations,
            policy,
            audit,
            bridge,
            default_ttl,
        }
    }

    /// The coordinator is the sole PDP (AD-19): authorize `subject` against
    /// `action`, then record the decision (allow AND deny, AD-21) before acting on
    /// it. A failed audit write fails closed (an unauditable action must not
    /// proceed). Returns the decision, or an internal `Status` on a backend error.
    async fn authorize_and_audit(
        &self,
        subject: &str,
        action: &ActionDescriptor,
    ) -> Result<Decision, Status> {
        let decision = match self.policy.authorize(subject, action).await {
            Ok(()) => Decision::Allow,
            Err(PortError::Denied) => Decision::Deny,
            Err(other) => {
                tracing::error!(error = %other, "authorization failed");
                return Err(Status::internal("authorization failed"));
            }
        };
        self.audit
            .append(AuditRecord {
                ts_unix: now_unix(),
                subject: subject.to_string(),
                kind: action.kind.clone(),
                target: action.target.clone(),
                run_as: action.run_as.clone(),
                decision,
            })
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "audit append failed");
                Status::internal("audit log unavailable")
            })?;
        Ok(decision)
    }

    /// Authorize (and audit) a shell open: parse the `host_id`, then run the
    /// deny-by-default RBAC PDP on (kind = "shell", host, run_as). Returns the host
    /// on allow, else a `Status` (INVALID_ARGUMENT / PERMISSION_DENIED) — no PTY is
    /// opened on a malformed or denied request. Extracted from [`Self::shell`] so the
    /// security-critical gate is unit-testable without a gRPC stream.
    async fn authorize_shell_open(
        &self,
        subject: &str,
        open: &ShellOpen,
    ) -> Result<HostId, Status> {
        let host = open
            .host_id
            .parse::<uuid::Uuid>()
            .map(HostId)
            .map_err(|_| Status::invalid_argument("host_id is not a UUID"))?;
        let action = ActionDescriptor {
            kind: "shell".to_string(),
            target: open.host_id.clone(),
            run_as: open.run_as.clone(),
            params_hash: Vec::new(),
        };
        match self.authorize_and_audit(subject, &action).await? {
            Decision::Allow => Ok(host),
            Decision::Deny => {
                tracing::info!(operator = %subject, host = %open.host_id, "shell denied");
                Err(Status::permission_denied(
                    "not authorized to open a shell here",
                ))
            }
        }
    }

    /// Resolve an exec target selector to host_ids (3.4). `*` → every host with a
    /// live session (asked of the bridge); otherwise a comma-separated list of
    /// host_id UUIDs. Tag/group selectors await the inventory (Epic 5).
    async fn resolve(&self, selector: &str) -> Result<Vec<HostId>, Status> {
        let mut hosts: Vec<HostId> = if selector == "*" {
            let (tx, rx) = tokio::sync::oneshot::channel();
            self.bridge
                .send(BridgeCommand::OnlineHosts { reply: tx })
                .await
                .map_err(|_| Status::unavailable("dispatch bridge unavailable"))?;
            rx.await
                .map_err(|_| Status::unavailable("dispatch bridge unavailable"))?
        } else {
            let mut v = Vec::new();
            for tok in selector.split(',') {
                let tok = tok.trim();
                if tok.is_empty() {
                    continue; // tolerate trailing/empty tokens in the list
                }
                let host = tok
                    .parse::<uuid::Uuid>()
                    .map(HostId)
                    .map_err(|_| Status::invalid_argument("selector token is not a host_id"))?;
                v.push(host);
            }
            v
        };
        // De-duplicate: a host named twice must not run the command twice.
        let mut seen = std::collections::HashSet::new();
        hosts.retain(|h| seen.insert(*h));
        if hosts.len() > MAX_FANOUT {
            return Err(Status::invalid_argument(format!(
                "selector resolves to {} hosts (max {MAX_FANOUT})",
                hosts.len()
            )));
        }
        Ok(hosts)
    }
}

/// The operator (AD-18), bound by the auth interceptor; `anonymous` only when the
/// API runs without OIDC — and deny-by-default means anonymous has no bindings.
fn operator_of<T>(request: &Request<T>) -> String {
    request.extensions().get::<Subject>().map_or_else(
        || crate::policy::ANONYMOUS_SUBJECT.to_string(),
        |s| s.0.clone(),
    )
}

/// Relay one agent `JobResult` as an operator-facing `ExecEvent`, keyed to its
/// host so a fan-out can interleave per-host results (the job_id is dropped — the
/// host_id is what the operator demuxes on).
fn to_exec_event(host: HostId, result: JobResult) -> ExecEvent {
    use osa_proto::v1::{exec_event, job_result};
    let event = match result.body {
        Some(job_result::Body::Chunk(c)) => Some(exec_event::Event::Chunk(c)),
        Some(job_result::Body::Outcome(o)) => Some(exec_event::Event::Outcome(o)),
        None => None,
    };
    ExecEvent {
        host_id: host.0.to_string(),
        event,
    }
}

/// Map a decoded agent stream frame to the operator-facing `ShellServerMsg`: an
/// `eof` frame becomes the terminal `closed`, everything else is `output` bytes.
fn to_shell_server_msg(frame: StreamFrame) -> ShellServerMsg {
    use osa_proto::v1::shell_server_msg::Msg;
    let msg = if frame.eof {
        Msg::Closed(true)
    } else {
        Msg::Output(frame.data)
    };
    ShellServerMsg { msg: Some(msg) }
}

/// A per-host terminal error result, surfaced as an event so the fan-out keeps
/// streaming the other hosts (a denial, an authz/audit backend error, or an
/// unreachable bridge — never an RPC-level abort that would mask partial runs).
fn outcome_error(msg: &str) -> JobResult {
    use osa_proto::v1::job_outcome::Terminal;
    use osa_proto::v1::{JobOutcome, job_result::Body};
    JobResult {
        job_id: String::new(),
        body: Some(Body::Outcome(JobOutcome {
            terminal: Some(Terminal::Error(msg.to_string())),
            output_truncated: false,
            timed_out: false,
        })),
    }
}

/// The current wall-clock as unix seconds, for audit timestamps.
fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[tonic::async_trait]
impl Operator for OperatorService {
    async fn mint_token(
        &self,
        request: Request<MintTokenRequest>,
    ) -> Result<Response<MintTokenResponse>, Status> {
        // The authenticated operator, bound by the auth interceptor (AD-18); the
        // PDP (story 2.2) will authorize on it. `anonymous` only when the API runs
        // without OIDC configured.
        let operator = request
            .extensions()
            .get::<Subject>()
            .map_or_else(|| "anonymous".to_string(), |s| s.0.clone());
        let ttl = match request.into_inner().ttl_seconds {
            0 => self.default_ttl,
            secs => Duration::from_secs(secs),
        };
        let (join_token, expires_at_unix) = self.tokens.mint(ttl).await.map_err(|e| match e {
            MintError::Full => Status::resource_exhausted("join token capacity reached"),
            MintError::Rng(_) | MintError::Backend(_) => {
                tracing::error!(error = %e, "token mint failed");
                Status::internal("token mint failed")
            }
        })?;
        tracing::info!(operator = %operator, "minted join token");
        Ok(Response::new(MintTokenResponse {
            join_token,
            expires_at_unix,
        }))
    }

    async fn revoke(
        &self,
        request: Request<RevokeRequest>,
    ) -> Result<Response<RevokeResponse>, Status> {
        let host_id = request
            .into_inner()
            .host_id
            .parse::<uuid::Uuid>()
            .map(HostId)
            .map_err(|_| Status::invalid_argument("host_id is not a UUID"))?;
        self.revocations.revoke(host_id).await.map_err(|e| {
            tracing::error!(error = %e, "revocation store write failed");
            Status::internal("revocation store unavailable")
        })?;
        tracing::info!(host_id = %host_id.0, "host identity revoked");
        Ok(Response::new(RevokeResponse {}))
    }

    async fn dispatch(
        &self,
        request: Request<DispatchRequest>,
    ) -> Result<Response<DispatchResponse>, Status> {
        let subject = operator_of(&request);
        let action = request
            .into_inner()
            .action
            .ok_or_else(|| Status::invalid_argument("missing action"))?;
        if action.kind.is_empty() {
            return Err(Status::invalid_argument("action kind is empty"));
        }
        match self.authorize_and_audit(&subject, &action).await? {
            Decision::Allow => {
                tracing::info!(operator = %subject, kind = %action.kind, target = %action.target, "dispatch authorized (execution stubbed; use Exec to stream)");
                Ok(Response::new(DispatchResponse {}))
            }
            Decision::Deny => {
                tracing::info!(operator = %subject, kind = %action.kind, target = %action.target, "dispatch denied");
                Err(Status::permission_denied("not authorized for this action"))
            }
        }
    }

    type ExecStream = Pin<Box<dyn Stream<Item = Result<ExecEvent, Status>> + Send>>;

    async fn exec(
        &self,
        request: Request<DispatchRequest>,
    ) -> Result<Response<Self::ExecStream>, Status> {
        let subject = operator_of(&request);
        let DispatchRequest { action, params } = request.into_inner();
        let action = action.ok_or_else(|| Status::invalid_argument("missing action"))?;
        if action.kind.is_empty() {
            return Err(Status::invalid_argument("action kind is empty"));
        }
        // Resolve the selector to host_ids: a single id, a comma-list, or "*" (all
        // online). A malformed token is a client error, rejected without an audit.
        let hosts = self.resolve(&action.target).await?;
        if hosts.is_empty() {
            return Err(Status::not_found("no hosts matched the selector"));
        }

        // Fan out in a spawned task so the response stream is returned (and drained)
        // immediately: the per-host loop authorizes + audits PER HOST (so the RBAC
        // selectors compose), then dispatches each allowed+online host. Denied,
        // unauthorizable, offline, and bridge-error hosts are each reported as a
        // per-host terminal EVENT — never an RPC abort that would leave hosts that
        // already ran unreported. Results share one stream, tagged with host_id.
        let (events_tx, events_rx) = mpsc::channel::<HostResult>(EXEC_EVENT_QUEUE);
        let svc = self.clone();
        let kind = action.kind.clone();
        let run_as = action.run_as.clone();
        let params_hash = action.params_hash.clone();
        tracing::info!(operator = %subject, kind = %kind, selector = %action.target, hosts = hosts.len(), "exec fanning out");
        tokio::spawn(async move {
            for host in hosts {
                let per_host = ActionDescriptor {
                    kind: kind.clone(),
                    target: host.0.to_string(),
                    run_as: run_as.clone(),
                    params_hash: params_hash.clone(),
                };
                match svc.authorize_and_audit(&subject, &per_host).await {
                    Ok(Decision::Allow) => {
                        let dispatch = Dispatch {
                            job_id: uuid::Uuid::new_v4().to_string(),
                            kind: kind.clone(),
                            run_as: run_as.clone(),
                            params: params.clone(),
                        };
                        if svc
                            .bridge
                            .send(BridgeCommand::Dispatch {
                                host_id: host,
                                dispatch,
                                events: events_tx.clone(),
                            })
                            .await
                            .is_err()
                        {
                            let _ = events_tx
                                .send((host, outcome_error("dispatch bridge unavailable")))
                                .await;
                        }
                    }
                    Ok(Decision::Deny) => {
                        tracing::info!(operator = %subject, host = %host.0, "exec denied for host");
                        let _ = events_tx
                            .send((host, outcome_error("not authorized for this host")))
                            .await;
                    }
                    Err(status) => {
                        tracing::error!(host = %host.0, error = %status.message(), "exec authorize/audit failed for host");
                        let _ = events_tx
                            .send((host, outcome_error("authorization unavailable")))
                            .await;
                    }
                }
            }
            // events_tx drops here; the stream closes once every dispatched host's
            // pending job completes (or is reaped).
        });

        let stream = ReceiverStream::new(events_rx).map(|(host, jr)| Ok(to_exec_event(host, jr)));
        Ok(Response::new(Box::pin(stream)))
    }

    type ShellStream = Pin<Box<dyn Stream<Item = Result<ShellServerMsg, Status>> + Send>>;

    async fn shell(
        &self,
        request: Request<Streaming<ShellClientMsg>>,
    ) -> Result<Response<Self::ShellStream>, Status> {
        let subject = operator_of(&request);
        let mut inbound = request.into_inner();
        // The first client message MUST be ShellOpen.
        let first = inbound
            .message()
            .await?
            .ok_or_else(|| Status::invalid_argument("shell stream closed before ShellOpen"))?;
        let open = match first.msg {
            Some(osa_proto::v1::shell_client_msg::Msg::Open(o)) => o,
            _ => {
                return Err(Status::invalid_argument(
                    "first shell message must be ShellOpen",
                ));
            }
        };
        // Authorize + audit the open (kind "shell" + run_as, deny-by-default RBAC),
        // exactly like a dispatch — no PTY is opened on a denied request.
        let host = self.authorize_shell_open(&subject, &open).await?;

        // Mint a fresh, never-recycled stream_id (it keys the per-stream AEAD subkey;
        // reuse would be catastrophic nonce reuse).
        let stream_id = uuid::Uuid::new_v4().to_string();
        let (output_tx, output_rx) = mpsc::channel::<StreamFrame>(EXEC_EVENT_QUEUE);
        if self
            .bridge
            .send(BridgeCommand::OpenShell {
                host_id: host,
                stream_id: stream_id.clone(),
                run_as: open.run_as,
                rows: open.rows,
                cols: open.cols,
                output: output_tx,
            })
            .await
            .is_err()
        {
            return Err(Status::unavailable("dispatch bridge unavailable"));
        }
        tracing::info!(operator = %subject, host = %open.host_id, "shell opened");

        // Pump operator input (keystrokes / close) to the bridge; the client stream
        // ending (disconnect) closes the shell so the agent reaps its PTY.
        let bridge = self.bridge.clone();
        let input_stream_id = stream_id.clone();
        tokio::spawn(async move {
            // Ends when the client stream closes (`Ok(None)`/`Err` fail the while-let)
            // or the operator sends `Close`.
            while let Ok(Some(msg)) = inbound.message().await {
                match msg.msg {
                    Some(osa_proto::v1::shell_client_msg::Msg::Input(data)) => {
                        if bridge
                            .send(BridgeCommand::ShellInput {
                                host_id: host,
                                stream_id: input_stream_id.clone(),
                                data,
                            })
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    Some(osa_proto::v1::shell_client_msg::Msg::Close(_)) => break,
                    _ => {} // a stray second Open or an empty message — ignore
                }
            }
            let _ = bridge
                .send(BridgeCommand::ShellClose {
                    host_id: host,
                    stream_id: input_stream_id,
                })
                .await;
        });

        // Response: decoded agent stream frames → ShellServerMsg (output, then closed).
        let out = ReceiverStream::new(output_rx).map(|frame| Ok(to_shell_server_msg(frame)));
        Ok(Response::new(Box::pin(out)))
    }

    async fn export_audit(
        &self,
        _request: Request<ExportAuditRequest>,
    ) -> Result<Response<ExportAuditResponse>, Status> {
        let entries = self.audit.export().await.map_err(|e| {
            tracing::error!(error = %e, "audit export failed");
            Status::internal("audit log unavailable")
        })?;
        let entries = entries
            .into_iter()
            .map(|e| osa_proto::v1::AuditEntry {
                seq: e.seq,
                ts_unix: e.record.ts_unix,
                subject: e.record.subject,
                kind: e.record.kind,
                target: e.record.target,
                run_as: e.record.run_as,
                decision: e.record.decision.as_str().to_string(),
                prev_hash: e.prev_hash.to_vec(),
                hash: e.hash.to_vec(),
            })
            .collect();
        Ok(Response::new(ExportAuditResponse { entries }))
    }
}

#[tonic::async_trait]
impl Enrollment for OperatorService {
    async fn enroll(
        &self,
        request: Request<EnrollRequest>,
    ) -> Result<Response<EnrollResponse>, Status> {
        let EnrollRequest { join_token, csr } = request.into_inner();

        // Validate the CSR BEFORE redeeming, so a malformed CSR cannot burn the
        // single-use token.
        self.ca
            .validate_csr(&csr)
            .map_err(|_| Status::invalid_argument("malformed CSR"))?;

        // Atomically redeem the single-use token. All failure reasons collapse to
        // one opaque status (no token-existence oracle); the reason is logged.
        self.tokens.redeem(&join_token).await.map_err(|reason| {
            tracing::info!(?reason, "join token redemption denied");
            Status::permission_denied("invalid or expired join token")
        })?;

        let host_id = HostId::new();
        let cert = self.ca.sign(host_id, &csr).await.map_err(|e| match e {
            PortError::Invalid(_) => Status::invalid_argument("malformed CSR"),
            other => {
                tracing::error!(error = %other, "signing failed after token redeemed");
                Status::internal("certificate issuance failed")
            }
        })?;

        Ok(Response::new(EnrollResponse {
            host_id: host_id.0.to_string(),
            cert,
            ca_root: self.ca.ca_root_der(),
        }))
    }

    async fn renew(
        &self,
        request: Request<RenewRequest>,
    ) -> Result<Response<RenewResponse>, Status> {
        let RenewRequest { current_cert, csr } = request.into_inner();
        // Validate the renewal (cert signed by us, valid, same-key CSR) and get
        // the identity. The revocation check (async, possibly Postgres-backed)
        // sits between validation and issuance.
        let host_id = self
            .ca
            .validate_renewal(&current_cert, &csr)
            .map_err(|e| match e {
                PortError::Invalid(m) => Status::permission_denied(m),
                other => {
                    tracing::error!(error = %other, "renewal validation failed");
                    Status::internal("certificate renewal failed")
                }
            })?;
        // Fail closed if the revocation store is unreachable (never issue when we
        // can't confirm the identity is live). A revoke landing between this check
        // and the issuance below would still let one renewal through — an accepted
        // window bounded by the short cert TTL (broker-connect enforcement is #16).
        if self.revocations.is_revoked(host_id).await.map_err(|e| {
            tracing::error!(error = %e, "revocation check failed");
            Status::internal("revocation check unavailable")
        })? {
            return Err(Status::permission_denied("identity revoked"));
        }
        let cert = self.ca.sign(host_id, &csr).await.map_err(|e| {
            tracing::error!(error = %e, "renewal issuance failed");
            Status::internal("certificate renewal failed")
        })?;
        Ok(Response::new(RenewResponse { cert }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::revocation::RevocationRegistry;
    use crate::token::JoinTokenRegistry;
    use rcgen::{CertificateParams, KeyPair};
    use x509_parser::prelude::{FromDer, X509Certificate};

    fn service() -> OperatorService {
        service_with_policy(Arc::new(crate::policy::RbacPolicyEngine::empty()))
    }

    fn service_with_policy(policy: Arc<dyn PolicyEngine>) -> OperatorService {
        service_with(policy, Arc::new(crate::audit_log::MemoryAuditLog::new()))
    }

    fn service_with(policy: Arc<dyn PolicyEngine>, audit: Arc<dyn AuditLog>) -> OperatorService {
        let ca = Arc::new(EmbeddedCa::new(time::Duration::hours(24)).unwrap());
        let tokens = Arc::new(JoinTokenRegistry::new(Duration::from_secs(3600)));
        let revocations = Arc::new(RevocationRegistry::new());
        // The unit tests exercise mint/enroll/dispatch-authz, none of which reach
        // the bridge (deny + invalid-arg paths return before it), so a closed
        // command channel is fine.
        let (bridge_tx, _bridge_rx) = mpsc::channel(8);
        OperatorService::new(
            ca,
            tokens,
            revocations,
            policy,
            audit,
            bridge_tx,
            Duration::from_secs(900),
        )
    }

    /// A `DispatchRequest` for `kind` against `target` as the default identity
    /// (empty `run_as`), carrying `subject` in the request extensions the way the
    /// auth interceptor would.
    fn dispatch_req(subject: Option<&str>, kind: &str, target: &str) -> Request<DispatchRequest> {
        dispatch_req_as(subject, kind, target, "")
    }

    /// As [`dispatch_req`], but with an explicit `run_as` (the #22 axis).
    fn dispatch_req_as(
        subject: Option<&str>,
        kind: &str,
        target: &str,
        run_as: &str,
    ) -> Request<DispatchRequest> {
        let mut req = Request::new(DispatchRequest {
            action: Some(osa_proto::v1::ActionDescriptor {
                kind: kind.into(),
                target: target.into(),
                run_as: run_as.into(),
                params_hash: Vec::new(),
            }),
            params: Vec::new(),
        });
        if let Some(s) = subject {
            req.extensions_mut().insert(Subject(s.to_string()));
        }
        req
    }

    fn csr() -> Vec<u8> {
        let key = KeyPair::generate().unwrap();
        CertificateParams::default()
            .serialize_request(&key)
            .unwrap()
            .der()
            .to_vec()
    }

    async fn mint(svc: &OperatorService) -> String {
        svc.mint_token(Request::new(MintTokenRequest { ttl_seconds: 0 }))
            .await
            .unwrap()
            .into_inner()
            .join_token
    }

    #[tokio::test]
    async fn enroll_with_valid_token_issues_identity() {
        let svc = service();
        let token = mint(&svc).await;
        let resp = svc
            .enroll(Request::new(EnrollRequest {
                join_token: token,
                csr: csr(),
            }))
            .await
            .unwrap()
            .into_inner();

        // host_id is a fresh UUIDv4.
        let id = uuid::Uuid::parse_str(&resp.host_id).expect("host_id must be a UUID");
        assert_eq!(id.get_version_num(), 4);

        // The returned leaf cert cryptographically verifies against the returned
        // CA root — i.e. the EnrollResponse wires the real cert + real CA root.
        let (_, leaf) = X509Certificate::from_der(&resp.cert).unwrap();
        let (_, ca_root) = X509Certificate::from_der(&resp.ca_root).unwrap();
        leaf.verify_signature(Some(ca_root.public_key()))
            .expect("issued cert must verify against the returned CA root");
    }

    #[tokio::test]
    async fn second_enroll_with_same_token_denied() {
        let svc = service();
        let token = mint(&svc).await;
        let req = || {
            Request::new(EnrollRequest {
                join_token: token.clone(),
                csr: csr(),
            })
        };
        svc.enroll(req()).await.unwrap();
        let err = svc.enroll(req()).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[tokio::test]
    async fn enroll_with_unknown_token_denied() {
        let svc = service();
        let err = svc
            .enroll(Request::new(EnrollRequest {
                join_token: "nope".into(),
                csr: csr(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[tokio::test]
    async fn bad_csr_is_rejected_without_burning_token() {
        let svc = service();
        let token = mint(&svc).await;
        let bad = svc
            .enroll(Request::new(EnrollRequest {
                join_token: token.clone(),
                csr: b"garbage".to_vec(),
            }))
            .await
            .unwrap_err();
        assert_eq!(bad.code(), tonic::Code::InvalidArgument);
        // The token survived the malformed CSR: a corrected enroll now succeeds.
        let ok = svc
            .enroll(Request::new(EnrollRequest {
                join_token: token,
                csr: csr(),
            }))
            .await;
        assert!(ok.is_ok(), "valid CSR with the same token must enroll");
    }

    #[tokio::test]
    async fn renew_is_denied_after_revocation() {
        let svc = service();
        let token = mint(&svc).await;
        let key = KeyPair::generate().unwrap();
        let csr_with = || {
            CertificateParams::default()
                .serialize_request(&key)
                .unwrap()
                .der()
                .to_vec()
        };

        let resp = svc
            .enroll(Request::new(EnrollRequest {
                join_token: token,
                csr: csr_with(),
            }))
            .await
            .unwrap()
            .into_inner();

        // Revoke the freshly enrolled identity.
        svc.revoke(Request::new(RevokeRequest {
            host_id: resp.host_id,
        }))
        .await
        .unwrap();

        // A renewal with a valid cert + same-key CSR is now denied.
        let err = svc
            .renew(Request::new(RenewRequest {
                current_cert: resp.cert,
                csr: csr_with(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    const HOST: &str = "11111111-1111-4111-8111-111111111111";

    #[tokio::test]
    async fn dispatch_is_denied_by_default() {
        // Deny-all policy: even an authenticated operator is rejected.
        let svc = service();
        let err = svc
            .dispatch(dispatch_req(Some("alice@example"), "exec", HOST))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[tokio::test]
    async fn exec_denied_emits_a_per_host_denied_event_and_no_dispatch() {
        // Fan-out reports denial PER HOST (so a partial denial doesn't fail the
        // whole RPC): deny-all yields a single denied outcome event, no dispatch.
        use tokio_stream::StreamExt;
        let svc = service(); // deny-all
        let mut stream = svc
            .exec(dispatch_req(Some("alice@example"), "exec", HOST))
            .await
            .expect("exec opens a stream")
            .into_inner();
        let mut events = Vec::new();
        while let Some(item) = stream.next().await {
            events.push(item.unwrap());
        }
        assert_eq!(events.len(), 1, "one host, one denied outcome");
        assert_eq!(events[0].host_id, HOST);
        let Some(osa_proto::v1::exec_event::Event::Outcome(o)) = &events[0].event else {
            panic!("expected a terminal outcome");
        };
        assert!(matches!(
            &o.terminal,
            Some(osa_proto::v1::job_outcome::Terminal::Error(m)) if m.contains("authorized")
        ));
    }

    #[tokio::test]
    async fn resolve_parses_a_host_id_list_and_rejects_a_bad_token() {
        let svc = service();
        let a = uuid::Uuid::new_v4().to_string();
        let b = uuid::Uuid::new_v4().to_string();
        let hosts = svc.resolve(&format!("{a}, {b}")).await.unwrap();
        assert_eq!(hosts.len(), 2, "comma-separated host_ids resolve to each");
        let err = svc.resolve("not-a-host-id").await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn exec_with_a_non_uuid_target_is_invalid() {
        let policy = Arc::new(
            crate::policy::RbacPolicyEngine::from_toml(
                r#"
                [[binding]]
                subject = "alice@example"
                verbs = ["exec"]
                selectors = ["*"]
                run_as = ["*"]
            "#,
            )
            .unwrap(),
        );
        let svc = service_with_policy(policy);
        let err = svc
            .exec(dispatch_req(Some("alice@example"), "exec", "not-a-host-id"))
            .await
            .err()
            .expect("a non-UUID target must be rejected");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn dispatch_is_allowed_by_a_matching_binding() {
        let policy = Arc::new(
            crate::policy::RbacPolicyEngine::from_toml(
                r#"
                [[binding]]
                subject = "alice@example"
                verbs = ["exec"]
                selectors = ["*"]
                run_as = ["*"]
            "#,
            )
            .unwrap(),
        );
        let svc = service_with_policy(policy);
        assert!(
            svc.dispatch(dispatch_req(Some("alice@example"), "exec", HOST))
                .await
                .is_ok()
        );
        // A different verb the binding doesn't grant is still denied.
        let err = svc
            .dispatch(dispatch_req(Some("alice@example"), "shell", HOST))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[tokio::test]
    async fn dispatch_enforces_run_as() {
        // Grants exec on any host, but only as `deploy` (#22): the action's
        // run_as must reach the PDP through the dispatch path.
        let policy = Arc::new(
            crate::policy::RbacPolicyEngine::from_toml(
                r#"
                [[binding]]
                subject = "alice@example"
                verbs = ["exec"]
                selectors = ["*"]
                run_as = ["deploy"]
            "#,
            )
            .unwrap(),
        );
        let svc = service_with_policy(policy);
        // The granted run_as is allowed.
        assert!(
            svc.dispatch(dispatch_req_as(
                Some("alice@example"),
                "exec",
                HOST,
                "deploy"
            ))
            .await
            .is_ok()
        );
        // A run_as outside the grant is denied.
        let err = svc
            .dispatch(dispatch_req_as(Some("alice@example"), "exec", HOST, "root"))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        // The default identity (empty run_as) is not implicitly granted.
        let err = svc
            .dispatch(dispatch_req(Some("alice@example"), "exec", HOST))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    fn shell_policy() -> Arc<crate::policy::RbacPolicyEngine> {
        Arc::new(
            crate::policy::RbacPolicyEngine::from_toml(
                r#"
                [[binding]]
                subject = "alice@example"
                verbs = ["shell"]
                selectors = ["*"]
                run_as = ["deploy"]
            "#,
            )
            .unwrap(),
        )
    }

    fn shell_open(host: &str, run_as: &str) -> ShellOpen {
        ShellOpen {
            host_id: host.into(),
            run_as: run_as.into(),
            rows: 24,
            cols: 80,
        }
    }

    #[tokio::test]
    async fn shell_open_is_allowed_by_a_matching_binding() {
        let svc = service_with_policy(shell_policy());
        let host = svc
            .authorize_shell_open("alice@example", &shell_open(HOST, "deploy"))
            .await
            .unwrap();
        assert_eq!(host.0.to_string(), HOST);
    }

    #[tokio::test]
    async fn shell_open_is_denied_without_a_binding() {
        // Deny-by-default: the empty-policy service denies a shell open.
        let err = service()
            .authorize_shell_open("alice@example", &shell_open(HOST, "deploy"))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[tokio::test]
    async fn shell_open_enforces_run_as() {
        // The #22 run_as axis applies to shells too: an ungranted user is denied.
        let svc = service_with_policy(shell_policy());
        assert!(
            svc.authorize_shell_open("alice@example", &shell_open(HOST, "deploy"))
                .await
                .is_ok()
        );
        let err = svc
            .authorize_shell_open("alice@example", &shell_open(HOST, "root"))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[tokio::test]
    async fn shell_open_with_a_non_uuid_host_is_invalid() {
        let err = service()
            .authorize_shell_open("alice@example", &shell_open("not-a-uuid", ""))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[test]
    fn to_shell_server_msg_maps_output_and_eof() {
        use osa_proto::v1::shell_server_msg::Msg;
        let out = to_shell_server_msg(StreamFrame {
            data: b"hi".to_vec(),
            eof: false,
        });
        assert!(matches!(out.msg, Some(Msg::Output(d)) if d == b"hi"));
        let closed = to_shell_server_msg(StreamFrame {
            data: Vec::new(),
            eof: true,
        });
        assert!(matches!(closed.msg, Some(Msg::Closed(true))));
    }

    #[tokio::test]
    async fn dispatch_without_a_subject_is_anonymous_and_denied() {
        // No bound Subject (auth disabled) → "anonymous", which has no grants.
        let policy = Arc::new(
            crate::policy::RbacPolicyEngine::from_toml(
                r#"
                [[binding]]
                subject = "alice@example"
                verbs = ["*"]
                selectors = ["*"]
                run_as = ["*"]
            "#,
            )
            .unwrap(),
        );
        let svc = service_with_policy(policy);
        let err = svc
            .dispatch(dispatch_req(None, "exec", HOST))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[tokio::test]
    async fn dispatch_without_an_action_is_invalid() {
        let svc = service();
        let mut req = Request::new(DispatchRequest {
            action: None,
            params: Vec::new(),
        });
        req.extensions_mut().insert(Subject("alice@example".into()));
        let err = svc.dispatch(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn dispatch_with_an_empty_kind_is_invalid() {
        let svc = service();
        let err = svc
            .dispatch(dispatch_req(Some("alice@example"), "", HOST))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn dispatch_audits_both_allow_and_deny() {
        let policy = Arc::new(
            crate::policy::RbacPolicyEngine::from_toml(
                r#"
                [[binding]]
                subject = "alice@example"
                verbs = ["exec"]
                selectors = ["*"]
                run_as = ["*"]
            "#,
            )
            .unwrap(),
        );
        let audit = Arc::new(crate::audit_log::MemoryAuditLog::new());
        let svc = service_with(policy, audit.clone());

        // One allowed (alice/exec) and one denied (alice/shell) dispatch.
        svc.dispatch(dispatch_req(Some("alice@example"), "exec", HOST))
            .await
            .unwrap();
        let _ = svc
            .dispatch(dispatch_req(Some("alice@example"), "shell", HOST))
            .await;

        let entries = audit.export().await.unwrap();
        assert_eq!(entries.len(), 2, "both decisions must be audited");
        assert_eq!(entries[0].record.decision, Decision::Allow);
        assert_eq!(entries[1].record.decision, Decision::Deny);
        assert_eq!(entries[1].record.subject, "alice@example");
        // The chain the operator would export must verify.
        osa_core::audit::verify(&entries, None).unwrap();
    }

    #[tokio::test]
    async fn dispatch_fails_closed_when_the_audit_log_is_unavailable() {
        // An AuditLog that always fails: the dispatch must not proceed
        // (unauditable action) and must surface Internal.
        struct FailingAuditLog;
        #[tonic::async_trait]
        impl AuditLog for FailingAuditLog {
            async fn append(&self, _r: AuditRecord) -> Result<(), PortError> {
                Err(PortError::Backend("audit down".into()))
            }
            async fn export(&self) -> Result<Vec<osa_core::audit::AuditEntry>, PortError> {
                Err(PortError::Backend("audit down".into()))
            }
        }
        // Grant the action so the only failure is the audit write.
        let policy = Arc::new(
            crate::policy::RbacPolicyEngine::from_toml(
                r#"
                [[binding]]
                subject = "alice@example"
                verbs = ["exec"]
                selectors = ["*"]
                run_as = ["*"]
            "#,
            )
            .unwrap(),
        );
        let svc = service_with(policy, Arc::new(FailingAuditLog));
        let err = svc
            .dispatch(dispatch_req(Some("alice@example"), "exec", HOST))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Internal);
    }

    #[tokio::test]
    async fn export_audit_returns_the_verifiable_chain() {
        let svc = service(); // deny-all policy
        // Two denied dispatches still produce audit entries.
        let _ = svc.dispatch(dispatch_req(Some("a@x"), "exec", HOST)).await;
        let _ = svc.dispatch(dispatch_req(Some("b@x"), "exec", HOST)).await;

        let resp = svc
            .export_audit(Request::new(ExportAuditRequest {}))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(resp.entries.len(), 2);
        assert_eq!(resp.entries[0].seq, 0);
        assert_eq!(resp.entries[0].decision, "deny");
        assert_eq!(resp.entries[0].hash.len(), 32);
        // prev_hash of entry 1 chains to hash of entry 0.
        assert_eq!(resp.entries[1].prev_hash, resp.entries[0].hash);
    }

    #[tokio::test]
    async fn revoke_rejects_a_non_uuid_host_id() {
        let svc = service();
        let err = svc
            .revoke(Request::new(RevokeRequest {
                host_id: "not-a-uuid".into(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    // --- Two-replica statelessness milestone (testcontainers; needs Docker) ---

    #[tokio::test]
    async fn two_replicas_share_enrollment_revocation_and_ca() {
        use testcontainers_modules::postgres::Postgres;
        use testcontainers_modules::testcontainers::ImageExt;
        use testcontainers_modules::testcontainers::runners::AsyncRunner;

        let node = Postgres::default()
            .with_tag("17-alpine")
            .start()
            .await
            .unwrap();
        let port = node.get_host_port_ipv4(5432).await.unwrap();
        let url = format!("postgres://postgres:postgres@127.0.0.1:{port}/postgres");
        let pool_a = crate::db::connect(&url).await.unwrap();
        crate::db::migrate(&pool_a).await.unwrap();
        let pool_b = crate::db::connect(&url).await.unwrap();

        // One shared CA, generated once; both replicas reconstruct it.
        let ca = Arc::new(
            crate::ca::load_or_generate(&pool_a, time::Duration::hours(24))
                .await
                .unwrap(),
        );
        let replica = |pool: sqlx::PgPool| {
            let (bridge_tx, _bridge_rx) = mpsc::channel(8);
            OperatorService::new(
                ca.clone(),
                Arc::new(crate::token::PgJoinTokens::new(
                    pool.clone(),
                    Duration::from_secs(3600),
                )),
                Arc::new(crate::revocation::PgRevocations::new(pool.clone())),
                Arc::new(crate::policy::RbacPolicyEngine::empty()),
                Arc::new(crate::audit_log::PgAuditLog::new(pool)),
                bridge_tx,
                Duration::from_secs(900),
            )
        };
        let a = replica(pool_a);
        let b = replica(pool_b);

        // Same-key CSR, reused for enroll + renew (renewal requires the same key).
        let key = KeyPair::generate().unwrap();
        let csr_bytes = || {
            CertificateParams::default()
                .serialize_request(&key)
                .unwrap()
                .der()
                .to_vec()
        };

        // Operator mints a token on replica A.
        let token = a
            .mint_token(Request::new(MintTokenRequest { ttl_seconds: 0 }))
            .await
            .unwrap()
            .into_inner()
            .join_token;

        // Agent enrolls via replica B: cross-replica single-use redeem + the
        // shared CA issues the cert.
        let enrolled = b
            .enroll(Request::new(EnrollRequest {
                join_token: token,
                csr: csr_bytes(),
            }))
            .await
            .expect("token minted on A must redeem on B")
            .into_inner();

        // Agent renews via replica A — A validates a cert that B issued (only
        // possible because both share one CA) and reissues.
        a.renew(Request::new(RenewRequest {
            current_cert: enrolled.cert.clone(),
            csr: csr_bytes(),
        }))
        .await
        .expect("A must renew a cert that B issued (shared CA)");

        // Operator revokes on A; the revocation is shared, so a renew via B is
        // now refused.
        a.revoke(Request::new(RevokeRequest {
            host_id: enrolled.host_id,
        }))
        .await
        .unwrap();
        let err = b
            .renew(Request::new(RenewRequest {
                current_cert: enrolled.cert,
                csr: csr_bytes(),
            }))
            .await
            .unwrap_err();
        assert_eq!(
            err.code(),
            tonic::Code::PermissionDenied,
            "revoke on A must refuse renew on B"
        );
    }
}
