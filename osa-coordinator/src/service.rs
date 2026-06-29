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

use std::sync::Arc;
use std::time::Duration;

use osa_core::HostId;
use osa_core::audit::{AuditRecord, Decision};
use osa_core::auth::Subject;
use osa_core::ports::{AuditLog, CertIssuer, PolicyEngine, PortError};
use osa_proto::v1::operator_server::Operator;
use osa_proto::v1::{
    DispatchRequest, DispatchResponse, EnrollRequest, EnrollResponse, ExportAuditRequest,
    ExportAuditResponse, MintTokenRequest, MintTokenResponse, RenewRequest, RenewResponse,
    RevokeRequest, RevokeResponse,
};
use tonic::{Request, Response, Status};

use crate::ca::EmbeddedCa;
use crate::revocation::Revocations;
use crate::token::{JoinTokens, MintError};

/// Implements the `Operator` service over the embedded CA + token registry.
pub struct OperatorService {
    ca: Arc<EmbeddedCa>,
    tokens: Arc<dyn JoinTokens>,
    revocations: Arc<dyn Revocations>,
    policy: Arc<dyn PolicyEngine>,
    audit: Arc<dyn AuditLog>,
    default_ttl: Duration,
}

impl OperatorService {
    pub fn new(
        ca: Arc<EmbeddedCa>,
        tokens: Arc<dyn JoinTokens>,
        revocations: Arc<dyn Revocations>,
        policy: Arc<dyn PolicyEngine>,
        audit: Arc<dyn AuditLog>,
        default_ttl: Duration,
    ) -> Self {
        Self {
            ca,
            tokens,
            revocations,
            policy,
            audit,
            default_ttl,
        }
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
        // The authenticated operator (AD-18), bound by the auth interceptor.
        // `anonymous` only when the API runs without OIDC — and deny-by-default
        // means anonymous has no bindings, so it is denied below.
        let subject = request.extensions().get::<Subject>().map_or_else(
            || crate::policy::ANONYMOUS_SUBJECT.to_string(),
            |s| s.0.clone(),
        );
        let action = request
            .into_inner()
            .action
            .ok_or_else(|| Status::invalid_argument("missing action"))?;
        if action.kind.is_empty() {
            return Err(Status::invalid_argument("action kind is empty"));
        }

        // The coordinator is the sole PDP (AD-19): authorize before any agent is
        // contacted. Both outcomes are auditable.
        let decision = match self.policy.authorize(&subject, &action).await {
            Ok(()) => Decision::Allow,
            Err(PortError::Denied) => Decision::Deny,
            Err(other) => {
                tracing::error!(error = %other, "authorization failed");
                return Err(Status::internal("authorization failed"));
            }
        };

        // Record the decision (allowed AND denied, AD-21) before acting on it. A
        // failure to write the audit log fails the dispatch closed — an
        // unauditable action must not proceed.
        self.audit
            .append(AuditRecord {
                ts_unix: now_unix(),
                subject: subject.clone(),
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

        match decision {
            Decision::Allow => {
                tracing::info!(operator = %subject, kind = %action.kind, target = %action.target, "dispatch authorized (execution stubbed until Epic 3)");
                Ok(Response::new(DispatchResponse {}))
            }
            Decision::Deny => {
                tracing::info!(operator = %subject, kind = %action.kind, target = %action.target, "dispatch denied");
                Err(Status::permission_denied("not authorized for this action"))
            }
        }
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
        OperatorService::new(
            ca,
            tokens,
            revocations,
            policy,
            audit,
            Duration::from_secs(900),
        )
    }

    /// A `DispatchRequest` for `kind` against `target`, carrying `subject` in the
    /// request extensions the way the auth interceptor would.
    fn dispatch_req(subject: Option<&str>, kind: &str, target: &str) -> Request<DispatchRequest> {
        let mut req = Request::new(DispatchRequest {
            action: Some(osa_proto::v1::ActionDescriptor {
                kind: kind.into(),
                target: target.into(),
                run_as: String::new(),
                params_hash: Vec::new(),
            }),
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
    async fn dispatch_is_allowed_by_a_matching_binding() {
        let policy = Arc::new(
            crate::policy::RbacPolicyEngine::from_toml(
                r#"
                [[binding]]
                subject = "alice@example"
                verbs = ["exec"]
                selectors = ["*"]
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
    async fn dispatch_without_a_subject_is_anonymous_and_denied() {
        // No bound Subject (auth disabled) → "anonymous", which has no grants.
        let policy = Arc::new(
            crate::policy::RbacPolicyEngine::from_toml(
                r#"
                [[binding]]
                subject = "alice@example"
                verbs = ["*"]
                selectors = ["*"]
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
        let mut req = Request::new(DispatchRequest { action: None });
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
}
