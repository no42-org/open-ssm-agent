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
use osa_core::auth::Subject;
use osa_core::ports::{CertIssuer, PortError};
use osa_proto::v1::operator_server::Operator;
use osa_proto::v1::{
    EnrollRequest, EnrollResponse, MintTokenRequest, MintTokenResponse, RenewRequest,
    RenewResponse, RevokeRequest, RevokeResponse,
};
use tonic::{Request, Response, Status};

use crate::ca::EmbeddedCa;
use crate::revocation::RevocationRegistry;
use crate::token::{JoinTokenRegistry, MintError};

/// Implements the `Operator` service over the embedded CA + token registry.
pub struct OperatorService {
    ca: Arc<EmbeddedCa>,
    tokens: Arc<JoinTokenRegistry>,
    revocations: Arc<RevocationRegistry>,
    default_ttl: Duration,
}

impl OperatorService {
    pub fn new(
        ca: Arc<EmbeddedCa>,
        tokens: Arc<JoinTokenRegistry>,
        revocations: Arc<RevocationRegistry>,
        default_ttl: Duration,
    ) -> Self {
        Self {
            ca,
            tokens,
            revocations,
            default_ttl,
        }
    }
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
        let (join_token, expires_at_unix) = self.tokens.mint(ttl).map_err(|e| match e {
            MintError::Full => Status::resource_exhausted("join token capacity reached"),
            MintError::Rng(rng) => {
                tracing::error!(error = %rng, "token mint failed");
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
        self.tokens.redeem(&join_token).map_err(|reason| {
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
        let cert = self
            .ca
            .renew(&current_cert, &csr, |h| self.revocations.is_revoked(h))
            .map_err(|e| match e {
                PortError::Invalid(m) => Status::permission_denied(m),
                PortError::Denied => Status::permission_denied("identity revoked"),
                other => {
                    tracing::error!(error = %other, "renewal failed");
                    Status::internal("certificate renewal failed")
                }
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
        self.revocations.revoke(host_id);
        tracing::info!(host_id = %host_id.0, "host identity revoked");
        Ok(Response::new(RevokeResponse {}))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, KeyPair};
    use x509_parser::prelude::{FromDer, X509Certificate};

    fn service() -> OperatorService {
        let ca = Arc::new(EmbeddedCa::new(time::Duration::hours(24)).unwrap());
        let tokens = Arc::new(JoinTokenRegistry::new(Duration::from_secs(3600)));
        let revocations = Arc::new(RevocationRegistry::new());
        OperatorService::new(ca, tokens, revocations, Duration::from_secs(900))
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
