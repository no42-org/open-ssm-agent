/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: MIT
 */

//! gRPC operator authentication interceptor (AD-18).
//!
//! Wraps the `Operator` service: every call must carry a bearer JWT in the
//! `authorization` metadata that validates against the configured OIDC issuer
//! (see [`osa_core::auth`]). On success the authenticated [`Subject`] is inserted
//! into the request extensions for the handlers (and, later, the PDP) to read; on
//! any failure the call is rejected `UNAUTHENTICATED` before it reaches a handler.

use std::sync::{Arc, RwLock};

use osa_core::auth::{AuthError, JwtValidator};
use tonic::service::Interceptor;
use tonic::{Request, Status};

/// A hot-swappable validator cell. The interceptor reads the current validator;
/// the JWKS refresh task (story 2.1b) swaps in a fresh one when the issuer
/// rotates its keys, without dropping connections.
pub type ValidatorCell = Arc<RwLock<Arc<JwtValidator>>>;

/// A cloneable interceptor holding the shared, swappable validator.
#[derive(Clone)]
pub struct JwtAuth {
    validator: ValidatorCell,
}

impl JwtAuth {
    pub fn new(validator: Arc<JwtValidator>) -> Self {
        Self {
            validator: Arc::new(RwLock::new(validator)),
        }
    }

    /// A handle to the validator cell, for a background refresher to swap keys.
    pub fn cell(&self) -> ValidatorCell {
        Arc::clone(&self.validator)
    }
}

impl Interceptor for JwtAuth {
    fn call(&mut self, mut request: Request<()>) -> Result<Request<()>, Status> {
        let token = bearer_token(&request)?;
        // Snapshot the current validator (a cheap Arc clone) and release the lock
        // before validating, so a concurrent key refresh never blocks a request.
        let validator = self
            .validator
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        match validator.validate(&token) {
            Ok(subject) => {
                request.extensions_mut().insert(subject);
                Ok(request)
            }
            Err(reason) => {
                // Log the specific reason; return an opaque status so the caller
                // learns only "unauthenticated", not *why* (no oracle).
                tracing::info!(?reason, "operator authentication rejected");
                Err(unauthenticated())
            }
        }
    }
}

/// Extract the bearer token from `authorization: Bearer <jwt>`.
fn bearer_token(request: &Request<()>) -> Result<String, Status> {
    let raw = request
        .metadata()
        .get("authorization")
        .ok_or_else(|| {
            tracing::info!(reason = ?AuthError::Missing, "operator authentication rejected");
            unauthenticated()
        })?
        .to_str()
        .map_err(|_| unauthenticated())?;
    // Scheme is case-insensitive per RFC 7235; the credential is the remainder.
    let (scheme, token) = raw.split_once(' ').ok_or_else(unauthenticated)?;
    if !scheme.eq_ignore_ascii_case("bearer") || token.is_empty() {
        return Err(unauthenticated());
    }
    Ok(token.to_string())
}

fn unauthenticated() -> Status {
    Status::unauthenticated("missing or invalid operator credential")
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    use osa_core::auth::{Subject, ValidationPolicy};
    use serde::Serialize;
    use tonic::metadata::MetadataValue;

    const TEST_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCfE4eSObMn1QZq
7aeBKXKo3K0mvMS+iZo9aQMbX7MrpQLfeMOxUiXPcdsIxputElzjQCazgkv3MxWF
e61qx6EGOuk+4CL46RG4Wq+SppaUoLCGlOdY3aFhX5t7d/ZsL1e4q/8lOSKLPTM6
0oQ4oTKvMhBuRjED7DLq6V4MmISoNNBF8ZPWuXgnMEqDwJmbrmMPPpP3F/SK0QcW
8LFBAMQfOO1pKQzcj1ayujE8afRwo7u1N64BM7ojf1XhzTwfn0SX0CiwOf4dcGBo
rcoHZe8GQxNKScz/1R42bHP7ItjbvvraFEyz9U/AQp2Vp6sdBakT5LQXk4IUH3J1
wEtLynatAgMBAAECggEAJP213CE6QbQ1/JX8ilrAzLcaNaSWTKdzXD3n6MzpfWfv
AdfTi8+qNrHHaSREDaw0OO0RQtN1BkwVAFgI9Mhsr6Xx2LrmrwKFqhy+cKf34qJ2
QilsnbvV++5vWbgE79XXfHxUhcuiNoY5/D75W7DSeC54Zyg/3CVoFrvDMMMjr/hQ
JzJsdmAJ7dG9358eQXdoTJiMrhNmxuIQHy9DqOcEVpsBp1uKrvEaRDb6phj5HHIz
TtoOPRTFC79dkZ9fyeYV/Ku5qPVT3wJrv+pWUylSaBGwrmP7rsgVumauqCR8Yx/p
dwSGsMYSKj4RDPJqdprVj8LP0u4b+KWDo+lsmp8qOQKBgQDO7DpCeDz7mOZbDAJz
4VlvaQt7YT3++wQ3eJSjBu2DzOdVdbaV4j6TIRS4zz45YV/WgvlP3cYCnXvdSX3P
6sPx+g0Eb9F7bwfyXNMSX1fyF1SagHuZ2NMDNu8xnh1HGVFpc/gIDvkKrVZojaXf
gtdUCOlmi3orGn6sBAz0ycjvRQKBgQDEzjKSYJClzDd0RbBEB8TJDIpzR+KwN+B7
SZ+D9VE6cKz2f2GMXckH+4m2tnncFhFD+ZK0pY41+LI5v72f2Q6K0qXT0rMWvj5j
WT8NlmoB3YxJVyryDQEdPJGnyy+dXXuUkQaVGCQUDTQF2FA4F8rxaDjYhvBZgvQP
Vj0XUhsMSQKBgQC4AoqsoZBZjVcMkFl+A2AtGxUC2y7umPre+XP0piyBkK4H6W49
S7ypyjlLP8Dt9hHsCPz8cROtL67+0mP3iaZGgT8iOu3m/o3qkXGCXRcwSl8KJkfE
QHUl3qxHS3xtxa4IQQDI6ce+HvdAcvaXFRu3t1UXw+EYg68x+UgsR2VQoQKBgAM2
kqDNLs9mLCmb0arqrY3SxJfpPow9/U5F/3K6GJ9po4lKvx75kQSuWKtBA3BSc+m2
M2z7nvzGmLJUrRXlB1XA5rA0qnPem0on9N2V7RkmstmnsK3PBIujp4Ujzh01n4Tn
cUIR6NTi+kx2IakoyklyuCrg2R+9AZsWf1zYHFTxAoGAR3I7LujdzIRNXPtZEmyl
hdSa21dZ/yguvJEGuXkEEA6uDbWZ8NJBQWgSO7er6526z+nEPMT3CxLHwan6bqAO
lC0IHFk6GDyzSxlPRKbLMCRIO+rU8vfX7PwolHxYzVqxX3MlrOD3sJdURsVp+Qh9
ycpRumeHZKJHtUrce7hTefI=
-----END PRIVATE KEY-----";

    const TEST_JWKS: &str = r#"{"keys":[{"kty":"RSA","kid":"test-key-1","use":"sig","alg":"RS256","n":"nxOHkjmzJ9UGau2ngSlyqNytJrzEvomaPWkDG1-zK6UC33jDsVIlz3HbCMabrRJc40Ams4JL9zMVhXutasehBjrpPuAi-OkRuFqvkqaWlKCwhpTnWN2hYV-be3f2bC9XuKv_JTkiiz0zOtKEOKEyrzIQbkYxA-wy6uleDJiEqDTQRfGT1rl4JzBKg8CZm65jDz6T9xf0itEHFvCxQQDEHzjtaSkM3I9WsroxPGn0cKO7tTeuATO6I39V4c08H59El9AosDn-HXBgaK3KB2XvBkMTSknM_9UeNmxz-yLY27762hRMs_VPwEKdlaerHQWpE-S0F5OCFB9ydcBLS8p2rQ","e":"AQAB"}]}"#;

    #[derive(Serialize)]
    struct TestClaims {
        sub: String,
        iss: String,
        aud: String,
        exp: i64,
    }

    fn auth() -> JwtAuth {
        let policy = ValidationPolicy {
            issuer: "https://issuer.example/".into(),
            audience: "osa-coordinator".into(),
            leeway_secs: 60,
        };
        let v = JwtValidator::from_jwks_json(policy, TEST_JWKS.as_bytes()).unwrap();
        JwtAuth::new(Arc::new(v))
    }

    fn valid_token() -> String {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let claims = TestClaims {
            sub: "alice@example".into(),
            iss: "https://issuer.example/".into(),
            aud: "osa-coordinator".into(),
            exp: now + 3600,
        };
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("test-key-1".into());
        encode(
            &header,
            &claims,
            &EncodingKey::from_rsa_pem(TEST_KEY_PEM.as_bytes()).unwrap(),
        )
        .unwrap()
    }

    fn with_auth_header(value: &str) -> Request<()> {
        let mut req = Request::new(());
        req.metadata_mut()
            .insert("authorization", MetadataValue::try_from(value).unwrap());
        req
    }

    #[test]
    fn valid_token_passes_and_binds_subject() {
        let req = auth().call(with_auth_header(&format!("Bearer {}", valid_token())));
        let req = req.expect("valid token must pass");
        assert_eq!(
            req.extensions().get::<Subject>(),
            Some(&Subject("alice@example".into()))
        );
    }

    #[test]
    fn missing_header_is_unauthenticated() {
        let err = auth().call(Request::new(())).unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }

    #[test]
    fn non_bearer_scheme_is_unauthenticated() {
        let err = auth()
            .call(with_auth_header(&format!("Basic {}", valid_token())))
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }

    #[test]
    fn bearer_scheme_is_case_insensitive() {
        // RFC 7235 makes the auth scheme case-insensitive.
        let req = auth()
            .call(with_auth_header(&format!("bEaReR {}", valid_token())))
            .expect("a case-varied Bearer scheme must still pass");
        assert!(req.extensions().get::<Subject>().is_some());
    }

    #[test]
    fn empty_token_after_scheme_is_unauthenticated() {
        let err = auth().call(with_auth_header("Bearer ")).unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }

    #[test]
    fn an_invalid_token_is_unauthenticated() {
        let err = auth()
            .call(with_auth_header("Bearer not.a.jwt"))
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }

    #[test]
    fn swapping_the_validator_changes_outcomes() {
        // The refresh task swaps the cell; the interceptor picks up the new
        // validator on the next request without being recreated.
        let auth = auth();
        let header = format!("Bearer {}", valid_token());
        assert!(auth.clone().call(with_auth_header(&header)).is_ok());

        // Swap in a validator that expects a different issuer → the same token
        // now fails against the freshly-installed keyset/policy.
        let other = JwtValidator::from_jwks_json(
            ValidationPolicy {
                issuer: "https://rotated.example/".into(),
                audience: "osa-coordinator".into(),
                leeway_secs: 60,
            },
            TEST_JWKS.as_bytes(),
        )
        .unwrap();
        *auth.cell().write().unwrap() = Arc::new(other);

        let err = auth.clone().call(with_auth_header(&header)).unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }
}
