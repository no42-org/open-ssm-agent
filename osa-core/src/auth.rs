/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: MIT
 */

//! Operator JWT validation (AD-18).
//!
//! The coordinator authenticates operator gRPC calls against an OIDC issuer:
//! a bearer JWT is accepted only if its signature verifies against a key in the
//! issuer's JWKS and its `iss`/`aud`/`exp`/`nbf` claims satisfy the configured
//! policy (with a small clock-skew leeway). The authenticated `sub` becomes the
//! request [`Subject`].
//!
//! This module is pure (no network, no clock injection beyond the JWT library's
//! own `exp`/`nbf` handling): it validates a token against an already-loaded key
//! set. Fetching and refreshing the JWKS over HTTP is an adapter concern wired in
//! the coordinator bin (story 2.1b).

use std::collections::HashMap;

use jsonwebtoken::jwk::{AlgorithmParameters, EllipticCurve, Jwk, JwkSet, KeyAlgorithm};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::Deserialize;

/// An authenticated operator principal — the JWT `sub`. Bound into the gRPC
/// request once the token validates; the PDP (AD-19, story 2.2) authorizes on it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Subject(pub String);

/// Why a presented credential was rejected. The gRPC layer collapses all of
/// these to `UNAUTHENTICATED` (no oracle); the specific reason is logged.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AuthError {
    #[error("no bearer token presented")]
    Missing,
    #[error("malformed token")]
    Malformed,
    #[error("signature verification failed")]
    BadSignature,
    #[error("token has expired")]
    Expired,
    #[error("token is not yet valid")]
    NotYetValid,
    #[error("wrong audience")]
    WrongAudience,
    #[error("wrong issuer")]
    WrongIssuer,
    #[error("no key matches the token's key id")]
    UnknownKey,
}

/// A JWKS could not be turned into a usable key set — a startup/config error,
/// distinct from a per-request [`AuthError`].
#[derive(Debug, thiserror::Error)]
pub enum JwksError {
    #[error("JWKS is not valid JSON")]
    Json,
    #[error("JWKS contains no usable signing keys")]
    Empty,
    #[error("JWKS has two keys sharing key id {kid}")]
    DuplicateKid { kid: String },
}

/// The claim policy a token must satisfy.
pub struct ValidationPolicy {
    /// Required `iss`.
    pub issuer: String,
    /// Required `aud`.
    pub audience: String,
    /// Clock-skew tolerance applied to `exp`/`nbf`, in seconds.
    pub leeway_secs: u64,
}

/// One verified signing key plus the algorithm it is pinned to (anti-confusion).
struct VerifyingKey {
    decoding: DecodingKey,
    alg: Algorithm,
}

/// Validates operator JWTs against a fixed key set under a fixed policy.
pub struct JwtValidator {
    policy: ValidationPolicy,
    keys: HashMap<String, VerifyingKey>,
}

#[derive(Deserialize)]
struct Claims {
    sub: String,
}

impl JwtValidator {
    /// Build a validator from a raw JWKS document (the bytes of the issuer's
    /// `jwks_uri` response).
    pub fn from_jwks_json(policy: ValidationPolicy, jwks: &[u8]) -> Result<Self, JwksError> {
        let set: JwkSet = serde_json::from_slice(jwks).map_err(|_| JwksError::Json)?;
        let mut keys = HashMap::new();
        for jwk in &set.keys {
            // A key we cannot index or verify with is skipped, not fatal: real
            // OIDC JWKS routinely mix in encryption / other-algorithm keys we
            // have no use for. We only require *some* usable signing key (below).
            let Some(kid) = jwk.common.key_id.clone() else {
                continue;
            };
            let Some(alg) = algorithm_of(jwk) else {
                continue;
            };
            let Ok(decoding) = DecodingKey::from_jwk(jwk) else {
                continue;
            };
            // A duplicated kid is a genuine ambiguity (which key verifies a token
            // bearing that kid?) — reject rather than silently pick last-wins.
            if keys
                .insert(kid.clone(), VerifyingKey { decoding, alg })
                .is_some()
            {
                return Err(JwksError::DuplicateKid { kid });
            }
        }
        if keys.is_empty() {
            return Err(JwksError::Empty);
        }
        Ok(Self { policy, keys })
    }

    /// Validate a bearer token, returning its authenticated [`Subject`].
    pub fn validate(&self, token: &str) -> Result<Subject, AuthError> {
        let header = decode_header(token).map_err(|_| AuthError::Malformed)?;
        let kid = header.kid.ok_or(AuthError::Malformed)?;
        // Select the key by `kid` and pin validation to *that key's* algorithm,
        // so a token cannot down/cross-grade the algorithm (e.g. RS256 -> HS256
        // keyed on the public modulus).
        let key = self.keys.get(&kid).ok_or(AuthError::UnknownKey)?;
        let mut v = Validation::new(key.alg);
        v.set_issuer(&[self.policy.issuer.as_str()]);
        v.set_audience(&[self.policy.audience.as_str()]);
        v.leeway = self.policy.leeway_secs;
        // `exp` is validated by default; `nbf` is opt-in.
        v.validate_nbf = true;
        // Require these claims to be *present*, not just well-formed when present
        // — so a token that simply omits `iss`/`aud`/`exp`/`sub` is rejected
        // rather than slipping through on a library default.
        v.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
        let data = decode::<Claims>(token, &key.decoding, &v).map_err(map_jwt_error)?;
        Ok(Subject(data.claims.sub))
    }
}

/// The signing algorithm a JWK is pinned to: its declared `alg` if present, else
/// inferred from the key type. Returns `None` for algorithms we do not accept.
fn algorithm_of(jwk: &Jwk) -> Option<Algorithm> {
    if let Some(ka) = jwk.common.key_algorithm {
        return key_algorithm_to_algorithm(ka);
    }
    match &jwk.algorithm {
        AlgorithmParameters::RSA(_) => Some(Algorithm::RS256),
        AlgorithmParameters::EllipticCurve(ec) => match ec.curve {
            EllipticCurve::P256 => Some(Algorithm::ES256),
            EllipticCurve::P384 => Some(Algorithm::ES384),
            _ => None,
        },
        _ => None,
    }
}

fn key_algorithm_to_algorithm(ka: KeyAlgorithm) -> Option<Algorithm> {
    Some(match ka {
        KeyAlgorithm::RS256 => Algorithm::RS256,
        KeyAlgorithm::RS384 => Algorithm::RS384,
        KeyAlgorithm::RS512 => Algorithm::RS512,
        KeyAlgorithm::PS256 => Algorithm::PS256,
        KeyAlgorithm::PS384 => Algorithm::PS384,
        KeyAlgorithm::PS512 => Algorithm::PS512,
        KeyAlgorithm::ES256 => Algorithm::ES256,
        KeyAlgorithm::ES384 => Algorithm::ES384,
        KeyAlgorithm::EdDSA => Algorithm::EdDSA,
        // HMAC algorithms have no place in OIDC issuer JWKS (symmetric); reject.
        _ => return None,
    })
}

fn map_jwt_error(e: jsonwebtoken::errors::Error) -> AuthError {
    use jsonwebtoken::errors::ErrorKind;
    match e.kind() {
        ErrorKind::ExpiredSignature => AuthError::Expired,
        ErrorKind::ImmatureSignature => AuthError::NotYetValid,
        ErrorKind::InvalidAudience => AuthError::WrongAudience,
        ErrorKind::InvalidIssuer => AuthError::WrongIssuer,
        ErrorKind::InvalidSignature => AuthError::BadSignature,
        _ => AuthError::Malformed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{EncodingKey, Header, encode};
    use serde::Serialize;

    // Hermetic RS256 test material: a throwaway 2048-bit RSA key (private PEM
    // used here to *mint* tokens) and the matching public JWKS the validator
    // parses. Generated offline; never used outside tests.
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

    const ISSUER: &str = "https://issuer.example/";
    const AUDIENCE: &str = "osa-coordinator";

    #[derive(Serialize)]
    struct TestClaims {
        sub: String,
        iss: String,
        aud: String,
        exp: i64,
        nbf: i64,
    }

    fn now() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    /// Mint a token signed by the test key, with overridable claims.
    fn mint(claims: &TestClaims, kid: &str) -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(kid.to_string());
        let key = EncodingKey::from_rsa_pem(TEST_KEY_PEM.as_bytes()).unwrap();
        encode(&header, claims, &key).unwrap()
    }

    fn valid_claims() -> TestClaims {
        let t = now();
        TestClaims {
            sub: "alice@example".into(),
            iss: ISSUER.into(),
            aud: AUDIENCE.into(),
            exp: t + 3600,
            nbf: t - 60,
        }
    }

    fn validator() -> JwtValidator {
        let policy = ValidationPolicy {
            issuer: ISSUER.into(),
            audience: AUDIENCE.into(),
            leeway_secs: 60,
        };
        JwtValidator::from_jwks_json(policy, TEST_JWKS.as_bytes()).unwrap()
    }

    #[test]
    fn accepts_a_valid_token_and_binds_the_subject() {
        let token = mint(&valid_claims(), "test-key-1");
        let subject = validator().validate(&token).unwrap();
        assert_eq!(subject, Subject("alice@example".into()));
    }

    #[test]
    fn rejects_an_expired_token() {
        let mut c = valid_claims();
        c.exp = now() - 3600;
        let token = mint(&c, "test-key-1");
        assert_eq!(validator().validate(&token), Err(AuthError::Expired));
    }

    #[test]
    fn rejects_a_not_yet_valid_token() {
        let mut c = valid_claims();
        c.nbf = now() + 3600;
        let token = mint(&c, "test-key-1");
        assert_eq!(validator().validate(&token), Err(AuthError::NotYetValid));
    }

    #[test]
    fn tolerates_small_skew_within_leeway() {
        // Expired 30s ago, but leeway is 60s → still accepted.
        let mut c = valid_claims();
        c.exp = now() - 30;
        let token = mint(&c, "test-key-1");
        assert!(validator().validate(&token).is_ok());
    }

    #[test]
    fn rejects_the_wrong_audience() {
        let mut c = valid_claims();
        c.aud = "some-other-service".into();
        let token = mint(&c, "test-key-1");
        assert_eq!(validator().validate(&token), Err(AuthError::WrongAudience));
    }

    #[test]
    fn rejects_the_wrong_issuer() {
        let mut c = valid_claims();
        c.iss = "https://evil.example/".into();
        let token = mint(&c, "test-key-1");
        assert_eq!(validator().validate(&token), Err(AuthError::WrongIssuer));
    }

    #[test]
    fn rejects_an_unknown_key_id() {
        let token = mint(&valid_claims(), "some-rotated-out-kid");
        assert_eq!(validator().validate(&token), Err(AuthError::UnknownKey));
    }

    #[test]
    fn rejects_a_bad_signature() {
        // Splice the header+signature of one validly-signed token onto a
        // different (also validly-signed) payload: the signature no longer
        // matches the body it now covers.
        let genuine = mint(&valid_claims(), "test-key-1");
        let forged = mint(
            &TestClaims {
                sub: "mallory@example".into(),
                ..valid_claims()
            },
            "test-key-1",
        );
        let mut parts: Vec<&str> = genuine.split('.').collect();
        parts[1] = forged.split('.').nth(1).unwrap();
        let spliced = parts.join(".");
        assert_eq!(validator().validate(&spliced), Err(AuthError::BadSignature));
    }

    #[test]
    fn rejects_garbage() {
        assert_eq!(validator().validate("not.a.jwt"), Err(AuthError::Malformed));
    }

    #[test]
    fn empty_jwks_is_a_config_error() {
        let policy = ValidationPolicy {
            issuer: ISSUER.into(),
            audience: AUDIENCE.into(),
            leeway_secs: 60,
        };
        let err = JwtValidator::from_jwks_json(policy, br#"{"keys":[]}"#);
        assert!(matches!(err, Err(JwksError::Empty)));
    }

    /// Mint a token from arbitrary claim JSON, so a required claim can be omitted.
    fn mint_value(claims: serde_json::Value, kid: &str) -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(kid.to_string());
        let key = EncodingKey::from_rsa_pem(TEST_KEY_PEM.as_bytes()).unwrap();
        encode(&header, &claims, &key).unwrap()
    }

    #[test]
    fn rejects_a_token_missing_a_required_claim() {
        let t = now();
        // Each map drops exactly one of exp/iss/aud/sub; all must be rejected.
        let omit_exp = serde_json::json!({"sub": "a", "iss": ISSUER, "aud": AUDIENCE});
        let omit_iss = serde_json::json!({"sub": "a", "aud": AUDIENCE, "exp": t + 3600});
        let omit_aud = serde_json::json!({"sub": "a", "iss": ISSUER, "exp": t + 3600});
        let omit_sub = serde_json::json!({"iss": ISSUER, "aud": AUDIENCE, "exp": t + 3600});
        for claims in [omit_exp, omit_iss, omit_aud, omit_sub] {
            let token = mint_value(claims, "test-key-1");
            assert!(
                validator().validate(&token).is_err(),
                "a token missing a required claim must be rejected"
            );
        }
    }

    #[test]
    fn duplicate_kid_is_a_config_error() {
        let policy = ValidationPolicy {
            issuer: ISSUER.into(),
            audience: AUDIENCE.into(),
            leeway_secs: 60,
        };
        // Two keys sharing one kid (here, the same key twice).
        let dup = format!(r#"{{"keys":[{0},{0}]}}"#, single_jwk());
        let err = JwtValidator::from_jwks_json(policy, dup.as_bytes());
        assert!(matches!(err, Err(JwksError::DuplicateKid { .. })));
    }

    #[test]
    fn skips_an_unusable_key_but_keeps_the_usable_one() {
        let policy = ValidationPolicy {
            issuer: ISSUER.into(),
            audience: AUDIENCE.into(),
            leeway_secs: 60,
        };
        // A symmetric (oct) key we cannot use, alongside our real RSA sig key:
        // the oct key is skipped, the RSA key still loads and validates tokens.
        let mixed = format!(
            r#"{{"keys":[{{"kty":"oct","kid":"sym","k":"AAAA"}},{}]}}"#,
            single_jwk()
        );
        let v = JwtValidator::from_jwks_json(policy, mixed.as_bytes()).unwrap();
        let token = mint(&valid_claims(), "test-key-1");
        assert!(v.validate(&token).is_ok());
    }

    /// The single RSA JWK object (without the surrounding `{"keys":[…]}`).
    fn single_jwk() -> String {
        let v: serde_json::Value = serde_json::from_str(TEST_JWKS).unwrap();
        v["keys"][0].to_string()
    }
}
