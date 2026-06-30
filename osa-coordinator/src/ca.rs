/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: MIT
 */

//! Embedded CA adapter implementing [`CertIssuer`] (AD-23).
//!
//! The coordinator owns a self-signed CA and signs agent-generated CSRs into
//! short-lived client certificates. Identity is **coordinator-assigned**: the
//! issued certificate is built from a *fresh* parameter set — only the agent's
//! public key is taken from the CSR. Every other field (subject DN, SAN, key
//! usages, validity, extensions) is set by the coordinator, so nothing the agent
//! requested in the CSR can influence the issued certificate (AD-10, AD-11). The
//! agent's private key never leaves the host.

use async_trait::async_trait;
use osa_core::HostId;
use osa_core::ports::{CertIssuer, PortError};
use rcgen::string::Ia5String;
use rcgen::{
    CertificateParams, CertificateSigningRequestParams, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, PublicKeyData, SanType,
};
use rustls_pki_types::CertificateSigningRequestDer;
use sqlx::{PgPool, Row};
use time::{Duration, OffsetDateTime};
use x509_parser::prelude::{FromDer, GeneralName, X509Certificate};

/// Backdate `not_before` to tolerate modest clock skew between the coordinator
/// and the relying parties that validate the issued certificate.
const CLOCK_SKEW: Duration = Duration::minutes(5);

/// Advisory-lock key serializing the CA generate-once across replicas.
const CA_LOCK_KEY: i64 = 0x05A_CA01;

/// SAN URI form for a host identity: `urn:osa:host:<uuid>`.
fn host_san_uri(host_id: HostId) -> String {
    format!("urn:osa:host:{}", host_id.0)
}

/// The CA's PEM material, for persistence (AD-24). The private key is sensitive:
/// v1 stores it in a trusted Postgres; at-rest encryption is tracked in #35.
pub struct CaMaterial {
    pub cert_pem: String,
    pub key_pem: String,
}

/// An embedded certificate authority that signs host CSRs (AD-23).
///
/// Holds the signing [`Issuer`] plus the CA root cert bytes. Built either freshly
/// ([`generate`](Self::generate)) or reconstructed from stored PEM material
/// ([`from_material`](Self::from_material)) so every replica shares one CA (AD-24).
pub struct EmbeddedCa {
    issuer: Issuer<'static, KeyPair>,
    cert_der: Vec<u8>,
    cert_pem: String,
    /// The CA signing key (PKCS#8 PEM). Held to sign session ServerHellos (#20);
    /// the agent verifies them against the pinned CA root's public key. Already
    /// online for CSR signing, so this is no new exposure (see
    /// docs/design/session-handshake.md "Signing-key posture").
    key_pem: String,
    cert_ttl: Duration,
}

/// A host certificate that verified against this CA: its identity and the ECDSA
/// P-256 public key (SEC1 point) the handshake signature is checked against (#20).
pub struct VerifiedHost {
    pub host_id: HostId,
    pub public_key_sec1: Vec<u8>,
}

/// The CA root certificate parameters (self-signed, long-lived, KeyCertSign).
fn ca_params() -> CertificateParams {
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params
        .distinguished_name
        .push(DnType::CommonName, "open-ssm-agent embedded CA");
    let now = OffsetDateTime::now_utc();
    params.not_before = now - CLOCK_SKEW;
    params.not_after = now + Duration::days(3650);
    params
}

impl EmbeddedCa {
    /// Generate a fresh in-memory CA (single-node / dev / tests). Not persisted —
    /// regenerates on restart. `cert_ttl` is the validity of the host certs it
    /// issues (kept short — AD-11/AD-28 favor renewal). Errors if `cert_ttl <= 0`.
    pub fn new(cert_ttl: Duration) -> Result<Self, PortError> {
        Ok(Self::generate(cert_ttl)?.0)
    }

    /// Generate a fresh CA and also return its PEM material so a caller can
    /// persist it (the Postgres path, AD-24).
    pub fn generate(cert_ttl: Duration) -> Result<(Self, CaMaterial), PortError> {
        if cert_ttl <= Duration::ZERO {
            return Err(PortError::Invalid("cert_ttl must be positive".into()));
        }
        let key = KeyPair::generate().map_err(|e| PortError::Backend(e.to_string()))?;
        let key_pem = key.serialize_pem();
        let cert = ca_params()
            .self_signed(&key)
            .map_err(|e| PortError::Backend(e.to_string()))?;
        let cert_pem = cert.pem();
        let ca = Self::from_material(&cert_pem, &key_pem, cert_ttl)?;
        Ok((ca, CaMaterial { cert_pem, key_pem }))
    }

    /// Reconstruct a CA from stored PEM material so every replica signs with the
    /// same identity (AD-24). An agent that pinned the CA root then trusts certs
    /// issued by any replica.
    pub fn from_material(
        cert_pem: &str,
        key_pem: &str,
        cert_ttl: Duration,
    ) -> Result<Self, PortError> {
        if cert_ttl <= Duration::ZERO {
            return Err(PortError::Invalid("cert_ttl must be positive".into()));
        }
        let key = KeyPair::from_pem(key_pem)
            .map_err(|e| PortError::Invalid(format!("stored CA key is unusable: {e}")))?;
        let cert_der = pem::parse(cert_pem)
            .map_err(|e| PortError::Invalid(format!("stored CA cert is not valid PEM: {e}")))?
            .into_contents();
        // Integrity: the key MUST correspond to the cert's public key. Otherwise
        // the rebuilt CA would sign with a key the published root doesn't match,
        // and every issued cert would silently fail to chain. (`from_ca_cert_pem`
        // does not check this.)
        let (_, parsed) = X509Certificate::from_der(&cert_der)
            .map_err(|e| PortError::Invalid(format!("stored CA cert could not be parsed: {e}")))?;
        if key.der_bytes() != parsed.public_key().subject_public_key.data.as_ref() {
            return Err(PortError::Invalid(
                "stored CA key does not match the stored CA cert".into(),
            ));
        }
        let issuer = Issuer::from_ca_cert_pem(cert_pem, key)
            .map_err(|e| PortError::Invalid(format!("stored CA cert is unusable: {e}")))?;
        Ok(Self {
            issuer,
            cert_der,
            cert_pem: cert_pem.to_string(),
            key_pem: key_pem.to_string(),
            cert_ttl,
        })
    }

    /// Verify a host cert presented in a `ClientHello` (#20): it must chain to
    /// this CA and be currently valid. Returns the host identity (from the SAN)
    /// and its ECDSA P-256 public key in SEC1 form, for the handshake signature
    /// check. Revocation and tenant-binding are the caller's (they need the async
    /// [`Revocations`](crate::revocation::Revocations) port and the topic tenant).
    pub fn verify_host_cert(&self, cert_der: &[u8]) -> Result<VerifiedHost, PortError> {
        let (_, cert) = X509Certificate::from_der(cert_der)
            .map_err(|_| PortError::Invalid("malformed host certificate".into()))?;
        let ca_der = self.ca_root_der();
        let (_, ca) =
            X509Certificate::from_der(&ca_der).map_err(|e| PortError::Backend(e.to_string()))?;
        cert.verify_signature(Some(ca.public_key()))
            .map_err(|_| PortError::Invalid("host cert was not issued by this CA".into()))?;
        if !cert.validity().is_valid() {
            return Err(PortError::Invalid(
                "host cert is expired or not yet valid".into(),
            ));
        }
        let host_id = host_id_from_cert(&cert)?;
        // Fail closed at the boundary if the key is not EC: for an EC
        // SubjectPublicKey the BIT STRING contents are exactly the SEC1 point
        // (0x04‖X‖Y) that `VerifyingKey::from_sec1_bytes` wants; for an RSA cert
        // `.data` is a DER SEQUENCE that downstream would merely *reject*, so guard
        // explicitly here. (The P-256 curve itself is enforced by `from_sec1_bytes`
        // in the handshake verify.)
        let public_key_sec1 = match cert.public_key().parsed() {
            Ok(x509_parser::public_key::PublicKey::EC(point)) => point.data().to_vec(),
            _ => {
                return Err(PortError::Invalid(
                    "host cert public key is not an EC key".into(),
                ));
            }
        };
        Ok(VerifiedHost {
            host_id,
            public_key_sec1,
        })
    }

    /// Respond to a verified `ClientHello` (#20): verify the agent's signature
    /// over its ephemeral, sign the `ServerHello` with the CA key, and derive the
    /// session keys — all via the reviewed [`osa_core::handshake::respond`], so
    /// the CA key never leaves this struct. `public_key_sec1`/`cert_der` come from
    /// [`verify_host_cert`](Self::verify_host_cert) (the cert was already chain-
    /// verified); `respond` then proves the agent holds that identity's key.
    pub fn respond_handshake(
        &self,
        sid: &[u8],
        client_eph: &[u8; 32],
        client_sig: &[u8],
        public_key_sec1: &[u8],
        cert_der: &[u8],
    ) -> Result<osa_core::handshake::ServerResponse, PortError> {
        osa_core::handshake::respond(
            sid,
            client_eph,
            client_sig,
            public_key_sec1,
            cert_der,
            &self.key_pem,
        )
        .map_err(|e| PortError::Invalid(format!("session handshake failed: {e}")))
    }

    /// DER of the CA root certificate — delivered to agents in the join bundle
    /// for pinning (AD-25).
    pub fn ca_root_der(&self) -> Vec<u8> {
        self.cert_der.clone()
    }

    /// Parse and verify a CSR without issuing a certificate. Enrollment uses this
    /// to reject a malformed CSR *before* it burns a single-use join token.
    pub fn validate_csr(&self, csr: &[u8]) -> Result<(), PortError> {
        let der = CertificateSigningRequestDer::from(csr);
        CertificateSigningRequestParams::from_der(&der)
            .map(|_| ())
            .map_err(|e| PortError::Invalid(format!("invalid CSR: {e}")))
    }

    /// PEM of the CA root certificate (for TLS trust stores).
    pub fn ca_root_pem(&self) -> String {
        self.cert_pem.clone()
    }

    /// Issue a short-lived **server** certificate (serverAuth) for the given DNS
    /// names, signed by this CA. Used for the embedded broker's TLS so an agent
    /// that pinned the CA root trusts the broker (AD-27).
    pub fn issue_server_cert(&self, dns_names: &[&str]) -> Result<ServerCert, PortError> {
        if dns_names.is_empty() {
            return Err(PortError::Invalid(
                "a server cert needs at least one DNS name".into(),
            ));
        }
        let key = KeyPair::generate().map_err(|e| PortError::Backend(e.to_string()))?;
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        for name in dns_names {
            let dns = Ia5String::try_from(*name).map_err(|e| PortError::Backend(e.to_string()))?;
            params.subject_alt_names.push(SanType::DnsName(dns));
        }
        params
            .distinguished_name
            .push(DnType::CommonName, *dns_names.first().unwrap_or(&"broker"));
        let now = OffsetDateTime::now_utc();
        params.not_before = now - CLOCK_SKEW;
        params.not_after = now + self.cert_ttl;

        let issuer: &Issuer<'_, KeyPair> = &self.issuer;
        let cert = params
            .signed_by(&key, issuer)
            .map_err(|e| PortError::Backend(format!("signing server cert: {e}")))?;
        Ok(ServerCert {
            cert_pem: cert.pem(),
            key_pem: key.serialize_pem(),
        })
    }

    /// Shared issuance path for enrollment and renewal: build a client cert for
    /// `host_id` from `csr`, discarding every CSR-supplied field except the
    /// proven public key.
    fn issue(&self, host_id: HostId, csr: &[u8]) -> Result<Vec<u8>, PortError> {
        let csr_der = CertificateSigningRequestDer::from(csr);
        let mut req = CertificateSigningRequestParams::from_der(&csr_der)
            .map_err(|e| PortError::Invalid(format!("invalid CSR: {e}")))?;

        let san = Ia5String::try_from(host_san_uri(host_id))
            .map_err(|e| PortError::Backend(e.to_string()))?;
        let now = OffsetDateTime::now_utc();
        let mut params = CertificateParams::default();
        params
            .distinguished_name
            .push(DnType::CommonName, host_id.0.to_string());
        // O = host_id as hyphen-stripped UUID hex. The broker's
        // `validate-tenant-prefix` reads this O field and confines the agent to
        // its own `/tenants/<O>/…` topic subtree (per-host isolation, #16). It
        // must be alphanumeric, hence the simple (hyphenless) form; the SAN keeps
        // the canonical dashed UUID as the mTLS identity.
        params
            .distinguished_name
            .push(DnType::OrganizationName, host_id.0.simple().to_string());
        params.subject_alt_names = vec![SanType::URI(san)];
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        params.not_before = now - CLOCK_SKEW;
        params.not_after = now + self.cert_ttl;
        req.params = params;

        let issuer: &Issuer<'_, KeyPair> = &self.issuer;
        let cert = req
            .signed_by(issuer)
            .map_err(|e| PortError::Backend(format!("signing failed: {e}")))?;
        Ok(cert.der().to_vec())
    }

    /// Validate a renewal request (AD-11/AD-28): verify `current_cert` was issued
    /// by this CA, is currently valid, and that `csr` carries the **same key** (so
    /// the CSR's proof-of-possession also proves the requester holds the current
    /// identity). Returns the identity to reissue for. The caller checks
    /// revocation (async, AD-28) and then issues via [`CertIssuer::sign`] — no
    /// join token. Splitting validation from issuance lets the (async,
    /// Postgres-backed) revocation check sit between them.
    pub fn validate_renewal(&self, current_cert: &[u8], csr: &[u8]) -> Result<HostId, PortError> {
        let (_, cert) = X509Certificate::from_der(current_cert)
            .map_err(|_| PortError::Invalid("malformed current certificate".into()))?;
        let ca_der = self.ca_root_der();
        let (_, ca) =
            X509Certificate::from_der(&ca_der).map_err(|e| PortError::Backend(e.to_string()))?;
        cert.verify_signature(Some(ca.public_key()))
            .map_err(|_| PortError::Invalid("current cert was not issued by this CA".into()))?;
        if !cert.validity().is_valid() {
            return Err(PortError::Invalid(
                "current cert is expired or not yet valid".into(),
            ));
        }
        let host_id = host_id_from_cert(&cert)?;

        // `from_der` verifies the CSR's proof-of-possession signature. Requiring
        // the CSR's public key to equal the current cert's key then means the
        // requester proved possession of *this identity's* key — this equality is
        // the renewal auth boundary (no token needed).
        let der = CertificateSigningRequestDer::from(csr);
        let req = CertificateSigningRequestParams::from_der(&der)
            .map_err(|e| PortError::Invalid(format!("invalid CSR: {e}")))?;
        if req.public_key.der_bytes() != cert.public_key().subject_public_key.data.as_ref() {
            return Err(PortError::Invalid(
                "CSR key does not match the current identity".into(),
            ));
        }
        Ok(host_id)
    }
}

/// Load the shared CA from Postgres, generating and persisting it exactly once
/// if absent (AD-23/AD-24, closes #7). A transaction-scoped advisory lock
/// serializes generation across replicas: only one replica generates the CA;
/// every other waits and reads the same persisted material, so all replicas sign
/// with one CA identity.
pub async fn load_or_generate(pool: &PgPool, cert_ttl: Duration) -> anyhow::Result<EmbeddedCa> {
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(CA_LOCK_KEY)
        .execute(&mut *tx)
        .await?;

    let existing = sqlx::query("SELECT cert_pem, key_pem FROM ca_identity ORDER BY id ASC LIMIT 1")
        .fetch_optional(&mut *tx)
        .await?;
    let ca = match existing {
        Some(row) => {
            let cert_pem: String = row.try_get("cert_pem")?;
            let key_pem: String = row.try_get("key_pem")?;
            EmbeddedCa::from_material(&cert_pem, &key_pem, cert_ttl)?
        }
        None => {
            let (ca, material) = EmbeddedCa::generate(cert_ttl)?;
            sqlx::query(
                "INSERT INTO ca_identity (cert_pem, key_pem, created_at_unix) VALUES ($1, $2, $3)",
            )
            .bind(&material.cert_pem)
            .bind(&material.key_pem)
            .bind(now_unix())
            .execute(&mut *tx)
            .await?;
            tracing::info!("generated and persisted the shared CA (AD-24)");
            ca
        }
    };
    tx.commit().await?;
    Ok(ca)
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Extract the `host_id` from a cert's `urn:osa:host:<uuid>` URI SAN.
fn host_id_from_cert(cert: &X509Certificate) -> Result<HostId, PortError> {
    let san = cert
        .subject_alternative_name()
        .ok()
        .flatten()
        .ok_or_else(|| PortError::Invalid("current cert has no SAN".into()))?;
    let uri = san
        .value
        .general_names
        .iter()
        .find_map(|gn| match gn {
            GeneralName::URI(u) => Some(*u),
            _ => None,
        })
        .ok_or_else(|| PortError::Invalid("current cert has no URI SAN".into()))?;
    let uuid = uri
        .strip_prefix("urn:osa:host:")
        .and_then(|s| uuid::Uuid::parse_str(s).ok())
        .ok_or_else(|| PortError::Invalid("SAN is not a host identity".into()))?;
    Ok(HostId(uuid))
}

/// A signed server certificate and its private key, both PEM-encoded.
pub struct ServerCert {
    pub cert_pem: String,
    pub key_pem: String,
}

#[async_trait]
impl CertIssuer for EmbeddedCa {
    async fn sign(&self, host_id: HostId, csr: &[u8]) -> Result<Vec<u8>, PortError> {
        self.issue(host_id, csr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A CSR built with the given keypair (no overridden fields survive issuance).
    fn csr_with_key(key: &KeyPair) -> Vec<u8> {
        CertificateParams::default()
            .serialize_request(key)
            .unwrap()
            .der()
            .to_vec()
    }

    /// A CSR an agent might submit — deliberately requesting a hostile subject CN
    /// and SAN that the coordinator must discard.
    fn agent_csr() -> Vec<u8> {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::default();
        params.distinguished_name.push(DnType::CommonName, "admin");
        params.subject_alt_names.push(SanType::DnsName(
            Ia5String::try_from("attacker.example").unwrap(),
        ));
        params.serialize_request(&key).unwrap().der().to_vec()
    }

    #[tokio::test]
    async fn signs_csr_with_coordinator_assigned_identity() {
        let ttl = Duration::hours(24);
        let ca = EmbeddedCa::new(ttl).unwrap();
        let host = HostId::new();
        let cert_der = ca.sign(host, &agent_csr()).await.unwrap();

        let (_, cert) = X509Certificate::from_der(&cert_der).unwrap();

        // Signed by the CA root (cryptographic check, not just DN matching).
        let ca_der = ca.ca_root_der();
        let (_, ca_cert) = X509Certificate::from_der(&ca_der).unwrap();
        cert.verify_signature(Some(ca_cert.public_key()))
            .expect("leaf must be signed by the CA root");

        // SAN is exactly the assigned host_id; the agent's requested SAN is gone.
        let san = cert.subject_alternative_name().unwrap().unwrap();
        let uris: Vec<&str> = san
            .value
            .general_names
            .iter()
            .filter_map(|gn| match gn {
                GeneralName::URI(u) => Some(*u),
                _ => None,
            })
            .collect();
        assert_eq!(uris, vec![host_san_uri(host).as_str()]);
        assert!(
            !san.value
                .general_names
                .iter()
                .any(|gn| matches!(gn, GeneralName::DNSName(_))),
            "agent-requested DNS SAN must not survive"
        );

        // Subject CN is the assigned host_id, not the agent's "admin".
        let cn = cert
            .subject()
            .iter_common_name()
            .next()
            .unwrap()
            .as_str()
            .unwrap();
        assert_eq!(cn, host.0.to_string());

        // A constrained client certificate.
        assert!(!cert.is_ca());
        let eku = cert.extended_key_usage().unwrap().unwrap();
        assert!(eku.value.client_auth, "must carry clientAuth EKU");

        // Short, bounded validity: exactly ttl + skew window.
        let span = cert.validity().not_after.timestamp() - cert.validity().not_before.timestamp();
        assert_eq!(span, (ttl + CLOCK_SKEW).whole_seconds());
    }

    #[tokio::test]
    async fn rejects_malformed_csr() {
        let ca = EmbeddedCa::new(Duration::hours(24)).unwrap();
        let err = ca
            .sign(HostId::new(), b"this is not a CSR")
            .await
            .unwrap_err();
        assert!(matches!(err, PortError::Invalid(_)));
    }

    #[tokio::test]
    async fn rejects_tampered_csr_signature() {
        let ca = EmbeddedCa::new(Duration::hours(24)).unwrap();
        let mut csr = agent_csr();
        // Corrupt the trailing signature bits — DER still parses, but the CSR's
        // proof-of-possession signature no longer verifies.
        *csr.last_mut().unwrap() ^= 0x01;
        let err = ca.sign(HostId::new(), &csr).await.unwrap_err();
        assert!(matches!(err, PortError::Invalid(_)));
    }

    #[tokio::test]
    async fn rejects_non_positive_ttl() {
        assert!(matches!(
            EmbeddedCa::new(Duration::ZERO),
            Err(PortError::Invalid(_))
        ));
    }

    #[test]
    fn validate_renewal_accepts_the_same_key_and_reissues() {
        let ca = EmbeddedCa::new(Duration::hours(24)).unwrap();
        let key = KeyPair::generate().unwrap();
        let host = HostId::new();
        let cert0 = ca.issue(host, &csr_with_key(&key)).unwrap();

        // Validation returns the identity; the same key is required (no token).
        let renewed = ca.validate_renewal(&cert0, &csr_with_key(&key)).unwrap();
        assert_eq!(renewed, host);

        // Issuance for that identity yields a cert with the same SAN, CA-signed.
        let cert1 = ca.issue(renewed, &csr_with_key(&key)).unwrap();
        let (_, c1) = X509Certificate::from_der(&cert1).unwrap();
        let san = c1.subject_alternative_name().unwrap().unwrap();
        let uri = san
            .value
            .general_names
            .iter()
            .find_map(|gn| match gn {
                GeneralName::URI(u) => Some(*u),
                _ => None,
            })
            .unwrap();
        assert_eq!(uri, host_san_uri(host));
        let ca_der = ca.ca_root_der();
        let (_, ca_cert) = X509Certificate::from_der(&ca_der).unwrap();
        c1.verify_signature(Some(ca_cert.public_key())).unwrap();
    }

    #[test]
    fn validate_renewal_rejects_a_csr_with_a_different_key() {
        let ca = EmbeddedCa::new(Duration::hours(24)).unwrap();
        let key = KeyPair::generate().unwrap();
        let cert0 = ca.issue(HostId::new(), &csr_with_key(&key)).unwrap();
        let other = KeyPair::generate().unwrap();
        assert!(matches!(
            ca.validate_renewal(&cert0, &csr_with_key(&other)),
            Err(PortError::Invalid(_))
        ));
    }

    #[test]
    fn validate_renewal_rejects_a_cert_from_another_ca() {
        let ca = EmbeddedCa::new(Duration::hours(24)).unwrap();
        let foreign_ca = EmbeddedCa::new(Duration::hours(24)).unwrap();
        let key = KeyPair::generate().unwrap();
        let foreign = foreign_ca
            .issue(HostId::new(), &csr_with_key(&key))
            .unwrap();
        assert!(matches!(
            ca.validate_renewal(&foreign, &csr_with_key(&key)),
            Err(PortError::Invalid(_))
        ));
    }

    #[test]
    fn validate_renewal_rejects_a_malformed_current_cert() {
        let ca = EmbeddedCa::new(Duration::hours(24)).unwrap();
        let key = KeyPair::generate().unwrap();
        assert!(matches!(
            ca.validate_renewal(b"not a certificate", &csr_with_key(&key)),
            Err(PortError::Invalid(_))
        ));
    }

    #[test]
    fn a_ca_reconstructed_from_material_still_signs_verifiably() {
        // generate -> material -> from_material yields a working signer whose
        // issued cert verifies against the (unchanged) CA root.
        let (orig, material) = EmbeddedCa::generate(Duration::hours(24)).unwrap();
        let rebuilt =
            EmbeddedCa::from_material(&material.cert_pem, &material.key_pem, Duration::hours(24))
                .unwrap();
        assert_eq!(orig.ca_root_der(), rebuilt.ca_root_der(), "same CA root");

        let key = KeyPair::generate().unwrap();
        let host = HostId::new();
        let cert = rebuilt.issue(host, &csr_with_key(&key)).unwrap();
        let root_der = rebuilt.ca_root_der();
        let (_, leaf) = X509Certificate::from_der(&cert).unwrap();
        let (_, ca_root) = X509Certificate::from_der(&root_der).unwrap();
        leaf.verify_signature(Some(ca_root.public_key()))
            .expect("rebuilt CA must sign verifiable certs");
        // Not just a raw signature: the leaf must actually chain to this root.
        assert_eq!(
            leaf.issuer(),
            ca_root.subject(),
            "leaf must chain to the root"
        );
    }

    #[test]
    fn from_material_rejects_unusable_or_mismatched_material() {
        let (_, material) = EmbeddedCa::generate(Duration::hours(24)).unwrap();
        // A key from a *different* CA does not match this cert → refused.
        let (_, other) = EmbeddedCa::generate(Duration::hours(24)).unwrap();
        assert!(matches!(
            EmbeddedCa::from_material(&material.cert_pem, &other.key_pem, Duration::hours(24)),
            Err(PortError::Invalid(_))
        ));
        // Garbage PEM, and a non-positive TTL, are also refused.
        assert!(
            EmbeddedCa::from_material("not pem", &material.key_pem, Duration::hours(24)).is_err()
        );
        assert!(matches!(
            EmbeddedCa::from_material(&material.cert_pem, &material.key_pem, Duration::ZERO),
            Err(PortError::Invalid(_))
        ));
    }

    #[test]
    fn verify_host_cert_returns_identity_and_a_usable_pubkey() {
        // A cert this CA issued verifies, yields its host_id, and the extracted
        // SEC1 pubkey verifies a signature the host's own key made — i.e. it is
        // exactly the key the handshake will check the ClientHello against (#20).
        let ca = EmbeddedCa::new(Duration::hours(24)).unwrap();
        let key = KeyPair::generate().unwrap();
        let host = HostId::new();
        let cert_der = ca.issue(host, &csr_with_key(&key)).unwrap();

        let verified = ca.verify_host_cert(&cert_der).unwrap();
        assert_eq!(verified.host_id, host);

        let msg = b"osa/v1 hs c2s transcript";
        let sig = osa_core::handshake::sign(&key.serialize_pem(), msg).unwrap();
        osa_core::handshake::verify(&verified.public_key_sec1, msg, &sig)
            .expect("extracted SEC1 pubkey must verify the host key's signature");
    }

    #[test]
    fn verify_host_cert_rejects_a_foreign_or_malformed_cert() {
        let ca = EmbeddedCa::new(Duration::hours(24)).unwrap();
        let foreign_ca = EmbeddedCa::new(Duration::hours(24)).unwrap();
        let key = KeyPair::generate().unwrap();
        let foreign = foreign_ca
            .issue(HostId::new(), &csr_with_key(&key))
            .unwrap();
        assert!(matches!(
            ca.verify_host_cert(&foreign),
            Err(PortError::Invalid(_))
        ));
        assert!(matches!(
            ca.verify_host_cert(b"not a cert"),
            Err(PortError::Invalid(_))
        ));
    }

    #[test]
    fn respond_handshake_completes_a_real_initiator() {
        // End-to-end through the CA: an agent runs Initiator::start with a
        // CA-issued identity; the coordinator verifies the cert and responds; the
        // agent finishes against the pinned CA root. Both sides derive the SAME
        // session keys — a payload sealed by one opens with the other (#20).
        use osa_core::handshake::Initiator;
        use osa_core::seal::Direction;

        let ca = EmbeddedCa::new(Duration::hours(24)).unwrap();
        let key = KeyPair::generate().unwrap();
        let host = HostId::new();
        let cert_der = ca.issue(host, &csr_with_key(&key)).unwrap();
        let sid = b"session-1";

        let (initiator, hello) = Initiator::start(sid, &cert_der, &key.serialize_pem()).unwrap();
        let client_eph: [u8; 32] = hello.client_eph;

        let verified = ca.verify_host_cert(&cert_der).unwrap();
        let resp = ca
            .respond_handshake(
                sid,
                &client_eph,
                &hello.sig,
                &verified.public_key_sec1,
                &cert_der,
            )
            .unwrap();

        let ca_der = ca.ca_root_der();
        let (_, root) = X509Certificate::from_der(&ca_der).unwrap();
        let ca_pub_sec1 = root.public_key().subject_public_key.data.to_vec();
        let agent_keys = initiator
            .finish(&resp.server_eph, &resp.sig, &ca_pub_sec1)
            .unwrap();

        let ct = resp.keys.seal(Direction::CoordToAgent, 0, b"h", b"ping");
        assert_eq!(
            agent_keys
                .open(Direction::CoordToAgent, 0, b"h", &ct)
                .unwrap(),
            b"ping"
        );
    }

    // --- Postgres shared-CA (testcontainers; needs Docker) ---

    use testcontainers_modules::postgres::Postgres;
    use testcontainers_modules::testcontainers::ImageExt;
    use testcontainers_modules::testcontainers::runners::AsyncRunner;

    async fn pg_url() -> (
        testcontainers_modules::testcontainers::ContainerAsync<Postgres>,
        String,
    ) {
        let node = Postgres::default()
            .with_tag("17-alpine")
            .start()
            .await
            .unwrap();
        let port = node.get_host_port_ipv4(5432).await.unwrap();
        let url = format!("postgres://postgres:postgres@127.0.0.1:{port}/postgres");
        let pool = crate::db::connect(&url).await.unwrap();
        crate::db::migrate(&pool).await.unwrap();
        (node, url)
    }

    #[tokio::test]
    async fn two_replicas_share_one_generated_ca() {
        // Two coordinators (independent pools) against one database: the first to
        // boot generates the CA under the advisory lock; the second reads it.
        // Both must end up with the SAME CA root, and a cert issued by one must
        // verify against the other's root — the cross-replica trust requirement.
        let (_node, url) = pg_url().await;
        let pool_a = crate::db::connect(&url).await.unwrap();
        let pool_b = crate::db::connect(&url).await.unwrap();

        // Both replicas reach load_or_generate *concurrently* — the advisory lock
        // must serialize them so exactly one generates and both get the same CA.
        let (ra, rb) = tokio::join!(
            load_or_generate(&pool_a, Duration::hours(24)),
            load_or_generate(&pool_b, Duration::hours(24)),
        );
        let ca_a = ra.unwrap();
        let ca_b = rb.unwrap();
        assert_eq!(
            ca_a.ca_root_der(),
            ca_b.ca_root_der(),
            "both replicas must share one CA"
        );

        // A cert enrolled via replica A verifies against replica B's CA root.
        let key = KeyPair::generate().unwrap();
        let cert = ca_a.issue(HostId::new(), &csr_with_key(&key)).unwrap();
        let b_root_der = ca_b.ca_root_der();
        let (_, leaf) = X509Certificate::from_der(&cert).unwrap();
        let (_, b_root) = X509Certificate::from_der(&b_root_der).unwrap();
        leaf.verify_signature(Some(b_root.public_key()))
            .expect("A-issued cert must verify against B's CA root");
        assert_eq!(
            leaf.issuer(),
            b_root.subject(),
            "A's leaf must chain to B's root"
        );
    }

    #[tokio::test]
    async fn ca_survives_a_restart() {
        // A fresh load over the same database (a coordinator restart) returns the
        // persisted CA, not a new one.
        let (_node, url) = pg_url().await;
        let pool = crate::db::connect(&url).await.unwrap();
        let first = load_or_generate(&pool, Duration::hours(24)).await.unwrap();
        let again = load_or_generate(&pool, Duration::hours(24)).await.unwrap();
        assert_eq!(first.ca_root_der(), again.ca_root_der());
    }
}
