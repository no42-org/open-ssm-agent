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
    CertificateParams, CertificateSigningRequestParams, CertifiedIssuer, DnType,
    ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose, SanType,
};
use rustls_pki_types::CertificateSigningRequestDer;
use time::{Duration, OffsetDateTime};

/// Backdate `not_before` to tolerate modest clock skew between the coordinator
/// and the relying parties that validate the issued certificate.
const CLOCK_SKEW: Duration = Duration::minutes(5);

/// SAN URI form for a host identity: `urn:osa:host:<uuid>`.
fn host_san_uri(host_id: HostId) -> String {
    format!("urn:osa:host:{}", host_id.0)
}

/// An embedded certificate authority that signs host CSRs (AD-23).
pub struct EmbeddedCa {
    issuer: CertifiedIssuer<'static, KeyPair>,
    cert_ttl: Duration,
}

impl EmbeddedCa {
    /// Generate a fresh self-signed CA. `cert_ttl` is the validity of the host
    /// certificates this CA issues (kept short — AD-11/AD-28 favor renewal over
    /// long-lived certs). Returns an error if `cert_ttl` is not positive.
    pub fn new(cert_ttl: Duration) -> Result<Self, PortError> {
        if cert_ttl <= Duration::ZERO {
            return Err(PortError::Invalid("cert_ttl must be positive".into()));
        }
        let key = KeyPair::generate().map_err(|e| PortError::Backend(e.to_string()))?;

        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params
            .distinguished_name
            .push(DnType::CommonName, "open-ssm-agent embedded CA");
        let now = OffsetDateTime::now_utc();
        params.not_before = now - CLOCK_SKEW;
        params.not_after = now + Duration::days(3650);

        let issuer = CertifiedIssuer::self_signed(params, key)
            .map_err(|e| PortError::Backend(e.to_string()))?;
        Ok(Self { issuer, cert_ttl })
    }

    /// DER of the CA root certificate — delivered to agents in the join bundle
    /// for pinning (AD-25).
    pub fn ca_root_der(&self) -> Vec<u8> {
        self.issuer.der().to_vec()
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
        self.issuer.pem()
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
}

/// A signed server certificate and its private key, both PEM-encoded.
pub struct ServerCert {
    pub cert_pem: String,
    pub key_pem: String,
}

#[async_trait]
impl CertIssuer for EmbeddedCa {
    async fn sign(&self, host_id: HostId, csr: &[u8]) -> Result<Vec<u8>, PortError> {
        // Parse + verify the CSR (rcgen validates the proof-of-possession
        // signature). A malformed or wrongly-signed CSR is a caller error and is
        // rejected here before anything is signed.
        let csr_der = CertificateSigningRequestDer::from(csr);
        let mut req = CertificateSigningRequestParams::from_der(&csr_der)
            .map_err(|e| PortError::Invalid(format!("invalid CSR: {e}")))?;

        // Build the issued certificate from a *fresh* parameter set so that NO
        // field the agent put in the CSR (subject DN, requested SAN, extensions,
        // basic constraints, …) can influence the result. Only `req.public_key`
        // — the key the agent proved possession of — is carried over.
        let san = Ia5String::try_from(host_san_uri(host_id))
            .map_err(|e| PortError::Backend(e.to_string()))?;
        let now = OffsetDateTime::now_utc();
        let mut params = CertificateParams::default();
        params
            .distinguished_name
            .push(DnType::CommonName, host_id.0.to_string());
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use x509_parser::prelude::{FromDer, GeneralName, X509Certificate};

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
}
