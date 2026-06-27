/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: MIT
 */

//! Agent enrollment (AD-11, AD-25).
//!
//! The agent generates its keypair **locally**, sends only a CSR (the public
//! key) to the coordinator's `Enroll` RPC, and persists the returned identity to
//! its state directory. The private key never leaves the host: it is written to
//! disk with owner-only permissions and is never transmitted.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Context;
use osa_proto::v1::operator_client::OperatorClient;
use osa_proto::v1::{EnrollRequest, RenewRequest};
use tokio::time::sleep;
use x509_parser::prelude::{FromDer, X509Certificate};

/// Renew once the cert is within this window of its expiry.
const RENEW_BEFORE: Duration = Duration::from_secs(8 * 3600);
/// How often the renewal loop checks the cert's remaining lifetime.
const RENEW_CHECK_EVERY: Duration = Duration::from_secs(30 * 60);

const KEY_FILE: &str = "host.key";
const CERT_FILE: &str = "host.crt";
const CA_FILE: &str = "ca.crt";
const HOST_ID_FILE: &str = "host_id";

/// The identity material an enrolled host persists. Certs are stored PEM-encoded
/// so the `ControlChannel` TLS layer can load them directly.
pub struct Identity {
    pub host_id: String,
    /// PEM-encoded private key — written locally, never transmitted.
    pub key_pem: String,
    pub cert_pem: String,
    pub ca_root_pem: String,
}

/// Wrap DER certificate bytes in PEM.
fn der_to_pem(der: Vec<u8>) -> String {
    pem::encode(&pem::Pem::new("CERTIFICATE", der))
}

/// Run enrollment end-to-end: generate a keypair + CSR, call `Enroll`, and
/// persist the returned identity under `state_dir`.
pub async fn run(
    coordinator: String,
    token: String,
    state_dir: &Path,
    force: bool,
) -> anyhow::Result<String> {
    if token.trim().is_empty() {
        anyhow::bail!("join token is empty");
    }
    // Refuse to clobber an existing identity before doing any work (and before
    // burning the single-use token on the network).
    ensure_not_enrolled(state_dir, force)?;

    let key = rcgen::KeyPair::generate().context("generating keypair")?;
    let csr = rcgen::CertificateParams::default()
        .serialize_request(&key)
        .context("building CSR")?
        .der()
        .to_vec();

    let mut client = OperatorClient::connect(coordinator)
        .await
        .context("connecting to coordinator")?;
    let resp = client
        .enroll(EnrollRequest {
            join_token: token,
            csr,
        })
        .await
        .context("enroll request failed")?
        .into_inner();

    let identity = Identity {
        host_id: resp.host_id,
        key_pem: key.serialize_pem(),
        cert_pem: der_to_pem(resp.cert),
        ca_root_pem: der_to_pem(resp.ca_root),
    };
    persist(state_dir, &identity, force)?;
    Ok(identity.host_id)
}

/// Error out if the host already holds an identity and `force` is not set.
fn ensure_not_enrolled(state_dir: &Path, force: bool) -> anyhow::Result<()> {
    let key_path = state_dir.join(KEY_FILE);
    if key_path.exists() && !force {
        anyhow::bail!(
            "already enrolled (found {}); pass --force to re-enroll",
            key_path.display()
        );
    }
    Ok(())
}

/// Write the identity to `state_dir`. Each file is written to a temp name and
/// atomically renamed into place; the private key is created owner-only (0600)
/// from the outset (no world-readable window) and written **last**, so it acts
/// as the all-or-nothing "enrolled" marker — a crash mid-write never leaves a
/// usable-looking identity. The cert, CA root, and host_id are world-readable.
///
/// On non-Unix platforms file permissions are not restricted; the agent targets
/// Linux (AD-1).
pub fn persist(state_dir: &Path, id: &Identity, force: bool) -> anyhow::Result<()> {
    ensure_not_enrolled(state_dir, force)?;
    fs::create_dir_all(state_dir)
        .with_context(|| format!("creating state dir {}", state_dir.display()))?;
    set_dir_owner_only(state_dir);

    write_atomic(state_dir, CERT_FILE, id.cert_pem.as_bytes(), None).context("writing cert")?;
    write_atomic(state_dir, CA_FILE, id.ca_root_pem.as_bytes(), None).context("writing CA root")?;
    write_atomic(state_dir, HOST_ID_FILE, id.host_id.as_bytes(), None)
        .context("writing host_id")?;
    // Key last (the commit marker), created 0600 atomically.
    write_atomic(state_dir, KEY_FILE, id.key_pem.as_bytes(), Some(0o600))
        .context("writing private key")?;
    Ok(())
}

/// Write `bytes` to `dir/name` atomically: open `dir/name.tmp` (with `mode` on
/// Unix if given), write + fsync, then rename over the target.
fn write_atomic(dir: &Path, name: &str, bytes: &[u8], mode: Option<u32>) -> anyhow::Result<()> {
    let tmp = dir.join(format!("{name}.tmp"));
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    if let Some(m) = mode {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(m);
    }
    #[cfg(not(unix))]
    let _ = mode;
    let mut f = opts
        .open(&tmp)
        .with_context(|| format!("creating {}", tmp.display()))?;
    f.write_all(bytes).and_then(|()| f.sync_all())?;
    drop(f);
    fs::rename(&tmp, dir.join(name)).with_context(|| format!("finalizing {name}"))?;
    Ok(())
}

#[cfg(unix)]
fn set_dir_owner_only(dir: &Path) {
    use std::os::unix::fs::PermissionsExt;
    // Best-effort: tightening the dir is hardening, not correctness.
    let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
}

#[cfg(not(unix))]
fn set_dir_owner_only(_dir: &Path) {}

/// Renew the host certificate over the coordinator's `Renew` RPC, reusing the
/// existing keypair (so the CSR's proof-of-possession also proves the current
/// identity — no join token). Persists the new cert, keeping the key.
pub async fn renew(coordinator: String, state_dir: &Path) -> anyhow::Result<()> {
    let key_pem = fs::read_to_string(state_dir.join(KEY_FILE))
        .with_context(|| format!("reading {KEY_FILE} (is the host enrolled?)"))?;
    let cert_pem = fs::read_to_string(state_dir.join(CERT_FILE))
        .with_context(|| format!("reading {CERT_FILE}"))?;
    let current_cert = pem::parse(cert_pem.as_bytes())
        .context("parsing current cert")?
        .into_contents();

    // Reuse the existing key: the CSR's proof-of-possession then proves we hold
    // the current identity's key.
    let key = rcgen::KeyPair::from_pem(&key_pem).context("loading private key")?;
    let csr = rcgen::CertificateParams::default()
        .serialize_request(&key)
        .context("building CSR")?
        .der()
        .to_vec();

    let mut client = OperatorClient::connect(coordinator)
        .await
        .context("connecting to coordinator")?;
    let resp = client
        .renew(RenewRequest { current_cert, csr })
        .await
        .context("renew request failed")?
        .into_inner();

    // Never overwrite our identity with an unverified response: the new cert must
    // chain to the CA we pinned at enrollment.
    verify_chains_to_pinned_ca(state_dir, &resp.cert).context("validating renewed cert")?;
    write_atomic(state_dir, CERT_FILE, der_to_pem(resp.cert).as_bytes(), None)
        .context("writing renewed cert")
}

/// Verify a DER cert chains to the CA root pinned in the state dir.
fn verify_chains_to_pinned_ca(state_dir: &Path, cert_der: &[u8]) -> anyhow::Result<()> {
    let ca_pem = fs::read_to_string(state_dir.join(CA_FILE))?;
    let ca_der = pem::parse(ca_pem.as_bytes())?.into_contents();
    let (_, ca) =
        X509Certificate::from_der(&ca_der).map_err(|_| anyhow::anyhow!("malformed pinned CA"))?;
    let (_, leaf) = X509Certificate::from_der(cert_der)
        .map_err(|_| anyhow::anyhow!("renewed cert is not valid X.509"))?;
    leaf.verify_signature(Some(ca.public_key()))
        .map_err(|_| anyhow::anyhow!("renewed cert does not chain to the pinned CA"))?;
    Ok(())
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Unix-seconds expiry (`notAfter`) of the persisted host certificate.
fn cert_expiry_unix(state_dir: &Path) -> anyhow::Result<i64> {
    let cert_pem = fs::read_to_string(state_dir.join(CERT_FILE))?;
    let der = pem::parse(cert_pem.as_bytes())?.into_contents();
    let (_, cert) = X509Certificate::from_der(&der)
        .map_err(|_| anyhow::anyhow!("malformed host certificate"))?;
    Ok(cert.validity().not_after.timestamp())
}

/// Background loop: renew the cert as it nears expiry. Runs alongside the control
/// channel; a renewed cert is adopted on the next reconnect — the renewal RPC
/// (separate gRPC) does not drop the live session.
pub async fn renewal_loop(coordinator: String, state_dir: PathBuf) {
    loop {
        match cert_expiry_unix(&state_dir) {
            Ok(not_after) => {
                let now = unix_now();
                if now >= not_after {
                    // Already lapsed: renewal will be refused — re-enrollment is the
                    // only recovery. Surfaced distinctly from a retryable failure.
                    tracing::error!("host certificate has expired — re-enrollment required");
                } else if not_after - now <= RENEW_BEFORE.as_secs() as i64 {
                    match renew(coordinator.clone(), &state_dir).await {
                        Ok(()) => tracing::info!("certificate renewed"),
                        Err(e) => {
                            tracing::warn!(error = %e, "certificate renewal failed — will retry")
                        }
                    }
                }
            }
            Err(e) => tracing::error!(error = %e, "cannot read certificate expiry"),
        }
        sleep(RENEW_CHECK_EVERY).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> Identity {
        Identity {
            host_id: "11111111-1111-4111-8111-111111111111".into(),
            key_pem: "-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----\n".into(),
            cert_pem: "-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----\n".into(),
            ca_root_pem: "-----BEGIN CERTIFICATE-----\nca\n-----END CERTIFICATE-----\n".into(),
        }
    }

    #[test]
    fn persist_writes_all_files_with_locked_key() {
        let dir = tempfile::tempdir().unwrap();
        persist(dir.path(), &identity(), false).unwrap();

        assert_eq!(
            fs::read_to_string(dir.path().join(HOST_ID_FILE)).unwrap(),
            identity().host_id
        );
        assert_eq!(
            fs::read_to_string(dir.path().join(CERT_FILE)).unwrap(),
            identity().cert_pem
        );
        assert_eq!(
            fs::read_to_string(dir.path().join(CA_FILE)).unwrap(),
            identity().ca_root_pem
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(dir.path().join(KEY_FILE))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "private key must be owner-only");
        }
    }

    #[test]
    fn refuses_overwrite_without_force() {
        let dir = tempfile::tempdir().unwrap();
        persist(dir.path(), &identity(), false).unwrap();
        let err = persist(dir.path(), &identity(), false).unwrap_err();
        assert!(err.to_string().contains("already enrolled"));
    }

    #[tokio::test]
    async fn empty_token_rejected_before_network() {
        let dir = tempfile::tempdir().unwrap();
        // Unroutable coordinator: must fail on the empty token, not a connect.
        let err = run("http://127.0.0.1:1".into(), "  ".into(), dir.path(), false)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("empty"));
        assert!(
            !dir.path().join(KEY_FILE).exists(),
            "no key written on failure"
        );
    }

    #[test]
    fn force_overwrites() {
        let dir = tempfile::tempdir().unwrap();
        persist(dir.path(), &identity(), false).unwrap();
        let mut id = identity();
        id.host_id = "22222222-2222-4222-8222-222222222222".into();
        persist(dir.path(), &id, true).unwrap();
        assert_eq!(
            fs::read_to_string(dir.path().join(HOST_ID_FILE)).unwrap(),
            id.host_id
        );
    }
}
