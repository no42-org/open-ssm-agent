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
use std::path::Path;

use anyhow::Context;
use osa_proto::v1::EnrollRequest;
use osa_proto::v1::operator_client::OperatorClient;

const KEY_FILE: &str = "host.key";
const CERT_FILE: &str = "host.crt";
const CA_FILE: &str = "ca.crt";
const HOST_ID_FILE: &str = "host_id";

/// The identity material an enrolled host persists.
pub struct Identity {
    pub host_id: String,
    /// PEM-encoded private key — written locally, never transmitted.
    pub key_pem: String,
    pub cert_der: Vec<u8>,
    pub ca_root_der: Vec<u8>,
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
        cert_der: resp.cert,
        ca_root_der: resp.ca_root,
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

    write_atomic(state_dir, CERT_FILE, &id.cert_der, None).context("writing cert")?;
    write_atomic(state_dir, CA_FILE, &id.ca_root_der, None).context("writing CA root")?;
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

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> Identity {
        Identity {
            host_id: "11111111-1111-4111-8111-111111111111".into(),
            key_pem: "-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----\n".into(),
            cert_der: vec![1, 2, 3],
            ca_root_der: vec![4, 5, 6],
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
        assert_eq!(fs::read(dir.path().join(CERT_FILE)).unwrap(), vec![1, 2, 3]);
        assert_eq!(fs::read(dir.path().join(CA_FILE)).unwrap(), vec![4, 5, 6]);

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
