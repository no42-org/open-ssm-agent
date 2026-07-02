/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: MIT
 */

//! The NetBox `InventorySink` adapter (AD-16, AD-17; story 5.2).
//!
//! The coordinator holds the single NetBox write-credential (no host ever does,
//! AD-17) and reconciles each host's observed [`Inventory`] into NetBox. This
//! module owns the **AD-16 decision logic**, kept behind a small [`NetboxDevices`]
//! seam so it is unit-tested against a fake in the fast gate. The real
//! `netbox`-crate adapter ([`NetboxClient`]) is exercised end-to-end against a live
//! NetBox by the `#[ignore]` testcontainer test below (run via `make test-netbox`
//! / the netbox-integration CI job), off the fast gate.
//!
//! Story 5.2a is the safe core: **match on the DMI serial** and field-scoped
//! update — stamping the host_id onto a NetBox custom field, never touching a
//! human-curated field (site, rack, role, tenant, description). The three safety
//! rules are enforced here: an absent/empty serial is never matched on; more than
//! one match is an alert with **no** write; a single match is updated. Record
//! creation, interfaces/IPs, the Device-vs-VM branch, content-hash dedup and
//! transient-error retry/queue are story 5.2b.
//!
//! # Deployment preconditions
//! - A text custom field named [`CF_HOST_ID`] bound to `dcim.device` MUST exist,
//!   or NetBox rejects every stamp PATCH with HTTP 400.
//!   [`NetboxClient::preflight`] warns at startup when it is absent.
//! - The `--netbox-token` MUST be a **V1** API token: this crate authenticates
//!   with `Authorization: Token <key>`, while NetBox 4.5 defaults to V2 (Bearer)
//!   tokens (which also require `API_TOKEN_PEPPERS`). Create a V1 token for the
//!   coordinator. See the README.
//!
//! # Known gaps (5.2b)
//! - Two hosts observing the **same** device (a cloned/duplicated serial) currently
//!   last-writer-wins the stamp with no alert — the "never guess which host" rule is
//!   only half-enforced until the duplicate-serial (Device-vs-VM) handling lands.
//! - AD-16 prefers `Bearer` auth; the `netbox` crate hardcodes `Token` (NetBox
//!   accepts both), so the preference is currently unmet.

use async_trait::async_trait;
use osa_core::HostId;
use osa_core::ports::{InventorySink, PortError, UpsertOutcome};
use osa_proto::v1::Inventory;

/// The NetBox custom field the agent's `host_id` is stamped onto (AD-16). It is
/// agent-owned, so writing it never collides with human-curated fields.
pub const CF_HOST_ID: &str = "osa_host_id";

/// A NetBox device the sink matched — its id is enough to field-scope-update it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceRef {
    pub id: i32,
}

/// How many devices matched a DMI serial — the **authoritative total** (from
/// NetBox's paginated `count`, not a page slice), so the AD-16 `count>1` rule is
/// decided correctly even when the true count exceeds one page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SerialMatch {
    /// No device matches the serial.
    None,
    /// Exactly one device matches.
    One(DeviceRef),
    /// More than one device matches — ambiguous (AD-16: alert, never write).
    Many(usize),
}

/// The minimal NetBox device operations the sink needs, behind a seam so the
/// AD-16 decision logic is tested against a fake (the real adapter talks to a live
/// NetBox and is covered by the `#[ignore]` integration test).
#[async_trait]
pub trait NetboxDevices: Send + Sync {
    /// Match devices by exact `serial`, reporting the authoritative total count.
    async fn match_by_serial(&self, serial: &str) -> Result<SerialMatch, PortError>;
    /// Stamp the agent-observed `host_id` onto `device_id`'s custom field, a
    /// field-scoped write that touches no human-curated field (AD-16).
    async fn stamp_host_id(&self, device_id: i32, host_id: &str) -> Result<(), PortError>;
}

/// The NetBox `InventorySink` (AD-16, AD-17), generic over the device seam.
pub struct NetboxInventorySink<D: NetboxDevices> {
    devices: D,
}

impl<D: NetboxDevices> NetboxInventorySink<D> {
    pub fn new(devices: D) -> Self {
        Self { devices }
    }
}

#[async_trait]
impl<D: NetboxDevices> InventorySink for NetboxInventorySink<D> {
    async fn upsert(
        &self,
        host_id: HostId,
        observed: &Inventory,
    ) -> Result<UpsertOutcome, PortError> {
        // AD-16: never match on an absent or empty serial — that risks stamping
        // the wrong device. A host without a usable serial is skipped (the agent
        // already reports the gap; the Device/VM branch for such hosts is 5.2b).
        let Some(serial) = observed
            .dmi_serial
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        else {
            return Ok(UpsertOutcome::SkippedNoSerial);
        };

        match self.devices.match_by_serial(serial).await? {
            SerialMatch::None => Ok(UpsertOutcome::Unmatched),
            SerialMatch::One(device) => {
                self.devices
                    .stamp_host_id(device.id, &host_id.0.to_string())
                    .await?;
                Ok(UpsertOutcome::Updated)
            }
            SerialMatch::Many(count) => {
                // AD-16: count>1 → alert, never blind-write. Two devices sharing a
                // serial is a data-quality problem an operator must resolve; the
                // sink must not guess which one is the real host.
                tracing::error!(
                    serial,
                    count,
                    host = %host_id.0,
                    "NetBox: multiple devices match the DMI serial — refusing to write (AD-16)"
                );
                Ok(UpsertOutcome::AmbiguousMatch { count })
            }
        }
    }
}

/// Connection settings for the coordinator's single NetBox credential (AD-17).
pub struct NetboxConfig {
    pub url: String,
    pub token: String,
}

/// The live NetBox adapter: implements [`NetboxDevices`] over the `netbox` crate
/// (reqwest + rustls). Constructed only when `--netbox-url` is configured.
pub struct NetboxClient {
    client: netbox::Client,
}

impl NetboxClient {
    pub fn new(config: &NetboxConfig) -> anyhow::Result<Self> {
        let client = netbox::Client::new(netbox::ClientConfig::new(&config.url, &config.token))?;
        Ok(Self { client })
    }

    /// Warn loudly (once, at startup) if the `osa_host_id` custom field is not
    /// registered on the Device model in NetBox. Without it, NetBox rejects every
    /// field-scoped PATCH with a 400 and no host is ever stamped — a silent inert
    /// feature. A non-blocking check: the coordinator still serves everything else.
    pub async fn preflight(&self) {
        let query = netbox::QueryBuilder::new().filter("name", CF_HOST_ID);
        match self.client.extras().custom_fields().list(Some(query)).await {
            Ok(page) if page.count == 0 => tracing::warn!(
                custom_field = CF_HOST_ID,
                "NetBox is missing the '{CF_HOST_ID}' custom field on dcim.device — inventory \
                 stamps will be rejected (HTTP 400). Register a text custom field named \
                 '{CF_HOST_ID}' bound to Device (see README)."
            ),
            Ok(_) => tracing::info!(custom_field = CF_HOST_ID, "NetBox custom field present"),
            Err(e) => tracing::warn!(error = %e, "NetBox preflight check failed (continuing)"),
        }
    }
}

/// Map a `netbox` crate error onto a typed [`PortError`]. A 4xx (except 429) is a
/// **permanent** client error — bad request (e.g. the `osa_host_id` custom field
/// not registered), not found, or auth — so it is [`PortError::Invalid`]. A 429,
/// a 5xx, or a transport failure is (possibly) transient [`PortError::Backend`];
/// the retry/queue that acts on that distinction is story 5.2b.
fn map_netbox_error(e: netbox::Error) -> PortError {
    match e.status_code() {
        Some(status) if (400..500).contains(&status) && status != 429 => {
            PortError::Invalid(e.to_string())
        }
        _ => PortError::Backend(e.to_string()),
    }
}

#[async_trait]
impl NetboxDevices for NetboxClient {
    async fn match_by_serial(&self, serial: &str) -> Result<SerialMatch, PortError> {
        // `limit(2)` is enough to fetch the single device while still letting the
        // authoritative `page.count` report >1; `count` is the total across all
        // pages, so the AD-16 ambiguity decision is not fooled by pagination.
        let query = netbox::QueryBuilder::new()
            .filter("serial", serial)
            .limit(2);
        let page = self
            .client
            .dcim()
            .devices()
            .list(Some(query))
            .await
            .map_err(map_netbox_error)?;
        match page.count {
            0 => Ok(SerialMatch::None),
            1 => {
                let device = page.results.first().ok_or_else(|| {
                    PortError::Backend("NetBox reported count=1 but returned no device".into())
                })?;
                // NetBox's `serial` filter is case-insensitive; a returned serial
                // that doesn't equal the query is a loose match, not our device —
                // fail closed rather than stamp the wrong one (AD-16).
                if device
                    .serial
                    .as_deref()
                    .map(|s| s.eq_ignore_ascii_case(serial))
                    != Some(true)
                {
                    return Ok(SerialMatch::None);
                }
                let id = device
                    .id
                    .ok_or_else(|| PortError::Backend("NetBox device has no id".into()))?;
                Ok(SerialMatch::One(DeviceRef { id }))
            }
            count => Ok(SerialMatch::Many(count)),
        }
    }

    async fn stamp_host_id(&self, device_id: i32, host_id: &str) -> Result<(), PortError> {
        // Field-scoped PATCH: only custom_fields.osa_host_id — no site/role/etc.
        let body = serde_json::json!({ "custom_fields": { CF_HOST_ID: host_id } });
        let id = u64::try_from(device_id)
            .map_err(|_| PortError::Backend("negative NetBox device id".into()))?;
        self.client
            .dcim()
            .devices()
            .patch(id, &body)
            .await
            .map_err(map_netbox_error)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// A fake NetBox: serial → device ids, and a record of what was stamped.
    #[derive(Default)]
    struct FakeDevices {
        by_serial: HashMap<String, Vec<i32>>,
        stamped: Mutex<Vec<(i32, String)>>,
    }

    impl FakeDevices {
        fn with(serial: &str, ids: &[i32]) -> Self {
            let mut by_serial = HashMap::new();
            by_serial.insert(serial.to_string(), ids.to_vec());
            Self {
                by_serial,
                stamped: Mutex::new(Vec::new()),
            }
        }
        fn stamps(&self) -> Vec<(i32, String)> {
            self.stamped.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl NetboxDevices for FakeDevices {
        async fn match_by_serial(&self, serial: &str) -> Result<SerialMatch, PortError> {
            Ok(match self.by_serial.get(serial).map(Vec::as_slice) {
                None | Some([]) => SerialMatch::None,
                Some([id]) => SerialMatch::One(DeviceRef { id: *id }),
                Some(many) => SerialMatch::Many(many.len()),
            })
        }
        async fn stamp_host_id(&self, device_id: i32, host_id: &str) -> Result<(), PortError> {
            self.stamped
                .lock()
                .unwrap()
                .push((device_id, host_id.to_string()));
            Ok(())
        }
    }

    fn inventory(serial: Option<&str>) -> Inventory {
        Inventory {
            dmi_serial: serial.map(|s| s.to_string()),
            system: None,
            interfaces: Vec::new(),
            gaps: Vec::new(),
        }
    }

    #[tokio::test]
    async fn a_single_match_is_field_scope_updated_with_the_host_id() {
        let host = HostId::new();
        let sink = NetboxInventorySink::new(FakeDevices::with("SN-42", &[7]));
        assert_eq!(
            sink.upsert(host, &inventory(Some("SN-42"))).await.unwrap(),
            UpsertOutcome::Updated
        );
        assert_eq!(sink.devices.stamps(), vec![(7, host.0.to_string())]);
    }

    #[tokio::test]
    async fn an_absent_or_empty_serial_is_skipped_without_touching_netbox() {
        let host = HostId::new();
        for serial in [None, Some(""), Some("   ")] {
            let sink = NetboxInventorySink::new(FakeDevices::default());
            assert_eq!(
                sink.upsert(host, &inventory(serial)).await.unwrap(),
                UpsertOutcome::SkippedNoSerial
            );
            assert!(
                sink.devices.stamps().is_empty(),
                "no write on an absent serial"
            );
        }
    }

    #[tokio::test]
    async fn no_match_is_unmatched_and_writes_nothing() {
        let host = HostId::new();
        let sink = NetboxInventorySink::new(FakeDevices::default());
        assert_eq!(
            sink.upsert(host, &inventory(Some("SN-unknown")))
                .await
                .unwrap(),
            UpsertOutcome::Unmatched
        );
        assert!(sink.devices.stamps().is_empty());
    }

    #[tokio::test]
    async fn more_than_one_match_alerts_and_writes_nothing() {
        let host = HostId::new();
        let sink = NetboxInventorySink::new(FakeDevices::with("DUP", &[1, 2]));
        assert_eq!(
            sink.upsert(host, &inventory(Some("DUP"))).await.unwrap(),
            UpsertOutcome::AmbiguousMatch { count: 2 }
        );
        assert!(
            sink.devices.stamps().is_empty(),
            "a count>1 match must never write (AD-16)"
        );
    }
}

/// Real-NetBox integration test (5.2a.2). Boots NetBox + Postgres + Redis on a
/// shared docker network, provisions the schema (the `osa_host_id` custom field
/// and one device with a known serial), then drives the **real** [`NetboxClient`]
/// end to end. `#[ignore]`d because NetBox is a multi-container ~2-3 min boot —
/// run it via the dedicated `make test-netbox` CI job, not the fast gate.
#[cfg(test)]
mod integration {
    use super::*;
    use std::time::Duration;

    use osa_core::ports::InventorySink;
    use testcontainers_modules::postgres::Postgres;
    use testcontainers_modules::redis::Redis;
    use testcontainers_modules::testcontainers::core::{ExecCommand, IntoContainerPort};
    use testcontainers_modules::testcontainers::runners::AsyncRunner;
    use testcontainers_modules::testcontainers::{GenericImage, ImageExt};

    // Hermetic test credentials (throwaway; never used outside this test). NetBox
    // 4.5 defaults to V2 (Bearer) tokens, but the `netbox` crate authenticates with
    // V1 `Token <key>`, so we create a V1 token (V1 needs no API_TOKEN_PEPPERS) —
    // the realistic deployment shape for this client.
    const TOKEN: &str = "0123456789abcdef0123456789abcdef01234567";
    const SECRET_KEY: &str = "test-secret-key-please-ignore-0123456789abcdefghij";
    const SERIAL: &str = "OSA-IT-SERIAL-1";
    const NETBOX_IMAGE: &str = "netboxcommunity/netbox";
    const NETBOX_TAG: &str = "v4.5";

    /// Poll NetBox's login page until it serves (200) or a deadline passes — our
    /// own readiness wait, since the image has no healthcheck and we avoid the
    /// `http_wait` feature (and its hickory-dns resolver).
    async fn wait_until_ready(http: &reqwest::Client, base: &str) {
        let deadline = std::time::Instant::now() + Duration::from_secs(300);
        loop {
            if let Ok(resp) = http.get(format!("{base}/login/")).send().await
                && resp.status().is_success()
            {
                return;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "NetBox did not become ready within the deadline"
            );
            tokio::time::sleep(Duration::from_secs(3)).await;
        }
    }

    /// POST `body` to `path` and return the created object's `id`.
    async fn create(
        http: &reqwest::Client,
        base: &str,
        path: &str,
        body: serde_json::Value,
    ) -> i64 {
        let resp = http
            .post(format!("{base}{path}"))
            .header("Authorization", format!("Token {TOKEN}"))
            .header("Content-Type", "application/json")
            .body(body.to_string())
            .send()
            .await
            .unwrap();
        let status = resp.status();
        let text = resp.text().await.unwrap();
        assert!(status.is_success(), "POST {path} -> {status}: {text}");
        serde_json::from_str::<serde_json::Value>(&text).unwrap()["id"]
            .as_i64()
            .unwrap_or_else(|| panic!("no id in {path} response: {text}"))
    }

    /// The `osa_host_id` custom field on the device matching `serial`, if any.
    async fn stamped_host_id(http: &reqwest::Client, base: &str, serial: &str) -> Option<String> {
        let text = http
            .get(format!("{base}/api/dcim/devices/?serial={serial}"))
            .header("Authorization", format!("Token {TOKEN}"))
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        v["results"][0]["custom_fields"]["osa_host_id"]
            .as_str()
            .map(str::to_string)
    }

    fn inventory(serial: &str) -> Inventory {
        Inventory {
            dmi_serial: Some(serial.to_string()),
            system: None,
            interfaces: Vec::new(),
            gaps: Vec::new(),
        }
    }

    #[tokio::test]
    #[ignore = "real NetBox testcontainer (Postgres+Redis+app, ~2-3 min boot); run via `make test-netbox`"]
    async fn real_netbox_reconciles_a_matched_device_and_stamps_the_host_id() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let net = format!("osa-netbox-it-{}", uuid::Uuid::new_v4().simple());

        // Postgres + Redis with stable hostnames on a shared network so the NetBox
        // app container can reach them by name.
        let _pg = Postgres::default()
            .with_tag("17-alpine")
            .with_container_name(format!("pg-{net}"))
            .with_network(net.clone())
            .start()
            .await
            .unwrap();
        let _redis = Redis::default()
            .with_container_name(format!("redis-{net}"))
            .with_network(net.clone())
            .start()
            .await
            .unwrap();

        // The NetBox app: migrate, create the superuser + API token, serve on 8080.
        // No wait strategy here (the image ships no healthcheck and we avoid the
        // http_wait feature); readiness is polled below with our own reqwest.
        let netbox = GenericImage::new(NETBOX_IMAGE, NETBOX_TAG)
            .with_exposed_port(8080.tcp())
            .with_network(net.clone())
            .with_startup_timeout(Duration::from_secs(360))
            .with_env_var("DB_HOST", format!("pg-{net}"))
            .with_env_var("DB_NAME", "postgres")
            .with_env_var("DB_USER", "postgres")
            .with_env_var("DB_PASSWORD", "postgres")
            .with_env_var("REDIS_HOST", format!("redis-{net}"))
            .with_env_var("REDIS_PORT", "6379")
            .with_env_var("REDIS_DATABASE", "0")
            .with_env_var("REDIS_SSL", "false")
            .with_env_var("REDIS_CACHE_HOST", format!("redis-{net}"))
            .with_env_var("REDIS_CACHE_PORT", "6379")
            .with_env_var("REDIS_CACHE_DATABASE", "1")
            .with_env_var("REDIS_CACHE_SSL", "false")
            .with_env_var("SECRET_KEY", SECRET_KEY)
            .with_env_var("SKIP_SUPERUSER", "false")
            .with_env_var("SUPERUSER_NAME", "admin")
            .with_env_var("SUPERUSER_EMAIL", "admin@example.com")
            .with_env_var("SUPERUSER_PASSWORD", "adminpassword")
            .with_env_var("ALLOWED_HOSTS", "*")
            .start()
            .await
            .unwrap();

        let port = netbox.get_host_port_ipv4(8080).await.unwrap();
        let base = format!("http://127.0.0.1:{port}");
        let http = reqwest::Client::new();

        // The image ships no healthcheck, so wait for the app to serve (migrations
        // + superuser creation done) before creating the token / provisioning.
        wait_until_ready(&http, &base).await;

        // The entrypoint created the `admin` superuser but no API token (V2 needs
        // API_TOKEN_PEPPERS). Create a V1 token with our known key for the client.
        let mut mk_token = netbox
            .exec(ExecCommand::new([
                "/opt/netbox/venv/bin/python",
                "/opt/netbox/netbox/manage.py",
                "shell",
                "-c",
                &format!(
                    "from users.models import Token, User; \
                     from users.choices import TokenVersionChoices; \
                     u = User.objects.get(username='admin'); \
                     Token.objects.create(user=u, token='{TOKEN}', version=TokenVersionChoices.V1)"
                ),
            ]))
            .await
            .unwrap();
        let token_stderr = mk_token.stderr_to_vec().await.unwrap();
        assert_eq!(
            mk_token.exit_code().await.unwrap(),
            Some(0),
            "creating the V1 API token failed: {}",
            String::from_utf8_lossy(&token_stderr)
        );

        // Provision: the osa_host_id custom field on dcim.device, and one device
        // (which needs a site, a manufacturer→device-type, and a role) with SERIAL.
        create(
            &http,
            &base,
            "/api/extras/custom-fields/",
            serde_json::json!({
                "object_types": ["dcim.device"],
                "name": CF_HOST_ID,
                "type": "text",
                "label": "OSA Host ID",
            }),
        )
        .await;
        let site = create(
            &http,
            &base,
            "/api/dcim/sites/",
            serde_json::json!({"name": "IT", "slug": "it"}),
        )
        .await;
        let mfr = create(
            &http,
            &base,
            "/api/dcim/manufacturers/",
            serde_json::json!({"name": "OSA", "slug": "osa"}),
        )
        .await;
        let device_type = create(
            &http,
            &base,
            "/api/dcim/device-types/",
            serde_json::json!({"manufacturer": mfr, "model": "OSA-Box", "slug": "osa-box"}),
        )
        .await;
        let role = create(
            &http,
            &base,
            "/api/dcim/device-roles/",
            serde_json::json!({"name": "server", "slug": "server", "color": "9e9e9e"}),
        )
        .await;
        create(
            &http,
            &base,
            "/api/dcim/devices/",
            serde_json::json!({
                "name": "host-1",
                "device_type": device_type,
                "role": role,
                "site": site,
                "serial": SERIAL,
                "status": "active",
            }),
        )
        .await;

        // Drive the REAL client end to end.
        let client = NetboxClient::new(&NetboxConfig {
            url: base.clone(),
            token: TOKEN.to_string(),
        })
        .unwrap();
        client.preflight().await; // exercises extras().custom_fields().list
        let host = HostId::new();
        let sink = NetboxInventorySink::new(client);

        // An unknown serial matches nothing.
        assert_eq!(
            sink.upsert(host, &inventory("NO-SUCH-SERIAL"))
                .await
                .unwrap(),
            UpsertOutcome::Unmatched
        );
        // The known serial matches exactly one device and is field-scope-stamped.
        assert_eq!(
            sink.upsert(host, &inventory(SERIAL)).await.unwrap(),
            UpsertOutcome::Updated
        );
        // The stamp actually landed on the device's custom field.
        assert_eq!(
            stamped_host_id(&http, &base, SERIAL).await.as_deref(),
            Some(host.0.to_string().as_str()),
            "the host_id must be written to the device's osa_host_id custom field"
        );
    }
}
