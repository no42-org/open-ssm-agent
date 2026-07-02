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
//! The three AD-16 safety rules are enforced: an absent/empty serial is never
//! matched on; more than one match is an alert with **no** write; a single match
//! is reconciled. On a match the sink **reconciles the observed interfaces and
//! IPs** onto the device in two-phase order (device → interface → IP →
//! `primary_ip4`), removing the interfaces/IPs the agent no longer reports (it
//! owns the full observed set), and stamps the `host_id`. An unchanged snapshot is
//! a **content-hash-deduped** no-op (5.2b-1).
//!
//! A **transient** NetBox failure is retried with backoff (5.2b-2a) so a blip
//! doesn't lose the snapshot; a permanent error (a 4xx → [`PortError::Invalid`])
//! fails fast.
//!
//! Deferred to 5.2b-2:
//! - record **creation** (count==0, with the Device-vs-VM branch + operator-
//!   configured defaults for the required human-curated fields),
//! - MAC sync (NetBox 4.2+ `MACAddress` objects), and
//! - the two-hosts-per-device alert.
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

use std::collections::{HashMap, HashSet};

use async_trait::async_trait;
use osa_core::HostId;
use osa_core::ports::{InventorySink, PortError, UpsertOutcome};
use osa_proto::v1::Inventory;

/// The NetBox custom field the agent's `host_id` is stamped onto (AD-16). It is
/// agent-owned, so writing it never collides with human-curated fields.
pub const CF_HOST_ID: &str = "osa_host_id";

/// Retries for a **transient** NetBox failure before giving up the snapshot
/// (AD-16: a transient error is retried, not lost). A longer outage is covered by
/// the agent's periodic re-report (5.3) — inventory is idempotent.
const MAX_TRANSIENT_RETRIES: u32 = 3;
/// Base backoff; doubles per attempt (100ms → 200ms → 400ms).
const RETRY_BASE_BACKOFF: std::time::Duration = std::time::Duration::from_millis(100);

/// Whether a port error is worth retrying — a backend/transport blip, not a
/// permanent client error (a 4xx maps to [`PortError::Invalid`], e.g. a missing
/// custom field, which retrying can't fix).
fn is_transient(e: &PortError) -> bool {
    matches!(e, PortError::Backend(_) | PortError::Transport(_))
}

/// A NetBox device the sink matched — its id is enough to field-scope-update it.
/// Ids are `i64` (NetBox uses `BigAutoField`); the seam never truncates them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceRef {
    pub id: i64,
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

/// A NetBox interface (and its assigned IPs) as currently stored on a device.
/// MAC is deliberately absent: NetBox 4.2+ models MACs as separate `MACAddress`
/// objects (the interface's `mac_address` is a read-only computed field), so MAC
/// sync is deferred to 5.2b-2. Interfaces are reconciled by name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NbInterface {
    pub id: i64,
    pub name: String,
    pub ips: Vec<NbIp>,
}

/// A NetBox IP address (its id and CIDR form, e.g. `"192.0.2.5/32"`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NbIp {
    pub id: i64,
    pub address: String,
}

/// The NetBox device operations the sink needs, behind a seam so the AD-16
/// reconcile logic is tested against a fake (the real adapter talks to a live
/// NetBox and is covered by the `#[ignore]` integration test). Every write is
/// field-scoped — interfaces, IPs, `primary_ip4`, and the `osa_host_id` custom
/// field are agent-managed; no human-curated field (site/rack/role/tenant/
/// description) is ever touched.
#[async_trait]
pub trait NetboxDevices: Send + Sync {
    /// Match devices by exact `serial`, reporting the authoritative total count.
    async fn match_by_serial(&self, serial: &str) -> Result<SerialMatch, PortError>;
    /// The device's current interfaces (with their IPs) — the agent-managed set to
    /// reconcile against.
    async fn read_interfaces(&self, device_id: i64) -> Result<Vec<NbInterface>, PortError>;
    /// Create an interface `name` on `device_id`, returning its id.
    async fn create_interface(&self, device_id: i64, name: &str) -> Result<i64, PortError>;
    /// Delete an interface (its IPs must already be removed / repointed).
    async fn delete_interface(&self, interface_id: i64) -> Result<(), PortError>;
    /// Assign `address` (CIDR) to `interface_id`, returning the new IP's id.
    async fn create_ip(&self, interface_id: i64, address: &str) -> Result<i64, PortError>;
    /// Re-assign an existing IP to `interface_id` (an IP that moved between NICs) —
    /// avoids destroying + recreating the row (which would drop its NetBox metadata
    /// and can trip global-unique enforcement mid-reconcile).
    async fn move_ip(&self, ip_id: i64, interface_id: i64) -> Result<(), PortError>;
    /// Delete an IP address.
    async fn delete_ip(&self, ip_id: i64) -> Result<(), PortError>;
    /// Set the device's `primary_ip4`/`primary_ip6` and stamp the agent `host_id` —
    /// the final phase, done before any stale IP is deleted so a primary IP never
    /// dangles (NetBox refuses to delete an IP that is a device's primary).
    async fn finalize_device(
        &self,
        device_id: i64,
        primary_ip4: Option<i64>,
        primary_ip6: Option<i64>,
        host_id: &str,
    ) -> Result<(), PortError>;
}

/// The NetBox `InventorySink` (AD-16, AD-17), generic over the device seam.
pub struct NetboxInventorySink<D: NetboxDevices> {
    devices: D,
    /// Per-host content hash of the last successfully-synced snapshot — the AD-16
    /// content-hash dedup. An unchanged snapshot is a no-op; kept in memory, so a
    /// coordinator restart re-syncs each host once (idempotent).
    synced: std::sync::Mutex<HashMap<HostId, String>>,
    /// Per-host lock so two concurrent snapshots for the same host (the bridge
    /// spawns upserts per message) can't interleave dedup-check + reconcile.
    locks: std::sync::Mutex<HashMap<HostId, std::sync::Arc<tokio::sync::Mutex<()>>>>,
}

impl<D: NetboxDevices> NetboxInventorySink<D> {
    pub fn new(devices: D) -> Self {
        Self {
            devices,
            synced: std::sync::Mutex::new(HashMap::new()),
            locks: std::sync::Mutex::new(HashMap::new()),
        }
    }

    fn already_synced(&self, host_id: HostId, hash: &str) -> bool {
        self.synced
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&host_id)
            .is_some_and(|h| h == hash)
    }

    fn mark_synced(&self, host_id: HostId, hash: String) {
        self.synced
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(host_id, hash);
    }

    fn host_lock(&self, host_id: HostId) -> std::sync::Arc<tokio::sync::Mutex<()>> {
        self.locks
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(host_id)
            .or_default()
            .clone()
    }

    /// Reconcile the observed interfaces/IPs onto the matched device in the AD-16
    /// two-phase order (device → interface → IP → `primary_ip4`/`primary_ip6`), then
    /// remove the interfaces/IPs the agent no longer reports (it owns the full
    /// observed set).
    async fn reconcile(
        &self,
        device_id: i64,
        host_id: HostId,
        observed: &Inventory,
    ) -> Result<(), PortError> {
        let current = self.devices.read_interfaces(device_id).await?;
        let current_by_name: HashMap<&str, &NbInterface> =
            current.iter().map(|i| (i.name.as_str(), i)).collect();
        let desired_names: HashSet<&str> = observed
            .interfaces
            .iter()
            .map(|i| i.name.as_str())
            .collect();
        // Existing IPs across the WHOLE device, so an IP that moved between NICs is
        // re-assigned (not destroyed + recreated, which drops metadata and can trip
        // NetBox's global-unique enforcement mid-reconcile).
        let mut existing_ips: HashMap<&str, (i64, i64)> = HashMap::new(); // cidr -> (ip_id, iface_id)
        for iface in &current {
            for ip in &iface.ips {
                existing_ips
                    .entry(ip.address.as_str())
                    .or_insert((ip.id, iface.id));
            }
        }

        let mut primary_ip4: Option<i64> = None;
        let mut primary_ip6: Option<i64> = None;
        let mut kept_ip_ids: HashSet<i64> = HashSet::new();

        // Phase 1+2: ensure every observed interface exists and every observed IP is
        // assigned to it. Reuse existing rows so a repeat run creates nothing.
        for iface in &observed.interfaces {
            let interface_id = match current_by_name.get(iface.name.as_str()) {
                Some(cur) => cur.id,
                None => {
                    self.devices
                        .create_interface(device_id, &iface.name)
                        .await?
                }
            };
            for cidr in iface.ip_addresses.iter().filter_map(|ip| to_cidr(ip)) {
                let ip_id = match existing_ips.get(cidr.as_str()) {
                    Some(&(id, cur_iface)) => {
                        if cur_iface != interface_id {
                            self.devices.move_ip(id, interface_id).await?;
                        }
                        id
                    }
                    None => self.devices.create_ip(interface_id, &cidr).await?,
                };
                kept_ip_ids.insert(ip_id);
                // The first observed IPv4 / IPv6 becomes the device's primary_ipN.
                if is_ipv4_cidr(&cidr) {
                    primary_ip4.get_or_insert(ip_id);
                } else {
                    primary_ip6.get_or_insert(ip_id);
                }
            }
        }

        // Phase 3: repoint both primary IPs (to a live/new IP, or None) and stamp the
        // host_id BEFORE any delete, so we never delete an IP a primary points at.
        self.devices
            .finalize_device(device_id, primary_ip4, primary_ip6, &host_id.0.to_string())
            .await?;

        // Phase 4: remove the IPs then the interfaces the agent no longer reports.
        for cur in &current {
            for ip in &cur.ips {
                if !kept_ip_ids.contains(&ip.id) {
                    self.devices.delete_ip(ip.id).await?;
                }
            }
        }
        for cur in &current {
            if !desired_names.contains(cur.name.as_str()) {
                self.devices.delete_interface(cur.id).await?;
            }
        }
        Ok(())
    }

    /// Match on the serial and reconcile the single match — the retryable core of
    /// [`InventorySink::upsert`]. Does NOT touch the dedup cache (the caller marks a
    /// successful `Updated`, so a retried transient failure never marks synced).
    async fn match_and_reconcile(
        &self,
        serial: &str,
        host_id: HostId,
        observed: &Inventory,
    ) -> Result<UpsertOutcome, PortError> {
        match self.devices.match_by_serial(serial).await? {
            SerialMatch::None => Ok(UpsertOutcome::Unmatched),
            SerialMatch::One(device) => {
                self.reconcile(device.id, host_id, observed).await?;
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

#[async_trait]
impl<D: NetboxDevices> InventorySink for NetboxInventorySink<D> {
    async fn upsert(
        &self,
        host_id: HostId,
        observed: &Inventory,
    ) -> Result<UpsertOutcome, PortError> {
        // AD-16: never match on an absent or empty serial — that risks writing the
        // wrong device. A host without a usable serial is skipped (the agent already
        // reports the gap; the Device/VM branch for such hosts is 5.2b-2).
        let Some(serial) = observed
            .dmi_serial
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        else {
            return Ok(UpsertOutcome::SkippedNoSerial);
        };

        // Serialize per host: hold the host's lock across the dedup check, the
        // reconcile, and the mark, so two concurrent snapshots can't both reconcile.
        let lock = self.host_lock(host_id);
        let _guard = lock.lock().await;

        // Content-hash dedup: an unchanged snapshot for an already-synced host is a
        // no-op — skip the match and every write (AD-16). The serial is in the key so
        // a serial change (→ a different device) is never deduped away.
        let hash = content_hash(serial, host_id, observed);
        if self.already_synced(host_id, &hash) {
            return Ok(UpsertOutcome::Unchanged);
        }

        // Match + reconcile, retrying a transient NetBox failure with backoff so a
        // blip doesn't lose the snapshot (AD-16). A permanent error (Invalid) or a
        // non-write outcome (Unmatched/AmbiguousMatch) returns immediately.
        let mut attempt = 0u32;
        let outcome = loop {
            match self.match_and_reconcile(serial, host_id, observed).await {
                Ok(outcome) => break outcome,
                Err(e) if is_transient(&e) && attempt < MAX_TRANSIENT_RETRIES => {
                    attempt += 1;
                    tracing::warn!(host = %host_id.0, attempt, error = %e, "transient NetBox error — retrying inventory upsert");
                    tokio::time::sleep(RETRY_BASE_BACKOFF * 2u32.pow(attempt - 1)).await;
                }
                Err(e) => return Err(e),
            }
        };
        if outcome == UpsertOutcome::Updated {
            self.mark_synced(host_id, hash);
        }
        Ok(outcome)
    }
}

/// A content hash of what we write (serial + host_id + interface names + IPs) for
/// dedup. The serial is included because it selects WHICH device is written, and
/// MAC is excluded because MAC sync is 5.2b-2. The agent already emits interfaces
/// sorted by name with sorted, de-duplicated IPs (5.1), so the snapshot is canonical.
fn content_hash(serial: &str, host_id: HostId, observed: &Inventory) -> String {
    let mut buf = Vec::new();
    buf.extend_from_slice(serial.as_bytes());
    buf.push(0x02);
    buf.extend_from_slice(host_id.0.as_bytes());
    for iface in &observed.interfaces {
        buf.push(0xff); // record separator
        buf.extend_from_slice(iface.name.as_bytes());
        for ip in &iface.ip_addresses {
            buf.push(0x00);
            buf.extend_from_slice(ip.as_bytes());
        }
    }
    osa_core::wire::sha256_hex(&buf)
}

/// A bare host IP as a NetBox CIDR: `/32` for IPv4, `/128` for IPv6. `None` for an
/// unparsable value (the agent emits `IpAddr` strings, so this is defensive).
fn to_cidr(ip: &str) -> Option<String> {
    match ip.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(_)) => Some(format!("{ip}/32")),
        Ok(std::net::IpAddr::V6(_)) => Some(format!("{ip}/128")),
        Err(_) => None,
    }
}

/// Whether a CIDR's address is IPv4 (a NetBox `primary_ip4` must be).
fn is_ipv4_cidr(cidr: &str) -> bool {
    cidr.split('/')
        .next()
        .and_then(|a| a.parse::<std::net::IpAddr>().ok())
        .is_some_and(|ip| ip.is_ipv4())
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
                Ok(SerialMatch::One(DeviceRef { id: i64::from(id) }))
            }
            count => Ok(SerialMatch::Many(count)),
        }
    }

    async fn read_interfaces(&self, device_id: i64) -> Result<Vec<NbInterface>, PortError> {
        let ifaces = self
            .client
            .resource("dcim/interfaces/")
            .list(Some(device_filter(device_id)))
            .await
            .map_err(map_netbox_error)?;
        let ips = self
            .client
            .resource("ipam/ip-addresses/")
            .list(Some(device_filter(device_id)))
            .await
            .map_err(map_netbox_error)?;

        // Group the device's IPs under the interface they're assigned to — only
        // dcim.interface assignments (a device's IPs could in principle be assigned
        // elsewhere; the id-spaces differ, so guard against wrong grouping).
        let mut ips_by_iface: HashMap<i64, Vec<NbIp>> = HashMap::new();
        for ip in &ips.results {
            if ip.get("assigned_object_type").and_then(|v| v.as_str()) != Some("dcim.interface") {
                continue;
            }
            if let (Some(iface_id), Some(addr), Some(id)) = (
                ip.get("assigned_object_id").and_then(|v| v.as_i64()),
                ip.get("address").and_then(|v| v.as_str()),
                ip.get("id").and_then(|v| v.as_i64()),
            ) {
                ips_by_iface.entry(iface_id).or_default().push(NbIp {
                    id,
                    address: addr.to_string(),
                });
            }
        }
        let mut out = Vec::new();
        for iface in &ifaces.results {
            let Some(id) = iface.get("id").and_then(|v| v.as_i64()) else {
                continue;
            };
            let name = iface
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            out.push(NbInterface {
                id,
                name,
                ips: ips_by_iface.remove(&id).unwrap_or_default(),
            });
        }
        Ok(out)
    }

    async fn create_interface(&self, device_id: i64, name: &str) -> Result<i64, PortError> {
        let body = serde_json::json!({ "device": device_id, "name": name, "type": "other" });
        let created = self
            .client
            .resource("dcim/interfaces/")
            .create(&body)
            .await
            .map_err(map_netbox_error)?;
        new_id(&created, "interface")
    }

    async fn delete_interface(&self, interface_id: i64) -> Result<(), PortError> {
        self.client
            .resource("dcim/interfaces/")
            .delete(to_u64(interface_id)?)
            .await
            .map_err(map_netbox_error)
    }

    async fn create_ip(&self, interface_id: i64, address: &str) -> Result<i64, PortError> {
        let body = serde_json::json!({
            "address": address,
            "assigned_object_type": "dcim.interface",
            "assigned_object_id": interface_id,
        });
        let created = self
            .client
            .resource("ipam/ip-addresses/")
            .create(&body)
            .await
            .map_err(map_netbox_error)?;
        new_id(&created, "ip-address")
    }

    async fn move_ip(&self, ip_id: i64, interface_id: i64) -> Result<(), PortError> {
        let body = serde_json::json!({
            "assigned_object_type": "dcim.interface",
            "assigned_object_id": interface_id,
        });
        self.client
            .resource("ipam/ip-addresses/")
            .patch(to_u64(ip_id)?, &body)
            .await
            .map_err(map_netbox_error)?;
        Ok(())
    }

    async fn delete_ip(&self, ip_id: i64) -> Result<(), PortError> {
        self.client
            .resource("ipam/ip-addresses/")
            .delete(to_u64(ip_id)?)
            .await
            .map_err(map_netbox_error)
    }

    async fn finalize_device(
        &self,
        device_id: i64,
        primary_ip4: Option<i64>,
        primary_ip6: Option<i64>,
        host_id: &str,
    ) -> Result<(), PortError> {
        // Field-scoped PATCH: primary_ip4/primary_ip6 (null clears them) + the
        // osa_host_id custom field only — no site/role/etc.
        let body = serde_json::json!({
            "primary_ip4": primary_ip4,
            "primary_ip6": primary_ip6,
            "custom_fields": { CF_HOST_ID: host_id },
        });
        self.client
            .resource("dcim/devices/")
            .patch(to_u64(device_id)?, &body)
            .await
            .map_err(map_netbox_error)?;
        Ok(())
    }
}

/// A `?device_id=<id>` list filter, generous page limit (a host's NICs/IPs are few).
fn device_filter(device_id: i64) -> netbox::QueryBuilder {
    netbox::QueryBuilder::new()
        .filter("device_id", device_id.to_string())
        .limit(1000)
}

/// A positive NetBox row id as `u64`, or a typed error.
fn to_u64(id: i64) -> Result<u64, PortError> {
    u64::try_from(id).map_err(|_| PortError::Backend("negative NetBox row id".into()))
}

/// The `id` of a just-created NetBox object.
fn new_id(created: &serde_json::Value, kind: &str) -> Result<i64, PortError> {
    created
        .get("id")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| PortError::Backend(format!("created {kind} has no id")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// A fake NetBox that models a device's interfaces + IPs mutably, so the
    /// reconcile create/move/delete/finalize sequence can be asserted.
    struct FakeDevices {
        by_serial: HashMap<String, Vec<i64>>,
        state: Mutex<FakeState>,
    }

    /// (device_id, primary_ip4, primary_ip6, host_id) recorded per finalize call.
    type Finalize = (i64, Option<i64>, Option<i64>, String);

    #[derive(Default)]
    struct FakeState {
        interfaces: HashMap<i64, Vec<NbInterface>>, // device_id -> interfaces
        next_id: i64,
        finalized: Vec<Finalize>,
        // Failure injection for the retry tests.
        match_attempts: u32,
        transient_failures: u32, // fail `match_by_serial` this many times, then succeed
        permanent_failure: bool, // fail `match_by_serial` with a non-retryable error
    }

    impl FakeDevices {
        /// Serials matching `ids` devices, with no interfaces seeded.
        fn matching(serial: &str, ids: &[i64]) -> Self {
            let mut by_serial = HashMap::new();
            by_serial.insert(serial.to_string(), ids.to_vec());
            Self {
                by_serial,
                state: Mutex::new(FakeState {
                    next_id: 1000,
                    ..Default::default()
                }),
            }
        }
        fn with_transient_failures(self, n: u32) -> Self {
            self.state.lock().unwrap().transient_failures = n;
            self
        }
        fn with_permanent_failure(self) -> Self {
            self.state.lock().unwrap().permanent_failure = true;
            self
        }
        fn match_attempts(&self) -> u32 {
            self.state.lock().unwrap().match_attempts
        }
        /// One device (`device_id`) matched by `serial`, seeded with `interfaces`.
        fn device(serial: &str, device_id: i64, interfaces: Vec<NbInterface>) -> Self {
            let s = Self::matching(serial, &[device_id]);
            s.state
                .lock()
                .unwrap()
                .interfaces
                .insert(device_id, interfaces);
            s
        }
        fn interfaces_of(&self, device_id: i64) -> Vec<NbInterface> {
            self.state
                .lock()
                .unwrap()
                .interfaces
                .get(&device_id)
                .cloned()
                .unwrap_or_default()
        }
        fn finalized(&self) -> Vec<Finalize> {
            self.state.lock().unwrap().finalized.clone()
        }
        fn ip_id(&self, device_id: i64, address: &str) -> Option<i64> {
            self.interfaces_of(device_id)
                .iter()
                .flat_map(|i| &i.ips)
                .find(|ip| ip.address == address)
                .map(|ip| ip.id)
        }
        /// Which interface an IP currently sits on (to assert a move).
        fn iface_of_ip(&self, device_id: i64, ip_id: i64) -> Option<i64> {
            self.interfaces_of(device_id)
                .iter()
                .find(|i| i.ips.iter().any(|ip| ip.id == ip_id))
                .map(|i| i.id)
        }
    }

    #[async_trait]
    impl NetboxDevices for FakeDevices {
        async fn match_by_serial(&self, serial: &str) -> Result<SerialMatch, PortError> {
            {
                let mut s = self.state.lock().unwrap();
                s.match_attempts += 1;
                if s.permanent_failure {
                    return Err(PortError::Invalid("permanent".into()));
                }
                if s.transient_failures > 0 {
                    s.transient_failures -= 1;
                    return Err(PortError::Backend("transient".into()));
                }
            }
            Ok(match self.by_serial.get(serial).map(Vec::as_slice) {
                None | Some([]) => SerialMatch::None,
                Some([id]) => SerialMatch::One(DeviceRef { id: *id }),
                Some(many) => SerialMatch::Many(many.len()),
            })
        }
        async fn read_interfaces(&self, device_id: i64) -> Result<Vec<NbInterface>, PortError> {
            Ok(self.interfaces_of(device_id))
        }
        async fn create_interface(&self, device_id: i64, name: &str) -> Result<i64, PortError> {
            let mut s = self.state.lock().unwrap();
            let id = s.next_id;
            s.next_id += 1;
            s.interfaces
                .entry(device_id)
                .or_default()
                .push(NbInterface {
                    id,
                    name: name.to_string(),
                    ips: Vec::new(),
                });
            Ok(id)
        }
        async fn delete_interface(&self, interface_id: i64) -> Result<(), PortError> {
            for ifaces in self.state.lock().unwrap().interfaces.values_mut() {
                ifaces.retain(|i| i.id != interface_id);
            }
            Ok(())
        }
        async fn create_ip(&self, interface_id: i64, address: &str) -> Result<i64, PortError> {
            let mut s = self.state.lock().unwrap();
            let id = s.next_id;
            s.next_id += 1;
            for ifaces in s.interfaces.values_mut() {
                if let Some(iface) = ifaces.iter_mut().find(|i| i.id == interface_id) {
                    iface.ips.push(NbIp {
                        id,
                        address: address.to_string(),
                    });
                }
            }
            Ok(id)
        }
        async fn move_ip(&self, ip_id: i64, interface_id: i64) -> Result<(), PortError> {
            let mut s = self.state.lock().unwrap();
            // Detach the IP from wherever it is, then attach it to interface_id.
            let mut moved: Option<NbIp> = None;
            for ifaces in s.interfaces.values_mut() {
                for iface in ifaces.iter_mut() {
                    if let Some(pos) = iface.ips.iter().position(|ip| ip.id == ip_id) {
                        moved = Some(iface.ips.remove(pos));
                    }
                }
            }
            if let Some(ip) = moved {
                for ifaces in s.interfaces.values_mut() {
                    if let Some(iface) = ifaces.iter_mut().find(|i| i.id == interface_id) {
                        iface.ips.push(ip);
                        break;
                    }
                }
            }
            Ok(())
        }
        async fn delete_ip(&self, ip_id: i64) -> Result<(), PortError> {
            for ifaces in self.state.lock().unwrap().interfaces.values_mut() {
                for iface in ifaces.iter_mut() {
                    iface.ips.retain(|ip| ip.id != ip_id);
                }
            }
            Ok(())
        }
        async fn finalize_device(
            &self,
            device_id: i64,
            primary_ip4: Option<i64>,
            primary_ip6: Option<i64>,
            host_id: &str,
        ) -> Result<(), PortError> {
            self.state.lock().unwrap().finalized.push((
                device_id,
                primary_ip4,
                primary_ip6,
                host_id.to_string(),
            ));
            Ok(())
        }
    }

    fn iface(name: &str, ips: &[&str]) -> osa_proto::v1::InventoryInterface {
        osa_proto::v1::InventoryInterface {
            name: name.to_string(),
            mac: String::new(),
            ip_addresses: ips.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn inventory(
        serial: Option<&str>,
        interfaces: Vec<osa_proto::v1::InventoryInterface>,
    ) -> Inventory {
        Inventory {
            dmi_serial: serial.map(|s| s.to_string()),
            system: None,
            interfaces,
            gaps: Vec::new(),
        }
    }

    #[tokio::test]
    async fn a_single_match_is_reconciled_and_the_host_id_stamped() {
        let host = HostId::new();
        let sink = NetboxInventorySink::new(FakeDevices::matching("SN-42", &[7]));
        assert_eq!(
            sink.upsert(host, &inventory(Some("SN-42"), vec![]))
                .await
                .unwrap(),
            UpsertOutcome::Updated
        );
        // No interfaces observed → finalize stamps the host_id with no primaries.
        assert_eq!(
            sink.devices.finalized(),
            vec![(7, None, None, host.0.to_string())]
        );
    }

    #[tokio::test]
    async fn an_absent_or_empty_serial_is_skipped_without_touching_netbox() {
        let host = HostId::new();
        for serial in [None, Some(""), Some("   ")] {
            let sink = NetboxInventorySink::new(FakeDevices::matching("x", &[]));
            assert_eq!(
                sink.upsert(host, &inventory(serial, vec![])).await.unwrap(),
                UpsertOutcome::SkippedNoSerial
            );
            assert!(
                sink.devices.finalized().is_empty(),
                "no write on an absent serial"
            );
        }
    }

    #[tokio::test]
    async fn no_match_is_unmatched_and_writes_nothing() {
        let host = HostId::new();
        let sink = NetboxInventorySink::new(FakeDevices::matching("other", &[1]));
        assert_eq!(
            sink.upsert(host, &inventory(Some("SN-unknown"), vec![]))
                .await
                .unwrap(),
            UpsertOutcome::Unmatched
        );
        assert!(sink.devices.finalized().is_empty());
    }

    #[tokio::test]
    async fn more_than_one_match_alerts_and_writes_nothing() {
        let host = HostId::new();
        let sink = NetboxInventorySink::new(FakeDevices::matching("DUP", &[1, 2]));
        assert_eq!(
            sink.upsert(host, &inventory(Some("DUP"), vec![]))
                .await
                .unwrap(),
            UpsertOutcome::AmbiguousMatch { count: 2 }
        );
        assert!(
            sink.devices.finalized().is_empty(),
            "a count>1 match must never write (AD-16)"
        );
    }

    #[tokio::test]
    async fn observed_interfaces_and_ips_are_created_with_the_first_ipv4_as_primary() {
        let host = HostId::new();
        let sink = NetboxInventorySink::new(FakeDevices::device("SN", 7, vec![]));
        let inv = inventory(Some("SN"), vec![iface("eth0", &["10.0.0.5", "fe80::1"])]);
        assert_eq!(
            sink.upsert(host, &inv).await.unwrap(),
            UpsertOutcome::Updated
        );

        let ifaces = sink.devices.interfaces_of(7);
        assert_eq!(ifaces.len(), 1);
        assert_eq!(ifaces[0].name, "eth0");
        let addrs: Vec<&str> = ifaces[0].ips.iter().map(|ip| ip.address.as_str()).collect();
        assert_eq!(addrs, vec!["10.0.0.5/32", "fe80::1/128"]);
        // primary_ip4 is the IPv4 and primary_ip6 is the IPv6.
        let v4 = sink.devices.ip_id(7, "10.0.0.5/32");
        let v6 = sink.devices.ip_id(7, "fe80::1/128");
        assert_eq!(
            sink.devices.finalized(),
            vec![(7, v4, v6, host.0.to_string())]
        );
    }

    #[tokio::test]
    async fn a_removed_nic_and_ip_are_deleted_from_netbox_full_observed_set() {
        let host = HostId::new();
        // Seed: eth0 with two IPs, and a stale eth1.
        let seed = vec![
            NbInterface {
                id: 1,
                name: "eth0".into(),
                ips: vec![
                    NbIp {
                        id: 10,
                        address: "10.0.0.5/32".into(),
                    },
                    NbIp {
                        id: 11,
                        address: "10.0.0.9/32".into(),
                    },
                ],
            },
            NbInterface {
                id: 2,
                name: "eth1".into(),
                ips: vec![NbIp {
                    id: 12,
                    address: "10.0.1.1/32".into(),
                }],
            },
        ];
        let sink = NetboxInventorySink::new(FakeDevices::device("SN", 7, seed));
        // Observe only eth0 with a single IP (10.0.0.9 removed, eth1 removed).
        let inv = inventory(Some("SN"), vec![iface("eth0", &["10.0.0.5"])]);
        assert_eq!(
            sink.upsert(host, &inv).await.unwrap(),
            UpsertOutcome::Updated
        );

        let ifaces = sink.devices.interfaces_of(7);
        assert_eq!(ifaces.len(), 1, "eth1 was removed");
        assert_eq!(ifaces[0].name, "eth0");
        let addrs: Vec<&str> = ifaces[0].ips.iter().map(|ip| ip.address.as_str()).collect();
        assert_eq!(addrs, vec!["10.0.0.5/32"], "the stale IP was removed");
    }

    #[tokio::test]
    async fn an_unchanged_snapshot_is_a_deduped_no_op() {
        let host = HostId::new();
        let sink = NetboxInventorySink::new(FakeDevices::device("SN", 7, vec![]));
        let inv = inventory(Some("SN"), vec![iface("eth0", &["10.0.0.5"])]);
        assert_eq!(
            sink.upsert(host, &inv).await.unwrap(),
            UpsertOutcome::Updated
        );
        let after_first = sink.devices.finalized().len();
        // The same snapshot again: no match, no reconcile, no finalize.
        assert_eq!(
            sink.upsert(host, &inv).await.unwrap(),
            UpsertOutcome::Unchanged
        );
        assert_eq!(
            sink.devices.finalized().len(),
            after_first,
            "a deduped no-op writes nothing"
        );
    }

    #[tokio::test]
    async fn removing_the_last_ipv4_clears_primary_ip4_before_deleting_it() {
        let host = HostId::new();
        // Seed: eth0 with an IPv4 (which is the device's primary) + an IPv6.
        let seed = vec![NbInterface {
            id: 1,
            name: "eth0".into(),
            ips: vec![
                NbIp {
                    id: 10,
                    address: "10.0.0.5/32".into(),
                },
                NbIp {
                    id: 11,
                    address: "2001:db8::5/128".into(),
                },
            ],
        }];
        let sink = NetboxInventorySink::new(FakeDevices::device("SN", 7, seed));
        // Observe eth0 with ONLY the IPv6 — the IPv4 is gone.
        let inv = inventory(Some("SN"), vec![iface("eth0", &["2001:db8::5"])]);
        assert_eq!(
            sink.upsert(host, &inv).await.unwrap(),
            UpsertOutcome::Updated
        );

        // finalize cleared primary_ip4 (None) — so the ex-primary IPv4 could then be
        // deleted — and set primary_ip6 to the retained IPv6.
        let v6 = sink.devices.ip_id(7, "2001:db8::5/128");
        assert_eq!(
            sink.devices.finalized(),
            vec![(7, None, v6, host.0.to_string())]
        );
        let addrs: Vec<String> = sink
            .devices
            .interfaces_of(7)
            .into_iter()
            .flat_map(|i| i.ips)
            .map(|ip| ip.address)
            .collect();
        assert_eq!(
            addrs,
            vec!["2001:db8::5/128"],
            "the ex-primary IPv4 was removed"
        );
    }

    #[tokio::test]
    async fn an_ip_that_moved_between_nics_is_reassigned_not_recreated() {
        let host = HostId::new();
        // Seed: 10.0.0.5 lives on eth0 (ip id 10) and eth1 exists (empty).
        let seed = vec![
            NbInterface {
                id: 1,
                name: "eth0".into(),
                ips: vec![NbIp {
                    id: 10,
                    address: "10.0.0.5/32".into(),
                }],
            },
            NbInterface {
                id: 2,
                name: "eth1".into(),
                ips: vec![],
            },
        ];
        let sink = NetboxInventorySink::new(FakeDevices::device("SN", 7, seed));
        // Now the agent reports 10.0.0.5 on eth1 (moved), eth0 has no IPs.
        let inv = inventory(
            Some("SN"),
            vec![iface("eth0", &[]), iface("eth1", &["10.0.0.5"])],
        );
        assert_eq!(
            sink.upsert(host, &inv).await.unwrap(),
            UpsertOutcome::Updated
        );

        // The SAME ip row (id 10) was re-assigned to eth1 — not deleted + recreated.
        assert_eq!(
            sink.devices.ip_id(7, "10.0.0.5/32"),
            Some(10),
            "same row reused"
        );
        assert_eq!(sink.devices.iface_of_ip(7, 10), Some(2), "now on eth1");
        // And it's still the primary_ip4 (id 10, reused).
        assert_eq!(
            sink.devices.finalized(),
            vec![(7, Some(10), None, host.0.to_string())]
        );
    }

    #[tokio::test]
    async fn a_transient_netbox_error_is_retried_until_it_succeeds() {
        let host = HostId::new();
        let sink =
            NetboxInventorySink::new(FakeDevices::matching("SN", &[7]).with_transient_failures(2));
        assert_eq!(
            sink.upsert(host, &inventory(Some("SN"), vec![]))
                .await
                .unwrap(),
            UpsertOutcome::Updated
        );
        assert_eq!(
            sink.devices.match_attempts(),
            3,
            "2 transient failures then a success"
        );
    }

    #[tokio::test]
    async fn a_permanent_netbox_error_is_not_retried() {
        let host = HostId::new();
        let sink =
            NetboxInventorySink::new(FakeDevices::matching("SN", &[7]).with_permanent_failure());
        assert!(
            sink.upsert(host, &inventory(Some("SN"), vec![]))
                .await
                .is_err()
        );
        assert_eq!(
            sink.devices.match_attempts(),
            1,
            "a permanent error fails fast, no retry"
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

    fn inventory(serial: &str, interfaces: Vec<osa_proto::v1::InventoryInterface>) -> Inventory {
        Inventory {
            dmi_serial: Some(serial.to_string()),
            system: None,
            interfaces,
            gaps: Vec::new(),
        }
    }

    fn iface(name: &str, ips: &[&str]) -> osa_proto::v1::InventoryInterface {
        osa_proto::v1::InventoryInterface {
            name: name.to_string(),
            mac: String::new(),
            ip_addresses: ips.iter().map(|s| s.to_string()).collect(),
        }
    }

    /// GET a JSON value from NetBox (authed), returning the parsed body.
    async fn get_json(http: &reqwest::Client, base: &str, path: &str) -> serde_json::Value {
        let text = http
            .get(format!("{base}{path}"))
            .header("Authorization", format!("Token {TOKEN}"))
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        serde_json::from_str(&text).unwrap()
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
            sink.upsert(host, &inventory("NO-SUCH-SERIAL", vec![]))
                .await
                .unwrap(),
            UpsertOutcome::Unmatched
        );

        // The known serial matches: reconcile an interface with an IPv4 + IPv6.
        let observed = inventory(SERIAL, vec![iface("eth0", &["192.0.2.5", "2001:db8::5"])]);
        assert_eq!(
            sink.upsert(host, &observed).await.unwrap(),
            UpsertOutcome::Updated
        );

        // The stamp landed on the device's custom field.
        assert_eq!(
            stamped_host_id(&http, &base, SERIAL).await.as_deref(),
            Some(host.0.to_string().as_str()),
            "the host_id must be written to the device's osa_host_id custom field"
        );
        // The interface and both IPs were created.
        let ifaces = get_json(&http, &base, "/api/dcim/interfaces/?device_id=1").await;
        assert_eq!(ifaces["count"].as_i64(), Some(1), "one interface: {ifaces}");
        assert_eq!(ifaces["results"][0]["name"].as_str(), Some("eth0"));
        let ips = get_json(&http, &base, "/api/ipam/ip-addresses/?device_id=1").await;
        let addrs: std::collections::HashSet<&str> = ips["results"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|ip| ip["address"].as_str())
            .collect();
        assert_eq!(
            addrs,
            ["192.0.2.5/32", "2001:db8::5/128"].into_iter().collect(),
            "both observed IPs assigned"
        );
        // primary_ip4 is the IPv4 address.
        let device = get_json(&http, &base, &format!("/api/dcim/devices/?serial={SERIAL}")).await;
        assert_eq!(
            device["results"][0]["primary_ip4"]["address"].as_str(),
            Some("192.0.2.5/32"),
            "primary_ip4 must be the IPv4"
        );

        // Re-sending the same snapshot is a deduped no-op.
        assert_eq!(
            sink.upsert(host, &observed).await.unwrap(),
            UpsertOutcome::Unchanged
        );

        // Dropping the IPv6 removes it (full observed set) — a NEW sink so the
        // in-memory dedup cache doesn't skip the reconcile.
        let sink2 = NetboxInventorySink::new(
            NetboxClient::new(&NetboxConfig {
                url: base.clone(),
                token: TOKEN.to_string(),
            })
            .unwrap(),
        );
        assert_eq!(
            sink2
                .upsert(
                    host,
                    &inventory(SERIAL, vec![iface("eth0", &["192.0.2.5"])])
                )
                .await
                .unwrap(),
            UpsertOutcome::Updated
        );
        let ips = get_json(&http, &base, "/api/ipam/ip-addresses/?device_id=1").await;
        assert_eq!(ips["count"].as_i64(), Some(1), "the IPv6 was removed");
        assert_eq!(ips["results"][0]["address"].as_str(), Some("192.0.2.5/32"));

        // Dropping the IPv4 too: NetBox forbids deleting an IP that is a device's
        // primary, so this exercises the real "clear primary_ip4 to null, THEN delete
        // the ex-primary" ordering — the path the two-phase design exists to satisfy.
        let sink3 = NetboxInventorySink::new(
            NetboxClient::new(&NetboxConfig {
                url: base.clone(),
                token: TOKEN.to_string(),
            })
            .unwrap(),
        );
        assert_eq!(
            sink3
                .upsert(host, &inventory(SERIAL, vec![iface("eth0", &[])]))
                .await
                .unwrap(),
            UpsertOutcome::Updated
        );
        let ips = get_json(&http, &base, "/api/ipam/ip-addresses/?device_id=1").await;
        assert_eq!(
            ips["count"].as_i64(),
            Some(0),
            "the ex-primary IPv4 was removed"
        );
        let device = get_json(&http, &base, &format!("/api/dcim/devices/?serial={SERIAL}")).await;
        assert!(
            device["results"][0]["primary_ip4"].is_null(),
            "primary_ip4 was cleared"
        );
    }
}
