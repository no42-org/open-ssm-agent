/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: MIT
 */

//! Ports — the swappable seams of the hexagon (AD-3, AD-13, AD-17, AD-19,
//! AD-23). Each is a trait named by role; concrete adapters (named by impl,
//! e.g. `MqttControlChannel`, `NetboxInventorySink`) live in the bins and are
//! injected at wiring time. These traits are `Send + Sync` and object-safe so a
//! bin can hold them behind `dyn`.

use async_trait::async_trait;
use osa_proto::v1::{ActionDescriptor, Envelope};

use crate::domain::HostId;

/// Errors crossing a port boundary. Adapters map their concrete failures onto
/// these typed domain errors (Conventions: typed errors in `osa-core`).
#[derive(Debug, thiserror::Error)]
pub enum PortError {
    #[error("transport failure: {0}")]
    Transport(String),
    #[error("denied by policy")]
    Denied,
    #[error("not found")]
    NotFound,
    /// Caller-supplied input was malformed or rejected at the boundary — a
    /// permanent client-side error, distinct from a (possibly transient)
    /// [`Backend`](Self::Backend) failure.
    #[error("invalid input: {0}")]
    Invalid(String),
    #[error("backend failure: {0}")]
    Backend(String),
}

/// Transport seam (AD-3). The default adapter is MQTT (`rumqttd`/`rumqttc`); the
/// domain never names a broker. Carries the AD-7 envelope; ordering/dedup is the
/// envelope's concern (AD-8), retransmit is delegated to the adapter (MQTT QoS).
#[async_trait]
pub trait ControlChannel: Send + Sync {
    /// Publish one envelope toward its routed peer.
    async fn publish(&self, envelope: Envelope) -> Result<(), PortError>;
}

/// Fire-and-collect capabilities — exec, inventory, file (AD-13·Job, AD-22).
/// Crash-recoverable and idempotent under redelivery keyed on `job_id`.
#[async_trait]
pub trait JobCapability: Send + Sync {
    /// The `action.kind` this capability answers to (e.g. `"exec"`).
    fn kind(&self) -> &str;
    /// Execute the job described by `action`; chunked results flow out of band
    /// over the [`ControlChannel`]. Returns when the terminal status is known.
    async fn run(&self, action: &ActionDescriptor) -> Result<(), PortError>;
}

/// Long-lived bidirectional byte streams — shell, port-forward (AD-13·Stream,
/// AD-14). Sessions run as isolated child processes and do not survive an agent
/// restart (AD-22).
#[async_trait]
pub trait StreamCapability: Send + Sync {
    /// The `action.kind` this capability answers to (e.g. `"shell"`).
    fn kind(&self) -> &str;
    /// Open a session under `action.run_as`, spawning the isolated child proc.
    async fn open(&self, action: &ActionDescriptor) -> Result<(), PortError>;
}

/// Authorization PDP (AD-19). The coordinator is the sole PDP/PEP; RBAC is the
/// default adapter, OPA/Cedar a later swap. Evaluated on the action descriptor.
#[async_trait]
pub trait PolicyEngine: Send + Sync {
    /// Authorize `subject` to perform `action`. `Err(PortError::Denied)` denies.
    async fn authorize(&self, subject: &str, action: &ActionDescriptor) -> Result<(), PortError>;
}

/// PKI seam (AD-23). Default adapter is an embedded `rcgen` CA; `step-ca`/ACME
/// is a later swap. Signs an agent-generated CSR into a short-lived mTLS cert
/// (SAN = `host_id`), and supports renewal on an existing identity.
#[async_trait]
pub trait CertIssuer: Send + Sync {
    /// Sign `csr` for `host_id`, returning the DER-encoded client certificate.
    async fn sign(&self, host_id: HostId, csr: &[u8]) -> Result<Vec<u8>, PortError>;
}

/// CMDB sink (AD-16, AD-17). Coordinator-side only — no host holds a write
/// token. One-way, field-scoped upsert matched on DMI serial; never touches
/// human-curated fields.
#[async_trait]
pub trait InventorySink: Send + Sync {
    /// Idempotently upsert one host's observed inventory snapshot.
    async fn upsert(&self, host_id: HostId, observed: &[u8]) -> Result<(), PortError>;
}
