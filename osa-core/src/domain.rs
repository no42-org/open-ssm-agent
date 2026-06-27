/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: MIT
 */

//! Domain newtypes. All inter-component IDs are UUIDv4 (Conventions table).

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Coordinator-assigned host identity (AD-10). Minted as a UUIDv4 at enrollment,
/// embedded in the agent mTLS cert SAN, and used as the topic, registry, and
/// authz key. Decoupled from the DMI serial, which is a collected attribute only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct HostId(pub Uuid);

/// Interactive-session identity (AD-30). Minted by the coordinator on session
/// open; carries a monotonic epoch elsewhere so a reconnect cannot resurrect it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Sid(pub Uuid);

/// Job identity for `JobCapability` work (AD-22). Redelivery dedups on this id
/// (never on `params_hash`, which would wrongly collapse intentional repeats).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct JobId(pub Uuid);

impl HostId {
    /// Mint a fresh host identity (enrollment, AD-25).
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for HostId {
    fn default() -> Self {
        Self::new()
    }
}
