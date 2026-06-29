/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: MIT
 */

//! MQTT topic scheme (AD-9, AD-31): every topic lives under a per-host **tenant
//! prefix** the broker enforces from the client cert (issue #16).
//!
//! The embedded `rumqttd` `validate-tenant-prefix` feature reads the client
//! cert's Organization (O) field and confines that client to `/tenants/<O>/…`,
//! rejecting any publish/subscribe outside it. We issue each agent's cert with
//! `O = host_id` in hyphen-stripped UUID hex (the feature requires an
//! alphanumeric tenant id), so a host can only reach its own subtree — a
//! compromised cert cannot touch another host's topics.
//!
//! Kept in `osa-core` so the agent (publisher) and coordinator (subscriber)
//! cannot drift. The coordinator's in-process bridge link presents no cert and is
//! therefore not tenant-confined; it subscribes across `/tenants/+/…`.

/// Versioned topic root (within a host's tenant subtree).
pub const ROOT: &str = "osa/v1";

/// Subscription filter (for the coordinator's in-process link) matching every
/// host's heartbeat across all tenants.
pub const HEARTBEAT_FILTER: &str = "/tenants/+/osa/v1/up/heartbeat";

/// The broker tenant id for a host: its `host_id` with hyphens stripped, so it is
/// alphanumeric as `validate-tenant-prefix` requires. Must equal the cert's O.
pub fn tenant(host_id: &str) -> String {
    host_id.replace('-', "")
}

/// A host's tenant prefix: `/tenants/<tenant>/`. Every topic this host may touch
/// begins with this.
pub fn tenant_prefix(host_id: &str) -> String {
    format!("/tenants/{}/", tenant(host_id))
}

/// The heartbeat (liveness) topic an agent publishes to.
pub fn heartbeat(host_id: &str) -> String {
    format!("{}{ROOT}/up/heartbeat", tenant_prefix(host_id))
}

/// Extract the tenant id (hyphen-stripped host_id) from a heartbeat topic, if it
/// matches the scheme.
pub fn tenant_from_heartbeat(topic: &str) -> Option<&str> {
    let rest = topic.strip_prefix("/tenants/")?;
    let (tenant, tail) = rest.split_once('/')?;
    (tail == "osa/v1/up/heartbeat" && !tenant.is_empty()).then_some(tenant)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn heartbeat_topic_is_tenant_scoped_and_round_trips() {
        let host = "11111111-2222-4333-8444-555555555555";
        let t = heartbeat(host);
        assert_eq!(
            t,
            "/tenants/11111111222243338444555555555555/osa/v1/up/heartbeat"
        );
        // The tenant in the topic is the hyphen-stripped host_id (= cert O).
        assert_eq!(tenant_from_heartbeat(&t), Some(tenant(host).as_str()));
    }

    #[test]
    fn tenant_strips_hyphens_to_match_the_cert_o_field() {
        assert_eq!(tenant("ab-cd-ef"), "abcdef");
        assert_eq!(tenant_prefix("ab-cd"), "/tenants/abcd/");
    }

    #[test]
    fn tenant_equals_the_simple_uuid_the_cert_o_uses() {
        // Cross-component invariant: the agent builds topics from the dashed
        // Display form of its host_id, while the coordinator sets the cert O to
        // the *simple* (hyphenless) form. Both must reconcile to the same tenant,
        // or an agent could not reach its own topics. Pin it here so a future
        // host_id rendering change can't silently break broker connectivity.
        let id = uuid::Uuid::new_v4();
        assert_eq!(tenant(&id.to_string()), id.simple().to_string());
    }

    #[test]
    fn filter_matches_the_heartbeat_shape() {
        let t = heartbeat("aaaa-bbbb");
        assert!(t.starts_with("/tenants/"));
        assert!(t.ends_with("/osa/v1/up/heartbeat"));
        assert_eq!(HEARTBEAT_FILTER, "/tenants/+/osa/v1/up/heartbeat");
    }

    #[test]
    fn rejects_foreign_or_malformed_topics() {
        assert_eq!(tenant_from_heartbeat("/tenants/x/osa/v1/up/other"), None);
        assert_eq!(tenant_from_heartbeat("osa/v1/x/up/heartbeat"), None);
        assert_eq!(tenant_from_heartbeat("/tenants//osa/v1/up/heartbeat"), None);
        assert_eq!(
            tenant_from_heartbeat("/tenants/x/osa/v1/up/heartbeat/extra"),
            None
        );
    }
}
