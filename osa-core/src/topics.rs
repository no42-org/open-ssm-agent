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

/// Filter matching every host's `ClientHello` (session handshake, #20).
pub const HS_UP_FILTER: &str = "/tenants/+/osa/v1/up/hs";

/// Filter matching every host's sealed control uplink (e.g. the session-open
/// ack, #20).
pub const CTRL_UP_FILTER: &str = "/tenants/+/osa/v1/up/ctrl";

/// Filter matching every host's sealed job-result uplink (Epic 3).
pub const RESULT_UP_FILTER: &str = "/tenants/+/osa/v1/up/result";

/// Filter matching every host's sealed stream uplink (Epic 4 — interactive shell /
/// port-forward bytes).
pub const STREAM_UP_FILTER: &str = "/tenants/+/osa/v1/up/stream";

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

/// The handshake uplink: an agent publishes its `ClientHello` here (#20).
pub fn hs_up(host_id: &str) -> String {
    format!("{}{ROOT}/up/hs", tenant_prefix(host_id))
}

/// The handshake downlink: the coordinator publishes the `ServerHello` here, and
/// the agent subscribes to it (#20).
pub fn hs_down(host_id: &str) -> String {
    format!("{}{ROOT}/down/hs", tenant_prefix(host_id))
}

/// The sealed control uplink: the agent publishes its session-open ack here, and
/// the coordinator subscribes across all tenants via [`CTRL_UP_FILTER`] (#20).
pub fn ctrl_up(host_id: &str) -> String {
    format!("{}{ROOT}/up/ctrl", tenant_prefix(host_id))
}

/// The sealed control downlink: the coordinator publishes its session-ready
/// beacon here, and the agent subscribes to it (#20).
pub fn ctrl_down(host_id: &str) -> String {
    format!("{}{ROOT}/down/ctrl", tenant_prefix(host_id))
}

/// The sealed dispatch downlink: the coordinator publishes sealed `Dispatch`
/// messages here, and the agent subscribes to it (Epic 3).
pub fn dispatch_down(host_id: &str) -> String {
    format!("{}{ROOT}/down/dispatch", tenant_prefix(host_id))
}

/// The sealed result uplink: the agent publishes sealed `Result` messages here,
/// and the coordinator subscribes across all tenants via [`RESULT_UP_FILTER`].
pub fn result_up(host_id: &str) -> String {
    format!("{}{ROOT}/up/result", tenant_prefix(host_id))
}

/// The sealed stream downlink: the coordinator publishes sealed `KIND_STREAM`
/// frames (operator→host bytes) here, and the agent subscribes to it (Epic 4).
pub fn stream_down(host_id: &str) -> String {
    format!("{}{ROOT}/down/stream", tenant_prefix(host_id))
}

/// The sealed stream uplink: the agent publishes sealed `KIND_STREAM` frames
/// (host→operator bytes) here, and the coordinator subscribes across all tenants
/// via [`STREAM_UP_FILTER`] (Epic 4).
pub fn stream_up(host_id: &str) -> String {
    format!("{}{ROOT}/up/stream", tenant_prefix(host_id))
}

/// Extract the tenant id (hyphen-stripped host_id) from a topic whose tail after
/// the tenant segment equals `tail`. The broker confines each client to its own
/// `/tenants/<O>/…` subtree, so a topic matching the scheme names the tenant that
/// could have published it.
fn tenant_for_tail<'a>(topic: &'a str, tail: &str) -> Option<&'a str> {
    let rest = topic.strip_prefix("/tenants/")?;
    let (tenant, rest_tail) = rest.split_once('/')?;
    (rest_tail == tail && !tenant.is_empty()).then_some(tenant)
}

/// Extract the tenant id from a heartbeat topic, if it matches the scheme.
pub fn tenant_from_heartbeat(topic: &str) -> Option<&str> {
    tenant_for_tail(topic, "osa/v1/up/heartbeat")
}

/// Extract the tenant id from a `ClientHello` (handshake uplink) topic (#20).
pub fn tenant_from_hs_up(topic: &str) -> Option<&str> {
    tenant_for_tail(topic, "osa/v1/up/hs")
}

/// Extract the tenant id from a sealed control uplink topic (#20).
pub fn tenant_from_ctrl_up(topic: &str) -> Option<&str> {
    tenant_for_tail(topic, "osa/v1/up/ctrl")
}

/// Extract the tenant id from a sealed job-result uplink topic (Epic 3).
pub fn tenant_from_result_up(topic: &str) -> Option<&str> {
    tenant_for_tail(topic, "osa/v1/up/result")
}

/// Extract the tenant id from a sealed stream uplink topic (Epic 4).
pub fn tenant_from_stream_up(topic: &str) -> Option<&str> {
    tenant_for_tail(topic, "osa/v1/up/stream")
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

    #[test]
    fn handshake_and_control_topics_are_tenant_scoped_and_round_trip() {
        let host = "11111111-2222-4333-8444-555555555555";
        let t = tenant(host);
        assert_eq!(hs_up(host), format!("/tenants/{t}/osa/v1/up/hs"));
        assert_eq!(hs_down(host), format!("/tenants/{t}/osa/v1/down/hs"));
        assert_eq!(ctrl_up(host), format!("/tenants/{t}/osa/v1/up/ctrl"));
        assert_eq!(ctrl_down(host), format!("/tenants/{t}/osa/v1/down/ctrl"));
        assert_eq!(
            dispatch_down(host),
            format!("/tenants/{t}/osa/v1/down/dispatch")
        );
        assert_eq!(result_up(host), format!("/tenants/{t}/osa/v1/up/result"));
        assert_eq!(
            stream_down(host),
            format!("/tenants/{t}/osa/v1/down/stream")
        );
        assert_eq!(stream_up(host), format!("/tenants/{t}/osa/v1/up/stream"));
        assert_eq!(tenant_from_hs_up(&hs_up(host)), Some(t.as_str()));
        assert_eq!(tenant_from_ctrl_up(&ctrl_up(host)), Some(t.as_str()));
        assert_eq!(tenant_from_result_up(&result_up(host)), Some(t.as_str()));
        assert_eq!(tenant_from_stream_up(&stream_up(host)), Some(t.as_str()));
        // The filters match the produced shapes.
        assert_eq!(HS_UP_FILTER, "/tenants/+/osa/v1/up/hs");
        assert_eq!(CTRL_UP_FILTER, "/tenants/+/osa/v1/up/ctrl");
        assert_eq!(RESULT_UP_FILTER, "/tenants/+/osa/v1/up/result");
        assert_eq!(STREAM_UP_FILTER, "/tenants/+/osa/v1/up/stream");
    }

    #[test]
    fn handshake_extractors_reject_the_wrong_channel() {
        // A handshake extractor must not match a heartbeat (or a downlink) topic.
        let host = "aaaa-bbbb";
        assert_eq!(tenant_from_hs_up(&heartbeat(host)), None);
        assert_eq!(tenant_from_hs_up(&hs_down(host)), None);
        assert_eq!(tenant_from_ctrl_up(&hs_up(host)), None);
        // The stream uplink extractor must not match the downlink or other channels.
        assert_eq!(tenant_from_stream_up(&stream_down(host)), None);
        assert_eq!(tenant_from_stream_up(&result_up(host)), None);
    }
}
