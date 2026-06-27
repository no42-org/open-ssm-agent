/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: MIT
 */

//! MQTT topic scheme (AD-9): a versioned root and a per-host subtree keyed on
//! `host_id`. `up` is the uplink (agent → coordinator). Kept in `osa-core` so the
//! agent (publisher) and coordinator (subscriber) cannot drift.

/// Versioned topic root.
pub const ROOT: &str = "osa/v1";

/// Subscription filter matching every host's heartbeat.
pub const HEARTBEAT_FILTER: &str = "osa/v1/+/up/heartbeat";

/// The heartbeat (liveness) topic an agent publishes to.
pub fn heartbeat(host_id: &str) -> String {
    format!("{ROOT}/{host_id}/up/heartbeat")
}

/// Extract the `host_id` from a heartbeat topic, if it matches the scheme.
pub fn host_id_from_heartbeat(topic: &str) -> Option<&str> {
    let rest = topic.strip_prefix(ROOT)?.strip_prefix('/')?;
    let (host_id, tail) = rest.split_once('/')?;
    (tail == "up/heartbeat" && !host_id.is_empty()).then_some(host_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn heartbeat_topic_round_trips() {
        let t = heartbeat("abc-123");
        assert_eq!(t, "osa/v1/abc-123/up/heartbeat");
        assert_eq!(host_id_from_heartbeat(&t), Some("abc-123"));
    }

    #[test]
    fn filter_is_the_heartbeat_shape_with_a_wildcard() {
        assert_eq!(heartbeat("+"), HEARTBEAT_FILTER);
    }

    #[test]
    fn rejects_foreign_or_malformed_topics() {
        assert_eq!(host_id_from_heartbeat("osa/v1/x/up/other"), None);
        assert_eq!(host_id_from_heartbeat("other/v1/x/up/heartbeat"), None);
        assert_eq!(host_id_from_heartbeat("osa/v1//up/heartbeat"), None);
        assert_eq!(host_id_from_heartbeat("osa/v1/x/up/heartbeat/extra"), None);
    }
}
