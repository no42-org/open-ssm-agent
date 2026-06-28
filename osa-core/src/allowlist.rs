/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: MIT
 */

//! Host-local action backstop (AD-20).
//!
//! An independent, deny-by-default check the **agent** applies to every
//! dispatched action *before any capability side effect*. It does not trust the
//! coordinator: even an action the coordinator's PDP (AD-19) authorized is
//! refused locally if it falls outside what this host permits. This bounds the
//! blast radius of a compromised coordinator (AD-20) — the host owner's allowlist
//! is the floor.
//!
//! The backstop sees only the routing-level [`ActionDescriptor`]: the action
//! `kind` (verb) and `run_as`. Path-level restrictions live in the opaque
//! capability params (not visible here); each capability enforces those when it
//! parses its params (Epic 3+). This module is the pure decision; loading the
//! allowlist from host config is an agent-bin concern.

use osa_proto::v1::ActionDescriptor;

/// Why the host backstop refused an action.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BackstopDenial {
    #[error("verb {kind:?} is not permitted by the host allowlist")]
    Verb { kind: String },
    #[error("run_as {run_as:?} is not permitted by the host allowlist")]
    RunAs { run_as: String },
}

/// The host's static allowlist: which action verbs, and which `run_as` users,
/// this host permits. `"*"` in either list is a wildcard.
pub struct LocalAllowlist {
    verbs: Vec<String>,
    run_as: Vec<String>,
}

impl LocalAllowlist {
    /// Build an allowlist from permitted verbs and `run_as` users.
    pub fn new(verbs: Vec<String>, run_as: Vec<String>) -> Self {
        Self { verbs, run_as }
    }

    /// An allowlist that permits nothing — the safe default when no host policy
    /// is configured.
    pub fn deny_all() -> Self {
        Self {
            verbs: Vec::new(),
            run_as: Vec::new(),
        }
    }

    /// The permitted verbs (for operator-facing summaries).
    pub fn verbs(&self) -> &[String] {
        &self.verbs
    }

    /// The permitted `run_as` users (for operator-facing summaries).
    pub fn run_as_users(&self) -> &[String] {
        &self.run_as
    }

    /// Decide whether this host permits `action`. Deny-by-default: an empty
    /// allowlist permits nothing, and an empty action `kind` is always refused.
    ///
    /// `run_as` is checked **unconditionally**, including the empty value that
    /// means "the agent's default user". A host that restricts `run_as` therefore
    /// does not silently permit its default identity (often root) just because the
    /// coordinator omitted the field — that omission is exactly how a compromised
    /// coordinator would try to escape the floor (AD-20). To allow default-user
    /// actions, include `""` (or `"*"`) in the run_as list.
    pub fn permits(&self, action: &ActionDescriptor) -> Result<(), BackstopDenial> {
        // An empty verb is never a real action; refuse it outright so a `"*"`
        // verb wildcard cannot wave through a malformed descriptor.
        if action.kind.is_empty() || !self.verbs.iter().any(|v| v == "*" || v == &action.kind) {
            return Err(BackstopDenial::Verb {
                kind: action.kind.clone(),
            });
        }
        if !self.run_as.iter().any(|u| u == "*" || u == &action.run_as) {
            return Err(BackstopDenial::RunAs {
                run_as: action.run_as.clone(),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn action(kind: &str, run_as: &str) -> ActionDescriptor {
        ActionDescriptor {
            kind: kind.into(),
            target: "11111111-1111-4111-8111-111111111111".into(),
            run_as: run_as.into(),
            params_hash: Vec::new(),
        }
    }

    fn allowlist(verbs: &[&str], run_as: &[&str]) -> LocalAllowlist {
        LocalAllowlist::new(
            verbs.iter().map(|s| s.to_string()).collect(),
            run_as.iter().map(|s| s.to_string()).collect(),
        )
    }

    #[test]
    fn deny_all_refuses_everything() {
        let a = LocalAllowlist::deny_all();
        assert!(a.permits(&action("exec", "")).is_err());
    }

    #[test]
    fn permits_a_listed_verb_with_explicitly_permitted_default_user() {
        // "" in the run_as list opts in to default-user actions.
        let a = allowlist(&["exec", "inventory"], &[""]);
        assert!(a.permits(&action("exec", "")).is_ok());
        assert!(a.permits(&action("inventory", "")).is_ok());
    }

    #[test]
    fn refuses_an_unlisted_verb() {
        let a = allowlist(&["inventory"], &["*"]);
        assert_eq!(
            a.permits(&action("exec", "")),
            Err(BackstopDenial::Verb {
                kind: "exec".into()
            })
        );
    }

    #[test]
    fn refuses_a_run_as_not_on_the_list() {
        // Verb is allowed, but root is not a permitted run_as → refused locally,
        // even though a (compromised) coordinator might have authorized it.
        let a = allowlist(&["exec"], &["deploy"]);
        assert_eq!(
            a.permits(&action("exec", "root")),
            Err(BackstopDenial::RunAs {
                run_as: "root".into()
            })
        );
        assert!(a.permits(&action("exec", "deploy")).is_ok());
    }

    #[test]
    fn an_empty_run_as_is_refused_unless_explicitly_permitted() {
        // The AD-20 bypass: a host that restricts run_as to `deploy` must NOT
        // permit the agent's default identity just because run_as is empty — a
        // compromised coordinator would omit the field to land on root.
        let a = allowlist(&["exec"], &["deploy"]);
        assert_eq!(
            a.permits(&action("exec", "")),
            Err(BackstopDenial::RunAs {
                run_as: String::new()
            })
        );
    }

    #[test]
    fn an_empty_kind_is_always_refused() {
        // Even a wildcard verb must not wave through a malformed empty kind.
        let a = allowlist(&["*"], &["*"]);
        assert!(matches!(
            a.permits(&action("", "root")),
            Err(BackstopDenial::Verb { .. })
        ));
    }

    #[test]
    fn wildcards_permit_broadly() {
        let a = allowlist(&["*"], &["*"]);
        assert!(a.permits(&action("exec", "root")).is_ok());
        assert!(a.permits(&action("file", "nobody")).is_ok());
        assert!(a.permits(&action("exec", "")).is_ok()); // "*" covers default too
    }
}
