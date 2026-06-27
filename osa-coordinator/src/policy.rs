/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: MIT
 */

//! Deny-by-default RBAC authorization (AD-19).
//!
//! The coordinator is the sole policy decision point: every dispatched
//! [`ActionDescriptor`] is checked against a set of role bindings before any
//! agent is contacted. A binding grants a subject a set of verbs (action kinds)
//! over a set of host-selectors. An action is allowed only if **some** binding
//! matches the subject, the verb, and a selector that resolves to the target
//! host; with no matching binding the default is deny.
//!
//! Selectors are `"*"` (every host) or an exact `host_id`. Tag/group selectors
//! await the host registry (Epic 5 inventory); until then a selector resolves by
//! identity, which is sufficient for the deny-by-default spine.

use anyhow::Context;
use async_trait::async_trait;
use osa_core::ports::{PolicyEngine, PortError};
use osa_proto::v1::ActionDescriptor;
use serde::Deserialize;
use uuid::Uuid;

/// The subject the dispatch handler uses when no authenticated `Subject` is
/// bound (i.e. the API is running without OIDC). It is **reserved**: a policy
/// may not grant it (enforced in [`RbacPolicyEngine::from_toml`]), so an
/// unauthenticated caller can never match a binding.
pub const ANONYMOUS_SUBJECT: &str = "anonymous";

/// A host selector — the set of targets a binding covers.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Selector {
    /// `"*"` — every host.
    Any,
    /// One specific host identity.
    Host(Uuid),
}

impl Selector {
    fn matches(&self, target: Uuid) -> bool {
        match self {
            Selector::Any => true,
            Selector::Host(h) => *h == target,
        }
    }
}

/// One RBAC grant: `subject` may perform `verbs` against hosts matched by
/// `selectors`. A verb of `"*"` matches any action kind.
struct Binding {
    subject: String,
    verbs: Vec<String>,
    selectors: Vec<Selector>,
}

impl Binding {
    fn allows(&self, subject: &str, kind: &str, target: Uuid) -> bool {
        self.subject == subject
            && self.verbs.iter().any(|v| v == "*" || v == kind)
            && self.selectors.iter().any(|s| s.matches(target))
    }
}

/// Deny-by-default RBAC PDP (AD-19).
pub struct RbacPolicyEngine {
    bindings: Vec<Binding>,
}

impl RbacPolicyEngine {
    /// An engine with no grants — denies everything. The safe default when no
    /// policy is configured.
    pub fn empty() -> Self {
        Self {
            bindings: Vec::new(),
        }
    }

    /// Whether the engine holds zero bindings (and therefore denies everything).
    pub fn is_empty(&self) -> bool {
        self.bindings.is_empty()
    }

    /// Parse role bindings from a TOML policy document.
    ///
    /// ```toml
    /// [[binding]]
    /// subject = "alice@example"
    /// verbs = ["exec", "shell"]
    /// selectors = ["*"]
    /// ```
    pub fn from_toml(doc: &str) -> anyhow::Result<Self> {
        let parsed: PolicyDoc = toml::from_str(doc).context("policy is not valid TOML")?;
        let mut bindings = Vec::with_capacity(parsed.binding.len());
        for b in parsed.binding {
            anyhow::ensure!(
                !b.subject.is_empty() && b.subject.trim() == b.subject,
                "a binding subject must be non-empty and not padded with whitespace"
            );
            anyhow::ensure!(
                b.subject != ANONYMOUS_SUBJECT,
                "{ANONYMOUS_SUBJECT:?} is reserved for unauthenticated callers and cannot be granted",
            );
            anyhow::ensure!(
                !b.verbs.is_empty(),
                "binding for {} lists no verbs",
                b.subject
            );
            anyhow::ensure!(
                !b.selectors.is_empty(),
                "binding for {} lists no selectors",
                b.subject
            );
            let selectors = b
                .selectors
                .iter()
                .map(|s| parse_selector(s))
                .collect::<anyhow::Result<Vec<_>>>()?;
            bindings.push(Binding {
                subject: b.subject,
                verbs: b.verbs,
                selectors,
            });
        }
        Ok(Self { bindings })
    }
}

fn parse_selector(s: &str) -> anyhow::Result<Selector> {
    if s == "*" {
        return Ok(Selector::Any);
    }
    s.parse::<Uuid>()
        .map(Selector::Host)
        .with_context(|| format!("selector {s:?} is neither \"*\" nor a host_id UUID"))
}

#[async_trait]
impl PolicyEngine for RbacPolicyEngine {
    async fn authorize(&self, subject: &str, action: &ActionDescriptor) -> Result<(), PortError> {
        // `run_as` (the privilege the action runs with) is not yet an axis of the
        // policy model — issue #22. Until it is, deny any non-empty `run_as`
        // rather than silently authorizing an unconstrained identity.
        if !action.run_as.is_empty() {
            return Err(PortError::Denied);
        }
        // A target that is not a valid host_id can never be resolved by a
        // selector — deny (deny-by-default holds for malformed input too).
        let target = action
            .target
            .parse::<Uuid>()
            .map_err(|_| PortError::Denied)?;
        if self
            .bindings
            .iter()
            .any(|b| b.allows(subject, &action.kind, target))
        {
            Ok(())
        } else {
            Err(PortError::Denied)
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyDoc {
    #[serde(default)]
    binding: Vec<BindingDoc>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BindingDoc {
    subject: String,
    verbs: Vec<String>,
    selectors: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOST_A: &str = "11111111-1111-4111-8111-111111111111";
    const HOST_B: &str = "22222222-2222-4222-8222-222222222222";

    fn action(kind: &str, target: &str) -> ActionDescriptor {
        ActionDescriptor {
            kind: kind.into(),
            target: target.into(),
            run_as: String::new(),
            params_hash: Vec::new(),
        }
    }

    async fn allowed(engine: &RbacPolicyEngine, subject: &str, kind: &str, target: &str) -> bool {
        engine
            .authorize(subject, &action(kind, target))
            .await
            .is_ok()
    }

    fn engine(toml: &str) -> RbacPolicyEngine {
        RbacPolicyEngine::from_toml(toml).unwrap()
    }

    #[tokio::test]
    async fn empty_policy_denies_everything() {
        let e = RbacPolicyEngine::empty();
        assert!(!allowed(&e, "alice@example", "exec", HOST_A).await);
    }

    #[tokio::test]
    async fn a_matching_binding_allows() {
        let e = engine(
            r#"
            [[binding]]
            subject = "alice@example"
            verbs = ["exec", "shell"]
            selectors = ["*"]
        "#,
        );
        assert!(allowed(&e, "alice@example", "exec", HOST_A).await);
        assert!(allowed(&e, "alice@example", "shell", HOST_B).await);
    }

    #[tokio::test]
    async fn denies_an_unbound_subject() {
        let e = engine(
            r#"
            [[binding]]
            subject = "alice@example"
            verbs = ["*"]
            selectors = ["*"]
        "#,
        );
        assert!(!allowed(&e, "mallory@example", "exec", HOST_A).await);
    }

    #[tokio::test]
    async fn denies_a_verb_outside_the_binding() {
        let e = engine(
            r#"
            [[binding]]
            subject = "alice@example"
            verbs = ["inventory"]
            selectors = ["*"]
        "#,
        );
        assert!(allowed(&e, "alice@example", "inventory", HOST_A).await);
        assert!(!allowed(&e, "alice@example", "exec", HOST_A).await);
    }

    #[tokio::test]
    async fn host_selector_scopes_to_one_host() {
        let e = engine(&format!(
            r#"
            [[binding]]
            subject = "alice@example"
            verbs = ["exec"]
            selectors = ["{HOST_A}"]
        "#
        ));
        assert!(allowed(&e, "alice@example", "exec", HOST_A).await);
        assert!(!allowed(&e, "alice@example", "exec", HOST_B).await);
    }

    #[tokio::test]
    async fn wildcard_verb_allows_any_kind() {
        let e = engine(
            r#"
            [[binding]]
            subject = "ops@example"
            verbs = ["*"]
            selectors = ["*"]
        "#,
        );
        assert!(allowed(&e, "ops@example", "exec", HOST_A).await);
        assert!(allowed(&e, "ops@example", "file", HOST_B).await);
    }

    #[tokio::test]
    async fn a_malformed_target_is_denied() {
        let e = engine(
            r#"
            [[binding]]
            subject = "alice@example"
            verbs = ["*"]
            selectors = ["*"]
        "#,
        );
        assert!(!allowed(&e, "alice@example", "exec", "not-a-uuid").await);
    }

    #[test]
    fn rejects_a_bad_selector() {
        let err = RbacPolicyEngine::from_toml(
            r#"
            [[binding]]
            subject = "alice@example"
            verbs = ["exec"]
            selectors = ["not-a-uuid"]
        "#,
        );
        assert!(err.is_err());
    }

    #[test]
    fn rejects_a_binding_with_no_verbs() {
        let err = RbacPolicyEngine::from_toml(
            r#"
            [[binding]]
            subject = "alice@example"
            verbs = []
            selectors = ["*"]
        "#,
        );
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn an_empty_document_is_a_deny_all_engine() {
        let e = RbacPolicyEngine::from_toml("").unwrap();
        assert!(!allowed(&e, "alice@example", "exec", HOST_A).await);
    }

    #[test]
    fn the_anonymous_subject_cannot_be_granted() {
        let err = RbacPolicyEngine::from_toml(
            r#"
            [[binding]]
            subject = "anonymous"
            verbs = ["*"]
            selectors = ["*"]
        "#,
        );
        assert!(
            err.is_err(),
            "a binding for the anonymous sentinel must be refused"
        );
    }

    #[test]
    fn rejects_a_padded_subject() {
        let err = RbacPolicyEngine::from_toml(
            r#"
            [[binding]]
            subject = " alice@example "
            verbs = ["*"]
            selectors = ["*"]
        "#,
        );
        assert!(err.is_err());
    }

    #[test]
    fn rejects_an_unknown_field() {
        // A misspelled key (here `verb` instead of `verbs`) is a hard error, not
        // a silently dropped field that loads the binding too broad/narrow.
        let err = RbacPolicyEngine::from_toml(
            r#"
            [[binding]]
            subject = "alice@example"
            verb = ["exec"]
            verbs = ["exec"]
            selectors = ["*"]
        "#,
        );
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn a_non_empty_run_as_is_denied() {
        let e = engine(
            r#"
            [[binding]]
            subject = "alice@example"
            verbs = ["*"]
            selectors = ["*"]
        "#,
        );
        let mut a = action("exec", HOST_A);
        a.run_as = "root".into();
        assert!(
            e.authorize("alice@example", &a).await.is_err(),
            "run_as is not yet an authorization axis (#22) — non-empty must deny"
        );
    }
}
