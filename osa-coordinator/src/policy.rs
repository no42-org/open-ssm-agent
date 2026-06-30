/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: MIT
 */

//! Deny-by-default RBAC authorization (AD-19).
//!
//! The coordinator is the sole policy decision point: every dispatched
//! [`ActionDescriptor`] is checked against a set of role bindings before any
//! agent is contacted. A binding grants a subject a set of verbs (action kinds)
//! over a set of host-selectors, each running as one of a set of permitted
//! `run_as` users. An action is allowed only if **some** binding matches the
//! subject, the verb, a selector that resolves to the target host, AND the
//! action's `run_as`; with no matching binding the default is deny.
//!
//! Selectors are `"*"` (every host) or an exact `host_id`. Tag/group selectors
//! await the host registry (Epic 5 inventory); until then a selector resolves by
//! identity, which is sufficient for the deny-by-default spine.
//!
//! `run_as` (AD-19, #22) is the unix user the action executes as. A binding's
//! `run_as` list mirrors the agent-local backstop (AD-20,
//! [`osa_core::allowlist`]) so the two enforcement points speak the same
//! language: `"*"` permits any user, `""` opts in to the agent's default
//! identity, and any other entry is a literal username. The empty `run_as` is
//! **never** an implicit free pass — it must be granted explicitly, closing the
//! escalation where omitting the field lands on the agent's (often root)
//! identity. Note `"*"` therefore grants *every* user **including** that default
//! identity; scope a binding to explicit usernames when that distinction
//! matters.

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
/// `selectors`, running as one of `run_as`. A verb of `"*"` matches any action
/// kind; a `run_as` of `"*"` matches any user and `""` the default identity.
struct Binding {
    subject: String,
    verbs: Vec<String>,
    selectors: Vec<Selector>,
    run_as: Vec<String>,
}

impl Binding {
    fn allows(&self, subject: &str, kind: &str, target: Uuid, run_as: &str) -> bool {
        // An empty `kind` is never a real action: refuse it outright so a `"*"`
        // verb wildcard cannot wave through a malformed descriptor. Mirrors the
        // agent backstop (AD-20, `osa_core::allowlist`) so the PDP is self-contained
        // and does not rely on a caller pre-rejecting empty kinds.
        self.subject == subject
            && !kind.is_empty()
            && self.verbs.iter().any(|v| v == "*" || v == kind)
            && self.selectors.iter().any(|s| s.matches(target))
            && self.run_as.iter().any(|u| u == "*" || u == run_as)
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
    /// run_as = ["deploy", "nobody"]  # "*" = any user, "" = the default identity
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
            anyhow::ensure!(
                !b.run_as.is_empty(),
                "binding for {} lists no run_as users (use [\"*\"] for any user, \
                 [\"\"] for the agent's default identity)",
                b.subject
            );
            // A padded entry (" deploy ") never matches a getpwnam'd user, so it
            // would be a silent dead grant — refuse it at load, mirroring the
            // subject check. `""` (the default identity) trims to itself and stays
            // valid.
            for u in &b.run_as {
                anyhow::ensure!(
                    u.trim() == u.as_str(),
                    "binding for {} has a run_as entry {u:?} padded with whitespace",
                    b.subject
                );
            }
            let selectors = b
                .selectors
                .iter()
                .map(|s| parse_selector(s))
                .collect::<anyhow::Result<Vec<_>>>()?;
            bindings.push(Binding {
                subject: b.subject,
                verbs: b.verbs,
                selectors,
                run_as: b.run_as,
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
        // A target that is not a valid host_id can never be resolved by a
        // selector — deny (deny-by-default holds for malformed input too).
        let target = action
            .target
            .parse::<Uuid>()
            .map_err(|_| PortError::Denied)?;
        // The action's `run_as` is authorized as part of the binding match (#22):
        // a binding must grant the subject the verb, a selector covering the
        // target, AND this `run_as` — including the empty default identity, which
        // is never an implicit free pass.
        if self
            .bindings
            .iter()
            .any(|b| b.allows(subject, &action.kind, target, &action.run_as))
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
    run_as: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOST_A: &str = "11111111-1111-4111-8111-111111111111";
    const HOST_B: &str = "22222222-2222-4222-8222-222222222222";

    fn action_as(kind: &str, target: &str, run_as: &str) -> ActionDescriptor {
        ActionDescriptor {
            kind: kind.into(),
            target: target.into(),
            run_as: run_as.into(),
            params_hash: Vec::new(),
        }
    }

    /// Authorize a default-identity (empty `run_as`) action — the axis under test
    /// in the verb/selector/subject cases.
    async fn allowed(engine: &RbacPolicyEngine, subject: &str, kind: &str, target: &str) -> bool {
        allowed_as(engine, subject, kind, target, "").await
    }

    async fn allowed_as(
        engine: &RbacPolicyEngine,
        subject: &str,
        kind: &str,
        target: &str,
        run_as: &str,
    ) -> bool {
        engine
            .authorize(subject, &action_as(kind, target, run_as))
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
            run_as = ["*"]
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
            run_as = ["*"]
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
            run_as = ["*"]
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
            run_as = ["*"]
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
            run_as = ["*"]
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
            run_as = ["*"]
        "#,
        );
        assert!(!allowed(&e, "alice@example", "exec", "not-a-uuid").await);
    }

    // --- run_as authorization axis (#22) ---

    #[tokio::test]
    async fn run_as_must_be_on_the_binding_list() {
        // The binding grants exec on any host, but only as `deploy` or `nobody`.
        let e = engine(
            r#"
            [[binding]]
            subject = "alice@example"
            verbs = ["exec"]
            selectors = ["*"]
            run_as = ["deploy", "nobody"]
        "#,
        );
        assert!(allowed_as(&e, "alice@example", "exec", HOST_A, "deploy").await);
        assert!(allowed_as(&e, "alice@example", "exec", HOST_A, "nobody").await);
        // A user the binding does not list is denied — even though verb + selector
        // match.
        assert!(!allowed_as(&e, "alice@example", "exec", HOST_A, "root").await);
        // The empty default identity is NOT implicitly granted by a non-empty list.
        assert!(!allowed_as(&e, "alice@example", "exec", HOST_A, "").await);
    }

    #[tokio::test]
    async fn empty_run_as_must_be_granted_explicitly() {
        // `""` in the list opts in to the agent's default identity; nothing else
        // is granted (the escalation guard: omitting run_as must not reach root).
        let e = engine(
            r#"
            [[binding]]
            subject = "alice@example"
            verbs = ["exec"]
            selectors = ["*"]
            run_as = [""]
        "#,
        );
        assert!(allowed_as(&e, "alice@example", "exec", HOST_A, "").await);
        assert!(!allowed_as(&e, "alice@example", "exec", HOST_A, "root").await);
    }

    #[tokio::test]
    async fn wildcard_run_as_allows_any_user_including_default() {
        let e = engine(
            r#"
            [[binding]]
            subject = "ops@example"
            verbs = ["exec"]
            selectors = ["*"]
            run_as = ["*"]
        "#,
        );
        assert!(allowed_as(&e, "ops@example", "exec", HOST_A, "root").await);
        assert!(allowed_as(&e, "ops@example", "exec", HOST_A, "deploy").await);
        assert!(allowed_as(&e, "ops@example", "exec", HOST_A, "").await);
    }

    #[tokio::test]
    async fn run_as_grants_compose_across_bindings() {
        // One binding grants `deploy` on any host; a second grants `root` only on
        // HOST_A. The action is allowed if ANY binding covers verb+selector+run_as.
        let e = engine(&format!(
            r#"
            [[binding]]
            subject = "alice@example"
            verbs = ["exec"]
            selectors = ["*"]
            run_as = ["deploy"]

            [[binding]]
            subject = "alice@example"
            verbs = ["exec"]
            selectors = ["{HOST_A}"]
            run_as = ["root"]
        "#
        ));
        assert!(allowed_as(&e, "alice@example", "exec", HOST_B, "deploy").await);
        assert!(allowed_as(&e, "alice@example", "exec", HOST_A, "root").await);
        // root is only granted on HOST_A, so root on HOST_B is denied.
        assert!(!allowed_as(&e, "alice@example", "exec", HOST_B, "root").await);
    }

    #[tokio::test]
    async fn an_empty_kind_is_denied_even_under_a_wildcard_verb() {
        // A `"*"` verb must not wave through a malformed empty kind (mirrors the
        // agent backstop, which refuses an empty kind outright).
        let e = engine(
            r#"
            [[binding]]
            subject = "alice@example"
            verbs = ["*"]
            selectors = ["*"]
            run_as = ["*"]
        "#,
        );
        assert!(!allowed(&e, "alice@example", "", HOST_A).await);
    }

    #[test]
    fn rejects_a_padded_run_as_entry() {
        // A padded run_as never matches a getpwnam'd user — refuse it at load so it
        // is not a silent dead grant (mirrors the subject padding check). `""` is
        // a valid entry (the default identity) and must still load.
        assert!(
            RbacPolicyEngine::from_toml(
                r#"
            [[binding]]
            subject = "alice@example"
            verbs = ["exec"]
            selectors = ["*"]
            run_as = [" deploy "]
        "#,
            )
            .is_err(),
            "a padded run_as entry must be refused"
        );
        assert!(
            RbacPolicyEngine::from_toml(
                r#"
            [[binding]]
            subject = "alice@example"
            verbs = ["exec"]
            selectors = ["*"]
            run_as = [""]
        "#,
            )
            .is_ok(),
            "the empty default-identity entry must still load"
        );
    }

    #[test]
    fn rejects_a_binding_with_no_run_as() {
        // run_as is a required, non-empty axis — a binding that omits it (or sets
        // it empty) is a hard config error, not a silent deny-all that looks like
        // a grant.
        assert!(
            RbacPolicyEngine::from_toml(
                r#"
            [[binding]]
            subject = "alice@example"
            verbs = ["exec"]
            selectors = ["*"]
        "#,
            )
            .is_err(),
            "a binding omitting run_as must be refused"
        );
        assert!(
            RbacPolicyEngine::from_toml(
                r#"
            [[binding]]
            subject = "alice@example"
            verbs = ["exec"]
            selectors = ["*"]
            run_as = []
        "#,
            )
            .is_err(),
            "a binding with an empty run_as list must be refused"
        );
    }

    #[test]
    fn rejects_a_bad_selector() {
        let err = RbacPolicyEngine::from_toml(
            r#"
            [[binding]]
            subject = "alice@example"
            verbs = ["exec"]
            selectors = ["not-a-uuid"]
            run_as = ["*"]
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
            run_as = ["*"]
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
            run_as = ["*"]
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
            run_as = ["*"]
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
            run_as = ["*"]
        "#,
        );
        assert!(err.is_err());
    }
}
