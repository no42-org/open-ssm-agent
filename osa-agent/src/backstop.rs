/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: MIT
 */

//! Loading the host-local allowlist (AD-20) from agent config.
//!
//! The decision logic is [`osa_core::allowlist::LocalAllowlist`]; this module
//! only turns a TOML document on disk into one. A missing config is **not** an
//! error — it yields a deny-all backstop, the safe default.

use std::path::Path;

use anyhow::Context;
use osa_core::allowlist::LocalAllowlist;
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AllowlistDoc {
    #[serde(default)]
    verbs: Vec<String>,
    #[serde(default)]
    run_as: Vec<String>,
}

/// Load the host allowlist from `path`. With no path, returns a deny-all
/// backstop and warns — an unconfigured host permits nothing.
pub fn load(path: Option<&Path>) -> anyhow::Result<LocalAllowlist> {
    let Some(path) = path else {
        tracing::warn!(
            "no --allowlist configured — the host backstop denies every action (deny-by-default, AD-20)"
        );
        return Ok(LocalAllowlist::deny_all());
    };
    let doc = std::fs::read_to_string(path)
        .with_context(|| format!("reading allowlist {}", path.display()))?;
    let parsed: AllowlistDoc = toml::from_str(&doc).context("allowlist is not valid TOML")?;
    let allowlist = LocalAllowlist::new(parsed.verbs, parsed.run_as);
    // A present-but-empty (or verb-less) file is deny-all; say so, so it is not
    // mistaken for an active policy.
    if allowlist.verbs().is_empty() {
        tracing::warn!(
            path = %path.display(),
            "allowlist permits no verbs — the host backstop denies every action"
        );
    }
    Ok(allowlist)
}

/// Log the active backstop policy at startup so the operator can see the floor.
pub fn log_active(allowlist: &LocalAllowlist) {
    tracing::info!(
        verbs = ?allowlist.verbs(),
        run_as = ?allowlist.run_as_users(),
        "host backstop active (AD-20) — dispatched actions are checked against this before any side effect"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use osa_proto::v1::ActionDescriptor;
    use std::io::Write;

    fn action(kind: &str, run_as: &str) -> ActionDescriptor {
        ActionDescriptor {
            kind: kind.into(),
            target: String::new(),
            run_as: run_as.into(),
            params_hash: Vec::new(),
        }
    }

    fn write_tmp(contents: &str) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(contents.as_bytes()).unwrap();
        f
    }

    #[test]
    fn no_path_is_deny_all() {
        let a = load(None).unwrap();
        assert!(a.permits(&action("exec", "")).is_err());
    }

    #[test]
    fn loads_and_enforces_a_toml_allowlist() {
        let f = write_tmp("verbs = [\"exec\"]\nrun_as = [\"deploy\"]\n");
        let a = load(Some(f.path())).unwrap();
        assert!(a.permits(&action("exec", "deploy")).is_ok());
        assert!(a.permits(&action("exec", "root")).is_err());
        assert!(a.permits(&action("shell", "")).is_err());
        // Default user (empty run_as) is not on the list → refused, not waved
        // through (AD-20).
        assert!(a.permits(&action("exec", "")).is_err());
    }

    #[test]
    fn a_present_but_empty_file_is_deny_all() {
        let f = write_tmp("");
        let a = load(Some(f.path())).unwrap();
        assert!(a.permits(&action("exec", "")).is_err());
    }

    #[test]
    fn rejects_an_unknown_field() {
        let f = write_tmp("verb = [\"exec\"]\n"); // misspelled key
        assert!(load(Some(f.path())).is_err());
    }

    #[test]
    fn a_missing_file_is_an_error_not_silent_deny() {
        let err = load(Some(Path::new("/no/such/allowlist.toml")));
        assert!(err.is_err());
    }
}
