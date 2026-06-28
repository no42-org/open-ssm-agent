/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: MIT
 */

//! Postgres connection + migrations (AD-24).
//!
//! When `--database-url` is set the coordinator keeps its mutable state in
//! Postgres so N replicas are stateless and durable. The pool is shared by the
//! Postgres-backed adapters (audit now; tokens/revocation/CA with story 2.5).
//! Migrations are **per-feature** files under `migrations/`, embedded at build
//! time and run on boot — no upfront mega-migration.

use std::time::Duration;

use anyhow::Context;
use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, migrate::Migrator};

/// All per-feature migrations, embedded from `migrations/` at build time.
static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

/// Connect to Postgres with a bounded pool and a connect timeout.
pub async fn connect(url: &str) -> anyhow::Result<PgPool> {
    PgPoolOptions::new()
        .max_connections(16)
        .acquire_timeout(Duration::from_secs(10))
        .connect(url)
        .await
        .context("connecting to Postgres")
}

/// Apply any pending migrations. Idempotent and safe to run on every replica's
/// boot (sqlx serializes via its own migration lock).
pub async fn migrate(pool: &PgPool) -> anyhow::Result<()> {
    MIGRATOR
        .run(pool)
        .await
        .context("running database migrations")
}
