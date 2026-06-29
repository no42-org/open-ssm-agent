/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: MIT
 */

//! Single-use join-token registry (AD-25).
//!
//! A join token is a high-entropy secret minted by the coordinator and redeemed
//! exactly once during enrollment. Redemption is **atomic** so simultaneous
//! redemptions of the same token yield exactly one winner — the in-memory
//! adapter serializes via a mutex; the Postgres adapter via a conditional UPDATE
//! that is atomic across replicas (AD-24).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};

/// Mint a single-use token and redeem it exactly once. The two adapters
/// ([`JoinTokenRegistry`] in-memory, [`PgJoinTokens`] durable/cross-replica)
/// differ only in storage and the scope of the redemption atomicity.
#[async_trait]
pub trait JoinTokens: Send + Sync {
    /// Mint a token valid for `ttl` (clamped to the registry max). Returns the
    /// token and its absolute expiry (unix seconds).
    async fn mint(&self, ttl: Duration) -> Result<(String, i64), MintError>;
    /// Redeem a token exactly once.
    async fn redeem(&self, token: &str) -> Result<(), RedeemError>;
}

/// Why a redemption was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedeemError {
    /// No such token.
    Unknown,
    /// The token's TTL has elapsed.
    Expired,
    /// The token was already redeemed.
    AlreadyRedeemed,
    /// The storage backend failed (logged at the adapter before mapping here).
    Backend,
}

/// Why minting failed.
#[derive(Debug)]
pub enum MintError {
    /// The OS CSPRNG failed.
    Rng(getrandom::Error),
    /// Too many outstanding tokens — back-pressure on the mint surface.
    Full,
    /// The storage backend failed.
    Backend(String),
}

impl std::fmt::Display for MintError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MintError::Rng(e) => write!(f, "rng failure: {e}"),
            MintError::Full => write!(f, "too many outstanding join tokens"),
            MintError::Backend(e) => write!(f, "token store failure: {e}"),
        }
    }
}

/// SHA-256 of a token — what the Postgres adapter stores, so the secret itself
/// never lands in the database.
fn token_hash(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

fn now_unix() -> i64 {
    unix_seconds(SystemTime::now())
}

/// Default cap on outstanding (unredeemed, unexpired) tokens.
const DEFAULT_MAX_OUTSTANDING: usize = 10_000;

struct TokenState {
    expires_at: SystemTime,
    redeemed: bool,
}

/// Registry of outstanding join tokens.
pub struct JoinTokenRegistry {
    tokens: Mutex<HashMap<String, TokenState>>,
    max_ttl: Duration,
    cap: usize,
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn unix_seconds(t: SystemTime) -> i64 {
    t.duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

impl JoinTokenRegistry {
    /// Create an empty registry. Requested TTLs are clamped to `max_ttl`.
    pub fn new(max_ttl: Duration) -> Self {
        Self::with_cap(max_ttl, DEFAULT_MAX_OUTSTANDING)
    }

    /// Create a registry with an explicit outstanding-token cap (used in tests).
    pub(crate) fn with_cap(max_ttl: Duration, cap: usize) -> Self {
        Self {
            tokens: Mutex::new(HashMap::new()),
            max_ttl,
            cap,
        }
    }

    /// Mint a fresh single-use token valid for `ttl` (clamped to `max_ttl`).
    /// Returns the token and its absolute expiry (unix seconds).
    pub fn mint(&self, ttl: Duration) -> Result<(String, i64), MintError> {
        let ttl = ttl.min(self.max_ttl);
        let expires_at = SystemTime::now() + ttl;
        let mut map = self.tokens.lock().unwrap_or_else(|e| e.into_inner());
        // Lazy sweep: there is no background reaper, so drop redeemed/expired
        // tokens here to keep the map bounded.
        let now = SystemTime::now();
        map.retain(|_, s| !s.redeemed && now < s.expires_at);
        if map.len() >= self.cap {
            return Err(MintError::Full);
        }
        let mut raw = [0u8; 32];
        getrandom::fill(&mut raw).map_err(MintError::Rng)?;
        let token = hex(&raw);
        map.insert(
            token.clone(),
            TokenState {
                expires_at,
                redeemed: false,
            },
        );
        Ok((token, unix_seconds(expires_at)))
    }

    /// Atomically redeem a token exactly once. The mutex is held across the
    /// existence/expiry/redeemed check and the mark, so concurrent redemptions
    /// of the same token produce exactly one `Ok`.
    pub fn redeem(&self, token: &str) -> Result<(), RedeemError> {
        let mut map = self.tokens.lock().unwrap_or_else(|e| e.into_inner());
        let state = map.get_mut(token).ok_or(RedeemError::Unknown)?;
        if state.redeemed {
            return Err(RedeemError::AlreadyRedeemed);
        }
        if SystemTime::now() >= state.expires_at {
            return Err(RedeemError::Expired);
        }
        state.redeemed = true;
        Ok(())
    }
}

/// The in-memory registry as a [`JoinTokens`] adapter (no-DB / dev mode). The
/// inherent sync methods above carry the logic; these just expose it on the
/// async port.
#[async_trait]
impl JoinTokens for JoinTokenRegistry {
    async fn mint(&self, ttl: Duration) -> Result<(String, i64), MintError> {
        JoinTokenRegistry::mint(self, ttl)
    }
    async fn redeem(&self, token: &str) -> Result<(), RedeemError> {
        JoinTokenRegistry::redeem(self, token)
    }
}

/// Durable, cross-replica single-use join tokens in Postgres (AD-24, AD-25).
/// Stores only the token hash; redemption is atomic across replicas.
///
/// Expiry is evaluated against each replica's wall clock, so replicas should be
/// NTP-synced — TTLs are minutes and typical skew is seconds, so the practical
/// window is small, but it is a distributed-correctness assumption.
pub struct PgJoinTokens {
    pool: PgPool,
    max_ttl: Duration,
    cap: usize,
}

impl PgJoinTokens {
    pub fn new(pool: PgPool, max_ttl: Duration) -> Self {
        Self::with_cap(pool, max_ttl, DEFAULT_MAX_OUTSTANDING)
    }

    /// With an explicit outstanding-token cap (used in tests).
    pub(crate) fn with_cap(pool: PgPool, max_ttl: Duration, cap: usize) -> Self {
        Self { pool, max_ttl, cap }
    }
}

#[async_trait]
impl JoinTokens for PgJoinTokens {
    async fn mint(&self, ttl: Duration) -> Result<(String, i64), MintError> {
        let ttl = ttl.min(self.max_ttl);
        let now = now_unix();
        // Expiry is half-open: a token is valid for `[mint, expires_at)`, so a
        // ZERO ttl is dead on arrival (`expires_at == now`, and `> now` is false).
        let expires_at = now.saturating_add(ttl.as_secs() as i64);

        // Reclaim terminal rows so the table tracks only *outstanding* tokens
        // (mirrors the in-memory sweep; bounds growth). Deleting already-redeemed
        // or already-expired rows is idempotent and cross-replica safe — it can
        // never affect a live, unredeemed token.
        sqlx::query(
            "DELETE FROM join_token WHERE redeemed_at_unix IS NOT NULL OR expires_at_unix <= $1",
        )
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|e| MintError::Backend(e.to_string()))?;

        // Best-effort back-pressure: cap outstanding tokens. A small race past
        // the cap under concurrency is acceptable (the surface is operator-gated).
        let outstanding: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM join_token WHERE redeemed_at_unix IS NULL AND expires_at_unix > $1",
        )
        .bind(now)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| MintError::Backend(e.to_string()))?;
        if outstanding as usize >= self.cap {
            return Err(MintError::Full);
        }

        let mut raw = [0u8; 32];
        getrandom::fill(&mut raw).map_err(MintError::Rng)?;
        let token = hex(&raw);
        sqlx::query("INSERT INTO join_token (token_hash, expires_at_unix) VALUES ($1, $2)")
            .bind(&token_hash(&token)[..])
            .bind(expires_at)
            .execute(&self.pool)
            .await
            .map_err(|e| MintError::Backend(e.to_string()))?;
        Ok((token, expires_at))
    }

    async fn redeem(&self, token: &str) -> Result<(), RedeemError> {
        let hash = token_hash(token);
        let now = now_unix();
        // Atomic single-use across replicas: mark redeemed only if currently
        // unredeemed and unexpired. Exactly one concurrent UPDATE affects the row.
        let res = sqlx::query(
            "UPDATE join_token SET redeemed_at_unix = $2 \
             WHERE token_hash = $1 AND redeemed_at_unix IS NULL AND expires_at_unix > $2",
        )
        .bind(&hash[..])
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "join token redeem failed");
            RedeemError::Backend
        })?;
        // `token_hash` is the PRIMARY KEY, so the predicate matches at most one
        // row; Postgres serializes the concurrent writers (row lock + re-check),
        // so exactly one caller — across all replicas — sees `rows_affected == 1`.
        if res.rows_affected() == 1 {
            return Ok(());
        }

        // The update matched nothing — classify why (for logging only; the
        // service collapses all redemption failures to one opaque status).
        let row = sqlx::query("SELECT redeemed_at_unix FROM join_token WHERE token_hash = $1")
            .bind(&hash[..])
            .fetch_optional(&self.pool)
            .await
            .map_err(|_| RedeemError::Backend)?;
        match row {
            None => Err(RedeemError::Unknown),
            Some(row) => {
                let redeemed: Option<i64> = row
                    .try_get("redeemed_at_unix")
                    .map_err(|_| RedeemError::Backend)?;
                if redeemed.is_some() {
                    Err(RedeemError::AlreadyRedeemed)
                } else {
                    Err(RedeemError::Expired)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn registry() -> JoinTokenRegistry {
        JoinTokenRegistry::new(Duration::from_secs(3600))
    }

    #[test]
    fn mint_then_redeem_once() {
        let r = registry();
        let (token, exp) = r.mint(Duration::from_secs(600)).unwrap();
        assert_eq!(token.len(), 64); // 32 bytes hex
        assert!(exp > unix_seconds(SystemTime::now()));
        assert_eq!(r.redeem(&token), Ok(()));
    }

    #[test]
    fn double_redeem_denied() {
        let r = registry();
        let (token, _) = r.mint(Duration::from_secs(600)).unwrap();
        assert_eq!(r.redeem(&token), Ok(()));
        assert_eq!(r.redeem(&token), Err(RedeemError::AlreadyRedeemed));
    }

    #[test]
    fn unknown_token_denied() {
        let r = registry();
        assert_eq!(r.redeem("deadbeef"), Err(RedeemError::Unknown));
    }

    #[test]
    fn expired_token_denied() {
        let r = registry();
        // A zero TTL is expired the instant it is redeemed.
        let (token, _) = r.mint(Duration::ZERO).unwrap();
        assert_eq!(r.redeem(&token), Err(RedeemError::Expired));
    }

    #[test]
    fn ttl_clamped_to_max() {
        let r = JoinTokenRegistry::new(Duration::from_secs(60));
        let before = unix_seconds(SystemTime::now());
        let (_, exp) = r.mint(Duration::from_secs(86_400)).unwrap();
        assert!(exp <= before + 61, "ttl must be clamped to max_ttl");
    }

    #[test]
    fn concurrent_redemption_has_exactly_one_winner() {
        let r = Arc::new(registry());
        let (token, _) = r.mint(Duration::from_secs(600)).unwrap();
        let mut handles = Vec::new();
        for _ in 0..16 {
            let r = Arc::clone(&r);
            let token = token.clone();
            handles.push(std::thread::spawn(move || r.redeem(&token).is_ok()));
        }
        let winners = handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .filter(|&ok| ok)
            .count();
        assert_eq!(winners, 1, "exactly one redemption must succeed");
    }

    #[test]
    fn mint_rejects_when_at_capacity() {
        let r = JoinTokenRegistry::with_cap(Duration::from_secs(600), 2);
        r.mint(Duration::from_secs(600)).unwrap();
        r.mint(Duration::from_secs(600)).unwrap();
        assert!(matches!(
            r.mint(Duration::from_secs(600)),
            Err(MintError::Full)
        ));
    }

    #[test]
    fn mint_sweeps_reclaimable_tokens() {
        let r = JoinTokenRegistry::with_cap(Duration::from_secs(600), 1);
        let (a, _) = r.mint(Duration::from_secs(600)).unwrap();
        r.redeem(&a).unwrap();
        // At cap, but `a` is redeemed and reclaimable: the next mint sweeps it.
        let (c, _) = r
            .mint(Duration::from_secs(600))
            .expect("sweep should reclaim the redeemed token");
        assert_eq!(r.redeem(&a), Err(RedeemError::Unknown));
        assert_eq!(r.redeem(&c), Ok(()));
    }

    // --- Postgres adapter (testcontainers; needs Docker) ---

    use testcontainers_modules::postgres::Postgres;
    use testcontainers_modules::testcontainers::ImageExt;
    use testcontainers_modules::testcontainers::runners::AsyncRunner;

    /// An ephemeral migrated Postgres; returns the container (keep it alive) and
    /// the connection URL so a test can open *independent* pools per "replica".
    async fn pg_node_url() -> (
        testcontainers_modules::testcontainers::ContainerAsync<Postgres>,
        String,
    ) {
        let node = Postgres::default()
            .with_tag("17-alpine")
            .start()
            .await
            .unwrap();
        let port = node.get_host_port_ipv4(5432).await.unwrap();
        let url = format!("postgres://postgres:postgres@127.0.0.1:{port}/postgres");
        let pool = crate::db::connect(&url).await.unwrap();
        crate::db::migrate(&pool).await.unwrap();
        (node, url)
    }

    async fn pg_tokens() -> (
        testcontainers_modules::testcontainers::ContainerAsync<Postgres>,
        PgJoinTokens,
    ) {
        let (node, url) = pg_node_url().await;
        let pool = crate::db::connect(&url).await.unwrap();
        (node, PgJoinTokens::new(pool, Duration::from_secs(3600)))
    }

    #[tokio::test]
    async fn pg_mint_then_redeem_once_then_denied() {
        let (_node, r) = pg_tokens().await;
        let (token, _) = r.mint(Duration::from_secs(600)).await.unwrap();
        assert_eq!(r.redeem(&token).await, Ok(()));
        assert_eq!(r.redeem(&token).await, Err(RedeemError::AlreadyRedeemed));
        assert_eq!(r.redeem("deadbeef").await, Err(RedeemError::Unknown));
    }

    #[tokio::test]
    async fn pg_expired_token_denied() {
        let (_node, r) = pg_tokens().await;
        let (token, _) = r.mint(Duration::ZERO).await.unwrap();
        assert_eq!(r.redeem(&token).await, Err(RedeemError::Expired));
    }

    #[tokio::test]
    async fn pg_concurrent_redemption_has_exactly_one_winner_across_replicas() {
        // Two adapters over *independent pools* to the same database stand in for
        // two replicas. The atomic conditional UPDATE must still yield exactly
        // one winner when both replicas race to redeem the same token.
        let (_node, url) = pg_node_url().await;
        let a = Arc::new(PgJoinTokens::new(
            crate::db::connect(&url).await.unwrap(),
            Duration::from_secs(3600),
        ));
        let b = Arc::new(PgJoinTokens::new(
            crate::db::connect(&url).await.unwrap(),
            Duration::from_secs(3600),
        ));
        let (token, _) = a.mint(Duration::from_secs(600)).await.unwrap();

        let mut tasks = Vec::new();
        for i in 0..20 {
            let replica = if i % 2 == 0 { a.clone() } else { b.clone() };
            let token = token.clone();
            tasks.push(tokio::spawn(
                async move { replica.redeem(&token).await.is_ok() },
            ));
        }
        let winners = futures_count(tasks).await;
        assert_eq!(
            winners, 1,
            "exactly one redemption must win across replicas"
        );
    }

    #[tokio::test]
    async fn pg_mint_rejects_when_at_capacity() {
        let (_node, url) = pg_node_url().await;
        let r = PgJoinTokens::with_cap(
            crate::db::connect(&url).await.unwrap(),
            Duration::from_secs(600),
            2,
        );
        r.mint(Duration::from_secs(600)).await.unwrap();
        r.mint(Duration::from_secs(600)).await.unwrap();
        assert!(matches!(
            r.mint(Duration::from_secs(600)).await,
            Err(MintError::Full)
        ));
    }

    async fn futures_count(tasks: Vec<tokio::task::JoinHandle<bool>>) -> usize {
        let mut wins = 0;
        for t in tasks {
            if t.await.unwrap() {
                wins += 1;
            }
        }
        wins
    }
}
