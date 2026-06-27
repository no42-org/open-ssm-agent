/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: MIT
 */

//! In-memory single-use join-token registry (AD-25).
//!
//! A join token is a high-entropy secret minted by the coordinator and redeemed
//! exactly once during enrollment. Redemption is **atomic** under concurrency —
//! the registry mutex serializes the check-and-mark so simultaneous redemptions
//! of the same token yield exactly one winner.
//!
//! Storage is in-memory for v1 (tens of hosts). Persistence across replicas
//! lands with the Postgres registry (Epic 2 / AD-24); expired-token pruning is a
//! follow-up.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Why a redemption was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedeemError {
    /// No such token.
    Unknown,
    /// The token's TTL has elapsed.
    Expired,
    /// The token was already redeemed.
    AlreadyRedeemed,
}

/// Why minting failed.
#[derive(Debug)]
pub enum MintError {
    /// The OS CSPRNG failed.
    Rng(getrandom::Error),
    /// Too many outstanding tokens — back-pressure against an unauthenticated
    /// mint surface (operator auth lands in Epic 2).
    Full,
}

impl std::fmt::Display for MintError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MintError::Rng(e) => write!(f, "rng failure: {e}"),
            MintError::Full => write!(f, "too many outstanding join tokens"),
        }
    }
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
}
