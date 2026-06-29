-- Single-use join-token registry (AD-25), shared across replicas. We store only
-- the SHA-256 *hash* of the token, never the secret. Redemption is atomic
-- cross-replica via a conditional UPDATE (see PgJoinTokens::redeem).
CREATE TABLE IF NOT EXISTS join_token (
    token_hash       BYTEA  PRIMARY KEY,
    expires_at_unix  BIGINT NOT NULL,
    redeemed_at_unix BIGINT          -- NULL until redeemed
);
