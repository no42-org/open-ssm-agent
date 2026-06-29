-- Revoked host identities (AD-28), shared across replicas so a revoke on one
-- coordinator is seen by every other's renewal check.
CREATE TABLE IF NOT EXISTS revoked_identity (
    host_id         UUID   PRIMARY KEY,
    revoked_at_unix BIGINT NOT NULL
);
