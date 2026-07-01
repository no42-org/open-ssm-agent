-- Per-host session-epoch high-water mark (AD-27, story 4.3b), shared across
-- replicas so the anti-resurrection guard survives a coordinator restart or
-- failover: the epoch a host reaches on one coordinator is honored by every
-- other's ClientHello admission check.
CREATE TABLE IF NOT EXISTS session_epoch (
    host_id UUID   PRIMARY KEY,
    epoch   BIGINT NOT NULL
);
