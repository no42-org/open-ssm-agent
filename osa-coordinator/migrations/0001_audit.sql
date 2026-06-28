-- Append-only, hash-chained audit log (AD-21). One row per dispatch decision.
-- The chain (prev_hash -> hash) is sealed in osa-core::audit; appends are
-- serialized by a pg_advisory_xact_lock so concurrent replicas cannot fork it.
CREATE TABLE IF NOT EXISTS audit_log (
    seq       BIGINT PRIMARY KEY,
    ts_unix   BIGINT NOT NULL,
    subject   TEXT   NOT NULL,
    kind      TEXT   NOT NULL,
    target    TEXT   NOT NULL,
    run_as    TEXT   NOT NULL,
    decision  TEXT   NOT NULL,
    prev_hash BYTEA  NOT NULL,
    hash      BYTEA  NOT NULL
);
