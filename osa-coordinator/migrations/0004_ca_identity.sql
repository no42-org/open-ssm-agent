-- The shared embedded CA (AD-23/AD-24). Generated once under an advisory lock,
-- then read by every replica, so all replicas sign with one CA identity and an
-- agent that pinned the CA root trusts certs issued by any replica.
-- NOTE: key_pem is the CA private key, stored plaintext in v1 (trusted DB);
-- at-rest encryption / KMS is tracked in issue #35.
CREATE TABLE IF NOT EXISTS ca_identity (
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    cert_pem        TEXT   NOT NULL,
    key_pem         TEXT   NOT NULL,
    created_at_unix BIGINT NOT NULL
);
-- Defense-in-depth: enforce a single CA row at the database, so a second CA can
-- never be inserted even if the application-level advisory lock is bypassed.
CREATE UNIQUE INDEX IF NOT EXISTS ca_identity_singleton ON ca_identity ((true));
