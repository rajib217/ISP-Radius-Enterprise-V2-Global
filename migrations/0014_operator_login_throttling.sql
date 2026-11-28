-- Persistent, privacy-preserving operator login throttling.
BEGIN;

CREATE TABLE operator_login_attempts (
    scope VARCHAR(8) NOT NULL CHECK (scope IN ('email', 'ip')),
    identifier_hash CHAR(64) NOT NULL CHECK (identifier_hash ~ '^[0-9a-f]{64}$'),
    failed_attempts INTEGER NOT NULL DEFAULT 0 CHECK (failed_attempts >= 0),
    window_started_at TIMESTAMPTZ NOT NULL,
    locked_until TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (scope, identifier_hash)
);
CREATE INDEX operator_login_attempts_lock_idx
    ON operator_login_attempts (locked_until)
    WHERE locked_until IS NOT NULL;

COMMIT;
