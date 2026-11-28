-- MFA factor, challenge and recovery-code storage for human operators.
BEGIN;

CREATE TABLE operator_webauthn_credentials (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES operator_users(id) ON DELETE RESTRICT,
    credential_id BYTEA NOT NULL UNIQUE CHECK (octet_length(credential_id) BETWEEN 1 AND 1024),
    public_key BYTEA NOT NULL CHECK (octet_length(public_key) BETWEEN 1 AND 8192),
    sign_count BIGINT NOT NULL DEFAULT 0 CHECK (sign_count >= 0),
    transports TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    aaguid UUID,
    backup_eligible BOOLEAN NOT NULL DEFAULT FALSE,
    backup_state BOOLEAN NOT NULL DEFAULT FALSE,
    status VARCHAR(16) NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    CHECK (NOT backup_state OR backup_eligible),
    CHECK ((status = 'revoked') = (revoked_at IS NOT NULL))
);
CREATE INDEX operator_webauthn_user_active_idx
    ON operator_webauthn_credentials (user_id, created_at) WHERE status = 'active';

-- AES-GCM ciphertext only. Encryption keys remain in an external KMS.
CREATE TABLE operator_totp_factors (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES operator_users(id) ON DELETE RESTRICT,
    secret_ciphertext BYTEA NOT NULL CHECK (octet_length(secret_ciphertext) BETWEEN 16 AND 512),
    nonce BYTEA NOT NULL CHECK (octet_length(nonce) = 12),
    key_version VARCHAR(128) NOT NULL CHECK (length(key_version) BETWEEN 1 AND 128),
    status VARCHAR(16) NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'active', 'revoked')),
    pending_expires_at TIMESTAMPTZ,
    last_accepted_step BIGINT NOT NULL DEFAULT -1 CHECK (last_accepted_step >= -1),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    activated_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    CHECK (
        (status = 'pending' AND pending_expires_at IS NOT NULL
            AND activated_at IS NULL AND revoked_at IS NULL)
        OR
        (status = 'active' AND pending_expires_at IS NULL
            AND activated_at IS NOT NULL AND revoked_at IS NULL)
        OR
        (status = 'revoked' AND revoked_at IS NOT NULL)
    )
);
CREATE UNIQUE INDEX operator_totp_one_active_per_user_uidx
    ON operator_totp_factors (user_id) WHERE status = 'active';
CREATE INDEX operator_totp_pending_expiry_idx
    ON operator_totp_factors (pending_expires_at) WHERE status = 'pending';

CREATE TABLE operator_mfa_challenges (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES operator_users(id) ON DELETE RESTRICT,
    challenge_hash CHAR(64) NOT NULL UNIQUE CHECK (challenge_hash ~ '^[0-9a-f]{64}$'),
    method VARCHAR(16) NOT NULL CHECK (method IN ('webauthn', 'totp', 'recovery')),
    origin VARCHAR(512) NOT NULL CHECK (length(origin) BETWEEN 8 AND 512),
    rp_id VARCHAR(253) NOT NULL CHECK (length(rp_id) BETWEEN 1 AND 253),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    failed_attempts SMALLINT NOT NULL DEFAULT 0 CHECK (failed_attempts BETWEEN 0 AND 5),
    CHECK (expires_at > created_at),
    CHECK (expires_at <= created_at + interval '5 minutes'),
    CHECK (consumed_at IS NULL OR consumed_at >= created_at)
);
CREATE INDEX operator_mfa_challenges_user_expiry_idx
    ON operator_mfa_challenges (user_id, expires_at) WHERE consumed_at IS NULL;

CREATE TABLE operator_mfa_recovery_codes (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES operator_users(id) ON DELETE RESTRICT,
    batch_id UUID NOT NULL,
    code_hash CHAR(64) NOT NULL CHECK (code_hash ~ '^[0-9a-f]{64}$'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    consumed_at TIMESTAMPTZ,
    UNIQUE (user_id, code_hash),
    CHECK (consumed_at IS NULL OR consumed_at >= created_at)
);
CREATE INDEX operator_mfa_recovery_available_idx
    ON operator_mfa_recovery_codes (user_id, batch_id) WHERE consumed_at IS NULL;

COMMIT;
