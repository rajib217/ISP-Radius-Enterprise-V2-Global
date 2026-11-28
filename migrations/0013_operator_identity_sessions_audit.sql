-- Human operator identity, tenant memberships, opaque sessions and append-only audit.
BEGIN;

CREATE TABLE operator_users (
    id UUID PRIMARY KEY,
    email VARCHAR(254) NOT NULL,
    password_hash VARCHAR(255) NOT NULL
        CHECK (password_hash LIKE '$argon2id$%'),
    status VARCHAR(16) NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'disabled')),
    email_verified_at TIMESTAMPTZ,
    password_changed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (email = lower(email)),
    CHECK (length(email) BETWEEN 3 AND 254)
);
CREATE UNIQUE INDEX operator_users_email_lower_uidx
    ON operator_users (lower(email));

CREATE TABLE operator_tenant_memberships (
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    user_id UUID NOT NULL REFERENCES operator_users(id) ON DELETE RESTRICT,
    role VARCHAR(24) NOT NULL
        CHECK (role IN ('owner', 'admin', 'operations', 'billing', 'support', 'viewer')),
    status VARCHAR(16) NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'suspended')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, user_id)
);
CREATE INDEX operator_memberships_user_status_idx
    ON operator_tenant_memberships (user_id, status, tenant_id);

-- Store only SHA-256 digests of high-entropy opaque cookie and CSRF tokens.
-- The raw tokens are returned once to the browser and are never persisted.
CREATE TABLE operator_sessions (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL,
    user_id UUID NOT NULL,
    token_hash CHAR(64) NOT NULL UNIQUE
        CHECK (token_hash ~ '^[0-9a-f]{64}$'),
    csrf_token_hash CHAR(64) NOT NULL
        CHECK (csrf_token_hash ~ '^[0-9a-f]{64}$'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    remote_ip INET,
    user_agent VARCHAR(512),
    FOREIGN KEY (tenant_id, user_id)
        REFERENCES operator_tenant_memberships (tenant_id, user_id) ON DELETE RESTRICT,
    CHECK (expires_at > created_at),
    CHECK (revoked_at IS NULL OR revoked_at >= created_at)
);
CREATE INDEX operator_sessions_active_user_idx
    ON operator_sessions (tenant_id, user_id, expires_at)
    WHERE revoked_at IS NULL;
CREATE INDEX operator_sessions_expiry_idx
    ON operator_sessions (expires_at);

CREATE TABLE operator_audit_events (
    id UUID PRIMARY KEY,
    tenant_id UUID REFERENCES tenants(id) ON DELETE RESTRICT,
    actor_user_id UUID REFERENCES operator_users(id) ON DELETE RESTRICT,
    actor_kind VARCHAR(16) NOT NULL
        CHECK (actor_kind IN ('operator', 'system')),
    action VARCHAR(96) NOT NULL,
    target_type VARCHAR(64),
    target_id VARCHAR(128),
    correlation_id VARCHAR(128),
    remote_ip INET,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb
        CHECK (jsonb_typeof(metadata) = 'object'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (actor_kind <> 'operator' OR actor_user_id IS NOT NULL)
);
CREATE INDEX operator_audit_tenant_created_idx
    ON operator_audit_events (tenant_id, created_at DESC);
CREATE INDEX operator_audit_actor_created_idx
    ON operator_audit_events (actor_user_id, created_at DESC);

CREATE FUNCTION prevent_operator_audit_mutation() RETURNS TRIGGER
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'operator audit events are append-only';
END;
$$;
CREATE TRIGGER operator_audit_events_append_only
BEFORE UPDATE OR DELETE ON operator_audit_events
FOR EACH ROW EXECUTE FUNCTION prevent_operator_audit_mutation();

COMMIT;
