-- Durable, tenant-scoped CoA/Disconnect command queue.
-- NAS shared secrets are deliberately not stored in this table.
BEGIN;

CREATE TABLE radius_command_outbox (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    nas_identifier VARCHAR(253) NOT NULL,
    session_id VARCHAR(256) NOT NULL,
    username VARCHAR(128) NOT NULL,
    command_type VARCHAR(32) NOT NULL
        CHECK (command_type IN ('disconnect', 'change_bandwidth')),
    attributes JSONB NOT NULL CHECK (jsonb_typeof(attributes) = 'object'),
    idempotency_key CHAR(64) NOT NULL
        CHECK (idempotency_key ~ '^[0-9a-f]{64}$'),
    status VARCHAR(16) NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'sent', 'acknowledged', 'failed')),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    dispatched_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    last_error_code VARCHAR(64),
    UNIQUE (tenant_id, idempotency_key)
);

CREATE INDEX radius_command_outbox_pending_idx
    ON radius_command_outbox (created_at, id)
    WHERE status = 'pending';
CREATE INDEX radius_command_outbox_session_idx
    ON radius_command_outbox (tenant_id, nas_identifier, session_id, created_at DESC);

COMMIT;
