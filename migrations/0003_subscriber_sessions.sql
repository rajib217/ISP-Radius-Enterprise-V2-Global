-- Current subscriber session projection, updated atomically with accounting events.
BEGIN;

CREATE TABLE subscriber_sessions (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    nas_identifier VARCHAR(253) NOT NULL,
    session_id VARCHAR(256) NOT NULL,
    username VARCHAR(128) NOT NULL,
    status VARCHAR(16) NOT NULL CHECK (status IN ('active','stopped')),
    started_at TIMESTAMPTZ,
    last_event_at TIMESTAMPTZ NOT NULL,
    stopped_at TIMESTAMPTZ,
    input_octets BIGINT CHECK (input_octets IS NULL OR input_octets >= 0),
    output_octets BIGINT CHECK (output_octets IS NULL OR output_octets >= 0),
    session_seconds BIGINT CHECK (session_seconds IS NULL OR session_seconds >= 0),
    terminate_cause VARCHAR(64),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, nas_identifier, session_id),
    CHECK (
        (status = 'active' AND stopped_at IS NULL)
        OR (status = 'stopped' AND stopped_at IS NOT NULL)
    )
);

CREATE INDEX subscriber_sessions_active_idx
    ON subscriber_sessions (tenant_id, username, last_event_at DESC)
    WHERE status = 'active';
CREATE INDEX subscriber_sessions_nas_active_idx
    ON subscriber_sessions (tenant_id, nas_identifier, last_event_at DESC)
    WHERE status = 'active';

COMMIT;
