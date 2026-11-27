-- Normalized RADIUS accounting event journal. No subscriber passwords are stored.
BEGIN;

CREATE TABLE accounting_events (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    idempotency_key CHAR(64) NOT NULL CHECK (idempotency_key ~ '^[0-9a-f]{64}$'),
    nas_identifier VARCHAR(253) NOT NULL,
    session_id VARCHAR(256) NOT NULL,
    username VARCHAR(128) NOT NULL,
    status VARCHAR(16) NOT NULL CHECK (status IN ('Start','Interim-Update','Stop')),
    event_time TIMESTAMPTZ NOT NULL,
    input_octets BIGINT CHECK (input_octets IS NULL OR input_octets >= 0),
    output_octets BIGINT CHECK (output_octets IS NULL OR output_octets >= 0),
    session_seconds BIGINT CHECK (session_seconds IS NULL OR session_seconds >= 0),
    terminate_cause VARCHAR(64),
    received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, idempotency_key)
);

CREATE INDEX accounting_events_session_idx
    ON accounting_events (tenant_id, nas_identifier, session_id, event_time DESC);
CREATE INDEX accounting_events_subscriber_idx
    ON accounting_events (tenant_id, username, event_time DESC);

COMMIT;
