-- Idempotent, tenant-scoped usage deltas linked to immutable accounting events.
BEGIN;
ALTER TABLE accounting_events
    ADD CONSTRAINT accounting_events_tenant_id_id_key UNIQUE (tenant_id, id);
CREATE TABLE subscriber_usage_deltas (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    nas_identifier VARCHAR(253) NOT NULL,
    session_id VARCHAR(256) NOT NULL,
    username VARCHAR(128) NOT NULL,
    previous_event_id UUID NOT NULL,
    current_event_id UUID NOT NULL,
    period_start TIMESTAMPTZ NOT NULL,
    period_end TIMESTAMPTZ NOT NULL,
    input_bytes BIGINT CHECK (input_bytes IS NULL OR input_bytes >= 0),
    output_bytes BIGINT CHECK (output_bytes IS NULL OR output_bytes >= 0),
    session_seconds BIGINT CHECK (session_seconds IS NULL OR session_seconds >= 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT usage_delta_distinct_events CHECK (previous_event_id <> current_event_id),
    CONSTRAINT usage_delta_ordered_period CHECK (period_end > period_start),
    CONSTRAINT usage_delta_previous_event_fk FOREIGN KEY (tenant_id, previous_event_id)
        REFERENCES accounting_events (tenant_id, id) ON DELETE RESTRICT,
    CONSTRAINT usage_delta_current_event_fk FOREIGN KEY (tenant_id, current_event_id)
        REFERENCES accounting_events (tenant_id, id) ON DELETE RESTRICT,
    CONSTRAINT usage_delta_current_event_unique UNIQUE (tenant_id, current_event_id)
);
CREATE INDEX subscriber_usage_deltas_subscriber_period_idx
    ON subscriber_usage_deltas (tenant_id, username, period_end DESC);
CREATE INDEX subscriber_usage_deltas_session_period_idx
    ON subscriber_usage_deltas (tenant_id, nas_identifier, session_id, period_end DESC);
COMMIT;
