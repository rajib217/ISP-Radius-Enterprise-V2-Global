-- Auditable outbox for RFC 5176 CoA and Disconnect operations.
-- Network transmission is deliberately performed by a separate worker.
BEGIN;

CREATE TABLE dynamic_authorization_requests (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL,
    nas_identifier VARCHAR(253) NOT NULL,
    session_id VARCHAR(256) NOT NULL,
    username VARCHAR(128) NOT NULL,
    request_type VARCHAR(16) NOT NULL CHECK (request_type IN ('coa','disconnect')),
    attributes JSONB NOT NULL DEFAULT '{}'::jsonb
        CHECK (jsonb_typeof(attributes) = 'object'),
    idempotency_key VARCHAR(128) NOT NULL,
    requested_by VARCHAR(128) NOT NULL,
    status VARCHAR(16) NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending','processing','acknowledged','rejected','failed')),
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    claimed_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    last_error_code VARCHAR(64),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (id),
    UNIQUE (tenant_id, idempotency_key),
    FOREIGN KEY (tenant_id, nas_identifier)
        REFERENCES nas_devices(tenant_id, name) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, nas_identifier, session_id)
        REFERENCES subscriber_sessions(tenant_id, nas_identifier, session_id)
        ON DELETE RESTRICT,
    CHECK (
        (request_type = 'disconnect' AND attributes = '{}'::jsonb)
        OR (request_type = 'coa' AND attributes <> '{}'::jsonb)
    ),
    CHECK (
        (status IN ('acknowledged','rejected','failed') AND completed_at IS NOT NULL)
        OR (status IN ('pending','processing') AND completed_at IS NULL)
    )
);

CREATE INDEX dynamic_authorization_pending_idx
    ON dynamic_authorization_requests (next_attempt_at, created_at)
    WHERE status IN ('pending','processing');
CREATE INDEX dynamic_authorization_session_idx
    ON dynamic_authorization_requests (tenant_id, nas_identifier, session_id, created_at DESC);

CREATE FUNCTION protect_dynamic_authorization_audit() RETURNS TRIGGER
LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.status IN ('acknowledged','rejected','failed') THEN
        RAISE EXCEPTION 'Completed dynamic authorization requests are immutable';
    END IF;
    IF NEW.id <> OLD.id
       OR NEW.tenant_id <> OLD.tenant_id
       OR NEW.nas_identifier <> OLD.nas_identifier
       OR NEW.session_id <> OLD.session_id
       OR NEW.username <> OLD.username
       OR NEW.request_type <> OLD.request_type
       OR NEW.attributes <> OLD.attributes
       OR NEW.idempotency_key <> OLD.idempotency_key
       OR NEW.requested_by <> OLD.requested_by
       OR NEW.created_at <> OLD.created_at THEN
        RAISE EXCEPTION 'Dynamic authorization request intent is immutable';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER dynamic_authorization_audit_immutable
BEFORE UPDATE ON dynamic_authorization_requests
FOR EACH ROW EXECUTE FUNCTION protect_dynamic_authorization_audit();

COMMIT;
