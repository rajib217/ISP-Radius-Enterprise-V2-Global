-- Subscriber authentication credentials: only Argon2id hashes are stored.
BEGIN;

CREATE TABLE subscriber_credentials (
    tenant_id UUID NOT NULL,
    subscriber_id UUID NOT NULL,
    password_hash VARCHAR(255) NOT NULL
        CHECK (password_hash LIKE '$argon2id$%'),
    password_changed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, subscriber_id),
    FOREIGN KEY (tenant_id, subscriber_id)
        REFERENCES subscribers(tenant_id, id) ON DELETE RESTRICT
);

COMMIT;
