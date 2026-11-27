BEGIN;
ALTER TABLE radius_command_outbox DROP CONSTRAINT radius_command_outbox_status_check;
ALTER TABLE radius_command_outbox ADD CONSTRAINT radius_command_outbox_status_check
    CHECK (status IN ('pending', 'processing', 'sent', 'acknowledged', 'failed'));
ALTER TABLE radius_command_outbox
    ADD COLUMN lease_token UUID,
    ADD COLUMN lease_expires_at TIMESTAMPTZ,
    ADD COLUMN next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now();
ALTER TABLE radius_command_outbox ADD CONSTRAINT radius_command_outbox_lease_consistency
    CHECK (
      (status = 'processing' AND lease_token IS NOT NULL AND lease_expires_at IS NOT NULL)
      OR (status <> 'processing' AND lease_token IS NULL AND lease_expires_at IS NULL)
    );
CREATE INDEX radius_command_outbox_dispatch_idx
    ON radius_command_outbox (next_attempt_at, created_at, id)
    WHERE status = 'pending';
COMMIT;
