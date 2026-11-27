BEGIN;

-- Retire the experimental duplicate queue. The application writes audited
-- operator requests to dynamic_authorization_requests.
DROP TABLE IF EXISTS radius_command_outbox;

-- Recover any legacy in-flight rows before adding fenced-lease invariants.
UPDATE dynamic_authorization_requests
   SET status = 'pending', claimed_at = NULL
 WHERE status = 'processing';

ALTER TABLE dynamic_authorization_requests
    ADD COLUMN lease_token UUID,
    ADD COLUMN lease_expires_at TIMESTAMPTZ,
    ADD COLUMN max_attempts INTEGER NOT NULL DEFAULT 8
        CHECK (max_attempts BETWEEN 1 AND 50);

ALTER TABLE dynamic_authorization_requests
    ADD CONSTRAINT dynamic_authorization_lease_consistency
    CHECK (
      (status = 'processing' AND lease_token IS NOT NULL AND lease_expires_at IS NOT NULL)
      OR (status <> 'processing' AND lease_token IS NULL AND lease_expires_at IS NULL)
    );

CREATE INDEX dynamic_authorization_dispatch_idx
    ON dynamic_authorization_requests (next_attempt_at, created_at, id)
    WHERE status = 'pending';

COMMIT;
