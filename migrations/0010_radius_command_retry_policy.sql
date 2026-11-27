BEGIN;
ALTER TABLE radius_command_outbox
    ADD COLUMN max_attempts INTEGER NOT NULL DEFAULT 8
        CHECK (max_attempts BETWEEN 1 AND 50);
COMMIT;
