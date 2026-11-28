-- Bound failed verification attempts during TOTP enrollment.
BEGIN;
ALTER TABLE operator_totp_factors
    ADD COLUMN enrollment_failed_attempts SMALLINT NOT NULL DEFAULT 0
    CHECK (enrollment_failed_attempts BETWEEN 0 AND 5);
COMMIT;
