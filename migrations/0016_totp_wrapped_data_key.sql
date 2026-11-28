-- Store the KMS-wrapped AES data key required for envelope-encrypted TOTP secrets.
BEGIN;

ALTER TABLE operator_totp_factors
    ADD COLUMN wrapped_data_key BYTEA;

-- NOT VALID permits any legacy rows to be reviewed and re-encrypted separately,
-- while enforcing the wrapped-key requirement for all new/updated records.
ALTER TABLE operator_totp_factors
    ADD CONSTRAINT operator_totp_wrapped_data_key_required
    CHECK (
        wrapped_data_key IS NOT NULL
        AND octet_length(wrapped_data_key) BETWEEN 1 AND 4096
    ) NOT VALID;

COMMIT;
