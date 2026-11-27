-- Explicit endpoint and secret reference for outbound CoA/Disconnect.
-- The shared secret itself must live in an external secret manager or injected environment.
BEGIN;
ALTER TABLE nas_devices
    ADD COLUMN coa_port INTEGER NOT NULL DEFAULT 3799
        CHECK (coa_port BETWEEN 1 AND 65535),
    ADD COLUMN secret_ref VARCHAR(256);
COMMENT ON COLUMN nas_devices.secret_ref IS
    'External secret reference, never a plaintext RADIUS shared secret';
COMMIT;
