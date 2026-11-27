-- Explicit NAS RADIUS attribute profile used by authorization adapters.
BEGIN;

ALTER TABLE nas_devices
    ADD COLUMN radius_profile VARCHAR(32) NOT NULL DEFAULT 'generic_wispr'
    CHECK (radius_profile IN ('generic_wispr', 'mikrotik'));

COMMIT;
