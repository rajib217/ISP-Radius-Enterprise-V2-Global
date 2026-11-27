-- Authentication lookup index for enabled NAS source addresses.
BEGIN;

CREATE INDEX nas_devices_enabled_address_idx
    ON nas_devices (address)
    WHERE enabled = TRUE;

COMMIT;
