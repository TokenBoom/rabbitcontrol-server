-- Track client application version and CPU architecture per registered device.
ALTER TABLE devices
    ADD COLUMN IF NOT EXISTS app_version TEXT NOT NULL DEFAULT '';

ALTER TABLE devices
    ADD COLUMN IF NOT EXISTS arch TEXT NOT NULL DEFAULT '';
