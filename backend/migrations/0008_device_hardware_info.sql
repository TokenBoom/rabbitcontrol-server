-- Persist device hardware metadata for the "All Devices" inventory view.
ALTER TABLE devices
    ADD COLUMN IF NOT EXISTS cpu_model TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS mac_address TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS total_memory_mb BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS os_version TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS gpu_model TEXT NOT NULL DEFAULT '';
