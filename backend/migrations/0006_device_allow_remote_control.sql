-- Separate remote-control permission (gates all remote control including same-account owner)
-- from remote-assist permission (gates non-owner third-party assistance).
ALTER TABLE devices
    ADD COLUMN IF NOT EXISTS allow_remote_control BOOLEAN NOT NULL DEFAULT TRUE;

UPDATE devices
    SET allow_remote_control = FALSE
    WHERE LOWER(os) LIKE '%android%' OR LOWER(os) LIKE '%ios%';
