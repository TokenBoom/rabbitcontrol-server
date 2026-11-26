-- Wake-on-LAN metadata and last observed network topology for offline wake routing.
ALTER TABLE devices
    ADD COLUMN IF NOT EXISTS mac_addr VARCHAR(17),
    ADD COLUMN IF NOT EXISTS wol_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS last_lan_addrs TEXT NOT NULL DEFAULT '[]',
    ADD COLUMN IF NOT EXISTS last_public_ip TEXT NOT NULL DEFAULT '';
