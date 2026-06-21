-- IP bans (fail2ban-style). expires_at = 0 means a permanent ban.
CREATE TABLE IF NOT EXISTS bans (
    ip         TEXT PRIMARY KEY,   -- IP or CIDR
    reason     TEXT NOT NULL DEFAULT '',
    manual     INTEGER NOT NULL DEFAULT 0,
    hits       INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_bans_expires ON bans(expires_at);
