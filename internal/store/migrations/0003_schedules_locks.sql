-- Host enable/disable schedules (Round 4a).
CREATE TABLE IF NOT EXISTS schedules (
    id         TEXT PRIMARY KEY,
    host_id    TEXT NOT NULL,
    action     TEXT NOT NULL,            -- enable | disable
    cron       TEXT NOT NULL,            -- 5-field cron
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_schedules_host ON schedules(host_id);

-- Leader-election leases (Round 4c): coordinate ACME renewal across instances
-- sharing one database so only the lease holder renews.
CREATE TABLE IF NOT EXISTS leases (
    name       TEXT PRIMARY KEY,
    holder     TEXT NOT NULL,
    expires_at INTEGER NOT NULL
);
