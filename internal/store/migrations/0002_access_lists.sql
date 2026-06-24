-- Reusable access lists (basic-auth users + IP allow-list), attached to hosts.
CREATE TABLE IF NOT EXISTS access_lists (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    users       TEXT NOT NULL DEFAULT '[]',  -- JSON [{username,hash}]
    allow_ips   TEXT NOT NULL DEFAULT '[]',  -- JSON [cidr]
    satisfy_any INTEGER NOT NULL DEFAULT 0,
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL
);
