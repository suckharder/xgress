-- xgress initial schema.
-- Written to be portable across SQLite and Postgres:
--   * primary keys are application-generated TEXT UUIDs (no AUTOINCREMENT/SERIAL),
--   * timestamps are INTEGER unix seconds,
--   * booleans are INTEGER 0/1,
--   * nested/flexible data is TEXT holding JSON.

CREATE TABLE IF NOT EXISTS users (
    id            TEXT PRIMARY KEY,
    email         TEXT NOT NULL UNIQUE,
    name          TEXT NOT NULL DEFAULT '',
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'admin',
    disabled      INTEGER NOT NULL DEFAULT 0,
    created_at    INTEGER NOT NULL,
    updated_at    INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    token      TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL,
    user_agent TEXT NOT NULL DEFAULT '',
    ip         TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);

CREATE TABLE IF NOT EXISTS hosts (
    id         TEXT PRIMARY KEY,
    kind       TEXT NOT NULL,
    enabled    INTEGER NOT NULL DEFAULT 1,
    domains    TEXT NOT NULL DEFAULT '[]',
    data       TEXT NOT NULL DEFAULT '{}', -- kind-specific fields as JSON
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_hosts_kind ON hosts(kind);

CREATE TABLE IF NOT EXISTS middlewares (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL UNIQUE,
    type       TEXT NOT NULL,
    params     TEXT NOT NULL DEFAULT '{}',
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS certificates (
    id              TEXT PRIMARY KEY,
    type            TEXT NOT NULL,
    domains         TEXT NOT NULL DEFAULT '[]',
    status          TEXT NOT NULL DEFAULT 'pending',
    challenge_type  TEXT NOT NULL DEFAULT '',
    dns_provider_id TEXT NOT NULL DEFAULT '',
    acme_account_id TEXT NOT NULL DEFAULT '',
    cert_pem        TEXT NOT NULL DEFAULT '',
    key_pem_enc     TEXT NOT NULL DEFAULT '',
    issued_at       INTEGER,
    expires_at      INTEGER,
    last_error      TEXT NOT NULL DEFAULT '',
    last_attempt_at INTEGER,
    auto_renew      INTEGER NOT NULL DEFAULT 1,
    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS acme_accounts (
    id              TEXT PRIMARY KEY,
    email           TEXT NOT NULL,
    ca_dir_url      TEXT NOT NULL,
    registration    TEXT NOT NULL DEFAULT '',
    private_key_enc TEXT NOT NULL DEFAULT '',
    created_at      INTEGER NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_acme_email_ca ON acme_accounts(email, ca_dir_url);

CREATE TABLE IF NOT EXISTS dns_providers (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    provider    TEXT NOT NULL,
    config_enc  TEXT NOT NULL DEFAULT '',
    config_keys TEXT NOT NULL DEFAULT '[]',
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS listeners (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL UNIQUE,
    proto      TEXT NOT NULL DEFAULT 'tcp',
    port       INTEGER NOT NULL,
    builtin    INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS settings (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL DEFAULT '',
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
    id         TEXT PRIMARY KEY,
    at         INTEGER NOT NULL,
    user_id    TEXT NOT NULL DEFAULT '',
    user_email TEXT NOT NULL DEFAULT '',
    action     TEXT NOT NULL,
    target     TEXT NOT NULL DEFAULT '',
    detail     TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_audit_at ON audit_log(at);

CREATE TABLE IF NOT EXISTS config_snapshots (
    version    INTEGER PRIMARY KEY,
    json       TEXT NOT NULL,
    hash       TEXT NOT NULL,
    valid      INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL
);
