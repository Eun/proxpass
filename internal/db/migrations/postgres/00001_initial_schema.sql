-- +goose Up

-- The Postgres schema, in its final state.
--
-- This is deliberately ONE migration rather than a transcription of the
-- SQLite history. Those four files exist because an installed database had to
-- be carried forward across releases; a Postgres database has no such history
-- to preserve, so replaying "add this column, then add that one" would be
-- re-enacting a past nobody lived through. The result must match what the
-- SQLite migrations add up to, which the schema-parity test asserts column by
-- column rather than leaving to inspection.
--
-- Differences from the SQLite files are only those the dialect forces:
--   INTEGER PRIMARY KEY AUTOINCREMENT -> BIGSERIAL PRIMARY KEY
--   INTEGER (64-bit ids)              -> BIGINT
--   TEXT                              -> TEXT (same)
-- The id columns are BIGINT because models.* use int64 throughout.

CREATE TABLE IF NOT EXISTS proxmox_instances (
    id               BIGSERIAL PRIMARY KEY,
    name             TEXT    NOT NULL UNIQUE,
    api_url          TEXT    NOT NULL UNIQUE,
    api_token_id     TEXT    NOT NULL,
    api_token_secret TEXT    NOT NULL,
    ssh_host         TEXT    NOT NULL,
    ssh_port         BIGINT  NOT NULL,
    ssh_user         TEXT    NOT NULL,
    ssh_key_path     TEXT    NOT NULL,
    ssh_key          TEXT    NOT NULL DEFAULT '',
    -- From 00002: how proxpass reaches the console.
    connection_type  TEXT    NOT NULL DEFAULT 'ssh',
    node             TEXT    NOT NULL DEFAULT '',
    -- From 00003: unused, kept so the two schemas agree.
    username         TEXT    NOT NULL DEFAULT '',
    password         TEXT    NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS guests (
    id          BIGSERIAL PRIMARY KEY,
    type        TEXT   NOT NULL,
    name        TEXT   NOT NULL,
    status      TEXT   NOT NULL,
    proxmox_id  BIGINT NOT NULL,
    instance_id BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS clients (
    id          BIGSERIAL PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    public_keys TEXT NOT NULL,
    group_ids   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS groups (
    id         BIGSERIAL PRIMARY KEY,
    name       TEXT NOT NULL UNIQUE,
    client_ids TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS access_rules (
    id         BIGSERIAL PRIMARY KEY,
    type       TEXT   NOT NULL,
    subject_id BIGINT NOT NULL,
    guest_id   BIGINT NOT NULL,
    UNIQUE (type, subject_id, guest_id)
);

CREATE TABLE IF NOT EXISTS default_policy (
    id                    BIGINT PRIMARY KEY CHECK (id = 1),
    authorized_client_ids TEXT NOT NULL,
    authorized_group_ids  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS admin_keys (
    public_key TEXT PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- +goose Down
DROP TABLE IF EXISTS settings;
DROP TABLE IF EXISTS admin_keys;
DROP TABLE IF EXISTS default_policy;
DROP TABLE IF EXISTS access_rules;
DROP TABLE IF EXISTS groups;
DROP TABLE IF EXISTS clients;
DROP TABLE IF EXISTS guests;
DROP TABLE IF EXISTS proxmox_instances;
