-- +goose Up

-- Create all tables in their final state,
-- incorporating all previous in-line migrations:
--   1. Initial schema
--   2. Add ssh_key column to proxmox_instances
--   3. Add UNIQUE constraints on name and api_url;
--      normalise api_url (trim trailing slashes)

CREATE TABLE IF NOT EXISTS proxmox_instances (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    name             TEXT    NOT NULL UNIQUE,
    api_url          TEXT    NOT NULL UNIQUE,
    api_token_id     TEXT    NOT NULL,
    api_token_secret TEXT    NOT NULL,
    ssh_host         TEXT    NOT NULL,
    ssh_port         INTEGER NOT NULL,
    ssh_user         TEXT    NOT NULL,
    ssh_key_path     TEXT    NOT NULL,
    ssh_key          TEXT    NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS guests (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    type        TEXT    NOT NULL,
    name        TEXT    NOT NULL,
    status      TEXT    NOT NULL,
    proxmox_id  INTEGER NOT NULL,
    instance_id INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS clients (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL UNIQUE,
    public_keys TEXT    NOT NULL,
    group_ids   TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS groups (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT    NOT NULL UNIQUE,
    client_ids TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS access_rules (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    type       TEXT    NOT NULL,
    subject_id INTEGER NOT NULL,
    guest_id   INTEGER NOT NULL,
    UNIQUE(type, subject_id, guest_id)
);

CREATE TABLE IF NOT EXISTS default_policy (
    id                     INTEGER PRIMARY KEY CHECK (id = 1),
    authorized_client_ids  TEXT    NOT NULL,
    authorized_group_ids   TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS admin_keys (
    public_key TEXT PRIMARY KEY
);

-- +goose Down
DROP TABLE IF EXISTS admin_keys;
DROP TABLE IF EXISTS default_policy;
DROP TABLE IF EXISTS access_rules;
DROP TABLE IF EXISTS groups;
DROP TABLE IF EXISTS clients;
DROP TABLE IF EXISTS guests;
DROP TABLE IF EXISTS proxmox_instances;
