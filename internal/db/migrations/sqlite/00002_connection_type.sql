-- +goose Up

-- Add connection_type and node columns to proxmox_instances.
-- Existing rows default to "ssh" so that instances created before
-- this migration continue working with the SSH proxy path.
ALTER TABLE proxmox_instances ADD COLUMN connection_type TEXT NOT NULL DEFAULT 'ssh';
ALTER TABLE proxmox_instances ADD COLUMN node            TEXT NOT NULL DEFAULT '';

-- +goose Down

-- SQLite does not support DROP COLUMN before 3.35 and modernc.org/sqlite
-- bundles an older version of the SQLite amalgamation. Re-create the table
-- without the new columns instead.
CREATE TABLE proxmox_instances_old (
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
INSERT INTO proxmox_instances_old
    SELECT id, name, api_url, api_token_id, api_token_secret,
           ssh_host, ssh_port, ssh_user, ssh_key_path, ssh_key
    FROM proxmox_instances;
DROP TABLE proxmox_instances;
ALTER TABLE proxmox_instances_old RENAME TO proxmox_instances;
