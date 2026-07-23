-- +goose Up

-- Add username and password columns for termproxy session ticket auth.
-- These are optional: when set, a Proxmox user session ticket is obtained via
-- POST /access/ticket and used for termproxy/vncwebsocket authentication.
-- Required for older Proxmox versions whose termproxy binary verifies via
-- /access/ticket (not /access/vncticket). When empty, API token auth is used.
ALTER TABLE proxmox_instances ADD COLUMN username TEXT NOT NULL DEFAULT '';
ALTER TABLE proxmox_instances ADD COLUMN password TEXT NOT NULL DEFAULT '';

-- +goose Down
-- SQLite: recreate table without the new columns.
CREATE TABLE proxmox_instances_old2 (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    name             TEXT    NOT NULL UNIQUE,
    api_url          TEXT    NOT NULL UNIQUE,
    api_token_id     TEXT    NOT NULL,
    api_token_secret TEXT    NOT NULL,
    connection_type  TEXT    NOT NULL DEFAULT 'ssh',
    node             TEXT    NOT NULL DEFAULT '',
    ssh_host         TEXT    NOT NULL DEFAULT '',
    ssh_port         INTEGER NOT NULL DEFAULT 22,
    ssh_user         TEXT    NOT NULL DEFAULT '',
    ssh_key_path     TEXT    NOT NULL DEFAULT '',
    ssh_key          TEXT    NOT NULL DEFAULT ''
);
INSERT INTO proxmox_instances_old2
    SELECT id, name, api_url, api_token_id, api_token_secret,
           connection_type, node, ssh_host, ssh_port, ssh_user, ssh_key_path, ssh_key
    FROM proxmox_instances;
DROP TABLE proxmox_instances;
ALTER TABLE proxmox_instances_old2 RENAME TO proxmox_instances;
