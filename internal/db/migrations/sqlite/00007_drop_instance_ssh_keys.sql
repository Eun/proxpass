-- +goose Up

-- Drop the per-instance SSH key columns.
--
-- proxpass now owns ONE key for the whole deployment. The entrypoint
-- generates it on the volume and PROXPASS_SSH_KEY_FILE names it; nothing
-- reads a key from the database any more.
--
-- Dropping the columns rather than leaving them unread is the point. A
-- private key sitting in a table nothing consults is a credential nobody is
-- auditing: it still leaks if the file is read, it still appears in a backup,
-- and the next reader has no way to tell that it stopped mattering. The
-- schema should not remember a secret the code has stopped using.
--
-- THIS DISCARDS KEY MATERIAL. An instance added with --ssh-key or
-- --ssh-key-path on an earlier version loses the key it was configured with
-- and falls back to the deployment key, so that key's public half has to be
-- installed on the Proxmox host before the instance can connect again.
-- `instance inspect' reports exactly that, and `instance add' prints the key
-- to install.
--
-- SQLite has supported DROP COLUMN since 3.35, but the table is rebuilt here
-- instead: the migrations above already rebuild it twice for the same reason
-- (00002, 00003), so the pattern is established, and a rebuild states the
-- resulting schema outright rather than leaving a reader to apply a sequence
-- of drops in their head.
-- username and password are carried across UNUSED. 00003 added them, nothing
-- reads them, and the Postgres schema has them too -- so dropping them here
-- would silently put the two backends out of step, which TestSchemasAgree
-- exists to catch. Retiring them is a separate change that has to touch both.
CREATE TABLE proxmox_instances_new (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    name             TEXT    NOT NULL UNIQUE,
    api_url          TEXT    NOT NULL,
    api_token_id     TEXT    NOT NULL DEFAULT '',
    api_token_secret TEXT    NOT NULL DEFAULT '',
    connection_type  TEXT    NOT NULL DEFAULT 'termproxy',
    node             TEXT    NOT NULL DEFAULT '',
    ssh_host         TEXT    NOT NULL,
    ssh_port         INTEGER NOT NULL,
    ssh_user         TEXT    NOT NULL,
    username         TEXT    NOT NULL DEFAULT '',
    password         TEXT    NOT NULL DEFAULT ''
);

INSERT INTO proxmox_instances_new
    (id, name, api_url, api_token_id, api_token_secret,
     connection_type, node, ssh_host, ssh_port, ssh_user, username, password)
SELECT id, name, api_url, api_token_id, api_token_secret,
       connection_type, node, ssh_host, ssh_port, ssh_user, username, password
FROM proxmox_instances;

DROP TABLE proxmox_instances;
ALTER TABLE proxmox_instances_new RENAME TO proxmox_instances;

-- +goose Down

-- The keys cannot come back: this migration destroyed them. The columns are
-- restored empty so that a rollback produces a schema the older code can read
-- and write, and that code will report a missing key rather than misbehave.
CREATE TABLE proxmox_instances_old (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    name             TEXT    NOT NULL UNIQUE,
    api_url          TEXT    NOT NULL,
    api_token_id     TEXT    NOT NULL DEFAULT '',
    api_token_secret TEXT    NOT NULL DEFAULT '',
    connection_type  TEXT    NOT NULL DEFAULT 'termproxy',
    node             TEXT    NOT NULL DEFAULT '',
    ssh_host         TEXT    NOT NULL,
    ssh_port         INTEGER NOT NULL,
    ssh_user         TEXT    NOT NULL,
    username         TEXT    NOT NULL DEFAULT '',
    password         TEXT    NOT NULL DEFAULT '',
    ssh_key_path     TEXT    NOT NULL DEFAULT '',
    ssh_key          TEXT    NOT NULL DEFAULT ''
);

INSERT INTO proxmox_instances_old
    (id, name, api_url, api_token_id, api_token_secret,
     connection_type, node, ssh_host, ssh_port, ssh_user, username, password)
SELECT id, name, api_url, api_token_id, api_token_secret,
       connection_type, node, ssh_host, ssh_port, ssh_user, username, password
FROM proxmox_instances;

DROP TABLE proxmox_instances;
ALTER TABLE proxmox_instances_old RENAME TO proxmox_instances;
