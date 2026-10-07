-- +goose Up

-- Rename connection_type to console_transport and give every instance an SSH
-- host. See the SQLite migration of the same name for why; the reasoning is
-- identical and is not repeated here.
ALTER TABLE proxmox_instances RENAME COLUMN connection_type TO console_transport;

-- Derive an SSH host for the rows that never got one, from the hostname of
-- api_url. Postgres has regexp_replace, so this is one expression rather than
-- the nested substr/instr the SQLite version needs:
--   ^[a-z]+://   strip the scheme
--   [:/].*$      strip the port and the path
UPDATE proxmox_instances
SET ssh_host = regexp_replace(
        regexp_replace(api_url, '^[a-zA-Z][a-zA-Z0-9+.-]*://', ''),
        '[:/].*$', '')
WHERE ssh_host = '';

UPDATE proxmox_instances SET ssh_port = 22 WHERE ssh_port = 0;
UPDATE proxmox_instances SET ssh_user = 'root' WHERE ssh_user = '';

-- +goose Down

ALTER TABLE proxmox_instances RENAME COLUMN console_transport TO connection_type;

-- The derived ssh_host is NOT reverted; see the SQLite migration.
