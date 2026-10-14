-- +goose Up

-- Make name uniqueness case-insensitive. See the SQLite migration of the
-- same name for why, including the note that lower() is locale-dependent
-- here and ASCII-only there, so the two dialects disagree on non-ASCII
-- names in the safe direction.
CREATE UNIQUE INDEX IF NOT EXISTS idx_clients_name_lower
    ON clients (lower(name));
CREATE UNIQUE INDEX IF NOT EXISTS idx_groups_name_lower
    ON groups (lower(name));
CREATE UNIQUE INDEX IF NOT EXISTS idx_proxmox_instances_name_lower
    ON proxmox_instances (lower(name));

-- +goose Down

DROP INDEX IF EXISTS idx_clients_name_lower;
DROP INDEX IF EXISTS idx_groups_name_lower;
DROP INDEX IF EXISTS idx_proxmox_instances_name_lower;
