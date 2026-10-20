-- +goose Up

-- Verify TLS and SSH host keys by default. See the SQLite 00010 migration for
-- the full rationale. The column TYPES deliberately match SQLite rather than
-- being idiomatic Postgres: the insecure flags are INTEGER, not BOOLEAN, so one
-- set of statements and one scan path serves both backends.
ALTER TABLE proxmox_instances ADD COLUMN insecure_tls INTEGER NOT NULL DEFAULT 0;
ALTER TABLE proxmox_instances ADD COLUMN insecure_ssh INTEGER NOT NULL DEFAULT 0;
ALTER TABLE proxmox_instances ADD COLUMN ssh_fingerprint TEXT NOT NULL DEFAULT '';

-- +goose Down

ALTER TABLE proxmox_instances DROP COLUMN ssh_fingerprint;
ALTER TABLE proxmox_instances DROP COLUMN insecure_ssh;
ALTER TABLE proxmox_instances DROP COLUMN insecure_tls;
