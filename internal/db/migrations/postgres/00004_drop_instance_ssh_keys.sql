-- +goose Up

-- Drop the per-instance SSH key columns. See the SQLite migration of the same
-- name for why; the reasoning is identical and is not repeated here.
--
-- THIS DISCARDS KEY MATERIAL: an instance configured with its own key falls
-- back to the deployment key, whose public half must be installed on the
-- Proxmox host before that instance can connect again.
--
-- Postgres can drop columns in place, so there is no table rebuild. IF EXISTS
-- keeps the migration idempotent against a database whose columns were
-- already removed by hand.
ALTER TABLE proxmox_instances DROP COLUMN IF EXISTS ssh_key;
ALTER TABLE proxmox_instances DROP COLUMN IF EXISTS ssh_key_path;

-- +goose Down

-- The keys cannot come back: this migration destroyed them. The columns are
-- restored empty so a rollback yields a schema the older code can read and
-- write; it will report a missing key rather than misbehave.
--
-- NOT NULL DEFAULT '' matches the Up schema these columns had, so the column
-- ORDER is the only difference from a database that never ran this migration.
-- TestSchemasAgree compares names, not order.
ALTER TABLE proxmox_instances ADD COLUMN IF NOT EXISTS ssh_key_path TEXT NOT NULL DEFAULT '';
ALTER TABLE proxmox_instances ADD COLUMN IF NOT EXISTS ssh_key TEXT NOT NULL DEFAULT '';
