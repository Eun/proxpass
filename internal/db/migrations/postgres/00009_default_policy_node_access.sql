-- +goose Up

-- See the SQLite migration of the same name. BOOLEAN here rather than INTEGER;
-- the Go scan path reads a bool either way.
ALTER TABLE default_policy ADD COLUMN node_access BOOLEAN NOT NULL DEFAULT FALSE;

-- +goose Down
ALTER TABLE default_policy DROP COLUMN node_access;
