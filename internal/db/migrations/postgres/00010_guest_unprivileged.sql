-- +goose Up

-- Record whether a container runs unprivileged. See the SQLite migration of
-- the same name for why; the reasoning is identical and is not repeated here.
ALTER TABLE guests ADD COLUMN unprivileged BOOLEAN NOT NULL DEFAULT FALSE;

-- +goose Down

ALTER TABLE guests DROP COLUMN unprivileged;
