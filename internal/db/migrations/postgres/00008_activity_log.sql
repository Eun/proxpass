-- +goose Up

-- The activity log. See the SQLite migration of the same name for what each
-- column holds and why occurred_at is an epoch BIGINT and params is JSON TEXT
-- rather than TIMESTAMP/JSONB; the reasoning is identical and not repeated.
CREATE TABLE IF NOT EXISTS activity_log (
    id          BIGSERIAL PRIMARY KEY,
    event_id    TEXT      NOT NULL,
    actor       TEXT      NOT NULL,
    occurred_at BIGINT    NOT NULL,
    params      TEXT      NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_activity_log_occurred_at
    ON activity_log (occurred_at);

-- +goose Down
DROP INDEX IF EXISTS idx_activity_log_occurred_at;
DROP TABLE IF EXISTS activity_log;
