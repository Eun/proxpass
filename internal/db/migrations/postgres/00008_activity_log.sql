-- +goose Up

-- The activity log. See the SQLite migration of the same name for what each
-- column holds and why occurred_at is an epoch BIGINT rather than a TIMESTAMP;
-- that reasoning is identical and not repeated.
--
-- params is JSONB here (not TEXT as on SQLite): Postgres validates it as JSON,
-- stores it in the efficient binary form, and keeps it queryable with the JSON
-- operators should an operator ever want to index or filter on a param. The Go
-- scan path is unchanged -- pgx accepts a Go string on insert (cast to jsonb)
-- and returns JSONB back into a string on select -- so both backends still use
-- the single string <-> json.Marshal/Unmarshal round-trip in sql_repository.go.
CREATE TABLE IF NOT EXISTS activity_log (
    id          BIGSERIAL PRIMARY KEY,
    event_id    TEXT      NOT NULL,
    actor       TEXT      NOT NULL,
    occurred_at BIGINT    NOT NULL,
    params      JSONB     NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_activity_log_occurred_at
    ON activity_log (occurred_at);

-- +goose Down
DROP INDEX IF EXISTS idx_activity_log_occurred_at;
DROP TABLE IF EXISTS activity_log;
