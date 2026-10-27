-- +goose Up

-- The activity log: one row per audited action (admin mutations and session
-- logins/console/sftp/commands). What is recorded is the event KIND (event_id,
-- an EventID enum value), WHO did it (actor = the resolved identity name, never
-- anything the request carried), WHEN, and the structured params needed to
-- render the line later -- the UI formats the human-readable text from the
-- event_id + params, so the log stores data, not prose.
--
-- params is a JSON object stored as TEXT, the same convention clients use for
-- public_keys/group_ids: one column type that scans identically on both
-- backends. occurred_at is a Unix epoch INTEGER rather than a TIMESTAMP, for
-- the same reason api_sessions uses INTEGER -- one scan path serves SQLite and
-- Postgres alike. The index on occurred_at backs the newest-first list and the
-- retention delete (DeleteActivityOlderThan).
CREATE TABLE IF NOT EXISTS activity_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id    TEXT    NOT NULL,
    actor       TEXT    NOT NULL,
    occurred_at INTEGER NOT NULL,
    params      TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_activity_log_occurred_at
    ON activity_log (occurred_at);

-- +goose Down
DROP INDEX IF EXISTS idx_activity_log_occurred_at;
DROP TABLE IF EXISTS activity_log;
