-- +goose Up

-- Bearer tokens handed to a session so it can call the API instead of
-- opening this database itself. See the SQLite copy of this migration
-- (migrations/sqlite/00005_session_tokens.sql) for why only hashes are
-- stored and how the tokens reach a session.
--
-- The column TYPES deliberately match SQLite rather than being idiomatic
-- Postgres. is_admin is INTEGER, not BOOLEAN, and expires_at is INTEGER unix
-- seconds, not TIMESTAMPTZ, so that one set of statements and one scan path
-- serves both backends: pgx hands a BOOLEAN back as a Go bool while SQLite
-- yields an int64, and that difference would have to be absorbed somewhere.
-- TestSchemasAgree compares column names only, so it would not have caught
-- the mismatch.
--
-- "login_name", not "user": user is a reserved word in Postgres and an
-- unquoted column of that name is a syntax error.
CREATE TABLE IF NOT EXISTS session_tokens (
    token_hash   TEXT    PRIMARY KEY,
    login_name   TEXT    NOT NULL,
    identity_name TEXT   NOT NULL,
    is_admin     INTEGER NOT NULL,
    client_id    BIGINT  NOT NULL,
    expires_at   BIGINT  NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_session_tokens_expires_at
    ON session_tokens (expires_at);

-- +goose Down
DROP INDEX IF EXISTS idx_session_tokens_expires_at;
DROP TABLE IF EXISTS session_tokens;
