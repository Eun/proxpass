-- +goose Up

-- The credential a session holds for the rest of its life. See the SQLite
-- copy of this migration (migrations/sqlite/00006_api_sessions.sql) for why
-- the environment token is exchanged for one of these, and why looking one
-- up does not consume it.
--
-- The column types match SQLite rather than being idiomatic Postgres, for
-- the reason given in 00002_session_tokens.sql: one scan path for both
-- drivers. TestSchemasAgree compares column names only and would not catch
-- a type mismatch here.
CREATE TABLE IF NOT EXISTS api_sessions (
    token_hash   TEXT    PRIMARY KEY,
    login_name   TEXT    NOT NULL,
    identity_name TEXT   NOT NULL,
    is_admin     INTEGER NOT NULL,
    client_id    BIGINT  NOT NULL,
    expires_at   BIGINT  NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_api_sessions_expires_at
    ON api_sessions (expires_at);

-- +goose Down
DROP INDEX IF EXISTS idx_api_sessions_expires_at;
DROP TABLE IF EXISTS api_sessions;
