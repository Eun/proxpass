-- +goose Up

-- The credential a session holds for the rest of its life.
--
-- The token minted by `proxpass authorized-keys' (session_tokens) is
-- single use and lives in the session's environment, where any process of
-- the same uid can read it. That is survivable only because it is spent
-- within a second of being issued -- but it also means a session can make
-- exactly ONE authenticated call, and a session needs several.
--
-- So the environment token is exchanged, once, for a row here. This one is
-- never written to the environment or to disk by the session: it is held in
-- memory for the lifetime of the process and revoked when the session ends.
-- Reading it therefore requires reading another process's memory rather
-- than its /proc/<pid>/environ, which is a materially higher bar.
--
-- Unlike session_tokens, looking one of these up does NOT consume it: a
-- session asks repeatedly. The single-use property stays where the exposure
-- is -- on the environment token -- rather than being weakened here.
--
-- Same column types as session_tokens, and for the same reason: INTEGER
-- rather than BOOLEAN/TIMESTAMPTZ so that one scan path serves both
-- backends.
CREATE TABLE IF NOT EXISTS api_sessions (
    token_hash   TEXT    PRIMARY KEY,
    login_name   TEXT    NOT NULL,
    display_name TEXT    NOT NULL,
    is_admin     INTEGER NOT NULL,
    client_id    INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_api_sessions_expires_at
    ON api_sessions (expires_at);

-- +goose Down
DROP INDEX IF EXISTS idx_api_sessions_expires_at;
DROP TABLE IF EXISTS api_sessions;
