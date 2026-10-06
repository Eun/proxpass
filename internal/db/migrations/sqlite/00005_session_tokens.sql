-- +goose Up

-- Bearer tokens handed to a session so it can call the API instead of
-- opening this database itself.
--
-- `proxpass authorized-keys' runs as root during authentication, before the
-- session exists, and is the only part of proxpass that learns which key
-- sshd accepted. It mints a token per offered key and attaches it to that
-- key's authorized_keys line; sshd applies the options of the matching key
-- only, so the session receives exactly the token for the identity that
-- authenticated. See internal/session/authorizedkeys.go.
--
-- Only the SHA-256 of each token is stored, never the token itself. The
-- database file is world-readable in the shipped image (0664 root:proxpass-
-- admin, so that an unprivileged session can still read it), which means a
-- client can read this table. Hashes make that harmless: the preimage is
-- what authenticates, and it never touches disk.
--
-- client_id is 0 for the administrator, matching session.Identity, rather
-- than NULL: there is no third state and a nullable column would only add
-- scanning ceremony.
CREATE TABLE IF NOT EXISTS session_tokens (
    token_hash   TEXT    PRIMARY KEY,
    login_name   TEXT    NOT NULL,
    display_name TEXT    NOT NULL,
    is_admin     INTEGER NOT NULL,
    client_id    INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL
);

-- Expired rows are swept on every mint, which is a range scan over this.
CREATE INDEX IF NOT EXISTS idx_session_tokens_expires_at
    ON session_tokens (expires_at);

-- +goose Down
DROP INDEX IF EXISTS idx_session_tokens_expires_at;
DROP TABLE IF EXISTS session_tokens;
