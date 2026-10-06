-- +goose Up

-- Configuration that the session process cannot read from its environment.
--
-- sshd builds a fresh environment for every session and does not inherit the
-- container's, so a value supplied as PROXPASS_* reaches `proxpass serve' and
-- nothing else. Anything a session needs therefore has to be written down
-- somewhere both processes can see, which is this table. The admin key solves
-- the same problem with its own table; this one is generic so the next such
-- value does not need a migration.
CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- +goose Down
DROP TABLE IF EXISTS settings;
