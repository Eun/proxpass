-- +goose Up

-- Opt-in node access for the default policy. When 1, a client (or group member)
-- the default policy authorises reaches EVERY Proxmox node, not just the guests
-- the policy covers. Off (0) by default, which keeps the historical behaviour:
-- a node is reachable only through an explicit `access grant --instance'. This
-- is the broadest grant proxpass can give -- a shell on every node -- so it is
-- never on unless an administrator deliberately turns it on (the UI warns first).
--
-- DEFAULT 0 backfills every existing row, so an upgrade changes nothing until
-- the flag is set.
ALTER TABLE default_policy ADD COLUMN node_access INTEGER NOT NULL DEFAULT 0;

-- +goose Down
ALTER TABLE default_policy DROP COLUMN node_access;
