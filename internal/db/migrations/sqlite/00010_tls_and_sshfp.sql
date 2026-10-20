-- +goose Up

-- Verify TLS and SSH host keys by default.
--
-- proxpass used to skip TLS certificate verification for every Proxmox API
-- connection and ignore every SSH host key, because Proxmox ships a
-- self-signed certificate and publishes no SSH host key to check against. That
-- made a man-in-the-middle between proxpass and a node undetectable.
--
-- Three columns move the decision into the row:
--
--   insecure_tls    when 1, TLS verification is skipped for this instance's
--                   REST API and termproxy WebSocket.
--
--   insecure_ssh    when 1, SSH host-key verification is skipped for this
--                   instance's node connections (node shell, SFTP, transfer).
--                   Independent of insecure_tls: the two connections have
--                   separate trust.
--
--   ssh_fingerprint when non-empty, a "SHA256:<base64>" the node's SSH host
--                   key must match. When empty, the host key is verified
--                   against DNS SSHFP records instead.
--
-- Booleans are stored as INTEGER, not BOOLEAN, so one scan path serves SQLite
-- and Postgres -- the same choice made for is_admin.
--
-- Existing rows get insecure_tls = 0 and insecure_ssh = 0: they are verified
-- from now on. This is a deliberate, secure default. An instance whose Proxmox
-- host serves a self-signed certificate must be re-pointed at a trusted
-- certificate or marked with `instance update --insecure-tls`.
ALTER TABLE proxmox_instances ADD COLUMN insecure_tls INTEGER NOT NULL DEFAULT 0;
ALTER TABLE proxmox_instances ADD COLUMN insecure_ssh INTEGER NOT NULL DEFAULT 0;
ALTER TABLE proxmox_instances ADD COLUMN ssh_fingerprint TEXT NOT NULL DEFAULT '';

-- +goose Down

ALTER TABLE proxmox_instances DROP COLUMN ssh_fingerprint;
ALTER TABLE proxmox_instances DROP COLUMN insecure_ssh;
ALTER TABLE proxmox_instances DROP COLUMN insecure_tls;
