-- +goose Up

-- Rename connection_type to console_transport, and give every instance an
-- SSH host.
--
-- The column decided two unrelated things. It picked the CONSOLE transport --
-- the Proxmox websocket, or `pct enter' over SSH -- which is what it was for.
-- But because only the ssh value populated ssh_host, it also silently decided
-- whether proxpass could reach the node at all, and so whether file transfer
-- was possible. A deployment using the websocket for consoles could not
-- transfer files, for no reason other than the name of this column.
--
-- The two are independent: how a terminal is attached says nothing about
-- whether the node answers SSH. So the column is renamed to what it actually
-- selects, and the SSH fields stand on their own.
ALTER TABLE proxmox_instances RENAME COLUMN connection_type TO console_transport;

-- Derive an SSH host for instances that never got one.
--
-- These are the termproxy rows: `instance add' only resolved ssh_host when
-- the type was ssh, so they hold ''. The value is derived the same way the
-- CLI derives it -- the hostname of api_url -- so the result is what an
-- administrator would have got had they added the instance today.
--
-- Writing a value nobody typed is a deliberate choice. The alternative is
-- leaving these instances unable to transfer files until someone edits each
-- one, and there is no command to do that with: `instance update' does not
-- exist. An administrator who does not want proxpass reaching a node simply
-- does not install the public key there, which is a stronger control than an
-- empty column.
--
-- rtrim/instr parse "scheme://host:port/path" without a regex, which SQLite
-- has no built-in for:
--   1. strip the scheme by taking everything after '//'
--   2. cut at the first '/' to drop the path
--   3. cut at the first ':' to drop the port
UPDATE proxmox_instances
SET ssh_host = (
    WITH after_scheme AS (
        SELECT CASE
            WHEN instr(api_url, '//') > 0
                THEN substr(api_url, instr(api_url, '//') + 2)
            ELSE api_url
        END AS v
    ),
    no_path AS (
        SELECT CASE
            WHEN instr(v, '/') > 0 THEN substr(v, 1, instr(v, '/') - 1)
            ELSE v
        END AS v FROM after_scheme
    )
    SELECT CASE
        WHEN instr(v, ':') > 0 THEN substr(v, 1, instr(v, ':') - 1)
        ELSE v
    END FROM no_path
)
WHERE ssh_host = '';

-- The default SSH port, for the same rows.
UPDATE proxmox_instances SET ssh_port = 22 WHERE ssh_port = 0;

-- And the default user, in case a row predates the ssh_user default.
UPDATE proxmox_instances SET ssh_user = 'root' WHERE ssh_user = '';

-- +goose Down

ALTER TABLE proxmox_instances RENAME COLUMN console_transport TO connection_type;

-- The derived ssh_host is NOT reverted. It cannot be distinguished from one
-- an administrator set, and clearing it would break an instance that is by
-- then relying on it.
