-- +goose Up

-- Record whether a container runs unprivileged (in its own user namespace).
--
-- A command entering the container uses this to decide whether to ask nsenter
-- for the user namespace (-U). A PRIVILEGED container shares the host's user
-- namespace, so requesting -U makes setns fail with
--   nsenter: reassociate to namespaces failed: Invalid argument
-- Before this column proxpass assumed every container was unprivileged, which
-- broke `ssh ct<id>@host <cmd>' on every privileged container.
--
-- Default 0 (privileged) is the SAFE choice: on a truly unprivileged container
-- omitting -U only drops writes to nobody:nogroup, while emitting -U on a
-- privileged one fails outright. Discovery overwrites the value from the
-- Proxmox lxc config on the next pass, so an existing row self-corrects.
ALTER TABLE guests ADD COLUMN unprivileged INTEGER NOT NULL DEFAULT 0;

-- +goose Down

ALTER TABLE guests DROP COLUMN unprivileged;
