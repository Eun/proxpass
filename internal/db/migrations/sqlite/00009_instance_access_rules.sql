-- +goose Up

-- Access rules whose target is a Proxmox node rather than a guest.
--
-- A separate table rather than a nullable column on access_rules. That
-- table's guest_id is NOT NULL and its uniqueness constraint is the triple
-- (type, subject_id, guest_id), which the ON CONFLICT upsert in grantAccess
-- depends on; making the target nullable would weaken both, and every query
-- that reads access_rules would have to start excluding rows whose target is
-- not a guest. A guest id and an instance id are different things that
-- happen to share a Go type, so they get different columns.
--
-- The shape otherwise mirrors access_rules exactly, including the absence of
-- a foreign key. That omission is deliberate there and for the same reason
-- here: proxmox_instances.id is AUTOINCREMENT, so a rule left behind after an
-- instance is removed would start granting access to whatever instance later
-- occupied that row id. RemoveProxmoxInstance deletes these rules explicitly,
-- which is the only thing keeping that from happening.
CREATE TABLE IF NOT EXISTS instance_access_rules (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    type        TEXT    NOT NULL,
    subject_id  INTEGER NOT NULL,
    instance_id INTEGER NOT NULL,
    UNIQUE(type, subject_id, instance_id)
);

-- +goose Down

DROP TABLE IF EXISTS instance_access_rules;
