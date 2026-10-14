-- +goose Up

-- Access rules whose target is a Proxmox node rather than a guest. See the
-- SQLite migration of the same name for why this is a separate table and why
-- it has no foreign key; the reasoning is identical and is not repeated here.
CREATE TABLE IF NOT EXISTS instance_access_rules (
    id          BIGSERIAL PRIMARY KEY,
    type        TEXT      NOT NULL,
    subject_id  BIGINT    NOT NULL,
    instance_id BIGINT    NOT NULL,
    UNIQUE(type, subject_id, instance_id)
);

-- +goose Down

DROP TABLE IF EXISTS instance_access_rules;
