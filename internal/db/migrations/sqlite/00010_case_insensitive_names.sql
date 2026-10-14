-- +goose Up

-- Make name uniqueness case-insensitive for the three things an
-- administrator refers to by name.
--
-- Lookups were already case-insensitive in most places -- a login name
-- resolves an instance with EqualFold, and the CLI's remove and update
-- commands do the same -- but the constraint underneath was not. So "alice"
-- and "Alice" could both exist as clients, and a case-insensitive lookup
-- would then match two rows and silently take whichever the scan yielded
-- first. For a client that means a uid; for a group it means the subject_id
-- written into an access rule. Both are decided non-deterministically, which
-- is worse than a lookup that is merely strict.
--
-- An expression index rather than COLLATE NOCASE on the column. NOCASE would
-- need the whole table rebuilt -- SQLite cannot alter a column -- and the
-- rebuild would have to be repeated verbatim in the Postgres migration with
-- different syntax. "UNIQUE INDEX ON lower(name)" is one statement, is the
-- same text in both dialects, and leaves the existing UNIQUE in place as the
-- case-sensitive special case of it.
--
-- NOTE: lower() is ASCII-only in SQLite and locale-dependent in Postgres, so
-- the two disagree on non-ASCII names -- "TOBÍAS" and "tobías" collide on
-- Postgres and not on SQLite. Login names deliberately allow non-ASCII (see
-- api.ValidLoginName), so this is a real difference, but it fails SAFE: the
-- stricter dialect refuses a name, rather than either one admitting a
-- duplicate it will later resolve at random.
--
-- This migration FAILS on a database that already holds names differing only
-- by case. That is deliberate -- there is no correct row to discard
-- automatically, and discarding one would orphan access rules that have no
-- foreign key to it. db.checkNameCollisions runs first and reports the
-- offending pairs by name, so the failure says what to rename rather than
-- "UNIQUE constraint failed".
CREATE UNIQUE INDEX IF NOT EXISTS idx_clients_name_lower
    ON clients (lower(name));
CREATE UNIQUE INDEX IF NOT EXISTS idx_groups_name_lower
    ON groups (lower(name));
CREATE UNIQUE INDEX IF NOT EXISTS idx_proxmox_instances_name_lower
    ON proxmox_instances (lower(name));

-- +goose Down

DROP INDEX IF EXISTS idx_clients_name_lower;
DROP INDEX IF EXISTS idx_groups_name_lower;
DROP INDEX IF EXISTS idx_proxmox_instances_name_lower;
