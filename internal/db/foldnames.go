package db

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strings"

	"proxpass/internal/models"
)

// nameTables are the tables whose name column is folded.
//
// Written out per table rather than built from a variable, because SQL has no
// placeholder for an identifier: a shared query would have to concatenate the
// table name in, which gosec flags as G202 and rightly -- the rule cannot tell
// a fixed list from user input.
var nameTables = []struct {
	// what names the thing in an error message: "client", not "clients".
	what   string
	selAll string
	update string
}{
	{
		what:   "client",
		selAll: `SELECT id, name FROM clients`,
		update: `UPDATE clients SET name = ? WHERE id = ?`,
	},
	{
		what:   "group",
		selAll: `SELECT id, name FROM groups`,
		update: `UPDATE groups SET name = ? WHERE id = ?`,
	},
	{
		what:   "instance",
		selAll: `SELECT id, name FROM proxmox_instances`,
		update: `UPDATE proxmox_instances SET name = ? WHERE id = ?`,
	},
}

// foldStoredNames brings existing rows into the form new writes use.
//
// Names are folded in Go on the way into the database (models.FoldName), so
// the plain UNIQUE(name) constraint enforces case-insensitive uniqueness. Rows
// written before that was true may hold any spelling, and an unfolded row is
// not merely cosmetic: GetClientByName matches `name = ?' against a folded
// argument, so a client stored as "Alice" would stop being found at all. They
// have to be rewritten.
//
// Two rows that fold to the same name cannot both be rewritten -- the UNIQUE
// constraint is the point -- so this refuses first and names the pair, rather
// than letting the UPDATE fail with
//
//	UNIQUE constraint failed: clients.name
//
// which says nothing about which rows are at fault.
//
// The collision is NOT resolved automatically. There is no correct row to
// discard: both may have keys, group memberships and access rules, and
// access_rules.subject_id has no foreign key -- deliberately, so a stale rule
// cannot follow a reused id -- so deleting the loser would leave rules
// pointing at an id a later row will occupy. An administrator has to decide,
// and `client rm' / `group rm' / `instance update --rename' are the tools.
//
// Detection folds in Go rather than asking the database for lower(name),
// because the two do not agree: SQLite's lower() is ASCII-only, so it reports
// no collision between "ALICÉ" and "alicé" while models.FoldName folds them
// together -- and the UPDATE would then hit the constraint this exists to
// anticipate. The check has to predict exactly what the write will do.
//
// Runs after goose on every open rather than once in a migration: it is cheap,
// it is idempotent, and a database can acquire an unfolded name by being
// written to by an older build.
func foldStoredNames(ctx context.Context, database *sql.DB, d *dialect) error {
	var problems []string
	type pending struct {
		id     int64
		folded string
	}
	todo := make(map[int][]pending, len(nameTables))

	for i, t := range nameTables {
		rows, err := namesIn(ctx, database, t.selAll)
		if err != nil {
			// The table may not exist on a database migrated to an older
			// version by a partial failure; nothing to fold either way.
			continue
		}
		// byFolded groups the spellings that would collapse together.
		byFolded := make(map[string][]string, len(rows))
		for _, row := range rows {
			folded := models.FoldName(row.name)
			byFolded[folded] = append(byFolded[folded], row.name)
			if folded != row.name {
				todo[i] = append(todo[i], pending{id: row.id, folded: folded})
			}
		}
		for folded, spellings := range byFolded {
			if len(spellings) < 2 {
				continue
			}
			sort.Strings(spellings)
			quoted := make([]string, 0, len(spellings))
			for _, s := range spellings {
				quoted = append(quoted, fmt.Sprintf("%q", s))
			}
			problems = append(problems, fmt.Sprintf(
				"  %s names %s differ only by case (all are %q)",
				t.what, strings.Join(quoted, " and "), folded))
		}
	}

	if len(problems) > 0 {
		// Sorted so the message does not depend on map iteration order.
		sort.Strings(problems)
		return fmt.Errorf(
			"names must be unique ignoring case, and these are not:\n%s\n"+
				"Rename or remove one of each pair, then start again. Names "+
				"are matched without regard to case so that `ssh ROME@host' "+
				"reaches the instance added as `rome'; while both spellings "+
				"exist there is no single answer to give",
			strings.Join(problems, "\n"))
	}

	for i, rows := range todo {
		for _, p := range rows {
			if _, err := database.ExecContext(ctx,
				d.rebind(nameTables[i].update), p.folded, p.id); err != nil {
				return fmt.Errorf("folding %s names: %w", nameTables[i].what, err)
			}
		}
	}
	return nil
}

// namesIn reads the id and name of every row in one of the name tables.
func namesIn(ctx context.Context, database *sql.DB, query string) ([]struct {
	id   int64
	name string
}, error) {
	rows, err := database.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []struct {
		id   int64
		name string
	}
	for rows.Next() {
		var r struct {
			id   int64
			name string
		}
		if err := rows.Scan(&r.id, &r.name); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
