package db

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

// checkNameCollisions refuses to migrate a database holding names that
// differ only by case.
//
// Migration 00010 makes name uniqueness case-insensitive. On a database
// already containing "alice" and "Alice" the index cannot be built, and
// goose would report
//
//	UNIQUE constraint failed: index 'idx_clients_name_lower'
//
// which says nothing about which rows are at fault. This runs first and
// names them.
//
// It does NOT resolve the collision. There is no correct row to discard
// automatically: both may have keys, group memberships and access rules,
// and access_rules.subject_id has no foreign key -- deliberately, so that a
// stale rule cannot follow a reused id -- so deleting the loser would leave
// rules pointing at an id a later row will occupy. An administrator has to
// decide, and `client rm' / `group rm' / `instance update --rename' are the
// tools for it.
//
// Run before every migration rather than once, because it is cheap and
// because a database can acquire a collision while running an older build
// that still permits one.
func checkNameCollisions(ctx context.Context, database *sql.DB) error {
	var problems []string
	for _, t := range []struct{ table, what string }{
		{"clients", "client"},
		{"groups", "group"},
		{"proxmox_instances", "instance"},
	} {
		names, err := collidingNames(ctx, database, t.table)
		if err != nil {
			// The table may not exist yet: this runs before the initial
			// migration on a fresh database. Nothing to collide, so the
			// error is not interesting.
			continue
		}
		for _, n := range names {
			problems = append(problems,
				fmt.Sprintf("  %s names %s differ only by case", t.what, n))
		}
	}
	if len(problems) == 0 {
		return nil
	}
	return fmt.Errorf(
		"names must be unique ignoring case, and these are not:\n%s\n"+
			"Rename or remove one of each pair, then start again. Names are "+
			"matched without regard to case so that `ssh ROME@host' reaches "+
			"the instance added as `rome'; while both spellings exist there "+
			"is no single answer to give",
		strings.Join(problems, "\n"))
}

// nameCollisionQueries are the per-table statements, written out rather than
// built from a table name.
//
// SQL has no placeholder for an identifier, so a shared query would have to
// concatenate the table in -- which gosec flags as G202, and rightly: the
// rule cannot tell a fixed list from user input. Three literals cost less
// than a suppression that a future caller could invalidate by passing
// something else.
//
// Each returns one row per collision, naming the lowest and highest
// spelling, which for a pair is both of them.
var nameCollisionQueries = map[string]string{
	"clients": `SELECT MIN(name), MAX(name) FROM clients
		GROUP BY lower(name) HAVING COUNT(*) > 1`,
	"groups": `SELECT MIN(name), MAX(name) FROM groups
		GROUP BY lower(name) HAVING COUNT(*) > 1`,
	"proxmox_instances": `SELECT MIN(name), MAX(name) FROM proxmox_instances
		GROUP BY lower(name) HAVING COUNT(*) > 1`,
}

// collidingNames returns the pairs of names in a table that are equal
// ignoring case.
func collidingNames(ctx context.Context, database *sql.DB, table string) ([]string, error) {
	query, ok := nameCollisionQueries[table]
	if !ok {
		return nil, fmt.Errorf("no collision query for table %q", table)
	}
	rows, err := database.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []string
	for rows.Next() {
		var lo, hi string
		if err := rows.Scan(&lo, &hi); err != nil {
			return nil, err
		}
		out = append(out, fmt.Sprintf("%q and %q", lo, hi))
	}
	return out, rows.Err()
}
