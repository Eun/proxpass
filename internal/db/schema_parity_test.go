package db

import (
	"database/sql"
	"os"
	"sort"
	"strings"
	"testing"
)

// The two schemas are written separately -- SQLite as the migration history a
// deployed database must follow, Postgres as one file stating the result -- so
// nothing but a test keeps them saying the same thing. A column added to one
// and forgotten in the other would not show up until a query failed on the
// backend that CI happened not to exercise.
//
// This compares the column NAMES per table. Types are deliberately not
// compared: BIGSERIAL against INTEGER PRIMARY KEY AUTOINCREMENT is a
// difference the dialect requires, and asserting on it would mean encoding
// the mapping twice.
func TestSchemasAgree(t *testing.T) {
	dsn := os.Getenv(testPostgresDSNEnv)
	if dsn == "" {
		t.Skipf("set %s to compare the schemas", testPostgresDSNEnv)
	}

	sqliteCols := schemaOfSQLite(t)
	pgCols := schemaOfPostgres(t, dsn)

	for table, want := range sqliteCols {
		got, ok := pgCols[table]
		if !ok {
			t.Errorf("table %q exists in SQLite but not in Postgres", table)
			continue
		}
		if strings.Join(want, ",") != strings.Join(got, ",") {
			t.Errorf("table %q columns differ:\n sqlite: %v\n   pg:   %v", table, want, got)
		}
	}
	for table := range pgCols {
		if _, ok := sqliteCols[table]; !ok {
			t.Errorf("table %q exists in Postgres but not in SQLite", table)
		}
	}
}

// schemaOfSQLite migrates a scratch SQLite database and reads its columns.
func schemaOfSQLite(t *testing.T) map[string][]string {
	t.Helper()
	f, err := os.CreateTemp("", "proxpass-parity-*.db")
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	t.Cleanup(func() { _ = os.Remove(f.Name()) })

	repo, err := NewSQLiteRepository(f.Name())
	if err != nil {
		t.Fatalf("migrating sqlite: %v", err)
	}
	t.Cleanup(func() { _ = repo.Close() })

	database, err := sql.Open("sqlite", f.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = database.Close() }()

	out := map[string][]string{}
	rows, err := database.QueryContext(t.Context(),
		`SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'`)
	if err != nil {
		t.Fatal(err)
	}
	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		tables = append(tables, name)
	}
	_ = rows.Close()

	for _, table := range tables {
		if isGooseTable(table) {
			continue
		}
		cRows, err := database.QueryContext(t.Context(), `SELECT name FROM pragma_table_info(?)`, table)
		if err != nil {
			t.Fatal(err)
		}
		var cols []string
		for cRows.Next() {
			var c string
			if err := cRows.Scan(&c); err != nil {
				t.Fatal(err)
			}
			cols = append(cols, c)
		}
		_ = cRows.Close()
		sort.Strings(cols)
		out[table] = cols
	}
	return out
}

// schemaOfPostgres migrates a scratch schema and reads its columns.
func schemaOfPostgres(t *testing.T, dsn string) map[string][]string {
	t.Helper()
	repo := newTestPostgresRepo(t, dsn)
	// newTestPostgresRepo put the schema on the search_path; ask the server
	// which one that is rather than recomputing the name.
	inner, ok := repo.(*sqlRepo)
	if !ok {
		t.Fatalf("expected *sqlRepo, got %T", repo)
	}
	var schema string
	if err := inner.db.QueryRowContext(t.Context(), `SELECT current_schema()`).Scan(&schema); err != nil {
		t.Fatal(err)
	}

	rows, err := inner.db.QueryContext(t.Context(),
		`SELECT table_name, column_name FROM information_schema.columns
		 WHERE table_schema = $1`, schema)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()

	out := map[string][]string{}
	for rows.Next() {
		var table, col string
		if err := rows.Scan(&table, &col); err != nil {
			t.Fatal(err)
		}
		if isGooseTable(table) {
			continue
		}
		out[table] = append(out[table], col)
	}
	for table := range out {
		sort.Strings(out[table])
	}
	return out
}

// isGooseTable reports whether name is goose's own bookkeeping.
func isGooseTable(name string) bool {
	return strings.HasPrefix(name, "goose_db_version")
}
