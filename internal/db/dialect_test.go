package db

import "testing"

// twoPlaceholders is reused across cases.
const twoPlaceholders = "SELECT a FROM t WHERE b = ? AND c = ?"

func TestRebind(t *testing.T) {
	for _, tc := range []struct {
		name  string
		d     dialect
		query string
		want  string
	}{
		{
			// SQLite takes the queries exactly as written, so there is no
			// rewriting to get wrong on the default backend.
			name:  "sqlite leaves the query alone",
			d:     sqliteDialect,
			query: twoPlaceholders,
			want:  twoPlaceholders,
		},
		{
			name:  "postgres numbers the placeholders in order",
			d:     postgresDialect,
			query: twoPlaceholders,
			want:  "SELECT a FROM t WHERE b = $1 AND c = $2",
		},
		{
			// Ten or more arguments is where a naive single-digit
			// substitution breaks.
			name:  "more than nine placeholders",
			d:     postgresDialect,
			query: "INSERT INTO t VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
			want:  "INSERT INTO t VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
		},
		{
			name:  "a query with no placeholders",
			d:     postgresDialect,
			query: "SELECT count(*) FROM t",
			want:  "SELECT count(*) FROM t",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.d.rebind(tc.query); got != tc.want {
				t.Errorf("rebind() =\n %q\nwant\n %q", got, tc.want)
			}
		})
	}
}

// A DSN decides the backend, so the classification has to be right: a
// Postgres URL misread as a path would silently create a file named after the
// URL and start with an empty database.
func TestIsPostgresDSN(t *testing.T) {
	for _, tc := range []struct {
		dsn  string
		want bool
	}{
		{"postgres://user:pass@host:5432/proxpass", true},
		{"postgresql://user@host/proxpass?sslmode=disable", true},
		{"/var/lib/proxpass/proxpass.db", false},
		{"proxpass.db", false},
		{"", false},
		// A path that merely mentions postgres is still a path.
		{"/var/lib/postgres-backup/proxpass.db", false},
	} {
		t.Run(tc.dsn, func(t *testing.T) {
			if got := isPostgresDSN(tc.dsn); got != tc.want {
				t.Errorf("isPostgresDSN(%q) = %v, want %v", tc.dsn, got, tc.want)
			}
		})
	}
}

func TestDialectForRejectsUnknownBackends(t *testing.T) {
	if _, err := dialectFor("mysql"); err == nil {
		t.Error("dialectFor accepted an unsupported backend")
	}
	for _, b := range []Backend{BackendSQLite, BackendPostgres} {
		if _, err := dialectFor(b); err != nil {
			t.Errorf("dialectFor(%q): %v", b, err)
		}
	}
}
