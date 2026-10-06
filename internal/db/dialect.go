package db

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5/pgconn"
)

// Backend names a supported database.
type Backend string

const (
	// BackendSQLite is the default: a single file, no server to run.
	BackendSQLite Backend = "sqlite"
	// BackendPostgres is for deployments that want the database outside the
	// container, or shared by more than one proxpass.
	BackendPostgres Backend = "postgres"
)

// dialect is the small set of differences between the backends.
//
// The SQL itself is shared. That is possible because the statements proxpass
// needs are standard everywhere it matters: SQLite has supported RETURNING
// since 3.35 and ON CONFLICT since 3.24, and the driver here bundles 3.53. So
// instead of two query sets that must be kept in step -- the usual way this
// goes wrong -- there is one, and the dialect supplies only what genuinely
// cannot be shared:
//
//   - placeholders, "?" against "$1"
//   - the driver name to open
//   - the goose dialect, and which migration directory to run
//   - how the driver reports a unique-constraint violation
type dialect struct {
	backend    Backend
	driver     string
	goose      string
	migrations string

	// numberedPlaceholders is true for backends that want $1, $2 rather
	// than a positional "?".
	numberedPlaceholders bool

	// isUniqueViolation reports whether err is a duplicate-key rejection.
	// This cannot be shared: the drivers report it differently, and one of
	// them has no typed error at all.
	isUniqueViolation func(error) bool
}

var sqliteDialect = dialect{
	backend:    BackendSQLite,
	driver:     "sqlite",
	goose:      "sqlite3",
	migrations: "migrations/sqlite",
	// modernc.org/sqlite does not export a typed constraint error, so the
	// message is all there is to match on. It is stable across versions and
	// is what the previous implementation matched.
	isUniqueViolation: func(err error) bool {
		return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
	},
}

var postgresDialect = dialect{
	backend:              BackendPostgres,
	driver:               "pgx",
	goose:                "postgres",
	migrations:           "migrations/postgres",
	numberedPlaceholders: true,
	// 23505 is unique_violation. Matching the SQLSTATE rather than the
	// message keeps this working whatever the server's locale is.
	isUniqueViolation: func(err error) bool {
		var pgErr *pgconn.PgError
		return errors.As(err, &pgErr) && pgErr.Code == "23505"
	},
}

// rebind converts a query written with "?" placeholders to the dialect's own
// form.
//
// Queries are written once, in the SQLite style, because that is what they
// already were -- this keeps the diff to the statements themselves empty and
// means there is no second copy to drift. For Postgres the "?" are numbered
// left to right.
//
// Literal "?" inside a string literal would be rewritten too. No query here
// contains one, and adding such a query would be visible in review, so the
// parser stays this simple rather than tracking quote state.
func (d *dialect) rebind(query string) string {
	if !d.numberedPlaceholders {
		return query
	}
	var sb strings.Builder
	sb.Grow(len(query) + 8) //nolint:mnd // a few extra bytes for the digits
	n := 0
	for i := range len(query) {
		if query[i] != '?' {
			sb.WriteByte(query[i])
			continue
		}
		n++
		sb.WriteByte('$')
		sb.WriteString(strconv.Itoa(n))
	}
	return sb.String()
}

// dialectFor returns the dialect for a backend.
func dialectFor(b Backend) (dialect, error) {
	switch b {
	case BackendSQLite:
		return sqliteDialect, nil
	case BackendPostgres:
		return postgresDialect, nil
	default:
		return dialect{}, fmt.Errorf("unsupported database backend %q", b)
	}
}
