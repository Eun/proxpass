package filter

import (
	"errors"
	"fmt"
	"strings"
)

// ErrInvalidFilter wraps every error caused by a malformed or disallowed
// client filter (bad JSON, unknown field, disallowed operator, bad value
// shape). Handlers use errors.Is to turn these into a 400 while a genuine
// database error still surfaces as a 500.
var ErrInvalidFilter = errors.New("invalid filter")

// Condition is a SQL WHERE fragment with its positional (`?`) arguments. It is
// the query type Q that Walk builds for the SQL backend. Leaf conditions carry
// a SQL snippet like "guest_id = ?"; composite conditions (built by the
// Combiner) wrap children in AND/OR/NOT groups.
type Condition struct {
	SQL  string
	Args []any
}

// FieldSpec describes one filterable field: the SQL column it maps to and the
// operators permitted on it. AllowedOps is an allow-list; an operator not in
// it -- including logical operators used to smuggle a disallowed comparison --
// is rejected so callers can return HTTP 400. An empty AllowedOps allows every
// operator the engine supports.
type FieldSpec struct {
	Column     string
	AllowedOps map[string]struct{}
}

// FieldSpecMap maps JSON filter field names to their FieldSpec. Keys are
// matched case-insensitively.
type FieldSpecMap map[string]FieldSpec

// OnlyEq is a convenience constructor for a FieldSpec that permits exact-match
// only, which is all that proxpass's integer-ID and enum columns support.
func OnlyEq(column string) FieldSpec {
	return FieldSpec{Column: column, AllowedOps: map[string]struct{}{OpEq: {}}}
}

// sqlCombiner implements Combiner[Condition] by wrapping child conditions in
// SQL logical groups.
type sqlCombiner struct{}

func (sqlCombiner) And(qs []Condition) Condition { return joinGroup(qs, " AND ") }
func (sqlCombiner) Or(qs []Condition) Condition  { return joinGroup(qs, " OR ") }

func (sqlCombiner) Nor(qs []Condition) Condition {
	// NOR = NOT (q1 OR q2 OR ...).
	g := joinGroup(qs, " OR ")
	return Condition{SQL: "NOT " + g.SQL, Args: g.Args}
}

func (sqlCombiner) Not(q Condition) Condition {
	return Condition{SQL: "NOT (" + q.SQL + ")", Args: q.Args}
}

// joinGroup combines conditions with sep into a single parenthesized group,
// concatenating their args in order so the `?` placeholders line up.
func joinGroup(qs []Condition, sep string) Condition {
	parts := make([]string, 0, len(qs))
	var args []any
	for _, q := range qs {
		parts = append(parts, q.SQL)
		args = append(args, q.Args...)
	}
	return Condition{SQL: "(" + strings.Join(parts, sep) + ")", Args: args}
}

// sqlFieldMapper returns a FieldMapper that resolves a field to its SQL column
// via the FieldSpecMap, enforces the per-field operator allow-list, and emits a
// leaf Condition. Unknown fields and disallowed operators are errors.
func sqlFieldMapper(fm FieldSpecMap) FieldMapper[Condition] {
	return func(field, op string, value any) (Condition, error) {
		spec, ok := fm[strings.ToLower(field)]
		if !ok {
			return Condition{}, fmt.Errorf("unsupported filter field %q", field)
		}
		if len(spec.AllowedOps) > 0 {
			if _, allowed := spec.AllowedOps[strings.ToLower(op)]; !allowed {
				return Condition{}, fmt.Errorf("operator %q is not allowed for field %q", op, field)
			}
		}
		return operatorToCondition(spec.Column, op, value)
	}
}

// operatorToCondition converts a (column, op, value) triplet into a leaf
// Condition. Values arrive as the JSON scalar; they are passed to the driver as
// bound arguments, so numeric columns compare correctly whether the client sent
// a JSON number or a string.
func operatorToCondition(col, op string, value any) (Condition, error) {
	s, err := scalarString(value)
	if err != nil {
		return Condition{}, fmt.Errorf("value for %q on field %q: %w", op, col, err)
	}
	switch strings.ToLower(op) {
	case OpEq:
		return Condition{SQL: col + " = ?", Args: []any{s}}, nil
	case OpIeq:
		return Condition{SQL: "LOWER(" + col + ") = LOWER(?)", Args: []any{s}}, nil
	case OpContains:
		return Condition{SQL: col + " LIKE ?", Args: []any{"%" + likeEscape(s) + "%"}}, nil
	case OpIContains:
		return Condition{SQL: "LOWER(" + col + ") LIKE LOWER(?)", Args: []any{"%" + likeEscape(s) + "%"}}, nil
	case OpStartsWith:
		return Condition{SQL: "LOWER(" + col + ") LIKE LOWER(?)", Args: []any{likeEscape(s) + "%"}}, nil
	case OpEndsWith:
		return Condition{SQL: "LOWER(" + col + ") LIKE LOWER(?)", Args: []any{"%" + likeEscape(s)}}, nil
	default:
		return Condition{}, fmt.Errorf("unsupported filter operator %q", op)
	}
}

// scalarString renders a JSON scalar as the string form used as a bound arg.
// It accepts strings, JSON numbers (float64) and bools; other shapes (arrays,
// objects, null) are rejected. Whole numbers render without a trailing ".0" so
// an integer ID sent as a JSON number matches the stored value.
func scalarString(value any) (string, error) {
	switch v := value.(type) {
	case string:
		return v, nil
	case float64:
		if v == float64(int64(v)) {
			return fmt.Sprintf("%d", int64(v)), nil
		}
		return fmt.Sprintf("%v", v), nil
	case bool:
		return fmt.Sprintf("%t", v), nil
	default:
		return "", fmt.Errorf("value must be a string, number or boolean, got %T", value)
	}
}

// likeEscape escapes LIKE wildcards so a user-supplied substring is matched
// literally. The backslash is the escape character; queries that use these
// patterns must declare ESCAPE '\' -- but proxpass only uses $eq today, so this
// is here for completeness of the ported operator set.
func likeEscape(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(s)
}

// BuildWhere parses rawFilter against the field map and returns a SQL WHERE
// fragment (without the leading "WHERE") and its positional args. The caller
// appends the fragment with `?` placeholders to its query and lets the repo's
// dialect rebind them.
//
// When rawFilter is nil or empty the fragment and args are empty and err is
// nil. A malformed filter, an unknown field, or a disallowed operator returns
// an error so the handler can surface a 400.
func BuildWhere(rawFilter *string, fm FieldSpecMap) (where string, args []any, err error) {
	if rawFilter == nil || *rawFilter == "" {
		return "", nil, nil
	}
	tl, err := Tokenize(*rawFilter)
	if err != nil {
		return "", nil, fmt.Errorf("%w: %w", ErrInvalidFilter, err)
	}
	if tl == nil || tl.Head == nil {
		return "", nil, nil
	}
	conds, err := Walk(tl, sqlFieldMapper(fm), sqlCombiner{})
	if err != nil {
		return "", nil, fmt.Errorf("%w: %w", ErrInvalidFilter, err)
	}
	if len(conds) == 0 {
		return "", nil, nil
	}
	// Top-level conditions are implicitly ANDed.
	combined := sqlCombiner{}.And(conds)
	return combined.SQL, combined.Args, nil
}
