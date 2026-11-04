package filter

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Match evaluates a filter against an in-memory list of rows and returns the
// rows that satisfy it. It uses the same language as the SQL backend
// (Tokenize/Walk), so endpoints that do not push filtering down to the database
// can still honor the same ?filter= parameter with identical semantics.
//
// Each row is any JSON-serializable value (typically an API struct); it is
// rendered to its JSON object form so filter field names match the field names
// the API exposes. allowed lists the filterable field names (case-insensitive);
// a filter on any other field is rejected with ErrInvalidFilter so the handler
// can return a 400. A nil/empty filter returns the rows unchanged.
func Match[T any](rawFilter *string, rows []T, allowed FieldSpecMap) ([]T, error) {
	if rawFilter == nil || *rawFilter == "" {
		return rows, nil
	}
	tl, err := Tokenize(*rawFilter)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidFilter, err)
	}
	if tl == nil || tl.Head == nil {
		return rows, nil
	}

	out := make([]T, 0, len(rows))
	for _, row := range rows {
		fields, err := rowToMap(row)
		if err != nil {
			return nil, fmt.Errorf("evaluating filter: %w", err)
		}
		conds, err := Walk(tl, matchMapper(fields, allowed), boolCombiner{})
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalidFilter, err)
		}
		// Top-level conditions are implicitly ANDed.
		if andAll(conds) {
			out = append(out, row)
		}
	}
	return out, nil
}

// rowToMap renders a row to its JSON object so field lookups use the API's
// field names. Rows that do not marshal to an object (unlikely for API structs)
// yield an empty map, which simply never matches.
func rowToMap(row any) (map[string]any, error) {
	b, err := json.Marshal(row)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		// Not a JSON object; treat as having no fields.
		return map[string]any{}, nil //nolint:nilerr // non-object rows simply never match
	}
	return m, nil
}

func andAll(conds []bool) bool {
	for _, c := range conds {
		if !c {
			return false
		}
	}
	return true
}

// boolCombiner implements Combiner[bool] for in-memory evaluation.
type boolCombiner struct{}

func (boolCombiner) And(qs []bool) bool {
	for _, q := range qs {
		if !q {
			return false
		}
	}
	return true
}

func (boolCombiner) Or(qs []bool) bool {
	for _, q := range qs {
		if q {
			return true
		}
	}
	return false
}

func (boolCombiner) Nor(qs []bool) bool { return !boolCombiner{}.Or(qs) }
func (boolCombiner) Not(q bool) bool    { return !q }

// matchMapper returns a FieldMapper that evaluates one (field, op, value) leaf
// against the row's fields. It enforces the same field allow-list and per-field
// operator restrictions as the SQL mapper.
func matchMapper(fields map[string]any, fm FieldSpecMap) FieldMapper[bool] {
	return func(field, op string, value any) (bool, error) {
		spec, ok := fm[strings.ToLower(field)]
		if !ok {
			return false, fmt.Errorf("unsupported filter field %q", field)
		}
		if len(spec.AllowedOps) > 0 {
			if _, allowed := spec.AllowedOps[strings.ToLower(op)]; !allowed {
				return false, fmt.Errorf("operator %q is not allowed for field %q", op, field)
			}
		}
		// spec.Column names the JSON field to read (defaults to the field name).
		key := spec.Column
		if key == "" {
			key = field
		}
		got, err := scalarString(fields[key])
		if err != nil {
			// A row whose field is absent or non-scalar just does not match.
			return false, nil //nolint:nilerr // absent/complex field is a non-match, not an error
		}
		want, err := scalarString(value)
		if err != nil {
			return false, fmt.Errorf("value for %q on field %q: %w", op, field, err)
		}
		return evalOp(op, got, want), nil
	}
}

// evalOp applies one comparison operator to two string-rendered scalars. The
// case-insensitive and substring operators mirror the SQL mapper's semantics.
func evalOp(op, got, want string) bool {
	switch strings.ToLower(op) {
	case OpEq:
		return got == want
	case OpIeq:
		return strings.EqualFold(got, want)
	case OpContains:
		return strings.Contains(got, want)
	case OpIContains:
		return strings.Contains(strings.ToLower(got), strings.ToLower(want))
	case OpStartsWith:
		return strings.HasPrefix(strings.ToLower(got), strings.ToLower(want))
	case OpEndsWith:
		return strings.HasSuffix(strings.ToLower(got), strings.ToLower(want))
	default:
		return false
	}
}
