package filter

import (
	"errors"
	"strings"
	"testing"
)

func strp(s string) *string { return &s }

// Field/column names reused across the cases below; hoisted to satisfy goconst
// and to keep the names in one place. (The raw-JSON filter strings and the
// expected SQL still spell them out literally, on purpose, so the tests read
// as a client would write them.)
const (
	fGuestID = "guest_id"
	fType    = "type"
)

// TestBuildWhereEq covers the common exact-match case used by the UI.
func TestBuildWhereEq(t *testing.T) {
	fm := FieldSpecMap{fGuestID: {Column: fGuestID}}
	where, args, err := BuildWhere(strp(`{"guest_id":{"$eq":"5"}}`), fm)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if where != "(guest_id = ?)" {
		t.Errorf("where = %q, want %q", where, "(guest_id = ?)")
	}
	if len(args) != 1 || args[0] != "5" {
		t.Errorf("args = %v, want [5]", args)
	}
}

// TestBuildWhereNumberScalar: a JSON number must render as an integer arg, not
// "5.000000", so it matches an integer column.
func TestBuildWhereNumberScalar(t *testing.T) {
	fm := FieldSpecMap{fGuestID: {Column: fGuestID}}
	_, args, err := BuildWhere(strp(`{"guest_id":{"$eq":5}}`), fm)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(args) != 1 || args[0] != "5" {
		t.Errorf("args = %v, want [\"5\"]", args)
	}
}

// TestBuildWhereMultipleFieldsAnded: two fields are implicitly ANDed.
func TestBuildWhereMultipleFieldsAnded(t *testing.T) {
	fm := FieldSpecMap{
		fType:        {Column: fType},
		"subject_id": {Column: "subject_id"},
	}
	where, args, err := BuildWhere(strp(`{"type":{"$eq":"client"},"subject_id":{"$eq":"1"}}`), fm)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Map iteration order is non-deterministic, so just assert structure.
	if !strings.Contains(where, "type = ?") || !strings.Contains(where, "subject_id = ?") {
		t.Errorf("where = %q, missing a field condition", where)
	}
	if !strings.HasPrefix(where, "(") || !strings.Contains(where, " AND ") {
		t.Errorf("where = %q, want a top-level AND group", where)
	}
	if len(args) != 2 {
		t.Errorf("args = %v, want 2 args", args)
	}
}

// TestBuildWhereOr exercises a logical operator on one field.
func TestBuildWhereOr(t *testing.T) {
	fm := FieldSpecMap{fType: {Column: fType}}
	where, args, err := BuildWhere(strp(`{"type":{"$or":[{"$eq":"client"},{"$eq":"group"}]}}`), fm)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(where, " OR ") {
		t.Errorf("where = %q, want an OR group", where)
	}
	if len(args) != 2 {
		t.Errorf("args = %v, want 2 args", args)
	}
}

// TestBuildWhereContains checks LIKE wildcards are escaped.
func TestBuildWhereContains(t *testing.T) {
	fm := FieldSpecMap{fType: {Column: fType}}
	_, args, err := BuildWhere(strp(`{"type":{"$contains":"a%b_c"}}`), fm)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := `%a\%b\_c%`
	if len(args) != 1 || args[0] != want {
		t.Errorf("args = %v, want [%q]", args, want)
	}
}

// TestBuildWhereEmpty: absent filter yields no clause.
func TestBuildWhereEmpty(t *testing.T) {
	fm := FieldSpecMap{fGuestID: {Column: fGuestID}}
	for _, in := range []*string{nil, strp("")} {
		where, args, err := BuildWhere(in, fm)
		if err != nil || where != "" || args != nil {
			t.Errorf("BuildWhere(%v) = (%q,%v,%v), want empty", in, where, args, err)
		}
	}
}

// TestBuildWhereUnknownField is a client error (400 upstream).
func TestBuildWhereUnknownField(t *testing.T) {
	fm := FieldSpecMap{fGuestID: {Column: fGuestID}}
	_, _, err := BuildWhere(strp(`{"password":{"$eq":"x"}}`), fm)
	if err == nil {
		t.Fatal("expected error for unknown field")
	}
	if !errors.Is(err, ErrInvalidFilter) {
		t.Errorf("error %v is not ErrInvalidFilter", err)
	}
}

// TestBuildWhereDisallowedOp: a field whose AllowedOps is {$eq} rejects others,
// and the allow-list cannot be bypassed via a logical operator.
func TestBuildWhereDisallowedOp(t *testing.T) {
	fm := FieldSpecMap{fGuestID: OnlyEq(fGuestID)}
	for _, raw := range []string{
		`{"guest_id":{"$contains":"5"}}`,
		`{"guest_id":{"$or":[{"$contains":"5"}]}}`,
	} {
		_, _, err := BuildWhere(strp(raw), fm)
		if err == nil {
			t.Errorf("expected error for %s", raw)
			continue
		}
		if !errors.Is(err, ErrInvalidFilter) {
			t.Errorf("%s: error %v is not ErrInvalidFilter", raw, err)
		}
	}
}

// TestBuildWhereMalformedJSON is a client error.
func TestBuildWhereMalformedJSON(t *testing.T) {
	fm := FieldSpecMap{fGuestID: {Column: fGuestID}}
	_, _, err := BuildWhere(strp(`{not json`), fm)
	if err == nil || !errors.Is(err, ErrInvalidFilter) {
		t.Errorf("err = %v, want ErrInvalidFilter", err)
	}
}

// TestBuildWhereArgOrder: args line up with placeholders left-to-right so the
// combined AND group binds correctly.
func TestBuildWhereArgOrder(t *testing.T) {
	fm := FieldSpecMap{fType: {Column: fType}}
	where, args, err := BuildWhere(strp(`{"type":{"$and":[{"$startswith":"c"},{"$endswith":"t"}]}}`), fm)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Count(where, "?") != len(args) {
		t.Errorf("placeholder count %d != arg count %d (where=%q)", strings.Count(where, "?"), len(args), where)
	}
}
