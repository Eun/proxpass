package models_test

import (
	"strings"
	"testing"

	"proxpass/internal/models"
)

const (
	lower    = "alice"
	upper    = "ALICE"
	accented = "alicé"
)

func TestNamesEqualIgnoresCase(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want bool
	}{
		{lower, lower, true},
		{lower, upper, true},
		{lower, "Alice", true},
		{lower, "aLiCe", true},
		{lower, "bob", false},
		{lower, lower + "2", false},
		{"", "", true},
		// Non-ASCII, which SQL's lower() would not have folded on SQLite.
		{accented, "ALICÉ", true},
		{"tobías", "TOBÍAS", true},
	} {
		if got := models.NamesEqual(tc.a, tc.b); got != tc.want {
			t.Errorf("NamesEqual(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}

// NamesEqual must agree with FoldName, because FoldName is what was stored.
//
// strings.EqualFold does not: it applies simple case-folding, so it reports
// "ſ" and "s" equal while FoldName maps them to different strings, and
// reports "İ" and "i" different while FoldName maps BOTH to "i". Either
// disagreement reintroduces the ambiguity folding exists to remove -- a name
// that compares equal to one already stored, yet occupies a different row.
func TestNamesEqualAgreesWithFoldName(t *testing.T) {
	for _, pair := range [][2]string{
		{"\u017f", "s"}, // long s: EqualFold says equal, FoldName does not
		{"\u0130", "i"}, // dotted capital I: EqualFold says different, FoldName folds both
		{"\u212a", "k"}, // kelvin sign
		{upper, lower},
		{"ALICÉ", accented},
	} {
		a, b := pair[0], pair[1]
		stored := models.FoldName(a) == models.FoldName(b)
		if got := models.NamesEqual(a, b); got != stored {
			t.Errorf("NamesEqual(%q, %q) = %v but folding gives %v",
				a, b, got, stored)
		}
	}
}

// The reserved administrator name is the case that makes the above matter.
//
// "admİn" is EqualFold-different from "admin" yet folds to exactly it, so a
// name validated with EqualFold but stored with FoldName could land on the
// administrator's name.
func TestAReservedNameCannotBeReachedByAnUnfoldedSpelling(t *testing.T) {
	const admin = "admin"
	sneaky := "adm\u0130n"

	if strings.EqualFold(sneaky, admin) {
		t.Fatalf("precondition: EqualFold(%q, %q) should be false", sneaky, admin)
	}
	if models.FoldName(sneaky) != admin {
		t.Fatalf("precondition: %q should fold to %q, got %q",
			sneaky, admin, models.FoldName(sneaky))
	}
	if !models.NamesEqual(sneaky, admin) {
		t.Errorf("NamesEqual(%q, %q) = false; the reserved name is reachable",
			sneaky, admin)
	}
}

func TestFoldNameIsIdempotent(t *testing.T) {
	for _, n := range []string{lower, upper, "Alicé", "ROME", "adm\u0130n", ""} {
		once := models.FoldName(n)
		if twice := models.FoldName(once); twice != once {
			t.Errorf("FoldName(%q) = %q but folding again gives %q", n, once, twice)
		}
	}
}
