package models

import "strings"

// FoldName reduces a name to the single form proxpass stores and compares.
//
// Clients, groups and Proxmox instances are referred to by name, and the name
// is matched without regard to case: `ssh ROME@host' reaches the instance
// added as `rome'. Case-insensitivity has to be decided somewhere, and this
// is the whole of that decision -- names are folded HERE, in Go, on the way
// into the database, so the plain UNIQUE(name) constraint that has existed
// since the initial schema enforces it, and a lookup is an ordinary equality
// test against an ordinary index.
//
// The alternative was a UNIQUE INDEX ON lower(name) with lookups written as
// `WHERE lower(name) = lower(?)'. That pushes the rule into the database,
// where it is stated twice -- once per dialect -- and where the two dialects
// do not agree: SQLite's lower() is ASCII-only, while Postgres' is
// locale-dependent, so "ALICÉ" folds to "alicé" on one and stays "alicÉ" on
// the other. Login names deliberately allow non-ASCII (see api.ValidLoginName),
// so that disagreement is reachable. strings.ToLower is Unicode-aware and
// identical on every backend, which is the point: one rule, one place.
//
// Note this is ToLower, not the simple case-folding strings.EqualFold applies.
// They differ on a handful of runes -- EqualFold("ſ", "s") is true while
// ToLower("ſ") is "ſ" -- so the two cannot be mixed without reintroducing
// exactly the ambiguity this removes. Compare names with NamesEqual, never
// with EqualFold.
func FoldName(name string) string {
	return strings.ToLower(name)
}

// NamesEqual reports whether two names refer to the same thing.
//
// Use this rather than strings.EqualFold wherever the names being compared
// are client, group or instance names: it is the comparison that agrees with
// what FoldName wrote.
func NamesEqual(a, b string) bool {
	return FoldName(a) == FoldName(b)
}
