package api_test

import (
	"strings"
	"testing"

	"proxpass/internal/api"
)

// The bound is generous enough for a qualified "guest@instance" pair.
//
// The old limit of 32 made that form impractical: a guest and an instance
// name plus a separator routinely exceed it.
func TestLoginNameLengthAllowsAQualifiedPair(t *testing.T) {
	for _, name := range []string{
		"my-long-guest-name@secondary-node", // 33: rejected by the old limit
		strings.Repeat("g", 120) + "@" + strings.Repeat("i", 120),
	} {
		if !api.ValidLoginName(name) {
			t.Errorf("ValidLoginName(%d chars) = false, want it served", len(name))
		}
	}
}

// The bound still exists, and is applied at the documented length.
//
// It is not a Unix constraint -- see MaxLoginNameLen -- but an absurd name
// must fail here rather than inside a lookup URL, an argv or a log line.
func TestLoginNameLengthIsBounded(t *testing.T) {
	if !api.ValidLoginName(strings.Repeat("a", api.MaxLoginNameLen)) {
		t.Errorf("a name of exactly %d characters must be accepted",
			api.MaxLoginNameLen)
	}
	if api.ValidLoginName(strings.Repeat("a", api.MaxLoginNameLen+1)) {
		t.Errorf("a name of %d characters must be refused",
			api.MaxLoginNameLen+1)
	}
}

// Length is measured in BYTES, because that is what the passwd entry, the
// lookup URL and the argv all carry. A multi-byte name must not slip past
// the bound by having fewer runes than bytes.
func TestLoginNameLengthIsMeasuredInBytes(t *testing.T) {
	// "ä" is two bytes, so this is over the limit in bytes but under it in
	// runes.
	name := strings.Repeat("ä", api.MaxLoginNameLen/2+1)
	if len(name) <= api.MaxLoginNameLen {
		t.Fatalf("test setup: %d bytes is not over the limit", len(name))
	}
	if api.ValidLoginName(name) {
		t.Errorf("a %d-byte name was accepted; the bound must count bytes",
			len(name))
	}
}
