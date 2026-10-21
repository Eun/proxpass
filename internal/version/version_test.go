package version

import "testing"

// String never returns empty: without an injected value it falls back to the
// build info or "dev".
func TestStringNeverEmpty(t *testing.T) {
	if String() == "" {
		t.Fatal("String() returned empty")
	}
}

// An injected value wins over the fallback.
func TestStringPrefersInjectedValue(t *testing.T) {
	old := value
	t.Cleanup(func() { value = old })
	value = "v1.2.3"
	if got := String(); got != "v1.2.3" {
		t.Fatalf("String() = %q, want the injected v1.2.3", got)
	}
}
