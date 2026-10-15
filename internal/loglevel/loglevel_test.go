package loglevel_test

import (
	"testing"

	"proxpass/internal/loglevel"
)

func TestParse(t *testing.T) {
	for _, tc := range []struct {
		in      string
		want    loglevel.Level
		wantErr bool
	}{
		{"debug", loglevel.Debug, false},
		{"DEBUG", loglevel.Debug, false},
		{" Debug ", loglevel.Debug, false},
		{"info", loglevel.Info, false},
		{"", loglevel.Info, false},
		{"warn", loglevel.Warn, false},
		{"warning", loglevel.Warn, false},
		{"error", loglevel.Error, false},
		{"verbose", loglevel.Info, true},
	} {
		got, err := loglevel.Parse(tc.in)
		if (err != nil) != tc.wantErr {
			t.Errorf("Parse(%q) error = %v, wantErr %v", tc.in, err, tc.wantErr)
		}
		if got != tc.want {
			t.Errorf("Parse(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

// A typo must be reported, not silently ignored.
//
// Falling back to the default would leave an operator waiting for
// diagnostics that were never switched on, which is the failure mode this
// change exists to remove.
func TestAnUnknownLevelIsAnError(t *testing.T) {
	if _, err := loglevel.Parse("trace"); err == nil {
		t.Error("an unknown level was accepted silently")
	}
}

func TestEnabled(t *testing.T) {
	if !loglevel.Debug.Enabled(loglevel.Debug) {
		t.Error("debug must enable debug")
	}
	if loglevel.Info.Enabled(loglevel.Debug) {
		t.Error("info must NOT enable debug; that is the whole point")
	}
	if !loglevel.Info.Enabled(loglevel.Info) {
		t.Error("info must enable info")
	}
	if loglevel.Error.Enabled(loglevel.Warn) {
		t.Error("error must not enable warn")
	}
}

func TestStringRoundTrips(t *testing.T) {
	for _, l := range []loglevel.Level{
		loglevel.Debug, loglevel.Info, loglevel.Warn, loglevel.Error,
	} {
		got, err := loglevel.Parse(l.String())
		if err != nil {
			t.Errorf("Parse(%q): %v", l.String(), err)
		}
		if got != l {
			t.Errorf("round trip of %v gave %v", l, got)
		}
	}
}
