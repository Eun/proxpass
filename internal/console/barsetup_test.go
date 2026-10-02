package console

import (
	"bytes"
	"strings"
	"testing"
)

func TestBarDisabledEnvIsTruthy(t *testing.T) {
	for _, tc := range []struct {
		val  string
		want bool
	}{
		{"", false},
		{"0", false},
		{"no", false},
		{"false", false},
		{"FALSE", false},
		{" 0 ", false},
		{"1", true},
		{"true", true},
		{"yes", true},
		{"anything", true},
	} {
		t.Run(tc.val, func(t *testing.T) {
			t.Setenv(DisableStatusBarEnv, tc.val)
			if got := barDisabled(); got != tc.want {
				t.Errorf("%s=%q: barDisabled() = %v, want %v",
					DisableStatusBarEnv, tc.val, got, tc.want)
			}
		})
	}
}

// A bar is only drawn on a raw PTY that is tall enough. Everywhere else the
// escape sequences would be noise in the output, so startBar must hand back
// the terminal unchanged and the full height.
func TestStartBarSkipsUnsuitableTerminals(t *testing.T) {
	for _, tc := range []struct {
		name string
		term *Terminal
	}{
		{"not raw", &Terminal{Out: &bytes.Buffer{}, Width: 80, Height: 24}},
		{"no writer", &Terminal{Raw: true, Width: 80, Height: 24}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bar, out, rows := startBar(tc.term, "label", testHint)
			if bar != nil {
				bar.Stop()
				t.Error("a bar was started on an unsuitable terminal")
			}
			if rows != tc.term.Height {
				t.Errorf("guest rows = %d, want the full %d", rows, tc.term.Height)
			}
			if out == nil {
				t.Error("startBar returned a nil writer")
			}
			if WillDrawBar(tc.term) {
				t.Error("WillDrawBar disagrees with startBar")
			}
		})
	}
}

// The env var must actually suppress the bar, and WillDrawBar must agree so
// the session does not hide the escape hint when no bar will show it.
func TestStartBarHonorsTheDisableEnv(t *testing.T) {
	t.Setenv(DisableStatusBarEnv, "1")
	term := &Terminal{Out: &bytes.Buffer{}, Raw: true, Width: 80, Height: 24}

	bar, _, rows := startBar(term, "label", testHint)
	if bar != nil {
		bar.Stop()
		t.Error("a bar was started even though it is disabled")
	}
	if rows != 24 {
		t.Errorf("guest rows = %d, want the full 24 when disabled", rows)
	}
	if WillDrawBar(term) {
		t.Error("WillDrawBar must be false when the bar is disabled")
	}
}

// On a suitable terminal a bar is created and one row is reserved.
func TestStartBarReservesARowOnARawTerminal(t *testing.T) {
	t.Setenv(DisableStatusBarEnv, "")
	buf := &lockedBuffer{}
	term := &Terminal{Out: buf, Raw: true, Width: 80, Height: 24}

	if !WillDrawBar(term) {
		t.Fatal("WillDrawBar should be true for a raw 80x24 terminal")
	}
	bar, out, rows := startBar(term, "label", testHint)
	if bar == nil {
		t.Fatal("no bar was started on a raw terminal")
	}
	defer bar.Stop()
	if rows != 23 {
		t.Errorf("guest rows = %d, want 23", rows)
	}
	if out == term.Out {
		t.Error("guest output should be routed through the bar's observer")
	}
	waitForBar(t, buf, "label")
}

// A terminal too short for a bar must keep its full height.
func TestWillDrawBarRejectsShortTerminals(t *testing.T) {
	t.Setenv(DisableStatusBarEnv, "")
	term := &Terminal{Out: &bytes.Buffer{}, Raw: true, Width: 80, Height: 2}
	if WillDrawBar(term) {
		t.Error("a 2-row terminal must not get a bar")
	}
}

// The observer must pass guest output through byte for byte: it exists to
// watch the stream, not to rewrite it.
func TestBarWriterForwardsDataUnchanged(t *testing.T) {
	// The bar and the guest share one terminal, as they do in a session:
	// barWriter reaches it through the bar so the two cannot interleave.
	sink := &lockedBuffer{}
	bar := NewStatusBar(sink, 80, 24)
	bar.Start()
	defer bar.Stop()

	w := &barWriter{bar: bar}

	const payload = "line one\n\x1b[31mred\x1b[0m\n\x1b[?1049hfullscreen"
	n, err := w.Write([]byte(payload))
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	if n != len(payload) {
		t.Errorf("wrote %d bytes, want %d", n, len(payload))
	}
	// The sink also holds the bar's own setup bytes, because the bar and the
	// guest now share one writer. What matters is that the guest's payload
	// reaches it as one unbroken, unmodified run: a rewriting proxy would
	// alter it, and an unsynchronized one could have a repaint spliced into
	// the middle of it.
	if !strings.Contains(sink.String(), payload) {
		t.Errorf("guest data was altered or interleaved:\n got %q\nwant it to contain %q",
			sink.String(), payload)
	}
}
