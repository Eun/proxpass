package console

import (
	"bytes"
	"strings"
	"testing"
)

// setRegion is the DECSTBM the bar installs for a barRows-tall terminal.
const setRegion = "\x1b[1;39r"

// The bug: an erase made the bar reinstall its scroll region, and DECSTBM
// homes the cursor on some terminals -- which Start's own comment records,
// and compensates for by positioning the cursor explicitly.
//
// BusyBox ash redraws its input line with ED on every keystroke: carriage
// return, reprint the prompt and line, then "\x1b[J" to erase the remains. So
// every arrow key made the bar emit DECSTBM into the middle of that redraw,
// and the guest's cursor jumped to the top of the screen. bash computes the
// line itself and never emits ED, which is why the fault looked like it lived
// in the shell rather than in the bar.
//
// An erase does not destroy the scroll region. Only the row's contents are
// gone, so the bar must repaint the row and touch nothing else.
func TestEraseRepaintsTheRowWithoutTouchingTheRegion(t *testing.T) {
	for _, erase := range []string{
		"\x1b[J",  // erase to end of screen: ash's line redraw
		"\x1b[0J", // the same, explicitly
		"\x1b[2J", // whole screen: Ctrl+L
		"\x1b[3J", // whole screen plus scrollback
	} {
		t.Run(strings.TrimPrefix(erase, "\x1b"), func(t *testing.T) {
			var out bytes.Buffer
			bar := newHeldBar(&out)

			out.Reset()
			bar.Observe([]byte(erase))

			if got := out.String(); got != "" {
				t.Errorf("erase %q made the bar write %q; DECSTBM homes the "+
					"cursor on some terminals, so this moves the guest's "+
					"cursor mid-redraw", erase, got)
			}
		})
	}
}

// The repaint itself must still happen: the erase wiped the bar's row, and
// the unchanged-repaint check would otherwise suppress the redraw forever
// because the text has not changed.
func TestEraseStillRepaintsTheBar(t *testing.T) {
	var out bytes.Buffer
	bar := newHeldBar(&out)

	// Paint once so lastBar holds the current text.
	bar.draw()
	if out.Len() == 0 {
		t.Fatal("bar did not paint initially")
	}

	bar.Observe([]byte("\x1b[2J"))
	out.Reset()
	bar.draw()
	if out.Len() == 0 {
		t.Error("bar did not repaint after its row was erased")
	}
}

// The three events that genuinely destroy the region must still reinstall it,
// with the cursor put back inside.
func TestRegionIsReinstalledWhenItIsActuallyGone(t *testing.T) {
	for _, tc := range []struct{ name, seq string }{
		{"terminal reset", "\x1b\x63"}, // RIS
		{"guest set its own region", "\x1b[1;10r"},
		{"returned from the alternate screen", "\x1b[?1049l"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			bar := newHeldBar(&out)
			if tc.seq == "\x1b[?1049l" {
				// Has to be on the alternate screen to come back from it.
				bar.Observe([]byte("\x1b[?1049h"))
			}

			out.Reset()
			bar.Observe([]byte(tc.seq))

			got := out.String()
			if !strings.Contains(got, setRegion) {
				t.Errorf("region not reinstalled after %s: %q", tc.name, got)
			}
			if !strings.Contains(got, "\x1b[1;1H") {
				t.Errorf("cursor not put back inside the region after %s: %q",
					tc.name, got)
			}
		})
	}
}

// Entering the alternate screen still releases the region, so the full-screen
// application gets every row.
func TestAltScreenEntryStillReleasesTheRegion(t *testing.T) {
	var out bytes.Buffer
	bar := newHeldBar(&out)

	out.Reset()
	bar.Observe([]byte("\x1b[?1049h"))

	if got := out.String(); !strings.Contains(got, "\x1b[r") {
		t.Errorf("bar did not release the region on alt-screen entry: %q", got)
	}
}

// A line redraw as ash actually performs it must leave the region alone from
// start to finish: the whole sequence is one erase plus ordinary text.
func TestAshStyleLineRedrawNeverMovesTheCursor(t *testing.T) {
	var out bytes.Buffer
	bar := newHeldBar(&out)

	// \r, reprint the prompt and the line, erase what the old line left.
	out.Reset()
	bar.Observe([]byte("\rproxpass:~# echo hello\x1b[J"))

	got := out.String()
	if strings.Contains(got, "r") && strings.Contains(got, "\x1b[1;") {
		t.Errorf("bar emitted a scroll-region change during a line redraw: %q", got)
	}
	if got != "" {
		t.Errorf("bar wrote %q during a plain line redraw, want nothing", got)
	}
}
