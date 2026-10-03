package console

import (
	"bytes"
	"regexp"
	"strings"
	"testing"
)

// setRegion is the DECSTBM the bar installs for a barRows-tall terminal.
const setRegion = "\x1b[1;39r"

// regionChanges returns the scroll-region sequences in s.
//
// The bar is allowed to repaint its row at any time; what it must not do
// outside the few events that destroy the region is emit DECSTBM, which homes
// the cursor on some terminals.
func regionChanges(s string) []string {
	return reRegion.FindAllString(s, -1)
}

var reRegion = regexp.MustCompile(`\x1b\[[0-9;]*r`)

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

			// A repaint of the row is expected and wanted -- the erase
			// blanked it. What must NOT appear is a scroll-region change:
			// DECSTBM homes the cursor on some terminals, so emitting one
			// here moves the guest's cursor mid-redraw.
			got := out.String()
			if region := regionChanges(got); len(region) > 0 {
				t.Errorf("erase %q made the bar emit %q, which moves the "+
					"guest's cursor mid-redraw", erase, region)
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

	// The repaint is synchronous: the row is blank from the moment the erase
	// lands, so waiting for the next tick would show a gap.
	out.Reset()
	bar.Observe([]byte("\x1b[2J"))
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

	// The bar repaints its row (the erase blanked it), but must not touch
	// the scroll region: that is what moved the guest's cursor.
	if region := regionChanges(out.String()); len(region) > 0 {
		t.Errorf("bar emitted %q during a line redraw, which moves the "+
			"guest's cursor", region)
	}
}

// The erase blanks the bar's row, so the repaint has to happen in the same
// call that observes it. Deferring to the draw loop leaves the row empty
// until the next tick, and that gap is visible: BusyBox ash erases to the end
// of the screen on every keystroke, so holding an arrow key made the bar
// blink once per key repeat. Measured against the live deployment, the row
// was blank for 8-38ms per keypress.
//
// Asserting on the terminal rather than on a flag is deliberate: what matters
// is that the bytes have been written by the time Observe returns, not that
// something was scheduled.
func TestEraseRepaintsWithoutWaitingForTheTick(t *testing.T) {
	var out bytes.Buffer
	bar := newHeldBar(&out)

	// Paint once so the only reason for a further paint is the erase.
	bar.draw()

	out.Reset()
	bar.Observe([]byte("\x1b[J"))

	got := out.String()
	if got == "" {
		t.Fatal("the bar row stayed blank after an erase: the repaint was " +
			"deferred to the draw loop, which is the flicker")
	}
	if !strings.Contains(got, "\x1b[40;1H") {
		t.Errorf("no repaint of the bar row in %q", got)
	}
}
