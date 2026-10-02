package console

import (
	"bytes"
	"strings"
	"testing"
)

// shrunkRows is a terminal one row shorter than barRows, used to resize into.
const shrunkRows = barRows - 1

// A guest that sets its own scroll region replaces the bar's reservation. The
// bar's row is then inside the guest's scrolling area and the guest scrolls
// through it, so the region has to be reinstalled rather than merely
// repainted.
//
// curses applications do this, and so does "tput csr". Nothing else reveals
// it: the region is write-only state, so it has to come from the stream.
func TestGuestScrollRegionIsReinstated(t *testing.T) {
	var out bytes.Buffer
	bar := newHeldBar(&out)

	out.Reset()
	bar.Observe([]byte("\x1b[1;10r")) // the guest takes rows 1..10

	got := out.String()
	want := "\x1b[1;39r" // the bar's region, reinstated
	if !strings.Contains(got, want) {
		t.Errorf("bar did not reinstate its scroll region after the guest "+
			"set one: got %q, want it to contain %q", got, want)
	}
	// The guest will have left the cursor inside its own region, which may
	// be outside the reinstated one, so it has to be put back.
	if !strings.Contains(got, "\x1b[1;1H") {
		t.Errorf("bar did not reposition the cursor after reinstating the "+
			"region: %q", got)
	}
}

// A guest resetting the region to the full screen is the same problem: the
// bar's row stops being reserved.
func TestGuestFullScreenRegionIsReinstated(t *testing.T) {
	var out bytes.Buffer
	bar := newHeldBar(&out)

	out.Reset()
	bar.Observe([]byte("\x1b[r"))

	if !strings.Contains(out.String(), "\x1b[1;39r") {
		t.Errorf("bar did not reinstate its region after the guest reset "+
			"the region: %q", out.String())
	}
}

// DECOM makes row coordinates relative to the scroll region and rows outside
// it unreachable. The bar's row is outside by construction, so an absolute
// move would be clamped into the guest's area and the bar would paint over
// the guest's bottom line. Not drawing is the lesser evil.
func TestBarDoesNotDrawUnderOriginMode(t *testing.T) {
	var out bytes.Buffer
	bar := newHeldBar(&out)

	bar.Observe([]byte("\x1b[?6h")) // DECOM on
	out.Reset()
	bar.draw()
	if out.Len() != 0 {
		t.Errorf("bar drew %q under origin mode, where its absolute row "+
			"coordinate is clamped into the guest's area", out.String())
	}
}

// ...and it comes back when the guest clears DECOM, rather than staying off
// for the rest of the session.
func TestBarReturnsWhenOriginModeIsCleared(t *testing.T) {
	var out bytes.Buffer
	bar := newHeldBar(&out)

	bar.Observe([]byte("\x1b[?6h"))
	out.Reset()
	bar.draw()
	if out.Len() != 0 {
		t.Fatalf("bar drew under origin mode: %q", out.String())
	}

	bar.Observe([]byte("\x1b[?6l"))
	out.Reset()
	bar.draw()
	if out.Len() == 0 {
		t.Error("bar never returned after the guest cleared origin mode")
	}
}

// A reset clears DECOM along with every other mode, so the bar must not stay
// suppressed after one.
func TestResetClearsOriginMode(t *testing.T) {
	var out bytes.Buffer
	bar := newHeldBar(&out)

	bar.Observe([]byte("\x1b[?6h"))
	bar.Observe([]byte("\x1bc")) // RIS

	out.Reset()
	bar.draw()
	if out.Len() == 0 {
		t.Error("bar still suppressed after a terminal reset cleared DECOM")
	}
}

// Modes that merely look similar must not suppress the bar. ?6 is DECOM; ?7
// is autowrap and ?1049 is the alternate screen, which has its own handling.
func TestUnrelatedModesDoNotSuppressTheBar(t *testing.T) {
	for _, seq := range []string{
		"\x1b[?7h",  // autowrap
		"\x1b[?25l", // hide cursor
		"\x1b[6n",   // DSR cursor report: ends in 'n', not 'r'
		"\x1b[0m",   // SGR
	} {
		var out bytes.Buffer
		bar := newHeldBar(&out)
		bar.Observe([]byte(seq))
		out.Reset()
		bar.draw()
		if out.Len() == 0 {
			t.Errorf("bar suppressed by unrelated sequence %q", seq)
		}
	}
}

// Shrinking the terminal moves the bar's row up, which can leave the cursor
// below the new region -- or on the bar's own row. Start positions the cursor
// explicitly after installing the region, documenting that DECSTBM homes it
// on some terminals and not others; Resize has to do the same or every
// SIGWINCH silently teleports the guest's cursor.
func TestResizePutsTheCursorBackInsideTheRegion(t *testing.T) {
	var out bytes.Buffer
	bar := newHeldBar(&out)

	out.Reset()
	bar.Resize(barCols, shrunkRows)

	got := out.String()
	if !strings.Contains(got, "\x1b[1;38r") {
		t.Errorf("resize did not reinstall the region at the new height: %q", got)
	}
	if !strings.Contains(got, "\x1b[38;1H") {
		t.Errorf("resize left the cursor outside the new region: %q, want it "+
			"to contain a move to row 38", got)
	}
}

// Growing the terminal cannot strand the cursor: every row it could be on is
// still inside the larger region. Moving it anyway would discard the guest's
// position on the terminals that leave the cursor alone, which is most of
// them, so the move is deliberately conditional.
func TestResizeDoesNotMoveTheCursorWhenGrowing(t *testing.T) {
	var out bytes.Buffer
	bar := newHeldBar(&out)

	out.Reset()
	bar.Resize(barCols, barRows+10)

	got := out.String()
	if !strings.Contains(got, "\x1b[1;49r") {
		t.Errorf("resize did not reinstall the region: %q", got)
	}
	if strings.Contains(got, ";1H") {
		t.Errorf("resize moved the cursor while growing, discarding the "+
			"guest's position: %q", got)
	}
}
