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

	// Observe repaints synchronously, so the paint lands here rather than on
	// the next draw().
	out.Reset()
	bar.Observe([]byte("\x1b[?6l"))
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

	out.Reset()
	bar.Observe([]byte("\x1bc")) // RIS
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

// Resizing must reinstall the region at the new height and give the guest
// back the cursor DECSTBM took.
//
// These two tests previously asserted the opposite and passed while the bug
// shipped: they pinned a move to row 38 when shrinking and the *absence* of
// any move when growing. Both followed from the belief that DECSTBM homes the
// cursor "on some terminals and leaves it alone on others", so that growing
// was safe and shrinking needed only a clamp into the region.
//
// Neither half holds. DECSTBM homes the cursor on every terminal checked, so
// growing strands it just as badly as shrinking; and a clamp to row 38
// column 1 is not where the guest was anyway. See reinstallRegion.
func TestResizeRestoresTheCursorWhenShrinking(t *testing.T) {
	var out bytes.Buffer
	bar := newHeldBar(&out)

	out.Reset()
	bar.Resize(barCols, shrunkRows)

	got := out.String()
	if !strings.Contains(got, "\x1b[1;38r") {
		t.Errorf("resize did not reinstall the region at the new height: %q", got)
	}
	if !strings.HasPrefix(got, "\x1b7") || !strings.HasSuffix(got, "\x1b8") {
		t.Errorf("resize did not bracket the region change with a cursor "+
			"save and restore: %q", got)
	}
}

func TestResizeRestoresTheCursorWhenGrowing(t *testing.T) {
	var out bytes.Buffer
	bar := newHeldBar(&out)

	out.Reset()
	bar.Resize(barCols, barRows+10)

	got := out.String()
	if !strings.Contains(got, "\x1b[1;49r") {
		t.Errorf("resize did not reinstall the region: %q", got)
	}
	if !strings.HasPrefix(got, "\x1b7") || !strings.HasSuffix(got, "\x1b8") {
		t.Errorf("growing left the cursor wherever DECSTBM put it: %q, want "+
			"the region change bracketed by a save and restore", got)
	}
}
