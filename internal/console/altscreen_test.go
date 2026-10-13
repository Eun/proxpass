package console

import (
	"fmt"
	"strings"
	"testing"
)

// Leaving a full-screen application must not move the guest's cursor.
//
// The reported symptom: open vi, quit it, and the cursor is on line 1 rather
// than back at the shell prompt vi was started from. Reported on a container,
// so it is not the resize path -- no window changed size.
//
// The cause is the same false premise #109 removed from Resize, left behind in
// Observe: the region-reinstall path hard-homed the cursor with "\x1b[1;1H".
// That is correct only if DECSTBM leaves the cursor alone, which no terminal
// does. Exiting the alternate screen restores the normal screen's cursor
// position -- that is what makes vi return you to your prompt -- and the bar
// then threw that restored position away.
//
// The bar's own escape hatch cannot help here either: the row below the
// prompt is the guest's, so a repaint does not repair the cursor.

// altScreenCols and altScreenRows are a terminal with room for a bar.
const (
	altScreenCols = 80
	altScreenRows = 24
)

// enterAndLeaveAltScreen runs the sequence a full-screen application produces:
// switch to the alternate screen, draw, then switch back. Real applications
// use ?1049, which saves and restores the cursor itself.
func enterAndLeaveAltScreen(t *testing.T, bar *StatusBar) {
	t.Helper()
	feedGuest(bar, "\x1b[?1049h")
	feedGuest(bar, "\x1b[1;1H~\r\n~\r\n~")
	feedGuest(bar, "\x1b[?1049l")
}

func TestLeavingAFullScreenApplicationKeepsTheCursor(t *testing.T) {
	s := realScreen(altScreenCols, altScreenRows)
	bar := newScreenBar(s, &screenWriter{s: s})

	// A shell prompt partway down the screen, where the user ran vi from.
	s.feed("\x1b[9;12H")
	wantRow, wantCol := s.at()

	enterAndLeaveAltScreen(t, bar)
	bar.draw()

	gotRow, gotCol := s.at()
	if gotRow != wantRow || gotCol != wantCol {
		t.Errorf("after leaving the alternate screen the cursor is at (%d,%d), "+
			"want (%d,%d): the guest was returned to the top of the screen "+
			"instead of to the prompt it started the application from",
			gotRow, gotCol, wantRow, wantCol)
	}
}

// The shell's next output has to continue at the prompt, which is what the
// user actually sees go wrong.
func TestOutputAfterLeavingAFullScreenApplicationLandsAtThePrompt(t *testing.T) {
	s := realScreen(altScreenCols, altScreenRows)
	bar := newScreenBar(s, &screenWriter{s: s})

	// Scrollback the user still wants, and a prompt below it.
	s.feed("\x1b[1;1H")
	for i := 1; i <= 4; i++ {
		feedGuest(bar, fmt.Sprintf("line %d\r\n", i))
	}
	feedGuest(bar, "$ ")
	wantRow, _ := s.at()

	enterAndLeaveAltScreen(t, bar)
	feedGuest(bar, "typed")
	bar.draw()

	if got := s.line(1); got != "line 1" {
		t.Errorf("row 1 is %q, want %q: output after quitting the application "+
			"overwrote the top of the screen\nscreen:\n%s",
			got, "line 1", s.render())
	}
	if got := s.line(wantRow); !strings.Contains(got, "typed") {
		t.Errorf("row %d is %q, want it to contain %q: the shell did not "+
			"resume at its prompt\nscreen:\n%s",
			wantRow, got, "typed", s.render())
	}
}

// The region must still come back, or the guest scrolls through the bar's row
// afterwards. This is what the hard-homing was protecting and must not be
// lost by fixing the cursor.
func TestLeavingAFullScreenApplicationReinstatesTheRegion(t *testing.T) {
	s := realScreen(altScreenCols, altScreenRows)
	bar := newScreenBar(s, &screenWriter{s: s})

	enterAndLeaveAltScreen(t, bar)
	bar.draw()

	if top, bottom := s.region(); top != 1 || bottom != altScreenRows-1 {
		t.Errorf("after leaving the alternate screen the scroll region is "+
			"%d..%d, want 1..%d: the bar's row is not reserved",
			top, bottom, altScreenRows-1)
	}

	// Prove it by scrolling past the bottom of the guest's area.
	s.feed("\x1b[1;1H")
	for i := 0; i < altScreenRows+6; i++ {
		feedGuest(bar, fmt.Sprintf("row %d\r\n", i))
	}
	bar.draw()
	if got := s.line(s.barRow()); !strings.Contains(got, "webserver") {
		t.Errorf("the guest scrolled through the bar's row: row %d is %q",
			s.barRow(), got)
	}
}

// The other two paths into the same branch must not home the cursor either.
//
// A guest that installs its own scroll region ("tput csr", any curses
// application) and a guest that resets the terminal both land in the same
// reinstall. A reset legitimately homes the cursor itself -- RIS clears the
// screen -- so only the region-lost case is asserted on position here.
func TestAGuestSettingItsOwnRegionKeepsItsCursor(t *testing.T) {
	s := realScreen(altScreenCols, altScreenRows)
	bar := newScreenBar(s, &screenWriter{s: s})

	s.feed("\x1b[14;30H")

	// The guest installs its own region and stays where it is.
	feedGuest(bar, "\x1b[1;20r")
	wantRow, wantCol := s.at()
	bar.draw()

	gotRow, gotCol := s.at()
	if gotRow != wantRow || gotCol != wantCol {
		t.Errorf("reinstating the bar's region moved the guest's cursor from "+
			"(%d,%d) to (%d,%d)", wantRow, wantCol, gotRow, gotCol)
	}
	if top, bottom := s.region(); top != 1 || bottom != altScreenRows-1 {
		t.Errorf("the bar did not reinstate its region after the guest "+
			"replaced it: region is %d..%d", top, bottom)
	}
}
