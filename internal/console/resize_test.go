package console

import (
	"fmt"
	"strings"
	"testing"
)

// The user-visible report this file exists for:
//
//	"the screen gets messed up, especially in VMs with serial console,
//	 when resizing the console"
//
// The VM qualifier is the clue. A container console is a PTY: when the window
// changes, the guest gets SIGWINCH and its shell redraws, which papers over a
// cursor that the bar left in the wrong place. A VM serial console is an
// emulated UART with no window-size concept at all, so the guest never learns
// the geometry changed and never redraws. Anything the bar does to the cursor
// on resize is therefore permanent there and transient on a CT -- which is
// exactly the asymmetry the report describes.
//
// That makes resize correctness a property of the screen, not of the bytes.
// These tests drive the real StatusBar against screenModel so they can assert
// where the guest's text and cursor actually end up.

const (
	// guestLabel and guestHint stand in for a session's bar content.
	guestLabel = "webserver@pve1 (vm210)"
	guestHint  = "Ctrl+A X: disconnect"

	// A terminal comfortably big enough for a bar, and the sizes a user
	// drags it to.
	startCols, startRows = 80, 24
	grownCols, grownRows = 80, 40
	shrunkCols2          = 80
	shrunkRows2          = 16
)

// screenWriter feeds everything written to it into a screenModel.
type screenWriter struct{ s *screenModel }

func (w *screenWriter) Write(p []byte) (int, error) {
	w.s.feed(string(p))
	return len(p), nil
}

// writeRecorder records each Write call separately, so a test can tell one
// atomic write from several that a guest could interleave with.
type writeRecorder struct {
	s      *screenModel
	writes []string
}

func (w *writeRecorder) Write(p []byte) (int, error) {
	w.writes = append(w.writes, string(p))
	if w.s != nil {
		w.s.feed(string(p))
	}
	return len(p), nil
}

// newScreenBar returns a started bar attached to s, with the draw loop not
// running so every paint is triggered explicitly.
//
// It performs the same initial region install that Start does, so the screen
// begins in the state a real session begins in.
func newScreenBar(s *screenModel, out interface {
	Write([]byte) (int, error)
},
) *StatusBar {
	bar := NewStatusBar(out, s.cols, s.rows)
	bar.SetText(guestLabel, guestHint)
	bar.active = true
	bar.write(fmt.Sprintf("\x1b[1;%dr\x1b[1;1H", bar.guestRowsLocked()))
	return bar
}

// feedGuest sends guest output through the bar exactly as barWriter does.
func feedGuest(bar *StatusBar, text string) {
	n, _ := bar.writeGuest([]byte(text))
	if n > 0 {
		bar.Observe([]byte(text)[:n])
	}
}

// realScreen returns a screen that behaves the way real terminals do.
//
// Both behaviors were verified against implementations rather than assumed,
// because the bar's correctness depends entirely on them:
//
// DECSTBM moves the cursor. DEC's specification requires it -- the VT100 User
// Guide's DECSTBM entry ends "The cursor is placed in the home position", and
// the VT510 manual says "DECSTBM moves the cursor to column 1, line 1 of the
// page" -- and xterm, VTE, alacritty, kitty, foot, wezterm, st, Windows
// Terminal, tmux and GNU screen all implement it. No terminal was found that
// leaves the cursor alone.
//
// A physical resize discards the scroll region: xterm's ScreenResize calls
// resetMargins (screen.c) and VTE's set_size calls reset_scrolling_region
// (vte.cc). That is why the bar must reinstall rather than merely repaint.
func realScreen(cols, rows int) *screenModel {
	s := newScreen(cols, rows)
	s.homesOnDECSTBM = true
	s.resetsRegionOnResize = true
	return s
}

// --- the headline defect ---

// Growing the terminal must not move the guest's cursor.
//
// Resize reinstalls the scroll region unconditionally but repositions the
// cursor only when the terminal shrank, on the stated theory that growing
// cannot strand the cursor. That theory holds only if DECSTBM leaves the
// cursor alone -- and per DEC's own specification it does not. So on a
// growing resize the bar emits a sequence that homes the cursor and then
// deliberately declines to put it back.
//
// On a container the shell's SIGWINCH redraw hides this. On a VM serial
// console nothing redraws, so the guest's next output appears at the top of
// the screen, over whatever was there.
func TestResizeLeavesTheGuestCursorWhereTheGuestLeftIt(t *testing.T) {
	s := realScreen(startCols, startRows)
	bar := newScreenBar(s, &screenWriter{s: s})

	// The guest is at a shell prompt partway down the screen.
	s.feed("\x1b[12;7H")
	wantRow, wantCol := s.at()

	// The window grows. The terminal resizes first, then proxpass reacts.
	s.resize(grownCols, grownRows)
	bar.Resize(grownCols, grownRows)

	gotRow, gotCol := s.at()
	if gotRow != wantRow || gotCol != wantCol {
		t.Errorf("after growing, the guest's cursor moved from (%d,%d) to (%d,%d); "+
			"DECSTBM homes the cursor, so reinstalling the scroll region without "+
			"putting the cursor back teleports the guest to the top of the screen",
			wantRow, wantCol, gotRow, gotCol)
	}
}

// Shrinking must preserve the cursor too, including its column.
//
// The existing reposition moves to column 1 of the last guest row. That is
// safe in the sense that it is inside the region, but it is still not where
// the guest is: a shell that believes its cursor is mid-line will draw the
// rest of the line from the wrong column.
func TestResizeKeepsTheGuestColumnWhenShrinking(t *testing.T) {
	s := realScreen(startCols, startRows)
	bar := newScreenBar(s, &screenWriter{s: s})

	s.feed("\x1b[8;25H")
	wantRow, wantCol := s.at()

	s.resize(shrunkCols2, shrunkRows2)
	bar.Resize(shrunkCols2, shrunkRows2)

	gotRow, gotCol := s.at()
	if gotRow != wantRow || gotCol != wantCol {
		t.Errorf("after shrinking, the guest's cursor moved from (%d,%d) to (%d,%d); "+
			"the row was still inside the new region, so nothing needed to move it",
			wantRow, wantCol, gotRow, gotCol)
	}
}

// The end-to-end form of the report, on the transport where it is permanent.
//
// A VM serial console never receives a window-size change, so the guest does
// not redraw after a resize. Whatever the bar did to the cursor is what the
// next line of output acts on. This reproduces the user's "screen gets messed
// up": output that should continue below the existing text lands on top of
// it instead.
func TestGuestOutputAfterAResizeContinuesWhereItLeftOff(t *testing.T) {
	s := realScreen(startCols, startRows)
	bar := newScreenBar(s, &screenWriter{s: s})

	// Some scrollback the user wants to keep reading.
	s.feed("\x1b[1;1H")
	for i := 1; i <= 5; i++ {
		feedGuest(bar, fmt.Sprintf("line %d\r\n", i))
	}

	// The user drags the window taller. The guest is a serial console: it is
	// told nothing and redraws nothing.
	s.resize(grownCols, grownRows)
	bar.Resize(grownCols, grownRows)

	feedGuest(bar, "line 6\r\n")

	if got := s.line(1); got != "line 1" {
		t.Errorf("row 1 is %q, want %q -- output after the resize overwrote the "+
			"top of the screen instead of continuing below the existing text.\n"+
			"screen:\n%s", got, "line 1", s.render())
	}
	if got := s.line(6); got != "line 6" {
		t.Errorf("row 6 is %q, want %q -- the guest's next line did not land "+
			"where the guest left off.\nscreen:\n%s", got, "line 6", s.render())
	}
}

// --- the region must not be reinstalled while something else owns the screen ---

// A full-screen application owns every row, and the bar releases its scroll
// region when it sees the switch to the alternate screen. A resize while vim
// is running must not quietly take the row back: vim has not been told it
// lost a row, so it keeps drawing its status line on the bottom one and the
// terminal scrolls underneath it.
//
// Resize checks active but not hidden, so it reinstates a region the bar had
// deliberately given up.
func TestResizeDoesNotTakeARowFromAFullScreenApplication(t *testing.T) {
	s := realScreen(startCols, startRows)
	rec := &writeRecorder{s: s}
	bar := newScreenBar(s, rec)

	// vim starts.
	feedGuest(bar, "\x1b[?1049h")
	if top, bottom := s.region(); top != 1 || bottom != s.rows {
		t.Fatalf("bar did not release the scroll region when the alternate "+
			"screen was entered: region is %d..%d", top, bottom)
	}

	rec.writes = nil
	s.resize(grownCols, grownRows)
	bar.Resize(grownCols, grownRows)

	if top, bottom := s.region(); bottom != s.rows {
		t.Errorf("resizing while a full-screen application owned the screen "+
			"reinstalled the bar's scroll region (%d..%d of %d rows); the "+
			"application still believes it has every row",
			top, bottom, s.rows)
	}
}

// A terminal that shrinks below the minimum a bar needs must be left alone,
// for the same reason Start refuses to touch one: the guest would be left
// with almost nothing.
//
// Start checks the size, Resize did not, so dragging a window short enough
// activated a bar that was never allowed to exist.
//
// One row is the case that makes the handling non-obvious. Reserving a row
// there would leave the guest none, and the region it implies ("\x1b[1;1r")
// is degenerate: DEC requires a scrolling region of at least two lines, so a
// terminal is entitled to ignore it and the bar would be left believing it
// had a reservation it does not have. Giving the region up explicitly is
// well defined at every size.
func TestResizeDoesNotInstallABarOnATerminalTooShort(t *testing.T) {
	for _, tiny := range []int{minBarRows - 1, 2, 1} {
		t.Run(fmt.Sprintf("%drows", tiny), func(t *testing.T) {
			s := realScreen(startCols, startRows)
			rec := &writeRecorder{s: s}
			bar := newScreenBar(s, rec)

			rec.writes = nil
			s.resize(startCols, tiny)
			rows := bar.Resize(startCols, tiny)
			bar.draw()

			if rows != tiny {
				t.Errorf("Resize reported %d guest rows on a %d-row terminal, "+
					"want the full %d: a terminal this short gets no bar",
					rows, tiny, tiny)
			}
			if top, bottom := s.region(); top != 1 || bottom != tiny {
				t.Errorf("a terminal too short for a bar had a scroll region "+
					"installed (%d..%d); Start refuses to touch one, so Resize "+
					"must too", top, bottom)
			}
			for _, w := range rec.writes {
				if strings.Contains(w, fmt.Sprintf("\x1b[1;%dr", tiny)) {
					t.Errorf("resize to %d rows emitted %q, a region the guest "+
						"has to share with the bar; want the region released",
						tiny, w)
				}
			}
			if got := s.line(tiny); strings.Contains(got, "webserver") {
				t.Errorf("a bar was drawn on a %d-row terminal: row %d is %q",
					tiny, tiny, got)
			}
		})
	}
}

// --- atomicity ---

// The region change and the cursor reposition have to reach the terminal as
// one write.
//
// draw() already builds its repaint in full before writing, for the stated
// reason that several smaller writes let guest output interleave and tear the
// result. Resize has exactly the same exposure and a worse consequence: a
// guest write landing between DECSTBM and the reposition is interpreted with
// the cursor homed, so the guest's own output is what lands in the wrong
// place.
func TestResizeChangesTheRegionAndCursorInOneWrite(t *testing.T) {
	s := realScreen(startCols, startRows)
	rec := &writeRecorder{s: s}
	bar := newScreenBar(s, rec)

	s.feed("\x1b[10;3H")
	rec.writes = nil

	s.resize(shrunkCols2, shrunkRows2)
	bar.Resize(shrunkCols2, shrunkRows2)

	var touching []string
	for _, w := range rec.writes {
		if strings.Contains(w, "r") || strings.Contains(w, "H") ||
			strings.Contains(w, "\x1b7") || strings.Contains(w, "\x1b8") {
			touching = append(touching, w)
		}
	}
	if len(touching) > 1 {
		t.Errorf("resize reached the terminal as %d separate writes (%q); guest "+
			"output can land between them, and until the sequence completes the "+
			"cursor is wherever DECSTBM left it", len(touching), touching)
	}
}

// --- the guest's cursor-save slot ---

// A terminal has one cursor-save slot and the guest may be holding it.
//
// draw() already yields the slot for exactly this reason. If Resize restores
// the cursor with DECSC/DECRC it acquires the same obligation: a resize that
// arrives between a shell's save and its restore would otherwise overwrite
// the position the shell is about to return to, and the shell's cursor would
// land wherever the bar's was.
//
// The guest must have moved between its save and the resize, or the test
// cannot tell the two slots apart: if the bar borrows the slot while the
// cursor is still where the guest saved it, it writes back the same value and
// the damage is invisible. A shell redrawing its input line does move -- that
// is what the save is for -- so the sequence here is the real one.
func TestResizeDoesNotClobberTheGuestCursorSaveSlot(t *testing.T) {
	s := realScreen(startCols, startRows)
	bar := newScreenBar(s, &screenWriter{s: s})

	// The shell saves at its prompt, then moves away to redraw the line.
	s.feed("\x1b[9;14H")
	feedGuest(bar, "\x1b7")
	savedRow, savedCol := s.at()
	feedGuest(bar, "\x1b[9;1Hprompt$ the line being redrawn")

	// A resize arrives mid-redraw.
	s.resize(grownCols, grownRows)
	bar.Resize(grownCols, grownRows)

	// The shell finishes its redraw and restores.
	feedGuest(bar, "\x1b8")

	gotRow, gotCol := s.at()
	if gotRow != savedRow || gotCol != savedCol {
		t.Errorf("the guest restored its cursor to (%d,%d) but had saved (%d,%d); "+
			"a resize overwrote the terminal's only cursor-save slot",
			gotRow, gotCol, savedRow, savedCol)
	}
}

// Narrowing the window must repaint the bar at the new width rather than
// leave the old, wider text in place.
//
// A terminal does not reflow a line that is already on screen, so a bar
// written at 100 columns keeps its trailing content when the window shrinks
// to 60 -- as a wrapped second line, or simply as text past the new edge.
// The guest cannot clean it up: the row is outside its scroll region.
func TestNarrowingRepaintsTheBarAtTheNewWidth(t *testing.T) {
	const (
		wideCols   = 100
		narrowCols = 60
	)
	s := realScreen(wideCols, startRows)
	bar := newScreenBar(s, &screenWriter{s: s})
	bar.draw()

	s.resize(narrowCols, startRows)
	bar.Resize(narrowCols, startRows)
	bar.draw()

	got := s.line(s.barRow())
	if cellWidth(got) > narrowCols {
		t.Errorf("after narrowing to %d columns the bar row is %d columns "+
			"wide: %q", narrowCols, cellWidth(got), got)
	}
	if !strings.Contains(got, "webserver") {
		t.Errorf("the bar did not repaint after narrowing: row %d is %q",
			s.barRow(), got)
	}
}

// Dragging a window resizes it many times in quick succession, and the bar
// has to be correct after the whole sequence rather than only after a single
// step. Each intermediate size emits its own DECSTBM, so an error in the
// cursor handling compounds across the drag rather than canceling out.
//
// The drag passes through sizes too short for a bar, where the region is
// given up and later taken back. That release is "\x1b[r" -- DECSTBM with
// omitted parameters, which homes the cursor exactly as setting a region
// does. Releasing therefore needs the same cursor handling as installing,
// and it is easy to miss because the sequence reads like a reset.
//
// The column is the assertion that matters. A terminal clamps the cursor
// onto a screen that no longer has that many rows, and that loss is the
// terminal's, not the bar's -- but nothing clamps a column that still
// exists, so a column that moved was moved by us.
func TestDraggingThroughManySizesDoesNotAccumulateCursorDrift(t *testing.T) {
	s := realScreen(startCols, grownRows)
	bar := newScreenBar(s, &screenWriter{s: s})

	s.feed("\x1b[7;11H")
	wantRow, wantCol := s.at()

	for _, size := range []struct{ cols, rows int }{
		{78, 36}, {70, 20}, {64, 8}, {64, minBarRows}, {64, minBarRows - 1},
		{70, 12}, {80, 30}, {startCols, grownRows},
	} {
		s.resize(size.cols, size.rows)
		bar.Resize(size.cols, size.rows)
		bar.draw()
	}

	if _, gotCol := s.at(); gotCol != wantCol {
		t.Errorf("after a drag through eight sizes the guest's cursor is in "+
			"column %d, want %d: every width in the drag was wider than the "+
			"column, so nothing clamped it", gotCol, wantCol)
	}
	// The row can only have been lost to the 3-row screen in the middle of
	// the drag, which no amount of care on our side can preserve.
	if gotRow, _ := s.at(); gotRow > wantRow {
		t.Errorf("the guest's cursor moved down to row %d, want at most %d",
			gotRow, wantRow)
	}
	if top, bottom := s.region(); top != 1 || bottom != grownRows-1 {
		t.Errorf("after returning to the original size the region is %d..%d, "+
			"want 1..%d", top, bottom, grownRows-1)
	}
}

// A drag that never goes below the bar's minimum must not move the cursor at
// all: nothing clamps it, so any movement is the bar's doing.
func TestDraggingAboveTheMinimumNeverMovesTheCursor(t *testing.T) {
	s := realScreen(startCols, grownRows)
	bar := newScreenBar(s, &screenWriter{s: s})

	s.feed("\x1b[6;9H")
	wantRow, wantCol := s.at()

	for _, size := range []struct{ cols, rows int }{
		{78, 36}, {70, 30}, {64, 12}, {70, 18}, {80, 34}, {startCols, grownRows},
	} {
		s.resize(size.cols, size.rows)
		bar.Resize(size.cols, size.rows)
		bar.draw()
	}

	gotRow, gotCol := s.at()
	if gotRow != wantRow || gotCol != wantCol {
		t.Errorf("after a drag that stayed above the bar's minimum the guest's "+
			"cursor is at (%d,%d), want (%d,%d)", gotRow, gotCol, wantRow, wantCol)
	}
}

// The one case the bar does not fix, pinned so it stays understood and
// cannot silently get worse.
//
// DECRC clamps to the screen rather than to the scroll region when DECOM is
// reset, which it always is here. So a terminal that shrinks past the guest's
// cursor clamps that cursor onto the new bottom row -- the bar's row -- and
// the restore puts it back there. The guest's row had ceased to exist, so
// there is no correct answer and every terminal would have clamped it
// somewhere.
//
// The recovery is an absolute move, not a line feed. A cursor below the
// scroll region is not scrolled by one and is already on the last row, so it
// stays put and the guest keeps writing over the bar. An interactive shell
// repositions at its next prompt; a guest that got SIGWINCH redraws at once.
// On a VM serial console neither happens on its own, which is the residual
// cost of the trade and the reason it is documented rather than hidden.
func TestACursorClampedOntoTheBarRow(t *testing.T) {
	s := realScreen(startCols, startRows)
	bar := newScreenBar(s, &screenWriter{s: s})

	// The guest is on the last row it owns before the resize.
	s.feed(fmt.Sprintf("\x1b[%d;40H", startRows-1))

	s.resize(startCols, shrunkRows2)
	bar.Resize(startCols, shrunkRows2)
	bar.draw()

	// The bar repaints over the row regardless of where the cursor is, so
	// the bar itself is never lost.
	if got := s.line(s.barRow()); !strings.Contains(got, "webserver") {
		t.Errorf("the bar did not repaint over a cursor clamped onto its row: "+
			"row %d is %q", s.barRow(), got)
	}

	// The guest recovers as soon as it positions itself absolutely, which is
	// what a prompt or a redraw does.
	feedGuest(bar, "\x1b[5;1Hguest is back")
	bar.draw()
	if got := s.line(5); !strings.Contains(got, "guest is back") {
		t.Errorf("the guest did not recover after an absolute move: row 5 is "+
			"%q\nscreen:\n%s", got, s.render())
	}
	if got := s.line(s.barRow()); !strings.Contains(got, "webserver") {
		t.Errorf("the bar did not survive the guest's recovery: row %d is %q",
			s.barRow(), got)
	}
}

// --- the bar's row stays reserved afterwards ---

// After a resize the region must actually protect the new bottom row, or the
// guest scrolls through the bar and the bar's repaint fights the guest's
// output for the same line.
func TestTheBarRowIsStillReservedAfterAResize(t *testing.T) {
	s := realScreen(startCols, startRows)
	bar := newScreenBar(s, &screenWriter{s: s})

	s.resize(grownCols, grownRows)
	bar.Resize(grownCols, grownRows)
	bar.draw()

	// Fill well past the bottom of the guest's area so the region has to
	// scroll.
	s.feed("\x1b[1;1H")
	for i := 0; i < grownRows+10; i++ {
		feedGuest(bar, fmt.Sprintf("row %d\r\n", i))
	}
	bar.draw()

	if got := s.line(s.barRow()); !strings.Contains(got, "webserver") {
		t.Errorf("after a resize the guest scrolled through the bar's row: "+
			"row %d is %q, want the bar", s.barRow(), got)
	}
}
