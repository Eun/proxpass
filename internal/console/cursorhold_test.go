package console

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

// guestPromptRow and guestPromptCol are where the guest's cursor sits when it
// saves: a shell prompt partway down the screen.
const (
	guestPromptRow = 5
	guestPromptCol = 10
)

// barRows and barCols are a terminal big enough for a bar.
const (
	barRows = 40
	barCols = 80
)

// newHeldBar returns a started bar writing to buf, with the draw loop not
// running so draws can be triggered deterministically.
func newHeldBar(buf *bytes.Buffer) *StatusBar {
	bar := NewStatusBar(buf, barCols, barRows)
	bar.SetText("webserver (ct100) @ pve1", EscapeHint)
	bar.active = true
	return bar
}

// The bug this guards: a terminal has one cursor-save slot, the bar used it on
// every repaint, and nothing noticed when the guest was using it too.
//
// terminfo defines sc=\E7 and rc=\E8, so a shell line editor saves and
// restores the cursor whenever it redraws -- which is exactly what an arrow
// key or Home/End causes. If the bar repaints in between, the guest's restore
// moves its cursor to wherever the bar was instead of where the guest left it.
//
// The sequence below is the reported failure, driven through the real draw().
func TestBarDoesNotClobberTheGuestSavedCursor(t *testing.T) {
	var out bytes.Buffer
	bar := newHeldBar(&out)
	term := &cursorModel{}

	// The guest is at its prompt and saves the cursor, as terminfo "sc".
	guest := func(s string) {
		bar.Observe([]byte(s))
		term.feed(s)
	}
	guest("\x1b[5;10H")
	guest("\x1b7")

	// It moves away to redraw part of the line.
	guest("\x1b[2;1H")

	// The bar's tick lands here. This must not touch the save slot.
	out.Reset()
	bar.draw()
	term.feed(out.String())

	// The guest restores, expecting its prompt back.
	guest("\x1b8")

	row, col := term.at()
	if row != guestPromptRow || col != guestPromptCol {
		t.Errorf("guest cursor restored to (%d,%d), want (%d,%d): the bar "+
			"overwrote the guest's saved position", row, col,
			guestPromptRow, guestPromptCol)
	}
}

// Both spellings have to hold the bar off. terminfo uses the two-byte DEC
// form, but the CSI form is what shox matched and some applications emit it,
// so a fix that handles only one of them leaves the bug reachable.
func TestBarYieldsTheCursorSlotForBothSpellings(t *testing.T) {
	for _, tc := range []struct{ name, save, restore string }{
		{"DECSC/DECRC", "\x1b7", "\x1b8"},
		{"CSI s/u", "\x1b[s", "\x1b[u"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			bar := newHeldBar(&out)
			term := &cursorModel{}

			guest := func(s string) {
				bar.Observe([]byte(s))
				term.feed(s)
			}
			guest("\x1b[5;10H")
			guest(tc.save)
			guest("\x1b[2;1H")

			out.Reset()
			bar.draw()
			if out.Len() != 0 {
				t.Errorf("bar drew %q while the guest held the cursor slot",
					out.String())
			}
			term.feed(out.String())

			guest(tc.restore)
			row, col := term.at()
			if row != guestPromptRow || col != guestPromptCol {
				t.Errorf("cursor at (%d,%d), want (%d,%d)",
					row, col, guestPromptRow, guestPromptCol)
			}
		})
	}
}

// Yielding the slot must not cost the bar its row permanently. The restore
// frees the slot, so it also has to ask for the repaint that was skipped --
// otherwise the bar stays stale until the idle tick a second later.
//
// The assertion is on the dirty channel, not on draw(): calling draw()
// directly would paint as soon as the latch cleared whether or not a repaint
// was ever requested, which is precisely the bug this guards against. What
// matters is that Observe signaled the draw loop.
func TestCursorRestoreRequestsARepaint(t *testing.T) {
	var out bytes.Buffer
	bar := newHeldBar(&out)

	bar.Observe([]byte("\x1b7"))
	out.Reset()
	bar.draw()
	if out.Len() != 0 {
		t.Fatalf("bar drew while the slot was held: %q", out.String())
	}

	// Drain any request the save left behind, so the next one is observable.
	select {
	case <-bar.dirty:
	default:
	}

	bar.Observe([]byte("\x1b8"))
	select {
	case <-bar.dirty:
	default:
		t.Error("the cursor restore did not request a repaint, so the bar " +
			"stays stale until the idle tick")
	}

	// And the repaint, once it happens, uses the slot again now it is free.
	out.Reset()
	bar.draw()
	if out.Len() == 0 {
		t.Error("bar did not repaint after the guest released the cursor slot")
	}
	if !strings.Contains(out.String(), "\x1b7") {
		t.Errorf("repaint did not use the save slot once free: %q", out.String())
	}
}

// A skipped draw must not be remembered as drawn. draw() returns early while
// the slot is held, so it must leave lastBar alone: otherwise the text is
// recorded as painted, the unchanged-repaint check suppresses every later
// draw, and the bar never appears.
func TestHeldDrawDoesNotMarkTheRowAsPainted(t *testing.T) {
	var out bytes.Buffer
	bar := newHeldBar(&out)

	bar.Observe([]byte("\x1b7"))
	bar.draw()

	bar.mu.Lock()
	last := bar.lastBar
	bar.mu.Unlock()
	if last != "" {
		t.Errorf("lastBar = %q after a skipped draw, want empty", last)
	}
}

// An unmatched save must not disable the bar for the rest of the session. A
// guest that saves and then blocks, or whose restore is lost, would otherwise
// hold the slot forever.
func TestCursorHoldExpires(t *testing.T) {
	var out bytes.Buffer
	bar := newHeldBar(&out)

	now := time.Now()
	bar.mu.Lock()
	bar.modes.now = func() time.Time { return now }
	bar.mu.Unlock()

	bar.Observe([]byte("\x1b7"))
	out.Reset()
	bar.draw()
	if out.Len() != 0 {
		t.Fatalf("bar drew while the slot was held: %q", out.String())
	}

	// Past the bound, with no restore ever arriving.
	bar.mu.Lock()
	bar.modes.now = func() time.Time { return now.Add(maxCursorHold) }
	bar.mu.Unlock()

	out.Reset()
	bar.draw()
	if out.Len() == 0 {
		t.Error("bar never recovered from an unmatched cursor save")
	}
}

// A repeated save refreshes the deadline: the guest is still using the slot.
func TestRepeatedSaveRefreshesTheHold(t *testing.T) {
	var out bytes.Buffer
	bar := newHeldBar(&out)

	now := time.Now()
	bar.mu.Lock()
	bar.modes.now = func() time.Time { return now }
	bar.mu.Unlock()

	bar.Observe([]byte("\x1b7"))

	// Almost expired, then the guest saves again.
	now = now.Add(maxCursorHold - time.Millisecond)
	bar.Observe([]byte("\x1b7"))

	// Past the ORIGINAL deadline but not the refreshed one.
	now = now.Add(2 * time.Millisecond)
	out.Reset()
	bar.draw()
	if out.Len() != 0 {
		t.Errorf("bar drew %q despite a refreshed hold", out.String())
	}
}

// A terminal reset clears the save slot along with everything else, so a hold
// must not survive it.
func TestResetClearsTheCursorHold(t *testing.T) {
	var out bytes.Buffer
	bar := newHeldBar(&out)

	bar.Observe([]byte("\x1b7"))
	bar.Observe([]byte("\x1bc")) // RIS

	out.Reset()
	bar.draw()
	if out.Len() == 0 {
		t.Error("bar still held off after a terminal reset")
	}
}

// The save/restore pair may be split across reads at any byte, like every
// other sequence the filter tracks.
func TestCursorSaveSplitAcrossWrites(t *testing.T) {
	var out bytes.Buffer
	bar := newHeldBar(&out)

	// ESC alone, then the '7' in the next read.
	bar.Observe([]byte("\x1b"))
	bar.Observe([]byte("7"))

	out.Reset()
	bar.draw()
	if out.Len() != 0 {
		t.Errorf("bar drew %q after a split cursor save", out.String())
	}
}

// Ordinary output must not be mistaken for a save. A literal '7' is not DECSC,
// and neither is a CSI with parameters ending in 's'.
func TestOrdinaryOutputDoesNotHoldTheSlot(t *testing.T) {
	for _, s := range []string{
		"7",             // a digit
		"print 7 and 8", // digits in text
		"\x1b[1;2s",     // parameterized CSI s: DECSLRM, not SCP
		"\x1b[?25l",     // hide cursor
	} {
		var out bytes.Buffer
		bar := newHeldBar(&out)
		bar.Observe([]byte(s))
		out.Reset()
		bar.draw()
		if out.Len() == 0 {
			t.Errorf("bar held off by ordinary output %q", s)
		}
	}
}
