package console

import (
	"bytes"
	"time"
)

// modeFilter watches a guest's output stream for the escape sequences that
// make a reserved status-bar row unsafe, and reports when the bar must hide
// itself. It forwards the stream byte-for-byte: it only observes.
//
// The case that matters is the alternate screen buffer. A full-screen
// application (vim, top, less) switches to it, takes over every row, and
// restores the previous screen on exit. While it is in control there is no
// row to reserve -- the application has been told the screen is one row
// shorter and will use all of it -- so the bar must stop drawing rather than
// paint over the application's bottom line.
//
// Three mode numbers do this and an implementation that checks only the
// modern one is wrong for older applications:
//
//	?47    legacy alternate screen (xterm, pre-1998)
//	?1047  alternate screen, clearing on exit
//	?1049  alternate screen + cursor save/restore (what vim uses today)
//
// Sequences may also set several modes at once -- "\x1b[?1049;1000h" enables
// the alternate screen AND mouse reporting -- and the "?" private marker
// applies to every parameter in the list, not just the first. Splitting on
// ";" without carrying the marker forward misses the alt-screen bit in
// "\x1b[?1000;1049h", so the marker is tracked across parameters here.
type modeFilter struct {
	// altScreen reports whether the guest is currently on the alternate
	// screen buffer.
	altScreen bool

	// partial holds a trailing incomplete escape sequence between Observe
	// calls. A sequence can be split across reads at any byte, so state has
	// to survive the call that saw only part of it.
	partial []byte

	// reset records that the guest reset the terminal, which discards the
	// scroll region as well as the screen. It is latched here and cleared by
	// TakeReset so the caller cannot miss it between observations.
	reset bool

	// cursorSaved reports whether the guest is between saving and restoring
	// its cursor. While it is, the bar must not draw: see CursorSaved.
	cursorSaved bool

	// cursorSavedAt is when cursorSaved was last set, so a guest that saves
	// and never restores cannot suppress the bar forever.
	cursorSavedAt time.Time

	// now is the clock, swappable in tests.
	now func() time.Time

	// regionLost records that the guest replaced the bar's scroll region
	// with its own. It is latched and cleared by TakeRegionLost.
	regionLost bool

	// originMode reports whether the guest has set DECOM, which makes row
	// coordinates relative to the scroll region instead of the screen.
	originMode bool

	// leftAltScreen records that the guest returned from the alternate
	// screen, which restores the normal screen's scroll region along with
	// the rest of its state. It is latched and cleared by TakeLeftAltScreen.
	leftAltScreen bool
}

// TakeLeftAltScreen reports whether the guest returned from the alternate
// screen since the last call, and clears the flag.
//
// Leaving the alternate screen restores the normal screen's saved state,
// including whatever scroll region was in effect before the bar installed
// its own, so the region has to be reinstalled.
func (m *modeFilter) TakeLeftAltScreen() bool {
	was := m.leftAltScreen
	m.leftAltScreen = false
	return was
}

// TakeRegionLost reports whether the guest installed its own scroll region
// since the last call, and clears the flag.
//
// A guest that sets DECSTBM itself -- curses applications do, and so does
// "tput csr" -- replaces the bar's reservation wholesale. The bar's row is
// then inside the guest's scrolling area, so the guest will scroll through
// it. Reinstalling the region is the only way to get the row back, and it
// has to be driven by observing the change: nothing else reveals it.
func (m *modeFilter) TakeRegionLost() bool {
	was := m.regionLost
	m.regionLost = false
	return was
}

// OriginMode reports whether DECOM is active.
//
// With origin mode set, CUP row coordinates are relative to the top margin of
// the scroll region and rows outside it are unreachable, so the bar's
// absolute move to the last row would be clamped into the guest's area and
// paint over the guest's bottom line. The bar cannot position itself
// reliably until the guest clears DECOM, so it stops drawing instead of
// drawing in the wrong place.
func (m *modeFilter) OriginMode() bool { return m.originMode }

// isSetScrollRegion reports whether seq is DECSTBM ("\x1b[...r").
//
// Only the guest's own region changes reach here: the bar's are written
// straight to the terminal and never pass through Observe.
func isSetScrollRegion(seq []byte) bool {
	return len(seq) >= 3 && seq[1] == '[' && seq[len(seq)-1] == 'r' &&
		// A private marker makes this a mode restore (DECRST-style), not
		// DECSTBM.
		seq[2] != '?'
}

// parseOriginMode reports whether seq sets or resets DECOM ("\x1b[?6h"/"l").
func parseOriginMode(seq []byte) (enabled, ok bool) {
	if len(seq) < 4 || seq[1] != '[' {
		return false, false
	}
	final := seq[len(seq)-1]
	if final != 'h' && final != 'l' {
		return false, false
	}
	private := false
	for _, param := range bytes.Split(seq[2:len(seq)-1], []byte(";")) {
		if len(param) > 0 && param[0] == '?' {
			private = true
			param = param[1:]
		}
		if !private {
			continue
		}
		if string(param) == "6" {
			return final == 'h', true
		}
	}
	return false, false
}

// maxCursorHold bounds how long the bar will defer to a guest's saved cursor.
//
// A save/restore pair around a line redraw is over in well under a
// millisecond. Nothing legitimate holds the slot for a second, but a guest
// that saves and then blocks -- or one whose restore is never seen, because a
// malformed stream desynchronized the scan -- would otherwise keep the bar
// from ever drawing again. After this long the bar reclaims the slot: a
// briefly wrong cursor is recoverable, a permanently missing bar is not.
const maxCursorHold = time.Second

func (m *modeFilter) clock() time.Time {
	if m.now != nil {
		return m.now()
	}
	return time.Now()
}

// CursorSaved reports whether the guest is currently holding a saved cursor
// position.
//
// A terminal has exactly one cursor-save slot per screen buffer, and the bar's
// own repaint uses it (statusbar.go draw). If the guest saves its cursor, the
// bar repaints, and the guest then restores, the guest gets the bar's saved
// position instead of its own and its cursor lands in the wrong place. That is
// not hypothetical: terminfo defines sc=\E7 and rc=\E8, so every shell line
// editor does exactly this when redrawing for an arrow key or Home/End.
//
// The slot cannot be shared, so the bar yields it: while this reports true the
// bar skips its repaint, leaving the slot to the guest for as long as the
// guest is relying on it. liamg/shox (Unlicense) fixed the same bug the same
// way in commit 2af5cf5, with a pauseDrawing flag set from its CSI s/u
// handlers -- though it latches only on the CSI form and so still misses
// terminfo's DECSC, which is the form that actually occurs.
//
// The bar is cosmetic and the guest's cursor is not, so a stale bar for the
// duration of a line redraw is the right trade. The hold is bounded by
// maxCursorHold so an unmatched save degrades to a late bar rather than a
// missing one.
func (m *modeFilter) CursorSaved() bool {
	if !m.cursorSaved {
		return false
	}
	if m.clock().Sub(m.cursorSavedAt) >= maxCursorHold {
		// Held too long to be a line redraw. Give up on the restore ever
		// arriving and let the bar have the slot back.
		m.cursorSaved = false
		return false
	}
	return true
}

// isCursorSave and isCursorRestore report whether seq saves or restores the
// cursor.
//
// Both spellings have to be matched. DECSC/DECRC ("\x1b7"/"\x1b8") is what
// terminfo's sc/rc capabilities expand to and therefore what shells actually
// emit; ANSI.SYS SCP/RCP ("\x1b[s"/"\x1b[u") is the CSI form, which some
// applications use directly. Matching only one leaves the other able to
// desynchronize the save slot.
func isCursorSave(seq []byte) bool {
	return (len(seq) == 2 && seq[0] == 0x1b && seq[1] == '7') ||
		(len(seq) == 3 && seq[1] == '[' && seq[2] == 's')
}

func isCursorRestore(seq []byte) bool {
	return (len(seq) == 2 && seq[0] == 0x1b && seq[1] == '8') ||
		(len(seq) == 3 && seq[1] == '[' && seq[2] == 'u')
}

// TakeReset reports whether the terminal was reset since the last call, and
// clears the flag.
func (m *modeFilter) TakeReset() bool {
	was := m.reset
	m.reset = false
	return was
}

// isFullReset reports whether seq is RIS ("\x1bc"), a full terminal reset.
//
// This is what "reset" and "tput reset" send. It clears the screen, the
// scroll region, and every mode, so a bar has to reinstall its region rather
// than just redraw its row.
func isFullReset(seq []byte) bool {
	return len(seq) == 2 && seq[0] == 0x1b && seq[1] == 'c'
}

// maxPartialEscape bounds the buffered prefix of an unterminated escape
// sequence.
//
// Without a bound, a guest that emits a lone ESC and then megabytes of
// printable text would have all of it buffered while the filter waited for a
// final byte that never comes. A CSI with a plausible parameter list is far
// shorter than this; anything longer is malformed, so the buffer is dropped
// and scanning resumes.
const maxPartialEscape = 64

// Observe inspects p for changes that affect the bar and reports whether the
// caller should redraw. p is never modified.
//
// Two kinds of sequence matter:
//
//   - A switch to or from the alternate screen, which changes whether a bar
//     may be drawn at all.
//   - Anything that erases the bar's row. A scroll region confines
//     *scrolling* to the rows above the bar, but it does not protect the row
//     from being erased: ED ("\x1b[2J") addresses the whole screen
//     regardless. Ctrl+L is the common way to hit this -- the shell answers
//     it with ED -- and the bar has to repaint rather than stay blank.
func (m *modeFilter) Observe(p []byte) (redraw bool) {
	buf := p
	if len(m.partial) > 0 {
		// Rescan the buffered prefix together with the new bytes so a
		// sequence split across reads is seen whole.
		//
		// This builds a fresh slice rather than appending to m.partial: its
		// backing array must not be reused, because a later Observe may
		// still be holding the tail it was copied from.
		joined := make([]byte, 0, len(m.partial)+len(p))
		joined = append(joined, m.partial...)
		joined = append(joined, p...)
		buf = joined
		m.partial = nil
	}

	for i := 0; i < len(buf); {
		if buf[i] != 0x1b {
			i++
			continue
		}
		seq, n, complete := scanEscape(buf[i:])
		if !complete {
			// Keep the tail for the next call, unless it is implausibly
			// long and so cannot be a real sequence.
			if tail := buf[i:]; len(tail) <= maxPartialEscape {
				m.partial = append([]byte(nil), tail...)
			}
			break
		}
		switch alt, ok := parseAltScreen(seq); {
		case ok:
			if alt != m.altScreen {
				if !alt {
					// Coming back from the alternate screen restores the
					// normal screen's scroll region, so the bar's is gone.
					m.leftAltScreen = true
				}
				m.altScreen = alt
				redraw = true
			}
		case isSetScrollRegion(seq):
			// The guest took the scroll region for itself, so the bar's row
			// is no longer reserved. Latch it: the caller has to reinstall
			// the region, not merely repaint the row.
			m.regionLost = true
			redraw = true
		case isFullReset(seq):
			// RIS resets everything, including the scroll region, so the
			// region has to be reinstalled and not merely repainted.
			m.reset = true
			m.altScreen = false
			m.cursorSaved = false
			m.originMode = false
			redraw = true
		case isCursorSave(seq):
			// The guest now owns the terminal's only cursor-save slot. The
			// bar must leave it alone until the guest restores.
			//
			// A repeated save refreshes the deadline rather than being
			// ignored: the guest is demonstrably still using the slot.
			m.cursorSaved = true
			m.cursorSavedAt = m.clock()
		case isCursorRestore(seq):
			// The slot is free again. Repaint: the bar may have skipped a
			// draw while the guest held it, so its row can be stale.
			if m.cursorSaved {
				m.cursorSaved = false
				redraw = true
			}
		case erasesBarRow(seq):
			redraw = true
		default:
			if origin, ok := parseOriginMode(seq); ok && origin != m.originMode {
				// DECOM changes what an absolute row coordinate means, so
				// the bar either cannot place itself (set) or can again
				// (reset). Both are worth a redraw decision.
				m.originMode = origin
				redraw = true
			}
		}
		i += n
	}
	return redraw
}

// AltScreen reports whether the guest currently owns the whole screen.
func (m *modeFilter) AltScreen() bool { return m.altScreen }

// scanEscape returns the escape sequence at the start of b, its length, and
// whether it is complete.
//
// Only CSI ("\x1b[...") is parsed, because the modes of interest are CSI
// private modes. Other introducers are reported as complete two-byte
// sequences so scanning moves past them; OSC and DCS strings are not framed
// properly here, but misreading their contents is harmless since the only
// thing acted on is a CSI final of 'h' or 'l'.
func scanEscape(b []byte) (seq []byte, n int, complete bool) {
	if len(b) < 2 {
		return nil, 0, false
	}
	if b[1] != '[' {
		return b[:2], 2, true
	}
	// CSI: parameter bytes 0x30-0x3F, then intermediates 0x20-0x2F, then a
	// final byte 0x40-0x7E (ECMA-48).
	for i := 2; i < len(b); i++ {
		c := b[i]
		switch {
		case c >= 0x30 && c <= 0x3F, c >= 0x20 && c <= 0x2F:
			continue
		case c >= 0x40 && c <= 0x7E:
			return b[:i+1], i + 1, true
		default:
			// Not a valid CSI byte: treat the sequence as ending here so a
			// malformed stream cannot stall the scan.
			return b[:i+1], i + 1, true
		}
	}
	return nil, 0, false
}

// erasesBarRow reports whether seq could have erased the bar's row.
//
// A scroll region keeps the guest's *scrolling* above the bar, but erasure is
// not scrolling: these sequences address the screen directly and reach the
// bar's row whatever the region is set to.
//
//	ED  "\x1b[J"   erase from the cursor to the end of the screen
//	    "\x1b[0J"  same, explicitly
//	    "\x1b[2J"  erase the whole screen -- what a shell sends for Ctrl+L
//	    "\x1b[3J"  whole screen plus scrollback
//
// "\x1b[1J" erases from the start of the screen to the cursor. The cursor is
// always inside the scroll region, above the bar, so that one cannot reach
// the bar's row and is deliberately not matched.
//
// DECALN ("\x1b#8", the alignment test) also fills the whole screen, but it
// is a diagnostic that no ordinary program emits, so it is not tracked.
func erasesBarRow(seq []byte) bool {
	if len(seq) < 3 || seq[1] != '[' {
		return false
	}
	if seq[len(seq)-1] != 'J' {
		return false
	}
	switch string(seq[2 : len(seq)-1]) {
	case "", "0", "2", "3":
		return true
	default:
		// Includes "1" (erase up to the cursor) and any private-marker or
		// multi-parameter form, which no erase actually uses.
		return false
	}
}

// parseAltScreen reports whether seq is an alternate-screen mode change and
// which direction it goes.
func parseAltScreen(seq []byte) (enabled, ok bool) {
	if len(seq) < 4 || seq[1] != '[' {
		return false, false
	}
	final := seq[len(seq)-1]
	if final != 'h' && final != 'l' {
		return false, false
	}
	params := seq[2 : len(seq)-1]

	// The "?" private marker applies to every parameter in the list, so it
	// is carried across the ";" separators rather than being tested only on
	// the first parameter.
	private := false
	for _, param := range bytes.Split(params, []byte(";")) {
		if len(param) > 0 && param[0] == '?' {
			private = true
			param = param[1:]
		}
		if !private {
			continue
		}
		switch string(param) {
		case "47", "1047", "1049":
			return final == 'h', true
		}
	}
	return false, false
}
