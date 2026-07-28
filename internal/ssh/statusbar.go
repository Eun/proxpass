package ssh

import (
	"fmt"
	"io"
	"sync"

	"proxpass/internal/models"
)

// statusBar reserves the bottom row of the terminal for a persistent info line
// and constrains the guest console to the remaining rows via DECSTBM.
//
// Terminal control sequences used:
//   - CSI Ps ; Ps r  (DECSTBM) — set top/bottom scroll margin
//   - CSI s          (SCOSC)   — save cursor position (used before writing bar)
//   - CSI u          (SCORC)   — restore cursor position
//   - CSI H          (CUP)     — move cursor to absolute position
//   - CSI 2J         (ED)      — erase screen (used only during teardown)
//   - CSI K          (EL)      — erase to end of line
//   - CSI ?25l/h              — hide/show cursor
const (
	seqSaveCursor    = "\x1b[s"
	seqRestoreCursor = "\x1b[u"
	seqHideCursor    = "\x1b[?25l"
	seqShowCursor    = "\x1b[?25h"
	seqResetScroll   = "\x1b[r"      // reset scroll region to full screen
	seqEraseToEOL    = "\x1b[K"      // erase from cursor to end of line
)

// seqScrollRegion returns the DECSTBM sequence to set the scroll region
// to rows top..bottom (1-based).
func seqScrollRegion(top, bottom int) string {
	return fmt.Sprintf("\x1b[%d;%dr", top, bottom)
}

// seqMoveTo returns the CUP sequence to move the cursor to row,col (1-based).
func seqMoveTo(row, col int) string {
	return fmt.Sprintf("\x1b[%d;%dH", row, col)
}

// statusBar manages the reserved bottom row of the terminal.
type statusBar struct {
	w     io.Writer // the SSH channel stdout
	guest *models.Guest
	inst  *models.ProxmoxInstance
	mu    sync.Mutex
	h     int // current total terminal height
	cols  int // current terminal width
}

func newStatusBar(w io.Writer, guest *models.Guest, inst *models.ProxmoxInstance) *statusBar {
	return &statusBar{w: w, guest: guest, inst: inst}
}

// setup initialises the scroll region and draws the initial status bar.
// guestHeight = totalHeight - 1 must be used as the PTY height forwarded
// to the guest so it never draws into the reserved row.
func (sb *statusBar) setup(cols, totalHeight int) {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	sb.cols = cols
	sb.h = totalHeight
	sb.apply()
}

// resize updates the scroll region and redraws the bar after a terminal resize.
// Returns the effective guest height (totalHeight - 1).
func (sb *statusBar) resize(cols, totalHeight int) int {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	sb.cols = cols
	sb.h = totalHeight
	sb.apply()
	return sb.guestHeight()
}

// teardown restores the full scroll region and clears the status bar row.
func (sb *statusBar) teardown() {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	_, _ = fmt.Fprintf(sb.w,
		"%s"+ // hide cursor while we tidy up
			"%s"+ // move to the bar row
			"%s"+ // erase the bar line
			"%s"+ // reset scroll region to full screen
			"%s", // show cursor
		seqHideCursor,
		seqMoveTo(sb.h, 1),
		seqEraseToEOL,
		seqResetScroll,
		seqShowCursor,
	)
}

// guestHeight returns the terminal height available to the guest
// (total height minus the one row reserved for the status bar).
func (sb *statusBar) guestHeight() int {
	h := sb.h - 1
	if h < 1 {
		h = 1
	}
	return h
}

// apply writes the scroll region + bar. Caller must hold sb.mu.
func (sb *statusBar) apply() {
	if sb.h < 2 || sb.cols < 1 { //nolint:mnd
		return
	}
	barText := sb.barText()
	_, _ = fmt.Fprintf(sb.w,
		"%s"+ // hide cursor
			"%s"+ // restrict scroll to rows 1..h-1
			"%s"+ // move to bar row
			"%s"+ // erase bar row
			"%s"+ // write bar text
			"%s"+ // restore cursor to wherever the guest left it
			"%s", // show cursor
		seqHideCursor,
		seqScrollRegion(1, sb.guestHeight()),
		seqMoveTo(sb.h, 1),
		seqEraseToEOL,
		barText,
		seqRestoreCursor,
		seqShowCursor,
	)
}

// barText builds the status bar string, truncated to fit the terminal width.
func (sb *statusBar) barText() string {
	left := fmt.Sprintf(" [proxpass] %s (%s%d) @ %s ",
		sb.guest.Name, sb.guest.Type, sb.guest.ProxmoxID, sb.inst.Name)
	right := " Ctrl+A X: disconnect "

	// Pad or truncate to fit cols exactly.
	available := sb.cols - len(left) - len(right)
	var mid string
	if available > 0 {
		mid = fmt.Sprintf("%*s", available, "") // spaces
	}

	full := left + mid + right
	// Safety truncation if terminal is very narrow.
	runes := []rune(full)
	if len(runes) > sb.cols {
		runes = runes[:sb.cols]
	}
	// Render with reverse video (swap fg/bg) for a visible bar.
	return "\x1b[7m" + string(runes) + "\x1b[m"
}
