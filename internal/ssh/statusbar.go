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
// Key insight: the guest's terminal output (clear screen, cursor movement, etc.)
// will overwrite anything we draw. We therefore redraw the bar after every
// chunk of output we forward from the guest. A writerWithBar wraps the
// destination writer and calls sb.draw() after each Write so the bar survives
// even a full clear-screen from the guest application.
//
// Terminal sequences:
//
//	CSI Ps;Ps r  (DECSTBM) – scroll region top..bottom
//	CSI row;col H (CUP)    – move cursor to absolute position
//	ESC 7 / ESC 8          – DEC save/restore cursor (more portable than CSI s/u)
//	CSI ?25l/h             – hide/show cursor
//	CSI K  (EL)            – erase to end of line
const (
	seqSaveCursor    = "\x1b7"
	seqRestoreCursor = "\x1b8"
	seqHideCursor    = "\x1b[?25l"
	seqShowCursor    = "\x1b[?25h"
	seqResetScroll   = "\x1b[r"
	seqEraseToEOL    = "\x1b[K"
)

func seqScrollRegion(top, bottom int) string {
	return fmt.Sprintf("\x1b[%d;%dr", top, bottom)
}

func seqMoveTo(row, col int) string {
	return fmt.Sprintf("\x1b[%d;%dH", row, col)
}

// statusBar manages the reserved bottom row.
type statusBar struct {
	w     io.Writer // raw SSH channel stdout
	guest *models.Guest
	inst  *models.ProxmoxInstance
	mu    sync.Mutex
	h     int // total terminal height
	cols  int // terminal width
}

func newStatusBar(w io.Writer, guest *models.Guest, inst *models.ProxmoxInstance) *statusBar {
	return &statusBar{w: w, guest: guest, inst: inst}
}

// setup sets the initial dimensions, restricts the scroll region, and draws
// the bar for the first time. Must be called before the guest session starts
// so the scroll region is in place before the guest's first output.
func (sb *statusBar) setup(cols, totalHeight int) {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	sb.cols = cols
	sb.h = totalHeight
	sb.draw()
}

// resize updates dimensions and redraws. Returns the adjusted guest height.
func (sb *statusBar) resize(cols, totalHeight int) int {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	sb.cols = cols
	sb.h = totalHeight
	sb.draw()
	return sb.guestHeight()
}

// teardown clears the bar and restores the full scroll region.
func (sb *statusBar) teardown() {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	_, _ = fmt.Fprintf(sb.w, "%s%s%s%s%s",
		seqHideCursor,
		seqMoveTo(sb.h, 1),
		seqEraseToEOL,
		seqResetScroll,
		seqShowCursor,
	)
}

// guestHeight is totalHeight - 1 (minimum 1).
func (sb *statusBar) guestHeight() int {
	h := sb.h - 1
	if h < 1 {
		h = 1
	}
	return h
}

// draw writes the scroll region restriction + bar text.
// Caller must hold sb.mu.
func (sb *statusBar) draw() {
	if sb.h < 2 || sb.cols < 1 { //nolint:mnd
		return
	}
	// We use ESC 7/8 (DEC save/restore) which is more portable than
	// CSI s/u (SCOSC/SCORC). The sequence order matters:
	//  1. Hide cursor to avoid flicker.
	//  2. Set scroll region so the guest is confined to rows 1..h-1.
	//  3. Save cursor (we'll restore to wherever the guest left it).
	//  4. Move to bar row, erase line, write bar.
	//  5. Restore cursor, show cursor.
	_, _ = fmt.Fprintf(sb.w, "%s%s%s%s%s%s%s%s",
		seqHideCursor,
		seqScrollRegion(1, sb.guestHeight()),
		seqSaveCursor,
		seqMoveTo(sb.h, 1),
		seqEraseToEOL,
		sb.barText(),
		seqRestoreCursor,
		seqShowCursor,
	)
}

// barText returns the bar string rendered in reverse video, padded to sb.cols.
func (sb *statusBar) barText() string {
	left := fmt.Sprintf(" [proxpass] %s (%s%d) @ %s ",
		sb.guest.Name, sb.guest.Type, sb.guest.ProxmoxID, sb.inst.Name)
	right := " Ctrl+A X: disconnect "

	avail := sb.cols - len(left) - len(right)
	mid := ""
	if avail > 0 {
		mid = fmt.Sprintf("%*s", avail, "")
	}
	full := left + mid + right
	runes := []rune(full)
	if len(runes) > sb.cols {
		runes = runes[:sb.cols]
	}
	return "\x1b[7m" + string(runes) + "\x1b[m"
}

// writerWithBar wraps an io.Writer so that after every Write it redraws the
// status bar. This ensures the bar survives any clear-screen or cursor-home
// sequences sent by the guest application.
type writerWithBar struct {
	w  io.Writer
	sb *statusBar
}

func (wb *writerWithBar) Write(p []byte) (int, error) {
	n, err := wb.w.Write(p)
	if n > 0 {
		wb.sb.mu.Lock()
		wb.sb.draw()
		wb.sb.mu.Unlock()
	}
	return n, err
}
