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
// Design:
//
//   - setup() / resize() emit DECSTBM once to restrict the scroll region.
//     DECSTBM must NOT be re-emitted on every write because many terminals
//     move the cursor to (1,1) when they receive it, which breaks the guest.
//
//   - writerWithBar.Write() redraws the bar after every chunk of guest output
//     using only: save-cursor → move-to-bar → erase → write → restore-cursor.
//     No DECSTBM here, so the guest's cursor position is preserved correctly.
//
// Terminal sequences:
//
//	CSI Ps;Ps r  (DECSTBM) – scroll region (emitted only on setup/resize)
//	CSI row;col H (CUP)    – move cursor to absolute row/col
//	ESC 7 / ESC 8          – DEC save/restore cursor position
//	CSI ?25l/h             – hide/show cursor (reduce flicker)
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
	w     io.Writer
	guest *models.Guest
	inst  *models.ProxmoxInstance
	mu    sync.Mutex
	h     int
	cols  int
}

func newStatusBar(w io.Writer, guest *models.Guest, inst *models.ProxmoxInstance) *statusBar {
	return &statusBar{w: w, guest: guest, inst: inst}
}

// setup sets the scroll region and draws the bar for the first time.
// Must be called before the guest session starts.
func (sb *statusBar) setup(cols, totalHeight int) {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	sb.cols = cols
	sb.h = totalHeight
	sb.applyScrollRegion()
	sb.drawBar()
}

// resize updates scroll region + redraws on terminal resize.
// Returns the effective guest height (totalHeight - 1).
func (sb *statusBar) resize(cols, totalHeight int) int {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	sb.cols = cols
	sb.h = totalHeight
	sb.applyScrollRegion()
	sb.drawBar()
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

// redraw repaints the bar without touching the scroll region.
// Safe to call after every guest write — no DECSTBM, no cursor teleport.
func (sb *statusBar) redraw() {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	sb.drawBar()
}

// guestHeight is totalHeight - 1 (minimum 1).
func (sb *statusBar) guestHeight() int {
	h := sb.h - 1
	if h < 1 {
		h = 1
	}
	return h
}

// applyScrollRegion emits DECSTBM to restrict scrolling to rows 1..h-1.
// Caller must hold sb.mu.
func (sb *statusBar) applyScrollRegion() {
	if sb.h < 2 || sb.cols < 1 { //nolint:mnd
		return
	}
	_, _ = fmt.Fprint(sb.w, seqScrollRegion(1, sb.guestHeight()))
}

// drawBar paints the status bar at the last row without emitting DECSTBM.
// Caller must hold sb.mu.
func (sb *statusBar) drawBar() {
	if sb.h < 2 || sb.cols < 1 { //nolint:mnd
		return
	}
	_, _ = fmt.Fprintf(sb.w, "%s%s%s%s%s%s%s",
		seqHideCursor,
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

// altScreenExit is the sequence a guest sends when exiting the alternate
// screen buffer (e.g. when top, vim, htop exit). The client terminal responds
// by restoring its pre-alt-screen state, which discards our DECSTBM scroll
// region. We must detect this and re-apply our scroll region + bar.
const altScreenExit = "\x1b[?1049l"

// writerWithBar wraps an io.Writer so the status bar is redrawn after every
// Write, surviving clear-screen sequences from the guest.
//
// It also watches for \x1b[?1049l (exit alternate screen) in the guest
// output. When the client terminal receives that sequence it restores its
// pre-alt-screen state, which discards our DECSTBM scroll region. We
// re-apply the scroll region immediately after forwarding such a chunk.
type writerWithBar struct {
	w  io.Writer
	sb *statusBar
}

func (wb *writerWithBar) Write(p []byte) (int, error) {
	n, err := wb.w.Write(p)
	if n > 0 {
		// If the guest exited the alternate screen the client terminal
		// restored its saved state, wiping our scroll region. Re-apply it.
		if contains(p[:n], altScreenExit) {
			wb.sb.mu.Lock()
			wb.sb.applyScrollRegion()
			wb.sb.drawBar()
			wb.sb.mu.Unlock()
		} else {
			wb.sb.redraw()
		}
	}
	return n, err
}

// contains reports whether haystack contains needle as a byte sequence.
func contains(haystack []byte, needle string) bool {
	n := []byte(needle)
	if len(n) == 0 || len(haystack) < len(n) {
		return false
	}
	for i := range haystack[:len(haystack)-len(n)+1] {
		if string(haystack[i:i+len(n)]) == needle {
			return true
		}
	}
	return false
}
