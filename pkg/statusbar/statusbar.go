// Package statusbar provides a persistent bottom status bar for raw SSH/PTY
// proxy sessions. It reserves the terminal's last row via DECSTBM and redraws
// the bar after every chunk of guest output, handling the edge cases that
// destroy the scroll region (alternate-screen exit, clear-screen, DECSTBM
// resets from the guest).
//
// Usage:
//
//	bar := statusbar.New(clientWriter,
//	    statusbar.WithText("myapp", "guest (ct100) @ host"),
//	    statusbar.WithHint("Ctrl+A X: disconnect"),
//	    statusbar.WithColors(statusbar.ColorReverse),
//	)
//	bar.Setup(cols, totalRows)             // call before the guest session starts
//	proxyOut := bar.Writer()               // wrap remote stdout with this writer
//	...
//	bar.Resize(newCols, newRows)           // on window-change; returns guestRows
//	bar.Teardown()                         // restore terminal on session end
package statusbar

import (
	"bytes"
	"fmt"
	"io"
	"regexp"
	"sync"
)

// ---- terminal escape sequences ----

const (
	seqSaveCursor    = "\x1b7"    // DECSC  — save cursor + attributes
	seqRestoreCursor = "\x1b8"    // DECRC  — restore cursor + attributes
	seqHideCursor    = "\x1b[?25l"
	seqShowCursor    = "\x1b[?25h"
	seqResetScroll   = "\x1b[r"   // DECSTBM with no args → full screen
	seqEraseToEOL    = "\x1b[K"   // EL — erase to end of line
	seqSGRReset      = "\x1b[0m"
	seqSGRReverse    = "\x1b[7m"  // reverse video
)

func seqScrollRegion(top, bottom int) string { return fmt.Sprintf("\x1b[%d;%dr", top, bottom) }
func seqMoveTo(row, col int) string          { return fmt.Sprintf("\x1b[%d;%dH", row, col) }

// ---- patterns that destroy the scroll region ----

// altScreenExitSeqs are sequences the guest sends when leaving the alternate
// screen buffer. The client terminal responds by restoring its pre-alt-screen
// state, which resets the scroll region to the full screen.
var altScreenExitSeqs = [][]byte{
	[]byte("\x1b[?1049l"),
	[]byte("\x1b[?1047l"),
	[]byte("\x1b[?47l"),
}

// clearScreenSeqs are sequences that clear the visible screen. With an active
// scroll region the clear is confined to the region, but we redraw the bar
// anyway to be safe.
var clearScreenSeqs = [][]byte{
	[]byte("\x1b[2J"),
	[]byte("\x1b[3J"),
}

// resetSeqs are hard-reset sequences that wipe all terminal state including
// the scroll region.
var resetSeqs = [][]byte{
	[]byte("\x1bc"),    // RIS — full reset
	[]byte("\x1b[!p"), // DECSTR — soft reset
}

// decstbmRe matches any DECSTBM sequence (CSI ... r) in the guest output
// so we can rewrite it to exclude the status bar row.
var decstbmRe = regexp.MustCompile(`\x1b\[(\d*);?(\d*)r`)

// ---- options ----

// ColorMode controls the visual style of the status bar.
type ColorMode int

const (
	ColorReverse ColorMode = iota // swap foreground and background (default)
)

// Option is a functional option for New.
type Option func(*StatusBar)

// WithText sets the left-side label (prefix) and centre/right content.
func WithText(prefix, content string) Option {
	return func(sb *StatusBar) {
		sb.prefix = prefix
		sb.content = content
	}
}

// WithHint sets a short right-aligned hint string (e.g. key binding).
func WithHint(hint string) Option {
	return func(sb *StatusBar) { sb.hint = hint }
}

// WithColors sets the colour mode. Currently only ColorReverse is supported.
func WithColors(_ ColorMode) Option { return func(_ *StatusBar) {} }

// ---- StatusBar ----

// StatusBar manages a one-line status bar pinned to the last row of a terminal.
type StatusBar struct {
	w       io.Writer
	mu      sync.Mutex
	rows    int
	cols    int
	prefix  string
	content string
	hint    string
}

// New creates a new StatusBar that writes escape sequences to w.
func New(w io.Writer, opts ...Option) *StatusBar {
	sb := &StatusBar{w: w}
	for _, o := range opts {
		o(sb)
	}
	return sb
}

// Setup restricts the scroll region to rows 1..totalRows-1 and draws the bar.
// Must be called before the guest session starts so the DECSTBM is in place
// before the first byte of guest output arrives.
// Returns the guest height (totalRows - 1) to use for the remote PTY.
func (sb *StatusBar) Setup(cols, totalRows int) int {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	sb.cols = cols
	sb.rows = totalRows
	sb.applyScrollRegion()
	sb.drawBar()
	return sb.guestRows()
}

// Resize updates the scroll region and redraws after a window-change event.
// Returns the new guest height (totalRows - 1).
func (sb *StatusBar) Resize(cols, totalRows int) int {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	sb.cols = cols
	sb.rows = totalRows
	sb.applyScrollRegion()
	sb.drawBar()
	return sb.guestRows()
}

// Clear erases the guest viewport (rows 1..guestRows) without touching the
// status bar row. Call this when the guest exits without clearing the screen
// itself (e.g. when a full-screen program is killed with Ctrl+C).
// The scroll region must already be in place (i.e. after Setup or Resize).
func (sb *StatusBar) Clear() {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	if sb.rows < 2 || sb.cols < 1 { //nolint:mnd
		return
	}
	// Move to top-left of scroll region and erase to the bottom of the region.
	// \x1b[J (ED without argument = 0) erases from cursor to end of display,
	// which is confined to the scroll region by DECSTBM.
	_, _ = io.WriteString(sb.w,
		seqHideCursor+
			seqMoveTo(1, 1)+ // top of scroll region
			"\x1b[J"+ // erase to bottom of scroll region
			seqMoveTo(1, 1)+ // leave cursor at home
			seqShowCursor,
	)
}

// Teardown clears the status bar row and restores the full scroll region.
// Call when the guest session ends.
func (sb *StatusBar) Teardown() {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	_, _ = io.WriteString(sb.w,
		seqHideCursor+
			seqMoveTo(sb.rows, 1)+
			seqEraseToEOL+
			seqResetScroll+
			seqShowCursor,
	)
}

// Writer returns an io.Writer that should be used for all guest→client output.
// It forwards data to the underlying writer and redraws the status bar after
// each chunk, handling the edge cases that would destroy the scroll region.
func (sb *StatusBar) Writer() io.Writer {
	return &barWriter{sb: sb}
}

// guestRows returns totalRows - 1 (minimum 1).
func (sb *StatusBar) guestRows() int {
	h := sb.rows - 1
	if h < 1 {
		h = 1
	}
	return h
}

// applyScrollRegion emits DECSTBM. Caller must hold sb.mu.
func (sb *StatusBar) applyScrollRegion() {
	if sb.rows < 2 || sb.cols < 1 { //nolint:mnd
		return
	}
	_, _ = io.WriteString(sb.w, seqScrollRegion(1, sb.guestRows()))
}

// drawBar paints the status bar at the last row. Caller must hold sb.mu.
func (sb *StatusBar) drawBar() {
	if sb.rows < 2 || sb.cols < 1 { //nolint:mnd
		return
	}
	_, _ = fmt.Fprintf(sb.w, "%s%s%s%s%s%s%s",
		seqHideCursor,
		seqSaveCursor,
		seqMoveTo(sb.rows, 1),
		seqEraseToEOL,
		sb.barText(),
		seqRestoreCursor,
		seqShowCursor,
	)
}

// barText builds the bar string in reverse video, padded to sb.cols.
func (sb *StatusBar) barText() string {
	left := fmt.Sprintf(" [%s] %s ", sb.prefix, sb.content)
	right := ""
	if sb.hint != "" {
		right = fmt.Sprintf(" %s ", sb.hint)
	}

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
	return seqSGRReverse + string(runes) + seqSGRReset
}

// ---- barWriter ----

// barWriter is the io.Writer returned by StatusBar.Writer(). It:
//  1. Rewrites any DECSTBM sequences from the guest to clamp bottom to guestRows.
//  2. Forwards the (patched) data to the underlying writer.
//  3. After each write, redraws the status bar.
//  4. After alt-screen exit or hard reset, also re-applies the scroll region.
type barWriter struct {
	sb *StatusBar
}

func (bw *barWriter) Write(p []byte) (int, error) {
	// Patch any DECSTBM sequences the guest sends so they can't expand
	// the scroll region back to the full screen.
	patched := bw.patchDECSTBM(p)

	// Detect sequences that destroy our scroll region so we can re-apply it.
	needsRegion := bw.containsRegionKiller(patched)

	n, err := bw.sb.w.Write(patched)

	if n > 0 {
		bw.sb.mu.Lock()
		if needsRegion {
			// Re-apply scroll region + redraw (e.g. after alt-screen exit,
			// clear-screen, or hard reset destroys our DECSTBM).
			bw.sb.applyScrollRegion()
		}
		bw.sb.drawBar()
		bw.sb.mu.Unlock()
	}

	// Return the original length so the caller doesn't think bytes were lost.
	if err == nil && len(patched) != len(p) {
		return len(p), nil
	}
	return n, err
}

// patchDECSTBM rewrites any DECSTBM sequence in data so that its bottom
// margin never exceeds guestRows, preventing the guest from expanding the
// scroll region into the status bar row.
func (bw *barWriter) patchDECSTBM(data []byte) []byte {
	bw.sb.mu.Lock()
	maxBottom := bw.sb.guestRows()
	bw.sb.mu.Unlock()

	if !bytes.Contains(data, []byte("\x1b[")) {
		return data // fast path: no CSI sequences at all
	}

	return decstbmRe.ReplaceAllFunc(data, func(m []byte) []byte {
		sub := decstbmRe.FindSubmatch(m)
		top, bottom := 1, maxBottom+1 // default: full screen → rewrite to our max
		if len(sub[1]) > 0 {
			fmt.Sscanf(string(sub[1]), "%d", &top) //nolint:errcheck
		}
		if len(sub[2]) > 0 {
			fmt.Sscanf(string(sub[2]), "%d", &bottom) //nolint:errcheck
		}
		if bottom > maxBottom {
			bottom = maxBottom
		}
		if bottom < top {
			bottom = top
		}
		return []byte(seqScrollRegion(top, bottom))
	})
}

// containsRegionKiller reports whether data contains a sequence that would
// reset or expand the scroll region beyond our status bar row.
func (bw *barWriter) containsRegionKiller(data []byte) bool {
	for _, seq := range altScreenExitSeqs {
		if bytes.Contains(data, seq) {
			return true
		}
	}
	for _, seq := range clearScreenSeqs {
		if bytes.Contains(data, seq) {
			return true
		}
	}
	for _, seq := range resetSeqs {
		if bytes.Contains(data, seq) {
			return true
		}
	}
	return false
}
