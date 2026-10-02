package console

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
	"unicode"
)

// StatusBar draws a persistent one-line bar on the bottom row of a terminal
// while a guest console owns the rest of the screen.
//
// # Why this is not the previous implementation
//
// proxpass used to do this with a full VT100 emulator (hinshun/vt10x): guest
// output was parsed into a cell grid and the entire grid was re-rendered to
// the client on every write. That is O(cols x rows) of escape-sequence
// generation per chunk of guest output, and it was slow enough that
// PROXPASS_DISABLE_STATUSBAR had to be added (#37) so that watching logs was
// usable at all. A status bar that has to be turned off to read a log file is
// not worth its cost.
//
// This version never parses the guest's output into cells and never redraws
// it. Instead it asks the terminal to do the work:
//
//	DECSTBM ("\x1b[1;{rows-1}r") sets the scroll region to every row above
//	the bar, so the terminal scrolls the guest's output natively and leaves
//	the bottom row alone.
//
// Guest output is then forwarded verbatim. The only writes proxpass makes are
// the bar itself, which is one row, on a timer, and only when its text has
// actually changed. The cost is independent of how much output the guest
// produces, so there is nothing to opt out of.
//
// The alternative, used by github.com/liamg/shox (Unlicense), is to lie to
// the child about the terminal size and rewrite the row coordinate of every
// absolute-positioning escape sequence in the stream. That needs a parser on
// the hot path and it paints the bar into the scrollback, so scrolling back
// shows bar remnants interleaved with output (shox issue #25). A scroll
// region avoids both problems, which is why it is used here.
//
// # What still needs the stream
//
// A scroll region does not protect the bar from an application that takes
// over the whole screen. modeFilter watches for the alternate screen buffer
// and the bar stops drawing while a full-screen application is in control.
// That is an observer on the stream, not a rewriter: it copies nothing and
// modifies nothing.
type StatusBar struct {
	out io.Writer

	mu      sync.Mutex
	rows    int
	cols    int
	left    string
	right   string
	lastBar string // last text written, to skip unchanged repaints
	active  bool   // scroll region is installed
	hidden  bool   // a full-screen application owns the screen

	modes modeFilter

	// dirty coalesces redraw requests. It is buffered with capacity 1 and
	// written non-blockingly, so any number of requests between ticks
	// collapse into a single repaint.
	dirty chan struct{}
	stop  chan struct{}
	done  chan struct{}
}

// Bar timing.
//
// tick is the maximum repaint rate: redraws are coalesced and applied at most
// this often, so a chatty guest cannot make proxpass draw faster than this.
// idle forces a repaint even with no activity, so time-based content stays
// current and a bar lost to an unobserved redraw comes back.
const (
	barTick = 50 * time.Millisecond
	barIdle = 1 * time.Second
)

// minBarRows is the smallest terminal a bar makes sense on. Below this the
// guest would be left with almost nothing, so the bar disables itself.
const minBarRows = 4

// NewStatusBar returns a bar that writes to out. Call Start to install it.
func NewStatusBar(out io.Writer, cols, rows int) *StatusBar {
	return &StatusBar{
		out:   out,
		cols:  cols,
		rows:  rows,
		dirty: make(chan struct{}, 1),
		stop:  make(chan struct{}),
		done:  make(chan struct{}),
	}
}

// SetText sets the bar's left and right content and requests a repaint.
func (b *StatusBar) SetText(left, right string) {
	b.mu.Lock()
	b.left, b.right = left, right
	b.mu.Unlock()
	b.request()
}

// GuestRows is the number of rows available to the guest: every row except
// the bar's. It returns the full height when the terminal is too small for a
// bar, so the caller always sizes the guest to what it can actually use.
func (b *StatusBar) GuestRows() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.guestRowsLocked()
}

func (b *StatusBar) guestRowsLocked() int {
	if b.rows < minBarRows {
		return b.rows
	}
	return b.rows - 1
}

// Start installs the scroll region and begins drawing.
func (b *StatusBar) Start() {
	b.mu.Lock()
	if b.rows < minBarRows {
		// Too small to reserve a row: leave the terminal untouched.
		b.mu.Unlock()
		close(b.done)
		return
	}
	b.active = true
	// Install the scroll region, then put the cursor inside it. DECSTBM
	// homes the cursor as a side effect on some terminals and leaves it
	// alone on others, so it is positioned explicitly.
	fmt.Fprintf(b.out, "\x1b[1;%dr\x1b[1;1H", b.guestRowsLocked())
	b.mu.Unlock()

	b.request()
	go b.loop()
}

// Stop removes the scroll region and clears the bar.
func (b *StatusBar) Stop() {
	b.mu.Lock()
	wasActive := b.active
	b.active = false
	b.mu.Unlock()

	if !wasActive {
		return
	}
	close(b.stop)
	<-b.done

	b.mu.Lock()
	defer b.mu.Unlock()
	// Reset the scroll region to the full screen, erase the bar row, and
	// leave the cursor on it so the shell prompt that follows does not
	// overwrite the guest's last line.
	fmt.Fprintf(b.out, "\x1b[r\x1b[%d;1H\x1b[2K", b.rows)
}

// Resize updates the terminal size, reinstalls the scroll region and
// repaints. It returns the new guest height.
func (b *StatusBar) Resize(cols, rows int) int {
	b.mu.Lock()
	b.cols, b.rows = cols, rows
	// Force the next repaint even if the text is unchanged: the bar has to
	// be rewritten at a new width and position.
	b.lastBar = ""
	guest := b.guestRowsLocked()
	if b.active {
		fmt.Fprintf(b.out, "\x1b[1;%dr", guest)
	}
	b.mu.Unlock()

	// Repaint immediately rather than waiting for the next tick, so a
	// resize does not leave a stale bar on screen.
	b.request()
	return guest
}

// Observe inspects guest output for mode changes that affect the bar. The
// data is not modified; callers forward it as-is.
func (b *StatusBar) Observe(p []byte) {
	b.mu.Lock()
	changed := b.modes.Observe(p)
	if !changed {
		b.mu.Unlock()
		return
	}
	// Something changed that the bar's own text does not reflect -- the row
	// was erased, or the screen was handed over and taken back. Clearing
	// lastBar forces the next draw to happen even though the text is the
	// same, which is what the unchanged-repaint skip would otherwise
	// suppress forever.
	b.lastBar = ""

	wasReset := b.modes.TakeReset()
	alt := b.modes.AltScreen()
	b.hidden = alt
	switch {
	case alt && b.active:
		// The application is taking the whole screen: drop the scroll
		// region so it can use every row, and stop drawing.
		fmt.Fprint(b.out, "\x1b[r")
	case b.active:
		// Either a full-screen application exited, the guest erased the
		// screen, or it reset the terminal. A reset discards the scroll
		// region, and an alt-screen exit restores whatever region was in
		// effect before, so the region is reinstalled in both cases rather
		// than assumed to have survived.
		fmt.Fprintf(b.out, "\x1b[1;%dr", b.guestRowsLocked())
		if wasReset {
			// A reset also returns the cursor to the top-left of a
			// now-unrestricted screen. Put it back inside the region so the
			// guest's next line does not land on the bar's row.
			fmt.Fprint(b.out, "\x1b[1;1H")
		}
	}
	b.mu.Unlock()
	b.request()
}

// request signals that the bar should be repainted. It never blocks: if a
// repaint is already pending the signal is dropped, which is what collapses a
// burst of changes into one draw.
func (b *StatusBar) request() {
	select {
	case b.dirty <- struct{}{}:
	default:
	}
}

// loop repaints on demand, rate-limited to one draw per tick.
func (b *StatusBar) loop() {
	defer close(b.done)
	ticker := time.NewTicker(barTick)
	defer ticker.Stop()

	last := time.Now()
	pending := false
	for {
		select {
		case <-b.stop:
			return
		case <-b.dirty:
			pending = true
		case <-ticker.C:
			if !pending && time.Since(last) < barIdle {
				continue
			}
			pending = false
			last = time.Now()
			b.draw()
		}
	}
}

// draw paints the bar row, unless nothing has changed since the last paint.
func (b *StatusBar) draw() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.active || b.hidden || b.cols < 1 {
		return
	}
	if b.modes.CursorSaved() {
		// The guest is between saving and restoring its cursor, and the
		// terminal has only one slot to save it in. Drawing now would
		// overwrite the guest's saved position with the bar's, so the guest's
		// restore would move its cursor to wherever the bar happened to be.
		//
		// lastBar is deliberately left alone: the text has not been written,
		// so the next draw must still treat it as changed. The repaint comes
		// from the restore (modeFilter.Observe) or from the idle tick,
		// whichever happens first.
		return
	}
	text := barText(b.left, b.right, b.cols)
	if text == b.lastBar {
		// Repainting an identical row is what makes a bar flicker on
		// terminals that do not double-buffer, so it is skipped.
		return
	}
	b.lastBar = text

	// One write, built in full first. Several smaller writes would let the
	// guest's own output interleave and tear the bar.
	//
	// DECSC/DECRC ("\x1b7"/"\x1b8") save and restore the cursor rather than
	// ANSI.SYS SCP/RCP ("\x1b[s"/"\x1b[u"): the latter collides with DECSLRM
	// (set left/right margin) on terminals that support margins, and shox
	// had to make exactly this change to fix rendering on macOS terminals
	// and IntelliJ (commit 2af5cf5).
	var sb strings.Builder
	sb.Grow(len(text) + 32)                //nolint:mnd // escape-sequence overhead
	sb.WriteString("\x1b7")                // save cursor
	fmt.Fprintf(&sb, "\x1b[%d;1H", b.rows) // move to the bar row
	sb.WriteString("\x1b[0m\x1b[7m")       // reset, then reverse video
	sb.WriteString(text)
	sb.WriteString("\x1b[0m") // reset attributes
	sb.WriteString("\x1b8")   // restore cursor
	_, _ = io.WriteString(b.out, sb.String())
}

// barText lays out the bar: left content, padding, right content, clipped to
// cols display columns.
func barText(left, right string, cols int) string {
	l, r := left, right
	lw, rw := cellWidth(l), cellWidth(r)

	// The right side is dropped before the left is truncated, on the
	// assumption that the left names what you are connected to and the
	// right is a hint.
	const gap = 1
	if lw+rw+gap > cols {
		r, rw = "", 0
	}
	if lw+rw+gap > cols {
		l = truncateCells(l, cols)
		lw = cellWidth(l)
	}
	pad := cols - lw - rw
	if pad < 0 {
		pad = 0
	}
	return l + strings.Repeat(" ", pad) + r
}

// cellWidth returns the number of terminal columns s occupies.
//
// This counts display cells, not bytes and not runes: a CJK ideograph or an
// emoji occupies two columns, and a combining mark occupies none. Measuring
// in bytes (as shox does when truncating, statusbar.go:84) both mismeasures
// and can split a rune, which prints mojibake.
func cellWidth(s string) int {
	n := 0
	for _, r := range s {
		n += runeCells(r)
	}
	return n
}

// runeCells returns the column width of a single rune.
//
// The ranges below are the East Asian Wide and Fullwidth classes from
// Unicode TR11 that matter in practice. This is deliberately a small table
// rather than a dependency on mattn/go-runewidth: the bar is one short line
// of mostly ASCII, so the full property database is not worth a new module.
func runeCells(r rune) int {
	switch {
	case r == 0:
		return 0
	case unicode.In(r, unicode.Mn, unicode.Me, unicode.Cf):
		// Combining marks and format characters occupy no column.
		return 0
	case r < 0x20, r == 0x7f:
		// Control characters are not printable; treat them as zero-width
		// rather than letting them inflate the measurement.
		return 0
	case isWideRune(r):
		return 2
	default:
		return 1
	}
}

func isWideRune(r rune) bool {
	switch {
	case r >= 0x1100 && r <= 0x115F, // Hangul Jamo
		r >= 0x2E80 && r <= 0xA4CF, // CJK radicals .. Yi
		r >= 0xAC00 && r <= 0xD7A3, // Hangul syllables
		r >= 0xF900 && r <= 0xFAFF, // CJK compatibility ideographs
		r >= 0xFE30 && r <= 0xFE6F, // CJK compatibility forms
		r >= 0xFF00 && r <= 0xFF60, // Fullwidth forms
		r >= 0xFFE0 && r <= 0xFFE6,
		r >= 0x1F300 && r <= 0x1F64F, // emoji
		r >= 0x1F900 && r <= 0x1F9FF,
		r >= 0x20000 && r <= 0x3FFFD: // CJK extension planes
		return true
	}
	return false
}

// truncateCells shortens s to at most cols display columns, never splitting a
// rune.
func truncateCells(s string, cols int) string {
	if cols <= 0 {
		return ""
	}
	w := 0
	for i, r := range s {
		cw := runeCells(r)
		if w+cw > cols {
			return s[:i]
		}
		w += cw
	}
	return s
}
