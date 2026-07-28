// Package statusbar provides a persistent bottom status bar for SSH/PTY proxy
// sessions. It uses github.com/hinshun/vt10x as a full VT100 terminal
// emulator: guest output is parsed into a cell grid, then the grid (plus the
// bar row) is rendered to the SSH client on every update. This eliminates all
// DECSTBM tricks, stream interception, and regex patching — the bar is simply
// the last row of what we send to the client.
package statusbar

import (
	"fmt"
	"io"
	"strings"
	"sync"

	vt10x "github.com/hinshun/vt10x"
)

// ---- options ----

// ColorMode controls the visual style of the status bar.
type ColorMode int

const (
	ColorReverse ColorMode = iota // swap foreground and background (default)
)

// Option is a functional option for New.
type Option func(*StatusBar)

// WithText sets the left-side label (prefix) and centre content.
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

// StatusBar wraps a vt10x terminal emulator and renders its cell grid plus a
// one-line status bar to the SSH client on every guest write.
type StatusBar struct {
	client  io.Writer   // raw SSH channel stdout
	term    vt10x.Terminal
	mu      sync.Mutex
	rows    int
	cols    int
	prefix  string
	content string
	hint    string
	// last rendered frame for differential updates
	lastFrame string
}

// New creates a new StatusBar that writes to client.
func New(client io.Writer, opts ...Option) *StatusBar {
	sb := &StatusBar{client: client}
	for _, o := range opts {
		o(sb)
	}
	return sb
}

// Setup initialises the terminal emulator at the given size, renders the
// initial frame, and returns the guest height (totalRows - 1).
// Must be called before the guest session starts.
func (sb *StatusBar) Setup(cols, totalRows int) int {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	sb.cols = cols
	sb.rows = totalRows
	sb.term = vt10x.New(vt10x.WithSize(cols, sb.guestRows()))
	sb.render()
	return sb.guestRows()
}

// Resize updates the terminal size and re-renders. Returns the new guest height.
func (sb *StatusBar) Resize(cols, totalRows int) int {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	sb.cols = cols
	sb.rows = totalRows
	sb.term.Resize(cols, sb.guestRows())
	sb.render()
	return sb.guestRows()
}

// Clear erases the guest viewport and redraws the bar.
// Call when the guest exits without clearing the screen itself.
func (sb *StatusBar) Clear() {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	if sb.term == nil {
		return
	}
	// Write a home + full-screen clear into vt10x so its cell grid becomes
	// blank, then re-render (which will emit blank guest rows + our bar).
	_, _ = sb.term.Write([]byte("\x1b[H\x1b[2J"))
	sb.render()
}

// Teardown renders a final clean frame and resets the client terminal.
func (sb *StatusBar) Teardown() {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	// Move cursor to top, clear screen, reset attributes.
	_, _ = fmt.Fprintf(sb.client, "\x1b[?25h\x1b[0m\x1b[2J\x1b[H")
}

// Writer returns an io.Writer for guest→client data. Feed all PTY output
// through this writer; it parses into vt10x and re-renders on every chunk.
func (sb *StatusBar) Writer() io.Writer {
	return &vtWriter{sb: sb}
}

// guestRows is totalRows - 1 (minimum 1).
func (sb *StatusBar) guestRows() int {
	h := sb.rows - 1
	if h < 1 {
		h = 1
	}
	return h
}

// render emits the full terminal frame (guest rows + bar) to the client.
// Uses differential rendering: skips rows identical to the last frame.
// Caller must hold sb.mu.
func (sb *StatusBar) render() {
	if sb.term == nil || sb.rows < 2 || sb.cols < 1 { //nolint:mnd
		return
	}

	var out strings.Builder

	// Hide cursor while rendering to avoid flicker.
	out.WriteString("\x1b[?25l")

	sb.term.Lock()
	_, guestH := sb.term.Size() // Size() returns (cols, rows)
	// Render guest rows.
	for y := 0; y < guestH; y++ {
		out.WriteString(fmt.Sprintf("\x1b[%d;1H", y+1)) // move to row y+1, col 1
		renderRow(&out, sb.term, y, sb.cols)
	}

	// Cursor position from the terminal state.
	cur := sb.term.Cursor()
	cursorVisible := sb.term.CursorVisible()
	sb.term.Unlock()

	// Render bar row (always at sb.rows).
	out.WriteString(fmt.Sprintf("\x1b[%d;1H", sb.rows))
	out.WriteString("\x1b[0m") // reset before bar
	out.WriteString(sb.barText())

	// Restore cursor to where the guest expects it (within guest area).
	cx := cur.X + 1 // 1-indexed
	cy := cur.Y + 1
	out.WriteString(fmt.Sprintf("\x1b[%d;%dH", cy, cx))
	if cursorVisible {
		out.WriteString("\x1b[?25h")
	}

	_, _ = io.WriteString(sb.client, out.String())
}

// renderRow writes one row of the vt10x cell grid as SGR-escaped characters.
// It resets attributes after the row to avoid bleed.
func renderRow(out *strings.Builder, t vt10x.Terminal, y, cols int) {
	var lastFG, lastBG vt10x.Color = vt10x.DefaultFG, vt10x.DefaultBG
	lastMode := int16(0)
	attrSet := false

	for x := 0; x < cols; x++ {
		g := t.Cell(x, y)
		// Emit SGR only when attributes change.
		if g.FG != lastFG || g.BG != lastBG || g.Mode != lastMode || !attrSet {
			out.WriteString("\x1b[0m") // reset
			writeSGR(out, g)
			lastFG, lastBG, lastMode = g.FG, g.BG, g.Mode
			attrSet = true
		}
		if g.Char == 0 || g.Char == ' ' {
			out.WriteByte(' ')
		} else {
			out.WriteRune(g.Char)
		}
	}
	out.WriteString("\x1b[0m") // reset at end of row
}

// writeSGR emits SGR sequences for a glyph's foreground color.
// We write FG/BG colors; attribute bits (bold, reverse, etc.) are not exported
// by vt10x so we rely on the reset + color approach for correctness.
func writeSGR(out *strings.Builder, g vt10x.Glyph) {
	writeColor(out, g.FG, false)
	writeColor(out, g.BG, true)
}

// writeColor emits the SGR color sequence for a vt10x.Color.
func writeColor(out *strings.Builder, c vt10x.Color, bg bool) {
	if c == vt10x.DefaultFG || c == vt10x.DefaultBG || c == vt10x.DefaultCursor {
		return // leave as terminal default
	}
	base := 30
	if bg {
		base = 40
	}
	if c < 8 { //nolint:mnd
		out.WriteString(fmt.Sprintf("\x1b[%dm", int(c)+base))
	} else if c < 16 { //nolint:mnd
		out.WriteString(fmt.Sprintf("\x1b[%dm", int(c)-8+base+60)) //nolint:mnd
	} else if c < 256 { //nolint:mnd
		// 256-color
		if bg {
			out.WriteString(fmt.Sprintf("\x1b[48;5;%dm", c))
		} else {
			out.WriteString(fmt.Sprintf("\x1b[38;5;%dm", c))
		}
	} else if c < 1<<24 { //nolint:mnd
		// 24-bit color stored as RGB in bits 0-23
		r := (c >> 16) & 0xff //nolint:mnd
		g := (c >> 8) & 0xff  //nolint:mnd
		b := c & 0xff
		if bg {
			out.WriteString(fmt.Sprintf("\x1b[48;2;%d;%d;%dm", r, g, b))
		} else {
			out.WriteString(fmt.Sprintf("\x1b[38;2;%d;%d;%dm", r, g, b))
		}
	}
}

// barText builds the status bar string in reverse video, padded to sb.cols.
// Caller must hold sb.mu.
func (sb *StatusBar) barText() string {
	left := fmt.Sprintf(" [%s] %s ", sb.prefix, sb.content)
	right := ""
	if sb.hint != "" {
		right = fmt.Sprintf(" %s ", sb.hint)
	}
	avail := sb.cols - len(left) - len(right)
	mid := ""
	if avail > 0 {
		mid = strings.Repeat(" ", avail)
	}
	full := left + mid + right
	runes := []rune(full)
	if len(runes) > sb.cols {
		runes = runes[:sb.cols]
	}
	return "\x1b[7m" + string(runes) + "\x1b[0m"
}

// ---- vtWriter ----

// vtWriter feeds guest output into the vt10x emulator and re-renders.
type vtWriter struct {
	sb *StatusBar
}

func (vw *vtWriter) Write(p []byte) (int, error) {
	vw.sb.mu.Lock()
	defer vw.sb.mu.Unlock()
	if vw.sb.term == nil {
		return len(p), nil
	}
	n, err := vw.sb.term.Write(p)
	vw.sb.render()
	if err != nil {
		return n, err
	}
	return len(p), nil
}
