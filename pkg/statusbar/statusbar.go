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
	"github.com/muesli/termenv"
)

// vt10x stores these glyph attribute bits in Glyph.Mode (int16).
// The constants are unexported in vt10x, so we mirror them here.
// Values must stay in sync with github.com/hinshun/vt10x state.go.
const (
	vtAttrReverse   = int16(1 << 0) // 1  – already baked into FG/BG by vt10x; kept for completeness
	vtAttrUnderline = int16(1 << 1) // 2
	vtAttrBold      = int16(1 << 2) // 4
	// attrGfx         = int16(1 << 3) // 8  – graphics character set; not an SGR attribute
	vtAttrItalic = int16(1 << 4) // 16
	vtAttrBlink  = int16(1 << 5) // 32
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

// WithTermType detects the SSH client's color capability from its TERM,
// COLORTERM, and NO_COLOR values and configures the status bar renderer
// accordingly. Pass the values from the SSH pty-req and any SSH env requests.
// termType is the TERM value (e.g. "xterm-256color", "dumb").
// colorTerm is the COLORTERM value (e.g. "truecolor", "24bit", or "").
// noColor is the NO_COLOR value (non-empty means no color).
func WithTermType(termType, colorTerm, noColor string) Option {
	return func(sb *StatusBar) {
		env := &singleEnv{term: termType, colorTerm: colorTerm, noColor: noColor}
		out := termenv.NewOutput(nil, termenv.WithEnvironment(env))
		p := out.EnvColorProfile()
		sb.colorProfile = p
	}
}

// singleEnv implements termenv.Environ for color-profile detection only.
type singleEnv struct {
	term      string
	colorTerm string
	noColor   string
}

func (e *singleEnv) Environ() []string {
	return []string{
		"TERM=" + e.term,
		"COLORTERM=" + e.colorTerm,
		"NO_COLOR=" + e.noColor,
	}
}

func (e *singleEnv) Getenv(key string) string {
	switch key {
	case "TERM":
		return e.term
	case "COLORTERM":
		return e.colorTerm
	case "NO_COLOR":
		return e.noColor
	}
	return ""
}

// ---- StatusBar ----

// StatusBar wraps a vt10x terminal emulator and renders its cell grid plus a
// one-line status bar to the SSH client on every guest write.
type StatusBar struct {
	client       io.Writer // raw SSH channel stdout
	term         vt10x.Terminal
	mu           sync.Mutex
	rows         int
	cols         int
	prefix       string
	content      string
	hint         string
	colorProfile termenv.Profile // TrueColor (default), ANSI256, ANSI, or Ascii
	// last rendered frame for differential updates
	lastFrame string
}

// New creates a new StatusBar that writes to client.
func New(client io.Writer, opts ...Option) *StatusBar {
	sb := &StatusBar{
		client:       client,
		colorProfile: termenv.TrueColor, // default: full color until told otherwise
	}
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
		renderRow(&out, sb.term, y, sb.cols, sb.colorProfile)
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
func renderRow(out *strings.Builder, t vt10x.Terminal, y, cols int, p termenv.Profile) {
	var lastFG, lastBG vt10x.Color = vt10x.DefaultFG, vt10x.DefaultBG
	lastMode := int16(0)
	attrSet := false

	for x := 0; x < cols; x++ {
		g := t.Cell(x, y)
		// Emit SGR only when attributes change.
		if g.FG != lastFG || g.BG != lastBG || g.Mode != lastMode || !attrSet {
			out.WriteString("\x1b[0m") // reset
			writeSGR(out, g, p)
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

// writeSGR emits SGR sequences for a glyph's colors and text attributes.
//
// vt10x already bakes the reverse-video swap into FG/BG during setChar, so we
// do NOT re-emit SGR 7 (reverse). We do emit the remaining attribute bits:
// bold (SGR 1), italic (SGR 3), underline (SGR 4), blink (SGR 5).
func writeSGR(out *strings.Builder, g vt10x.Glyph, p termenv.Profile) {
	// Text attributes (independent of color profile).
	if g.Mode&vtAttrBold != 0 {
		out.WriteString("\x1b[1m")
	}
	if g.Mode&vtAttrItalic != 0 {
		out.WriteString("\x1b[3m")
	}
	if g.Mode&vtAttrUnderline != 0 {
		out.WriteString("\x1b[4m")
	}
	if g.Mode&vtAttrBlink != 0 {
		out.WriteString("\x1b[5m")
	}
	// Colors: only emit when the client supports them.
	if p == termenv.Ascii {
		return
	}
	writeColor(out, g.FG, false, p)
	writeColor(out, g.BG, true, p)
}

// writeColor emits the SGR color sequence for a vt10x.Color, downgrading to
// the capabilities expressed by p.
//
// p == Ascii: caller must not call this function (no colors).
// p == ANSI:  only 16-color ANSI codes; 256/24-bit colors are quantised.
// p == ANSI256: 256-color palette; 24-bit colors are quantised.
// p == TrueColor: full 24-bit support.
func writeColor(out *strings.Builder, c vt10x.Color, bg bool, p termenv.Profile) { //nolint:cyclop
	if c == vt10x.DefaultFG || c == vt10x.DefaultBG || c == vt10x.DefaultCursor {
		return // leave as terminal default
	}
	base := 30
	if bg {
		base = 40
	}
	// Determine what level of color this vt10x.Color value represents.
	switch {
	case c < 8: //nolint:mnd // standard ANSI (0-7)
		out.WriteString(fmt.Sprintf("\x1b[%dm", int(c)+base))
	case c < 16: //nolint:mnd // bright ANSI (8-15)
		out.WriteString(fmt.Sprintf("\x1b[%dm", int(c)-8+base+60)) //nolint:mnd
	case c < 256: //nolint:mnd // 256-color index
		if p == termenv.ANSI {
			// Quantise 256-color to nearest ANSI-16 index.
			idx := ansi256ToANSI(int(c))
			if idx < 8 { //nolint:mnd
				out.WriteString(fmt.Sprintf("\x1b[%dm", idx+base))
			} else {
				out.WriteString(fmt.Sprintf("\x1b[%dm", idx-8+base+60)) //nolint:mnd
			}
		} else {
			// ANSI256 or TrueColor: emit as 256-color.
			if bg {
				out.WriteString(fmt.Sprintf("\x1b[48;5;%dm", c))
			} else {
				out.WriteString(fmt.Sprintf("\x1b[38;5;%dm", c))
			}
		}
	default: // 24-bit color stored as RGB in bits 0-23 (vt10x encodes this way)
		r := (c >> 16) & 0xff //nolint:mnd
		g := (c >> 8) & 0xff  //nolint:mnd
		b := c & 0xff
		switch p {
		case termenv.TrueColor:
			if bg {
				out.WriteString(fmt.Sprintf("\x1b[48;2;%d;%d;%dm", r, g, b))
			} else {
				out.WriteString(fmt.Sprintf("\x1b[38;2;%d;%d;%dm", r, g, b))
			}
		case termenv.ANSI256:
			// Quantise to 256-color.
			idx := rgbToANSI256(int(r), int(g), int(b))
			if bg {
				out.WriteString(fmt.Sprintf("\x1b[48;5;%dm", idx))
			} else {
				out.WriteString(fmt.Sprintf("\x1b[38;5;%dm", idx))
			}
		case termenv.ANSI:
			// Quantise to ANSI-16.
			idx256 := rgbToANSI256(int(r), int(g), int(b))
			idx := ansi256ToANSI(idx256)
			if idx < 8 { //nolint:mnd
				out.WriteString(fmt.Sprintf("\x1b[%dm", idx+base))
			} else {
				out.WriteString(fmt.Sprintf("\x1b[%dm", idx-8+base+60)) //nolint:mnd
			}
		}
	}
}

// ansi256ToANSI maps an ANSI-256 palette index to the nearest ANSI-16 index.
// The first 16 entries map directly; entries 16-231 (the 6×6×6 colour cube)
// are rounded to the closest standard colour; entries 232-255 (greyscale ramp)
// map to black or white depending on luminance.
func ansi256ToANSI(idx int) int {
	if idx < 16 { //nolint:mnd
		return idx
	}
	if idx > 231 { //nolint:mnd // greyscale ramp (232-255)
		if idx >= 244 { //nolint:mnd
			return 15 // bright white
		}
		return 0 // black
	}
	// 6×6×6 colour cube: index 16 = (0,0,0), step = 40 per channel.
	i := idx - 16 //nolint:mnd
	b := i % 6    //nolint:mnd
	g := (i / 6) % 6 //nolint:mnd
	r := i / 36      //nolint:mnd
	// Map each channel: 0→0, 1-2→0 (dark), 3-5→1 (bright).
	ansiR, ansiG, ansiB := 0, 0, 0
	if r >= 3 { //nolint:mnd
		ansiR = 1
	}
	if g >= 3 { //nolint:mnd
		ansiG = 1
	}
	if b >= 3 { //nolint:mnd
		ansiB = 1
	}
	ansiIdx := ansiR*4 + ansiG*2 + ansiB //nolint:mnd // maps to 0-7
	// Use bright variant when at least two channels are strong.
	if r+g+b >= 9 { //nolint:mnd
		ansiIdx += 8 //nolint:mnd
	}
	return ansiIdx
}

// rgbToANSI256 returns the nearest ANSI-256 palette index for an RGB triplet.
func rgbToANSI256(r, g, b int) int {
	// Check greyscale ramp first (232-255): steps of ~10 from 8 to 238.
	if r == g && g == b {
		if r < 8 { //nolint:mnd
			return 16 // use colour-cube black
		}
		if r > 248 { //nolint:mnd
			return 231 // use colour-cube white
		}
		return 232 + (r-8)/10 //nolint:mnd
	}
	// 6×6×6 colour cube: index = 16 + 36*r6 + 6*g6 + b6 where x6 = (x*6-1)/256.
	r6 := (r*6 - 1) / 256 //nolint:mnd
	g6 := (g*6 - 1) / 256 //nolint:mnd
	b6 := (b*6 - 1) / 256 //nolint:mnd
	if r6 < 0 {
		r6 = 0
	}
	if g6 < 0 {
		g6 = 0
	}
	if b6 < 0 {
		b6 = 0
	}
	return 16 + 36*r6 + 6*g6 + b6 //nolint:mnd
}

// barText builds the status bar string, padded to sb.cols.
// When the client supports at least ANSI colors, the bar is rendered in reverse
// video (SGR 7). On Ascii-profile clients the bar text is emitted plain.
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
	if sb.colorProfile == termenv.Ascii {
		return string(runes)
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
