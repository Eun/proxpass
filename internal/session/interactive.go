package session

import (
	"fmt"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"

	"proxpass/internal/models"
)

// Terminal control sequences. Written directly rather than through a terminfo
// database: sshd only ever hands us a VT-compatible terminal, and these five
// sequences are supported by every one of them.
const (
	seqAltScreenOn  = "\x1b[?1049h"
	seqAltScreenOff = "\x1b[?1049l"
	seqHideCursor   = "\x1b[?25l"
	seqShowCursor   = "\x1b[?25h"
	seqClear        = "\x1b[H\x1b[2J"
	seqReset        = "\x1b[0m"
)

// Styles. Kept to the 8 ANSI colors plus bold/dim/reverse so the picker looks
// correct on any palette, including a light background.
const (
	styleTitle    = "\x1b[1;35m" // bold magenta
	styleHeader   = "\x1b[1m"    // bold
	styleSelected = "\x1b[7m"    // reverse video
	styleRunning  = "\x1b[32m"   // green
	styleStopped  = "\x1b[2m"    // dim
	styleMatch    = "\x1b[4m"    // underline
	styleHelp     = "\x1b[2m"    // dim
	styleWarn     = "\x1b[33m"   // yellow
)

// reservedRows is the number of rows the chrome outside the list occupies:
// title, blank, header, blank, filter/status and help.
const reservedRows = 6

// minListRows keeps the list usable on a very short terminal.
const minListRows = 3

// pickerState is the interactive picker's model.
type pickerState struct {
	all    []guestRow
	shown  []guestRow
	filter string
	cursor int
	offset int
	width  int
	height int
	user   string
	notice string
	// sort is the column the unfiltered list is ordered by. While a filter
	// is active the list is ordered by match relevance instead, because
	// that is the whole point of filtering; see setFilter.
	sort sortMode
}

// pickInteractive runs the full-screen picker.
//
// The terminal is already in raw mode, so this reads keystrokes one at a time
// and repaints the whole frame itself. It restores the screen on every exit
// path, including an error, so a failure never leaves the user's terminal in
// the alternate screen with a hidden cursor.
func (d *Deps) pickInteractive(rows []guestRow) (guestRow, error) {
	t := d.Terminal
	out := t.UIOut()

	s := &pickerState{
		all:    rows,
		shown:  rows,
		user:   d.User,
		width:  t.Width,
		height: t.Height,
	}
	if s.width <= 0 {
		s.width = 80
	}
	if s.height <= 0 {
		s.height = 24
	}

	// The alternate screen keeps the picker from scrolling the user's real
	// scrollback away, and guarantees the guest console starts on a clean
	// screen.
	fmt.Fprint(out, seqAltScreenOn+seqHideCursor)
	restore := func() { fmt.Fprint(out, seqShowCursor+seqAltScreenOff+seqReset) }

	// Resizes arrive as SIGWINCH on a separate channel; apply them between
	// keystrokes so the frame tracks the window.
	resizes := t.Resizes

	s.render(out)
	for {
		if resizes != nil {
			// Drain without blocking: a resize that arrived while we were
			// painting should take effect before the next frame.
			for drained := false; !drained; {
				select {
				case sz, ok := <-resizes:
					if !ok {
						resizes = nil
						drained = true
						break
					}
					s.width, s.height = sz.Width, sz.Height
					s.render(out)
				default:
					drained = true
				}
			}
		}

		key, err := readKey(t.In)
		if err != nil {
			restore()
			return guestRow{}, errQuit
		}

		switch action := s.apply(key); action {
		case actionQuit:
			restore()
			return guestRow{}, errQuit
		case actionSelect:
			row := s.shown[s.cursor]
			restore()
			return row, nil
		case actionNone:
		}
		s.render(out)
	}
}

// pickerAction is what a keystroke asked the picker to do.
type pickerAction int

const (
	actionNone pickerAction = iota
	actionQuit
	actionSelect
)

// apply folds a keystroke into the state and reports what to do next.
func (s *pickerState) apply(k key) pickerAction {
	s.notice = ""

	switch k.kind {
	case keyCtrlC:
		return actionQuit

	case keyEnter:
		if len(s.shown) == 0 {
			s.notice = "no guest matches the filter"
			return actionNone
		}
		row := s.shown[s.cursor]
		if !row.isRunning() {
			// Refuse rather than connect and fail: pct enter and qm terminal
			// only work on a running guest.
			s.notice = fmt.Sprintf("%s is %s and has no console",
				row.guest.Name, row.guest.Status)
			return actionNone
		}
		return actionSelect

	case keyEsc:
		// Esc clears an active filter before it quits, which is the
		// behavior every list UI has and what the old picker did.
		if s.filter != "" {
			s.setFilter("")
			return actionNone
		}
		return actionQuit

	case keyUp:
		s.move(-1)
	case keyDown:
		s.move(1)
	case keyPageUp:
		s.move(-s.listRows())
	case keyPageDown:
		s.move(s.listRows())
	case keyHome:
		s.move(-len(s.shown))
	case keyEnd:
		s.move(len(s.shown))

	case keyBackspace:
		if s.filter == "" {
			return actionNone
		}
		_, size := utf8.DecodeLastRuneInString(s.filter)
		s.setFilter(s.filter[:len(s.filter)-size])

	case keyCtrlU:
		s.setFilter("")

	case keyTab:
		s.cycleSort(true)
	case keyShiftTab:
		s.cycleSort(false)

	case keyLeft, keyRight, keyUnknown:
		// Horizontal movement has no meaning in a single-column list, and
		// an unrecognized sequence must not land in the filter as text.

	case keyRune:
		// "q" quits only when it would not otherwise be typed into a
		// filter, matching the old picker: once filtering, q is text.
		if k.r == 'q' && s.filter == "" {
			return actionQuit
		}
		s.setFilter(s.filter + string(k.r))
	}
	return actionNone
}

// setFilter re-runs the filter and keeps the cursor on something sensible.
func (s *pickerState) setFilter(f string) {
	s.filter = f
	s.shown = filterRows(s.all, f)
	if f == "" {
		// No filter: the chosen sort column decides the order. With a
		// filter, filterRows has already ordered by relevance and
		// re-sorting here would throw that away and make the filter much
		// less useful.
		sortRows(s.shown, s.sort)
	}
	s.cursor = 0
	s.offset = 0
}

// cycleSort moves to the next or previous sort column and reorders the list.
//
// It keeps the highlighted guest selected across the reorder rather than
// resetting to the top: the point of re-sorting is usually to find where a
// guest sits under a different order, and losing it defeats that.
func (s *pickerState) cycleSort(forward bool) {
	if forward {
		s.sort = s.sort.next()
	} else {
		s.sort = s.sort.prev()
	}

	if s.filter != "" {
		// Relevance ordering stays in force while filtering, so the new
		// mode cannot be applied yet. Say so rather than appear to do
		// nothing.
		s.notice = fmt.Sprintf("sort: %s (applies once the filter is cleared)", s.sort.label())
		return
	}

	var selected *models.Guest
	if s.cursor < len(s.shown) {
		selected = s.shown[s.cursor].guest
	}
	sortRows(s.shown, s.sort)
	s.restoreCursor(selected)
}

// restoreCursor puts the cursor back on guest after a reorder, and scrolls so
// it is visible.
func (s *pickerState) restoreCursor(guest *models.Guest) {
	if guest == nil {
		s.cursor, s.offset = 0, 0
		return
	}
	for i := range s.shown {
		if s.shown[i].guest == guest {
			s.cursor = i
			s.scrollToCursor()
			return
		}
	}
	s.cursor, s.offset = 0, 0
}

// move shifts the cursor by delta, clamped to the list.
func (s *pickerState) move(delta int) {
	if len(s.shown) == 0 {
		s.cursor, s.offset = 0, 0
		return
	}
	s.cursor += delta
	if s.cursor < 0 {
		s.cursor = 0
	}
	if s.cursor > len(s.shown)-1 {
		s.cursor = len(s.shown) - 1
	}
	s.scrollToCursor()
}

// scrollToCursor adjusts the viewport so the cursor is visible.
func (s *pickerState) scrollToCursor() {
	rows := s.listRows()
	if s.cursor < s.offset {
		s.offset = s.cursor
	}
	if s.cursor >= s.offset+rows {
		s.offset = s.cursor - rows + 1
	}
	if maxOffset := len(s.shown) - rows; s.offset > maxOffset {
		s.offset = maxOffset
	}
	if s.offset < 0 {
		s.offset = 0
	}
}

// listRows is how many guest rows fit on screen.
func (s *pickerState) listRows() int {
	n := s.height - reservedRows
	if n < minListRows {
		return minListRows
	}
	return n
}

// render paints a full frame.
//
// Every line is written with an explicit "\r\n" and the frame is assembled in
// one buffer before being written: the terminal is in raw mode, so a bare
// "\n" would not return the cursor to column 0, and painting line by line
// flickers.
func (s *pickerState) render(w io.Writer) {
	var b strings.Builder
	b.WriteString(seqClear)

	total := len(s.all)
	b.WriteString(styleTitle)
	b.WriteString(truncate(fmt.Sprintf("proxpass — guests available to %s", s.user), s.width))
	b.WriteString(seqReset + "\r\n\r\n")

	widths := columnWidths(s.shown)
	b.WriteString(styleHeader)
	b.WriteString(truncate("  "+s.headerRow(widths), s.width))
	b.WriteString(seqReset + "\r\n")

	rows := s.listRows()
	end := s.offset + rows
	if end > len(s.shown) {
		end = len(s.shown)
	}
	for i := s.offset; i < end; i++ {
		b.WriteString(s.renderRow(s.shown[i], widths, i == s.cursor))
		b.WriteString("\r\n")
	}
	// Pad so the chrome below never jumps as the result count changes.
	for i := end - s.offset; i < rows; i++ {
		b.WriteString("\r\n")
	}

	b.WriteString("\r\n")
	b.WriteString(s.renderStatus(total))
	b.WriteString("\r\n")
	b.WriteString(styleHelp)
	b.WriteString(truncate(
		"  ↑/↓ move · type to filter · ⏎ connect · tab sort · esc clear · ctrl+c quit",
		s.width))
	b.WriteString(seqReset)

	_, _ = io.WriteString(w, b.String())
}

// headerRow renders the column headings, marking the one the list is
// currently sorted by.
//
// The marker is an arrow appended to the active heading rather than a
// separate line, so it costs no vertical space and sits where the user is
// already looking. While a filter is active the list is ordered by relevance
// instead, so no column is marked -- claiming otherwise would be a lie.
func (s *pickerState) headerRow(widths colWidths) string {
	active := s.sort
	if s.filter != "" {
		// Out of range of every real mode, so nothing is marked.
		active = sortModeCount
	}
	return fmt.Sprintf("%-*s  %-*s  %-*s  %s",
		widths.id, headerCell(colID, active == sortByID),
		widths.name, headerCell(colName, active == sortByName),
		widths.status, headerCell(colStatus, active == sortByStatus),
		headerCell(colHost, active == sortByHost))
}

// headerCell appends the sort marker to a heading when it is the active one.
func headerCell(label string, active bool) string {
	if !active {
		return label
	}
	return label + sortMarker
}

// sortMarker flags the column the list is sorted by. Ascending is the only
// direction offered, so a single glyph suffices.
const sortMarker = " ▲"

// renderRow renders one guest line.
func (s *pickerState) renderRow(r guestRow, widths colWidths, selected bool) string {
	marker := "  "
	if selected {
		marker = "▸ "
	}

	id := pad(highlight(r.id, s.filter), displayWidth(r.id), widths.id)
	name := pad(highlight(r.guest.Name, s.filter), displayWidth(r.guest.Name), widths.name)
	status := pad(string(r.guest.Status), displayWidth(string(r.guest.Status)), widths.status)
	// The host is the last column, so it needs no padding of its own.
	host := highlight(r.instName, s.filter)

	body := fmt.Sprintf("%s%s  %s  %s  %s", marker, id, name, status, host)

	style := styleRunning
	if !r.isRunning() {
		style = styleStopped
	}
	if selected {
		style = styleSelected
	}
	return style + truncateStyled(body, s.width) + seqReset
}

// renderStatus renders the filter prompt and the result count.
func (s *pickerState) renderStatus(total int) string {
	if s.notice != "" {
		return styleWarn + truncate("  "+s.notice, s.width) + seqReset
	}
	if s.filter == "" {
		// The sort column is named here as well as marked in the header:
		// the header marker says which column, this says it in words, and
		// the two together make the Tab key discoverable.
		return styleHelp + truncate(fmt.Sprintf("  %d guests · sort: %s",
			total, s.sort.label()), s.width) + seqReset
	}
	// The block is a fake cursor: the real one is hidden so it cannot be
	// left behind in the wrong place by a repaint.
	//
	// "sort: best match" rather than the chosen column, because that is
	// what the list is actually ordered by while filtering.
	return truncate(fmt.Sprintf("  filter: %s\u2588  (%d/%d) · sort: best match",
		s.filter, len(s.shown), total), s.width)
}

// highlight underlines the characters of text that the filter matched.
func highlight(text, filter string) string {
	if filter == "" {
		return text
	}
	idx := matchIndices(text, filter)
	if len(idx) == 0 {
		return text
	}
	var b strings.Builder
	marked := make(map[int]bool, len(idx))
	for _, i := range idx {
		marked[i] = true
	}
	for i, r := range []rune(text) {
		if marked[i] {
			b.WriteString(styleMatch)
			b.WriteRune(r)
			b.WriteString("\x1b[24m") // underline off only
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// matchIndices returns the rune offsets in text matched by filter, using the
// same left-to-right subsequence walk as fuzzyScore.
func matchIndices(text, filter string) []int {
	hay := []rune(strings.ToLower(text))
	needle := []rune(strings.ToLower(strings.TrimSpace(filter)))
	var out []int
	hi := 0
	for _, c := range needle {
		for ; hi < len(hay); hi++ {
			if hay[hi] == c {
				out = append(out, hi)
				hi++
				break
			}
		}
	}
	// A partial walk means the filter matched some other field (the instance
	// name, say), so do not highlight a misleading subset.
	if len(out) != len(needle) {
		return nil
	}
	return out
}

// displayWidth is the printable width of s, ignoring escape sequences.
func displayWidth(s string) int {
	n := 0
	inEsc := false
	for _, r := range s {
		switch {
		case inEsc:
			if unicode.IsLetter(r) {
				inEsc = false
			}
		case r == '\x1b':
			inEsc = true
		default:
			n++
		}
	}
	return n
}

// pad right-pads styled text whose printable width is known.
func pad(styled string, width, to int) string {
	if width >= to {
		return styled
	}
	return styled + strings.Repeat(" ", to-width)
}

// truncate cuts plain text to width columns.
func truncate(s string, width int) string {
	if width <= 0 {
		return s
	}
	r := []rune(s)
	if len(r) <= width {
		return s
	}
	if width == 1 {
		return "…"
	}
	return string(r[:width-1]) + "…"
}

// truncateStyled cuts text that may contain escape sequences to width
// printable columns, keeping the sequences intact.
func truncateStyled(s string, width int) string {
	if width <= 0 || displayWidth(s) <= width {
		return s
	}
	var (
		b     strings.Builder
		shown int
		inEsc bool
	)
	for _, r := range s {
		switch {
		case inEsc:
			b.WriteRune(r)
			if unicode.IsLetter(r) {
				inEsc = false
			}
		case r == '\x1b':
			b.WriteRune(r)
			inEsc = true
		default:
			if shown >= width-1 {
				b.WriteString("…")
				return b.String()
			}
			b.WriteRune(r)
			shown++
		}
	}
	return b.String()
}
