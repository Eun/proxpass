package console

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// screenModel is a terminal, as far as the status bar can affect one.
//
// cursorModel (cursormodel_test.go) models the cursor and the single DECSC
// slot, which was enough for the save/restore bug. It is not enough for
// resize: that bug is about the scroll region, the alternate screen and the
// physical geometry changing underneath both, and about where the guest's
// text ends up as a result. Asserting on emitted bytes cannot catch it,
// because every sequence the bar emits is individually well formed -- the
// fault is in what they do to shared terminal state that the guest also owns.
//
// So this models the screen: a grid, a cursor, a scroll region, and the
// alternate buffer. The guest's output and the bar's output are fed through
// one instance, which is the only way to reproduce an interaction between
// them.
//
// Two behaviors are deliberately configurable rather than assumed, because
// real terminals disagree and the bar has to be correct on both:
//
//   - homesOnDECSTBM: whether setting a scroll region moves the cursor.
//   - resetsRegionOnResize: whether a physical resize discards the region.
type screenModel struct {
	rows, cols int

	// cur is the cursor, 1-based, as a terminal reports it.
	cur cursorPos
	// saved is the terminal's single cursor-save slot.
	saved    cursorPos
	hasSaved bool

	// top and bottom are the scroll region, 1-based and inclusive.
	top, bottom int

	alt bool
	// normal holds the normal screen's state while the alternate screen is
	// in use, since leaving the alternate screen restores it.
	normal *screenModel

	grid [][]rune

	homesOnDECSTBM       bool
	resetsRegionOnResize bool
}

type cursorPos struct{ row, col int }

// newScreen returns a blank screen of the given size with no scroll region.
func newScreen(cols, rows int) *screenModel {
	s := &screenModel{
		rows: rows,
		cols: cols,
		cur:  cursorPos{row: 1, col: 1},
		top:  1, bottom: rows,
	}
	s.allocate()
	return s
}

func (s *screenModel) allocate() {
	s.grid = make([][]rune, s.rows)
	for i := range s.grid {
		s.grid[i] = blankRow(s.cols)
	}
}

func blankRow(cols int) []rune {
	row := make([]rune, cols)
	for i := range row {
		row[i] = ' '
	}
	return row
}

// at reports the cursor position.
func (s *screenModel) at() (row, col int) { return s.cur.row, s.cur.col }

// region reports the scroll region.
func (s *screenModel) region() (top, bottom int) { return s.top, s.bottom }

// line returns the text on a row, 1-based, with trailing blanks removed.
func (s *screenModel) line(row int) string {
	if row < 1 || row > s.rows {
		return ""
	}
	return strings.TrimRight(string(s.grid[row-1]), " ")
}

// render returns the whole screen, one row per line, for failure messages.
func (s *screenModel) render() string {
	var sb strings.Builder
	for i := 1; i <= s.rows; i++ {
		fmt.Fprintf(&sb, "%2d|%s|\n", i, s.line(i))
	}
	return sb.String()
}

// resize applies a physical terminal resize, the way a window manager does:
// the grid changes size and the cursor is clamped onto it. The guest is not
// consulted and nothing is redrawn, because a terminal does not redraw -- only
// the application does, and only if it is told.
func (s *screenModel) resize(cols, rows int) {
	old := s.grid
	s.cols, s.rows = cols, rows
	s.allocate()
	for i := 0; i < len(old) && i < rows; i++ {
		copy(s.grid[i], old[i])
	}
	s.cur.row = clamp(s.cur.row, rows)
	s.cur.col = clamp(s.cur.col, cols)
	if s.resetsRegionOnResize {
		s.top, s.bottom = 1, rows
	} else {
		s.top = clamp(s.top, rows)
		s.bottom = clamp(s.bottom, rows)
	}
}

// clamp confines v to 1..hi, which is the range of every 1-based terminal
// coordinate.
func clamp(v, hi int) int {
	if v < 1 {
		return 1
	}
	if v > hi {
		return hi
	}
	return v
}

var (
	reCUP     = regexp.MustCompile(`^\x1b\[(\d*)(?:;(\d*))?H`)
	reDECSTBM = regexp.MustCompile(`^\x1b\[(\d*)(?:;(\d*))?r`)
	reAlt     = regexp.MustCompile(`^\x1b\[\?(47|1047|1049)([hl])`)
	reEraseL  = regexp.MustCompile(`^\x1b\[(\d*)K`)
	reEraseD  = regexp.MustCompile(`^\x1b\[(\d*)J`)
	reSGR     = regexp.MustCompile(`^\x1b\[[0-9;]*m`)
	reOtherPM = regexp.MustCompile(`^\x1b\[\?[0-9;]*[hl]`)
)

// feed applies s to the screen.
//
// One case per escape sequence; splitting it would scatter the terminal's
// behavior across several functions.
func (s *screenModel) feed(data string) {
	for i := 0; i < len(data); {
		rest := data[i:]
		switch {
		case strings.HasPrefix(rest, "\x1b7"), strings.HasPrefix(rest, "\x1b[s"):
			s.saved, s.hasSaved = s.cur, true
			i += escapeWidth(rest)
		case strings.HasPrefix(rest, "\x1b8"), strings.HasPrefix(rest, "\x1b[u"):
			if s.hasSaved {
				// A restore is clamped to the screen: the saved row may no
				// longer exist after a resize.
				s.cur.row = clamp(s.saved.row, s.rows)
				s.cur.col = clamp(s.saved.col, s.cols)
			}
			i += escapeWidth(rest)
		case strings.HasPrefix(rest, "\x1bc"):
			*s = *newScreen(s.cols, s.rows)
			i += 2
		case reCUP.MatchString(rest):
			m := reCUP.FindStringSubmatch(rest)
			s.cur.row = clamp(param(m[1], 1), s.rows)
			s.cur.col = clamp(param(m[2], 1), s.cols)
			i += len(m[0])
		case reDECSTBM.MatchString(rest):
			m := reDECSTBM.FindStringSubmatch(rest)
			top, bottom := param(m[1], 1), param(m[2], s.rows)
			if top < 1 {
				top = 1
			}
			if bottom > s.rows || bottom < 1 {
				bottom = s.rows
			}
			if top < bottom {
				s.top, s.bottom = top, bottom
			}
			if s.homesOnDECSTBM {
				s.cur = cursorPos{row: 1, col: 1}
			}
			i += len(m[0])
		case reAlt.MatchString(rest):
			m := reAlt.FindStringSubmatch(rest)
			s.setAlt(m[2] == "h")
			i += len(m[0])
		case reEraseL.MatchString(rest):
			m := reEraseL.FindStringSubmatch(rest)
			s.eraseLine(param(m[1], 0))
			i += len(m[0])
		case reEraseD.MatchString(rest):
			m := reEraseD.FindStringSubmatch(rest)
			s.eraseDisplay(param(m[1], 0))
			i += len(m[0])
		case reSGR.MatchString(rest), reOtherPM.MatchString(rest):
			i += len(firstMatch(rest, reSGR, reOtherPM))
		case rest[0] == '\n':
			s.lineFeed()
			i++
		case rest[0] == '\r':
			s.cur.col = 1
			i++
		case rest[0] == 0x1b:
			// An escape this model does not implement. Skip the introducer
			// only; the remainder is harmless for what is asserted here.
			i++
		default:
			s.put(rune(rest[0]))
			i++
		}
	}
}

func firstMatch(s string, res ...*regexp.Regexp) string {
	for _, re := range res {
		if m := re.FindString(s); m != "" {
			return m
		}
	}
	return ""
}

func param(s string, def int) int {
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return n
}

// escapeWidth returns 3 for the CSI spellings and 2 for the two-byte DEC ones.
func escapeWidth(s string) int {
	if len(s) >= 2 && s[1] == '[' {
		return 3
	}
	return 2
}

func (s *screenModel) setAlt(on bool) {
	if on == s.alt {
		return
	}
	if on {
		saved := *s
		saved.grid = cloneGrid(s.grid)
		s.normal = &saved
		s.alt = true
		s.allocate()
		// The alternate screen has no scroll region of its own until one is
		// set, and it starts at the home position.
		s.top, s.bottom = 1, s.rows
		s.cur = cursorPos{row: 1, col: 1}
		return
	}
	// Leaving the alternate screen restores the normal screen wholesale,
	// which is why the bar's region has to be reinstalled afterwards.
	if s.normal != nil {
		restored := s.normal
		restored.rows, restored.cols = s.rows, s.cols
		restored.homesOnDECSTBM = s.homesOnDECSTBM
		restored.resetsRegionOnResize = s.resetsRegionOnResize
		*s = *restored
	}
	s.alt = false
}

func cloneGrid(g [][]rune) [][]rune {
	out := make([][]rune, len(g))
	for i := range g {
		out[i] = append([]rune(nil), g[i]...)
	}
	return out
}

func (s *screenModel) eraseLine(mode int) {
	row := s.grid[s.cur.row-1]
	switch mode {
	case 1:
		for i := 0; i < s.cur.col && i < len(row); i++ {
			row[i] = ' '
		}
	case 2:
		copy(row, blankRow(s.cols))
	default:
		for i := s.cur.col - 1; i < len(row); i++ {
			row[i] = ' '
		}
	}
}

func (s *screenModel) eraseDisplay(mode int) {
	switch mode {
	case 1:
		for r := 1; r < s.cur.row; r++ {
			copy(s.grid[r-1], blankRow(s.cols))
		}
		s.eraseLine(1)
	case 2, 3:
		for r := range s.grid {
			copy(s.grid[r], blankRow(s.cols))
		}
	default:
		s.eraseLine(0)
		for r := s.cur.row + 1; r <= s.rows; r++ {
			copy(s.grid[r-1], blankRow(s.cols))
		}
	}
}

// put writes a printable rune at the cursor and advances it.
func (s *screenModel) put(r rune) {
	if s.cur.row < 1 || s.cur.row > s.rows || s.cur.col < 1 || s.cur.col > s.cols {
		return
	}
	s.grid[s.cur.row-1][s.cur.col-1] = r
	if s.cur.col < s.cols {
		s.cur.col++
	}
}

// lineFeed moves down a row, scrolling the region when the cursor is on its
// last line. This is the behavior a scroll region exists to produce, and the
// reason the bar's row survives a chatty guest.
func (s *screenModel) lineFeed() {
	if s.cur.row == s.bottom {
		copy(s.grid[s.top-1:s.bottom-1], s.grid[s.top:s.bottom])
		s.grid[s.bottom-1] = blankRow(s.cols)
		return
	}
	if s.cur.row < s.rows {
		s.cur.row++
	}
}

// barRow returns the row the bar occupies on a screen of this height.
func (s *screenModel) barRow() int { return s.rows }
