package console

import (
	"fmt"
	"regexp"
)

// cursorModel is the part of a terminal this package could not previously
// test: the cursor, and the single slot DECSC saves it in.
//
// Every existing test asserts on the bytes the bar emits. That cannot catch a
// cursor landing in the wrong place, because the defect is not in the bytes --
// each sequence is individually well formed -- but in what they do to shared
// terminal state. Feeding both the guest's stream and the bar's output through
// one model reproduces the interaction.
//
// Only what the bug needs is modeled: absolute positioning, and save/restore
// in both spellings. Per DEC STD 070 and xterm's ctlseqs there is exactly one
// save slot per screen buffer, which is the whole reason the bug exists, so
// the model deliberately has one too.
type cursorModel struct {
	row, col   int
	savedRow   int
	savedCol   int
	hasSaved   bool
	saveWrites int // how many times the slot was written
}

var reCursorPos = regexp.MustCompile(`^\x1b\[(\d*);(\d*)H`)

// feed applies s to the model.
func (c *cursorModel) feed(s string) {
	for i := 0; i < len(s); {
		rest := s[i:]
		switch {
		case len(rest) >= 2 && rest[0] == 0x1b && rest[1] == '7',
			len(rest) >= 3 && rest[0] == 0x1b && rest[1] == '[' && rest[2] == 's':
			c.savedRow, c.savedCol, c.hasSaved = c.row, c.col, true
			c.saveWrites++
			i += escLen(rest)
		case len(rest) >= 2 && rest[0] == 0x1b && rest[1] == '8',
			len(rest) >= 3 && rest[0] == 0x1b && rest[1] == '[' && rest[2] == 'u':
			if c.hasSaved {
				c.row, c.col = c.savedRow, c.savedCol
			}
			i += escLen(rest)
		case reCursorPos.MatchString(rest):
			m := reCursorPos.FindStringSubmatch(rest)
			row, col := 1, 1
			if m[1] != "" {
				_, _ = fmt.Sscanf(m[1], "%d", &row)
			}
			if m[2] != "" {
				_, _ = fmt.Sscanf(m[2], "%d", &col)
			}
			c.row, c.col = row, col
			i += len(m[0])
		default:
			i++
		}
	}
}

// escLen returns 2 for the two-byte DEC forms and 3 for the CSI forms.
func escLen(s string) int {
	if len(s) >= 2 && s[1] == '[' {
		return 3
	}
	return 2
}

// at reports the cursor position.
func (c *cursorModel) at() (row, col int) { return c.row, c.col }
