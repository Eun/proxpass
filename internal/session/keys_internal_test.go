package session

import (
	"io"
	"strings"
	"testing"
)

// The picker reads raw bytes from a PTY, so it has to decode the escape
// sequences terminals actually send. Getting this wrong made the old picker
// treat an arrow key as three filter characters.
func TestReadKeyDecodesTerminalInput(t *testing.T) {
	for name, tc := range map[string]struct {
		in   string
		want key
	}{
		"plain rune":     {"a", key{kind: keyRune, r: 'a'}},
		"enter as CR":    {"\r", key{kind: keyEnter}},
		"enter as LF":    {"\n", key{kind: keyEnter}},
		"ctrl+c":         {"\x03", key{kind: keyCtrlC}},
		"tab":            {"\x09", key{kind: keyTab}},
		"shift+tab":      {"\x1b[Z", key{kind: keyShiftTab}},
		"ctrl+u":         {"\x15", key{kind: keyCtrlU}},
		"backspace":      {"\x7f", key{kind: keyBackspace}},
		"backspace 0x08": {"\x08", key{kind: keyBackspace}},
		"up":             {"\x1b[A", key{kind: keyUp}},
		"down":           {"\x1b[B", key{kind: keyDown}},
		"right":          {"\x1b[C", key{kind: keyRight}},
		"left":           {"\x1b[D", key{kind: keyLeft}},
		"home":           {"\x1b[H", key{kind: keyHome}},
		"end":            {"\x1b[F", key{kind: keyEnd}},
		"application up": {"\x1bOA", key{kind: keyUp}},
		"page up":        {"\x1b[5~", key{kind: keyPageUp}},
		"page down":      {"\x1b[6~", key{kind: keyPageDown}},
		"home numeric":   {"\x1b[1~", key{kind: keyHome}},
		"end numeric":    {"\x1b[4~", key{kind: keyEnd}},
		"lone esc":       {"\x1b", key{kind: keyEsc}},
		"utf-8 rune":     {"ä", key{kind: keyRune, r: 'ä'}},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := readKey(strings.NewReader(tc.in))
			if err != nil {
				t.Fatalf("readKey: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

// An arrow key must consume its whole sequence, or the remaining bytes are
// read as filter input.
func TestReadKeyConsumesTheWholeSequence(t *testing.T) {
	r := strings.NewReader("\x1b[Ax")

	if got, err := readKey(r); err != nil || got.kind != keyUp {
		t.Fatalf("first key = %+v (err %v), want up", got, err)
	}
	got, err := readKey(r)
	if err != nil {
		t.Fatalf("second key: %v", err)
	}
	if got.kind != keyRune || got.r != 'x' {
		t.Errorf("second key = %+v, want the rune x", got)
	}
}

// A closed stream must surface as an error so the picker exits instead of
// spinning on EOF.
func TestReadKeyReportsEOF(t *testing.T) {
	if _, err := readKey(strings.NewReader("")); err == nil {
		t.Error("readKey on an empty reader must return an error")
	}
}

// readLine backs the non-interactive fallback prompt. A raw-mode terminal
// sends a bare CR, so it must accept CR, LF and CRLF.
func TestReadLineAcceptsEveryLineEnding(t *testing.T) {
	for name, tc := range map[string]struct{ in, want string }{
		"CR":   {"12\r", "12"},
		"LF":   {"12\n", "12"},
		"CRLF": {"12\r\n", "12"},
		"EOF":  {"12", "12"},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := readLine(strings.NewReader(tc.in))
			if err != nil {
				t.Fatalf("readLine: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// readLine must not read past the line terminator: the same reader is handed
// to the guest console afterwards, so anything swallowed here is input the
// console never receives.
func TestReadLineLeavesTheRestOfTheStream(t *testing.T) {
	r := strings.NewReader("1\rrest-of-the-stream")
	if got, err := readLine(r); err != nil || got != "1" {
		t.Fatalf("readLine = %q (err %v), want %q", got, err, "1")
	}
	remaining, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("reading the remainder: %v", err)
	}
	if string(remaining) != "rest-of-the-stream" {
		t.Errorf("remaining = %q, want the console's input intact",
			string(remaining))
	}
}
