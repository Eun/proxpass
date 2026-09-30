package console_test

import (
	"bytes"
	"strings"
	"testing"

	"proxpass/internal/console"
)

// A raw-mode PTY has ONLCR disabled, so a bare "\n" moves down without
// returning to column 0 and the output staircases across the screen.
// The smallest input that shows the problem: one bare newline between two
// printable characters, and the same text correctly terminated.
const (
	twoLines     = "a\nb"
	twoLinesCRLF = "a\r\nb"
)

func TestCRLFWriterTranslatesBareNewlines(t *testing.T) {
	for name, tc := range map[string]struct{ in, want string }{
		"bare LF":         {twoLines, twoLinesCRLF},
		"already CRLF":    {twoLinesCRLF, twoLinesCRLF},
		"trailing LF":     {"a\n", "a\r\n"},
		"several lines":   {"1\n2\n3\n", "1\r\n2\r\n3\r\n"},
		"lone CR kept":    {"a\rb", "a\rb"},
		"no newline":      {"abc", "abc"},
		"empty":           {"", ""},
		"blank lines":     {"\n\n", "\r\n\r\n"},
		"CR then LF only": {"\r\n", "\r\n"},
	} {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			w := console.NewCRLFWriter(&buf)
			n, err := w.Write([]byte(tc.in))
			if err != nil {
				t.Fatalf("Write: %v", err)
			}
			// The inserted carriage returns are not the caller's bytes, so n
			// must be the input length; a larger n breaks io.Writer's
			// contract and makes io.Copy report a short write.
			if n != len(tc.in) {
				t.Errorf("n = %d, want %d", n, len(tc.in))
			}
			if got := buf.String(); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// A "\r\n" split across two writes must not become "\r\r\n".
func TestCRLFWriterRemembersACarriageReturnAcrossWrites(t *testing.T) {
	var buf bytes.Buffer
	w := console.NewCRLFWriter(&buf)
	if _, err := w.Write([]byte("a\r")); err != nil {
		t.Fatalf("first write: %v", err)
	}
	if _, err := w.Write([]byte("\nb")); err != nil {
		t.Fatalf("second write: %v", err)
	}
	if got, want := buf.String(), twoLinesCRLF; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// UIOut must only translate when the terminal is actually in raw mode, and a
// guest console (Out) must never be wrapped: its bytes may be binary escape
// sequences in which a 0x0a is data rather than a line break.
func TestUIWritersOnlyTranslateInRawMode(t *testing.T) {
	var out bytes.Buffer
	term := &console.Terminal{Out: &out, Err: &out}

	fmtLine := "x\ny"

	if _, err := term.UIOut().Write([]byte(fmtLine)); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got := out.String(); strings.Contains(got, "\r") {
		t.Errorf("cooked terminal must not get CRLF translation, got %q", got)
	}

	out.Reset()
	term.Raw = true
	if _, err := term.UIOut().Write([]byte(fmtLine)); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got, want := out.String(), "x\r\ny"; got != want {
		t.Errorf("raw terminal got %q, want %q", got, want)
	}

	// The raw guest stream itself is untouched.
	out.Reset()
	if _, err := term.Out.Write([]byte(fmtLine)); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got := out.String(); got != fmtLine {
		t.Errorf("guest console stream was altered: got %q, want %q", got, fmtLine)
	}
}

// A nil stream must not panic: a session without a PTY has no Err.
func TestUIWritersHandleANilStream(t *testing.T) {
	term := &console.Terminal{}
	if _, err := term.UIOut().Write([]byte("x")); err != nil {
		t.Errorf("UIOut on a nil stream: %v", err)
	}
	if _, err := term.UIErr().Write([]byte("x")); err != nil {
		t.Errorf("UIErr on a nil stream: %v", err)
	}
}
