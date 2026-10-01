package console

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

// readAll drains r through the escape reader the way a transport does, in
// small chunks, and reports what reached the guest plus whether it escaped.
func drain(t *testing.T, r io.Reader, chunk int) (forwarded string, escaped bool) {
	t.Helper()
	var got bytes.Buffer
	er := newEscapeReader(r, func() { escaped = true })
	buf := make([]byte, chunk)
	for {
		n, err := er.Read(buf)
		got.Write(buf[:n])
		if err != nil {
			if !errors.Is(err, io.EOF) {
				t.Fatalf("read: %v", err)
			}
			return got.String(), escaped
		}
	}
}

func TestEscapeReaderDisconnectsOnCtrlAX(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input string
	}{
		{"upper X", "hi\x01X"},
		{"lower x", "hi\x01x"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			forwarded, escaped := drain(t, strings.NewReader(tc.input), 64)
			if !escaped {
				t.Fatal("expected the escape to fire")
			}
			// Neither the Ctrl+A nor the X may reach the guest.
			if strings.ContainsAny(forwarded, "\x01Xx") {
				t.Errorf("escape bytes leaked to the guest: %q", forwarded)
			}
		})
	}
}

// The sequence must work when it is split across reads, which is the normal
// case for a human typing: each keystroke arrives in its own Read.
func TestEscapeReaderWorksOneByteAtATime(t *testing.T) {
	_, escaped := drain(t, strings.NewReader("\x01X"), 1)
	if !escaped {
		t.Fatal("expected the escape to fire across separate reads")
	}
}

func TestEscapeReaderForwardsOrdinaryInput(t *testing.T) {
	const input = "ls -la\r\nexit\r\n"
	forwarded, escaped := drain(t, strings.NewReader(input), 64)
	if escaped {
		t.Error("ordinary input must not escape")
	}
	if forwarded != input {
		t.Errorf("input was altered: got %q want %q", forwarded, input)
	}
}

// Ctrl+A is start-of-line in a shell, so it has to survive when it is not
// followed by X. This documents the known wart: the 0x01 is forwarded, so the
// guest still receives it.
func TestEscapeReaderKeepsCtrlAUsable(t *testing.T) {
	forwarded, escaped := drain(t, strings.NewReader("\x01e"), 64)
	if escaped {
		t.Error("Ctrl+A followed by another key must not escape")
	}
	if forwarded != "\x01e" {
		t.Errorf("Ctrl+A was swallowed: got %q", forwarded)
	}
}

// A second Ctrl+A re-arms rather than canceling, so Ctrl+A Ctrl+A X escapes.
func TestEscapeReaderRearmsOnRepeatedCtrlA(t *testing.T) {
	_, escaped := drain(t, strings.NewReader("\x01\x01X"), 64)
	if !escaped {
		t.Fatal("expected a repeated Ctrl+A to stay armed")
	}
}

// X on its own is just text; only the prefixed form escapes.
func TestEscapeReaderIgnoresBareX(t *testing.T) {
	forwarded, escaped := drain(t, strings.NewReader("XxX"), 64)
	if escaped {
		t.Error("a bare X must not escape")
	}
	if forwarded != "XxX" {
		t.Errorf("text was altered: got %q", forwarded)
	}
}

// Once escaped the reader stays at EOF, so a transport that reads again does
// not fire the callback twice or resume forwarding.
func TestEscapeReaderStaysClosedAfterEscape(t *testing.T) {
	calls := 0
	er := newEscapeReader(strings.NewReader("\x01Xmore"), func() { calls++ })
	buf := make([]byte, 64)
	for range 3 {
		n, err := er.Read(buf)
		if n != 0 || !errors.Is(err, io.EOF) {
			// The first read is allowed to return the escape EOF; any
			// later read must behave identically.
			if !errors.Is(err, io.EOF) {
				t.Fatalf("expected EOF, got n=%d err=%v", n, err)
			}
		}
	}
	if calls != 1 {
		t.Errorf("onEscape fired %d times, want 1", calls)
	}
}

// A nil callback is the termproxy transport's configuration: the EOF alone
// tears that one down, so the reader must not panic without a callback.
func TestEscapeReaderToleratesNilCallback(t *testing.T) {
	er := newEscapeReader(strings.NewReader("\x01X"), nil)
	buf := make([]byte, 8)
	if _, err := er.Read(buf); !errors.Is(err, io.EOF) {
		t.Fatalf("expected EOF, got %v", err)
	}
}

// An underlying read error must propagate rather than be reported as an
// escape, so a broken terminal is distinguishable from a deliberate exit.
func TestEscapeReaderPropagatesReadErrors(t *testing.T) {
	want := errors.New("terminal exploded")
	calls := 0
	er := newEscapeReader(errReader{err: want}, func() { calls++ })
	if _, err := er.Read(make([]byte, 8)); !errors.Is(err, want) {
		t.Fatalf("got %v, want %v", err, want)
	}
	if calls != 0 {
		t.Error("a read error must not count as an escape")
	}
}

type errReader struct{ err error }

func (e errReader) Read([]byte) (int, error) { return 0, e.err }
