package console

import (
	"bytes"
	"io"
)

// NewCRLFWriter returns a writer that translates a bare "\n" into "\r\n".
//
// It is required for anything proxpass prints to a PTY it has put into raw
// mode. Raw mode clears ONLCR, so the terminal no longer maps "\n" to
// "carriage return + line feed": a bare "\n" moves the cursor down but leaves
// it in the column it was already in, and every line starts further to the
// right than the last -- the classic staircase.
//
// Only proxpass's own UI output needs this. A guest console must NOT be
// wrapped: the guest's own PTY already emits "\r\n", and full-screen
// applications send binary escape sequences in which a 0x0a byte is data, not
// a line break, so inserting a carriage return would corrupt them.
func NewCRLFWriter(w io.Writer) io.Writer {
	return &crlfWriter{w: w}
}

type crlfWriter struct {
	w io.Writer
	// lastWasCR remembers whether the previous byte written was a carriage
	// return, so a "\r\n" split across two Write calls is not turned into
	// "\r\r\n".
	lastWasCR bool
}

func (c *crlfWriter) Write(p []byte) (int, error) {
	// Translate into one buffer and issue a single write: a terminal shows
	// partial writes, and splitting a frame into many small writes is both
	// slower and visibly flickery.
	buf := make([]byte, 0, len(p)+bytes.Count(p, []byte{'\n'}))
	for _, b := range p {
		if b == '\n' && !c.lastWasCR {
			buf = append(buf, '\r')
		}
		buf = append(buf, b)
		c.lastWasCR = b == '\r'
	}
	if _, err := c.w.Write(buf); err != nil {
		return 0, err
	}
	// Report the caller's byte count, not the translated one: the inserted
	// carriage returns are not bytes the caller asked to write, and an n
	// greater than len(p) violates the io.Writer contract.
	return len(p), nil
}
