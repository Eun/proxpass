package ssh

import (
	"bytes"
	"io"
)

// crlfWriter wraps an io.Writer and converts bare \n to \r\n,
// which is required by SSH terminals in raw (PTY) mode.
type crlfWriter struct {
	w io.Writer
}

func newCRLFWriter(w io.Writer) io.Writer {
	return &crlfWriter{w: w}
}

func (c *crlfWriter) Write(p []byte) (n int, err error) {
	written := 0
	for len(p) > 0 {
		idx := bytes.IndexByte(p, '\n')
		if idx == -1 {
			// No newline -- write remaining bytes verbatim.
			nn := 0
			nn, err = c.w.Write(p)
			written += nn
			return written, err
		}
		// Check whether this \n is already preceded by \r.
		if idx > 0 && p[idx-1] == '\r' {
			// Already \r\n -- write up to and including \n as-is.
			nn := 0
			nn, err = c.w.Write(p[:idx+1])
			written += nn
			if err != nil {
				return written, err
			}
			p = p[idx+1:]
			continue
		}
		// Write everything before the \n.
		if idx > 0 {
			nn := 0
			nn, err = c.w.Write(p[:idx])
			written += nn
			if err != nil {
				return written, err
			}
		}
		// Replace \n with \r\n.
		nn := 0
		nn, err = c.w.Write([]byte{'\r', '\n'})
		if nn > 0 {
			written++ // credit one byte (\n) to the caller
		}
		if err != nil {
			return written, err
		}
		p = p[idx+1:]
	}
	return written, nil
}
