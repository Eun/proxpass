package console

import "io"

// Escape sequence bytes: Ctrl+A followed by X.
const (
	escapeByte  = 0x01 // Ctrl+A
	escapeKeyUp = 'X'
	escapeKeyLo = 'x'
)

// EscapeHint describes the escape sequence for the user.
//
// Worth saying out loud because it is undiscoverable otherwise: without it a
// user whose guest has stopped responding has no way out of the console short
// of killing the ssh client from another terminal.
const EscapeHint = "Ctrl+A X: disconnect"

// escapeReader wraps a console's stdin and invokes onEscape when it sees
// Ctrl+A followed by X, giving the user a way to leave a guest console that
// does not depend on the guest itself being healthy enough to exit.
//
// On a match it reports io.EOF, which is what actually tears the session down:
// the copy loop feeding the guest stops, and each transport already treats a
// stdin EOF as "close the connection". onEscape exists for the extra teardown
// a transport needs beyond that (the SSH transport must signal the remote
// command, since closing stdin alone does not make a shell exit).
//
// Two deliberate imprecisions, inherited from the implementation this restores
// and kept because both only affect the stream being torn down:
//
//   - A bare Ctrl+A is forwarded to the guest immediately rather than held
//     back pending the next byte. That keeps Ctrl+A usable for start-of-line
//     in a shell with no added latency, at the cost of the guest seeing a
//     stray 0x01 just before it is disconnected.
//   - Bytes read in the same call before the X are dropped rather than
//     spliced out, because the Ctrl+A may have arrived in an earlier call.
//
// It is NOT a general terminal escape: it does not care about line position,
// so a literal Ctrl+A X inside a password or a file transfer would also
// trigger it. Users running something that needs raw Ctrl+A (screen, tmux,
// which take it as their own prefix) should expect to nest prefixes.
type escapeReader struct {
	r        io.Reader
	onEscape func()

	// pending is true when the previous byte was Ctrl+A and the next byte
	// decides whether this is an escape.
	pending bool
	// done suppresses a second onEscape call, since Read may be called
	// again after the match.
	done bool
}

// newEscapeReader wraps r. onEscape may be nil.
func newEscapeReader(r io.Reader, onEscape func()) *escapeReader {
	return &escapeReader{r: r, onEscape: onEscape}
}

func (e *escapeReader) Read(p []byte) (int, error) {
	if e.done {
		return 0, io.EOF
	}
	n, err := e.r.Read(p)
	for i := range n {
		switch {
		case e.pending:
			if p[i] == escapeKeyUp || p[i] == escapeKeyLo {
				e.done = true
				if e.onEscape != nil {
					e.onEscape()
				}
				// Zero bytes so neither the Ctrl+A nor the X is
				// forwarded to the guest.
				return 0, io.EOF
			}
			// Stay armed if this byte is itself a Ctrl+A, so
			// "Ctrl+A Ctrl+A X" escapes. Holding a key long enough
			// to repeat, or pressing it twice while deciding, should
			// not silently disarm the hatch.
			e.pending = p[i] == escapeByte
		case p[i] == escapeByte:
			e.pending = true
		}
	}
	return n, err
}
