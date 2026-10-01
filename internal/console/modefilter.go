package console

import "bytes"

// modeFilter watches a guest's output stream for the escape sequences that
// make a reserved status-bar row unsafe, and reports when the bar must hide
// itself. It forwards the stream byte-for-byte: it only observes.
//
// The case that matters is the alternate screen buffer. A full-screen
// application (vim, top, less) switches to it, takes over every row, and
// restores the previous screen on exit. While it is in control there is no
// row to reserve -- the application has been told the screen is one row
// shorter and will use all of it -- so the bar must stop drawing rather than
// paint over the application's bottom line.
//
// Three mode numbers do this and an implementation that checks only the
// modern one is wrong for older applications:
//
//	?47    legacy alternate screen (xterm, pre-1998)
//	?1047  alternate screen, clearing on exit
//	?1049  alternate screen + cursor save/restore (what vim uses today)
//
// Sequences may also set several modes at once -- "\x1b[?1049;1000h" enables
// the alternate screen AND mouse reporting -- and the "?" private marker
// applies to every parameter in the list, not just the first. Splitting on
// ";" without carrying the marker forward misses the alt-screen bit in
// "\x1b[?1000;1049h", so the marker is tracked across parameters here.
type modeFilter struct {
	// altScreen reports whether the guest is currently on the alternate
	// screen buffer.
	altScreen bool

	// partial holds a trailing incomplete escape sequence between Observe
	// calls. A sequence can be split across reads at any byte, so state has
	// to survive the call that saw only part of it.
	partial []byte
}

// maxPartialEscape bounds the buffered prefix of an unterminated escape
// sequence.
//
// Without a bound, a guest that emits a lone ESC and then megabytes of
// printable text would have all of it buffered while the filter waited for a
// final byte that never comes. A CSI with a plausible parameter list is far
// shorter than this; anything longer is malformed, so the buffer is dropped
// and scanning resumes.
const maxPartialEscape = 64

// Observe inspects p for mode changes and reports whether the caller should
// redraw. p is never modified.
func (m *modeFilter) Observe(p []byte) (redraw bool) {
	buf := p
	if len(m.partial) > 0 {
		// Rescan the buffered prefix together with the new bytes so a
		// sequence split across reads is seen whole.
		//
		// This builds a fresh slice rather than appending to m.partial: its
		// backing array must not be reused, because a later Observe may
		// still be holding the tail it was copied from.
		joined := make([]byte, 0, len(m.partial)+len(p))
		joined = append(joined, m.partial...)
		joined = append(joined, p...)
		buf = joined
		m.partial = nil
	}

	for i := 0; i < len(buf); {
		if buf[i] != 0x1b {
			i++
			continue
		}
		seq, n, complete := scanEscape(buf[i:])
		if !complete {
			// Keep the tail for the next call, unless it is implausibly
			// long and so cannot be a real sequence.
			if tail := buf[i:]; len(tail) <= maxPartialEscape {
				m.partial = append([]byte(nil), tail...)
			}
			break
		}
		if alt, ok := parseAltScreen(seq); ok && alt != m.altScreen {
			m.altScreen = alt
			redraw = true
		}
		i += n
	}
	return redraw
}

// AltScreen reports whether the guest currently owns the whole screen.
func (m *modeFilter) AltScreen() bool { return m.altScreen }

// scanEscape returns the escape sequence at the start of b, its length, and
// whether it is complete.
//
// Only CSI ("\x1b[...") is parsed, because the modes of interest are CSI
// private modes. Other introducers are reported as complete two-byte
// sequences so scanning moves past them; OSC and DCS strings are not framed
// properly here, but misreading their contents is harmless since the only
// thing acted on is a CSI final of 'h' or 'l'.
func scanEscape(b []byte) (seq []byte, n int, complete bool) {
	if len(b) < 2 {
		return nil, 0, false
	}
	if b[1] != '[' {
		return b[:2], 2, true
	}
	// CSI: parameter bytes 0x30-0x3F, then intermediates 0x20-0x2F, then a
	// final byte 0x40-0x7E (ECMA-48).
	for i := 2; i < len(b); i++ {
		c := b[i]
		switch {
		case c >= 0x30 && c <= 0x3F, c >= 0x20 && c <= 0x2F:
			continue
		case c >= 0x40 && c <= 0x7E:
			return b[:i+1], i + 1, true
		default:
			// Not a valid CSI byte: treat the sequence as ending here so a
			// malformed stream cannot stall the scan.
			return b[:i+1], i + 1, true
		}
	}
	return nil, 0, false
}

// parseAltScreen reports whether seq is an alternate-screen mode change and
// which direction it goes.
func parseAltScreen(seq []byte) (enabled, ok bool) {
	if len(seq) < 4 || seq[1] != '[' {
		return false, false
	}
	final := seq[len(seq)-1]
	if final != 'h' && final != 'l' {
		return false, false
	}
	params := seq[2 : len(seq)-1]

	// The "?" private marker applies to every parameter in the list, so it
	// is carried across the ";" separators rather than being tested only on
	// the first parameter.
	private := false
	for _, param := range bytes.Split(params, []byte(";")) {
		if len(param) > 0 && param[0] == '?' {
			private = true
			param = param[1:]
		}
		if !private {
			continue
		}
		switch string(param) {
		case "47", "1047", "1049":
			return final == 'h', true
		}
	}
	return false, false
}
