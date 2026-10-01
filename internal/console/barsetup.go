package console

import (
	"io"
	"os"
	"strings"
)

// DisableStatusBarEnv turns the status bar off.
//
// The previous implementation needed this because it re-rendered the whole
// screen through a VT emulator on every write, which made watching logs
// unusable (#37). This one reserves a row with a scroll region and repaints
// a single line only when its text changes, so the escape hatch is kept for
// terminals that mishandle DECSTBM rather than for throughput.
const DisableStatusBarEnv = "PROXPASS_DISABLE_STATUSBAR"

// barDisabled reports whether the status bar is switched off.
//
// Anything other than unset, "0", "no" or "false" disables it, so a user who
// sets it to "1", "true" or "yes" gets what they meant.
func barDisabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(DisableStatusBarEnv))) {
	case "", "0", "no", "false":
		return false
	default:
		return true
	}
}

// WillDrawBar reports whether a guest console on term would get a status bar.
//
// Callers use this to avoid duplicating what the bar already shows. It is
// kept in step with startBar by sharing barEligible.
func WillDrawBar(term *Terminal) bool {
	return barEligible(term) && term.Height >= minBarRows
}

// barEligible reports whether a bar may be drawn on term at all, ignoring
// its size.
func barEligible(term *Terminal) bool {
	return !barDisabled() && term.Raw && term.Out != nil
}

// startBar sets up a status bar for a guest console, or returns nil when one
// should not be drawn.
//
// It returns the bar, the writer guest output must be sent through, and the
// number of rows the guest may use. The caller sizes the remote PTY to that
// height so the guest never writes into the bar's row.
func startBar(term *Terminal, label, hint string) (*StatusBar, io.Writer, int) {
	// A bar needs a terminal that will honor a scroll region. Without raw
	// mode this is proxpass's own stdout in a pipe or a test, where the
	// escape sequences would simply be noise in the output.
	//
	// The size check is left to StatusBar itself rather than duplicated
	// here: it reports GuestRows as the full height when the terminal is
	// too short, so the caller still sizes the guest correctly.
	if !barEligible(term) {
		// Never hand back a nil writer: normalize ensures term.Out is set
		// for a real session, but a caller constructing a Terminal directly
		// would otherwise get a writer that panics on first use.
		out := term.Out
		if out == nil {
			out = io.Discard
		}
		return nil, out, term.Height
	}

	bar := NewStatusBar(term.Out, term.Width, term.Height)
	bar.SetText(label, hint)
	bar.Start()
	rows := bar.GuestRows()
	return bar, &barWriter{out: term.Out, bar: bar}, rows
}

// barWriter forwards guest output unchanged while letting the bar watch it
// for mode changes.
//
// The data is passed to the terminal exactly as it arrived. Observe only
// reads it, so unlike a rewriting proxy this cannot corrupt an escape
// sequence that happens to straddle a read boundary.
type barWriter struct {
	out io.Writer
	bar *StatusBar
}

func (w *barWriter) Write(p []byte) (int, error) {
	// Forward first. The bar is cosmetic and the guest's output is not, so a
	// write is never delayed by the inspection.
	n, err := w.out.Write(p)
	if n > 0 {
		w.bar.Observe(p[:n])
	}
	return n, err
}
