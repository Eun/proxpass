package console

import (
	"fmt"
	"io"
	"os"
	"strings"

	"proxpass/internal/models"
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

// barLabel builds the status bar's left-hand text.
//
// The shape follows the login form a client would type to reach the same
// guest, so the bar reads as the answer to "where am I?" in the same
// vocabulary the user connects with:
//
//	webserver@rome@proxpass.example.com (ct100)
//	^ guest   ^ instance ^ public endpoint ^ the id that is unambiguous
//
// The endpoint is appended only when the deployment has been told what it is
// (PROXPASS_PUBLIC_ENDPOINT); proxpass cannot discover it, because the name
// clients use is a DNS and port-forwarding fact that the server never sees.
// Without it the label is just "webserver@rome (ct100)".
//
// The qualifier order matches `ssh ct100@rome@host': guest first, then where
// it lives, then how you got there.
func barLabel(guest *models.Guest, inst *models.ProxmoxInstance, publicEndpoint string) string {
	var sb strings.Builder
	sb.WriteString(guest.Name)
	sb.WriteString("@")
	sb.WriteString(inst.Name)
	if publicEndpoint != "" {
		sb.WriteString("@")
		sb.WriteString(publicEndpoint)
	}
	fmt.Fprintf(&sb, " (%s%d)", guest.Type, guest.ProxmoxID)
	return sb.String()
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
	return bar, &barWriter{bar: bar}, rows
}

// barWriter forwards guest output unchanged while letting the bar watch it
// for mode changes.
//
// The data is passed to the terminal exactly as it arrived. Observe only
// reads it, so unlike a rewriting proxy this cannot corrupt an escape
// sequence that happens to straddle a read boundary.
//
// The terminal is reached through the bar rather than held here, so that
// guest output and bar repaints are serialized against each other.
type barWriter struct {
	bar *StatusBar
}

func (w *barWriter) Write(p []byte) (int, error) {
	// Forward under the bar's write lock. A PTY write is not atomic -- it can
	// be split -- and the bar and the guest share one terminal, so without
	// this guest bytes could land between the bar's cursor save and its
	// restore. The restore would then discard the position the guest's own
	// output had just set, and a repaint could equally be cut into the middle
	// of a guest escape sequence.
	//
	// Only the write is serialized. Observe runs afterwards, outside the
	// lock, because it takes the bar's state mutex and the lock order is
	// state-then-write.
	n, err := w.bar.writeGuest(p)
	if n > 0 {
		w.bar.Observe(p[:n])
	}
	return n, err
}
