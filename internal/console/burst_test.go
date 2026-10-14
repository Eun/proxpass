package console_test

import (
	"strings"
	"testing"
	"time"

	"proxpass/internal/console"
)

// A chatty guest must not kill the session.
//
// Reported as "docker logs crashes the process". Measured on a real
// container: the same command run without a PTY returned 2,010,819 bytes and
// exited 0, while an interactive console stopped after ~128,600 bytes --
// truncated in the middle of an escape sequence -- and the session closed
// with no error message at all.
//
// The cause is the WebSocket read limit. github.com/coder/websocket defaults
// to 32768 bytes per message (read.go, defaultReadLimit) and termproxy
// forwards raw PTY output, so one burst from a guest writing faster than the
// terminal drains produces a frame larger than that. conn.Read then fails,
// and because it discards the partial message the output stops mid-sequence.
//
// What made it look like a crash rather than an error is that the read loop
// breaks without logging and connectTermProxy returns nil, so an abnormal
// end was reported as an ordinary disconnect.
//
// The transport is a terminal stream, not an RPC channel: there is no
// message size that is meaningfully "too big", which is why the limit is
// disabled rather than raised.
const (
	// burstBytes is comfortably past the 32768-byte default. The exact size
	// does not matter, only that one message exceeds it -- which is why the
	// failure appeared at an arbitrary offset rather than a round number.
	burstBytes = 128 * 1024

	// burstMarker ends the burst, so the test asserts the whole message
	// arrived rather than merely that something did.
	burstMarker = "<<<END-OF-BURST>>>"
)

func TestAGuestBurstLargerThanTheReadLimitIsDelivered(t *testing.T) {
	api, inst, guest := termProxyEnv(t)

	// One frame, bigger than the default limit, ending in a marker. This is
	// what a log dump looks like to the transport.
	burst := strings.Repeat("x", burstBytes) + burstMarker
	api.SetTermProxyGreeting(burst)

	pt := newPipeTerminal()
	done := make(chan error, 1)
	go func() {
		done <- console.DefaultProxier{}.Connect(pt.term, guest, inst, "", discardLogger())
	}()

	// The marker only arrives if the whole message was read. Against the
	// unfixed code the read fails, the payload is dropped, and this times
	// out with an empty buffer.
	waitFor(t, pt.out, burstMarker)

	if got := pt.out.String(); len(got) < burstBytes {
		t.Errorf("terminal received %d bytes, want at least %d: the guest's "+
			"output was truncated", len(got), burstBytes)
	}

	_ = pt.stdin.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("session did not return after the terminal closed")
	}
}
