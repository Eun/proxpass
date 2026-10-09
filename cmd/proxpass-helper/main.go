// Command proxpass-helper serves filesystem operations from inside a
// container's namespaces.
//
// proxpass pushes this binary to a Proxmox node and starts one copy per
// transfer session, inside the target container, with:
//
//	nsenter -t <pid> -m -U -p -S 0 -G 0 -- <helper> serve
//
// It then speaks the guesthelper protocol over stdin and stdout until the
// transfer finishes. See internal/guesthelper for the framing.
//
// # The -p flag is load-bearing
//
// Verified against a real PVE 9.2 node: without -p the process is not in the
// container's PID namespace, so the container's /proc holds no entry for it
// and the /proc/self/fd path used to execute a streamed binary is ENOENT.
// With -p it resolves. This is why the launcher passes it.
//
// # Why this exits on its own
//
// A helper is started by a session that may vanish without closing anything
// -- a dropped network, a killed client, a node reboot of the proxpass side.
// Nothing would then reap it, and a Proxmox node would accumulate idle
// processes inside its containers. So the helper watches its own idleness and
// exits when no request has arrived for the configured period.
//
// Closing stdin is the ORDINARY path and is immediate; the timeout is the
// backstop for when stdin never closes because the peer died rather than
// hung up.
package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"time"

	"proxpass/internal/guesthelper"
)

// defaultIdleTimeout is how long the helper waits for a request before
// deciding it has been abandoned.
//
// Sixty seconds is comfortably longer than any gap a live transfer produces
// -- SFTP clients pipeline, and even an interactive sftp session sends
// something when the user does -- while still being short enough that a
// leaked helper is gone before anyone notices it.
const defaultIdleTimeout = 60 * time.Second

func main() {
	if len(os.Args) > 1 && os.Args[1] == "version" {
		fmt.Printf("proxpass-helper protocol=%d arch=%s\n",
			guesthelper.Version, runtime.GOARCH)
		return
	}
	if err := serve(os.Stdin, os.Stdout, defaultIdleTimeout); err != nil {
		fmt.Fprintf(os.Stderr, "proxpass-helper: %v\n", err)
		os.Exit(1)
	}
}

// serve runs the request loop until stdin closes, a quit arrives, or the
// idle timeout expires.
func serve(in io.Reader, out io.Writer, idleTimeout time.Duration) error {
	s := &session{in: in, out: out, idle: idleTimeout}
	return s.run()
}

type session struct {
	in   io.Reader
	out  io.Writer
	idle time.Duration
}

// request is one decoded message plus whatever payload followed it.
type request struct {
	hdr     guesthelper.Request
	payload []byte
	err     error
}

// run reads requests on a goroutine so the main loop can apply a deadline.
//
// A blocking read cannot be canceled, which is the whole difficulty: the
// reader goroutine may outlive this function, parked in Read forever. That is
// acceptable precisely because the process exits when run returns -- the
// goroutine dies with it. It must NOT be given a buffered-channel-free send,
// though, or it would block forever on a send nobody receives and the process
// would not be able to exit cleanly; hence the buffer of one.
func (s *session) run() error {
	reqs := make(chan request, 1)
	go s.readLoop(reqs)

	timer := time.NewTimer(s.idle)
	defer timer.Stop()

	for {
		select {
		case <-timer.C:
			// Nothing arrived in time. Say so on stderr, which the
			// caller sees in the SSH session's stderr, then exit 0:
			// an abandoned helper timing out is not a failure.
			fmt.Fprintf(os.Stderr,
				"proxpass-helper: idle for %s, exiting\n", s.idle)
			return nil

		case req := <-reqs:
			if req.err != nil {
				if errors.Is(req.err, io.EOF) {
					// stdin closed: the ordinary end of a session.
					return nil
				}
				return req.err
			}
			if req.hdr.Op == guesthelper.OpQuit {
				return nil
			}
			resp, payload := s.dispatch(&req)
			resp.Len = int64(len(payload))
			if err := guesthelper.WriteMessage(s.out, resp, payload); err != nil {
				return fmt.Errorf("writing reply: %w", err)
			}
			// Reset only after a completed exchange, so a long
			// transfer keeps the helper alive and a stalled peer
			// does not.
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(s.idle)
		}
	}
}

// readLoop decodes messages until the stream ends, reporting errors in band.
func (s *session) readLoop(out chan<- request) {
	for {
		var hdr guesthelper.Request
		if err := guesthelper.ReadHeader(s.in, &hdr); err != nil {
			out <- request{err: err}
			return
		}
		var payload []byte
		if hdr.Len > 0 {
			p, err := guesthelper.ReadPayload(s.in, hdr.Len)
			if err != nil {
				out <- request{err: err}
				return
			}
			payload = p
		}
		out <- request{hdr: hdr, payload: payload}
	}
}
