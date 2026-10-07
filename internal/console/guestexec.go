package console

import (
	"errors"
	"fmt"
	"io"

	gossh "golang.org/x/crypto/ssh"
)

// ExecOptions describes one command run inside a guest.
type ExecOptions struct {
	// Command is the shell command line to run on the Proxmox node, which
	// is expected to enter the container itself.
	Command string

	// PTY requests a terminal for the remote session.
	//
	// This MIRRORS what the client asked proxpass for, and the mirroring is
	// the whole point. lxc-attach has no flag to request or refuse a
	// terminal: it allocates one when any of ITS OWN standard descriptors is
	// a tty, so asking for one here is what gives the command a terminal
	// inside the container.
	//
	// Getting it wrong is visible in both directions. With a terminal where
	// the client wanted none, the line discipline rewrites "\n" as "\r\n"
	// and folds stderr into stdout, so `ssh ct100@host cat f.bin > out'
	// silently corrupts every 0x0a and `2>/dev/null' stops working. Without
	// one where the client asked, `top' draws nothing and a password prompt
	// never appears.
	PTY bool

	// Term is the terminal type to request, e.g. "xterm-256color". Only
	// meaningful with PTY.
	Term string
	// Width and Height are the initial terminal dimensions.
	Width, Height int

	// Resizes delivers new dimensions as the client's terminal changes. It
	// may be nil. Without it a full-screen program keeps drawing at the size
	// the session started with.
	Resizes <-chan Size

	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
}

// Exec runs one command on the node and returns its exit status.
//
// A non-zero status is returned as a value rather than an error: the whole
// point is to report the GUEST's exit code, so `ssh ct100@host false' exits 1
// locally like any other ssh. Only a failure to run it at all is an error.
func (r *NodeRunner) Exec(opts *ExecOptions) (int, error) {
	r.mu.Lock()
	client := r.client
	r.mu.Unlock()
	if client == nil {
		return 0, errors.New("connection to the proxmox host is closed")
	}

	session, err := client.NewSession()
	if err != nil {
		return 0, fmt.Errorf("opening remote session: %w", err)
	}
	defer func() { _ = session.Close() }()

	session.Stdin = opts.Stdin
	session.Stdout = opts.Stdout
	session.Stderr = opts.Stderr

	if opts.PTY {
		term := opts.Term
		if term == "" {
			term = "xterm"
		}
		w, h := opts.Width, opts.Height
		if w <= 0 {
			w = defaultWidth
		}
		if h <= 0 {
			h = defaultHeight
		}
		// ECHO is left to the remote side: the container's own line
		// discipline should decide, exactly as it would over a direct ssh.
		if err := session.RequestPty(term, h, w, gossh.TerminalModes{}); err != nil {
			return 0, fmt.Errorf("requesting remote pty: %w", err)
		}
		stop := forwardResizes(session, opts.Resizes)
		defer stop()
	}

	runErr := session.Run(opts.Command)
	if runErr == nil {
		return 0, nil
	}
	var exitErr *gossh.ExitError
	if errors.As(runErr, &exitErr) {
		return exitErr.ExitStatus(), nil
	}
	// A signal, or the transport failing. Neither is an exit status the
	// caller can hand back to its own caller.
	var signalErr *gossh.ExitMissingError
	if errors.As(runErr, &signalErr) {
		// The command died without reporting a status, which is what a
		// killed process looks like. 128 is the shell's convention.
		return 128, nil
	}
	return 0, fmt.Errorf("running remote command: %w", runErr)
}

// forwardResizes relays terminal size changes to the remote session until the
// returned function is called.
//
// Without this a full-screen program keeps drawing at the size the session
// started with, so resizing the local window corrupts the display until the
// program redraws of its own accord.
func forwardResizes(session *gossh.Session, resizes <-chan Size) func() {
	if resizes == nil {
		return func() {}
	}
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-done:
				return
			case size, ok := <-resizes:
				if !ok {
					return
				}
				// A failure here is not worth reporting: the session is
				// either gone, in which case Run is already returning, or
				// the peer does not support the request.
				_ = session.WindowChange(size.Height, size.Width)
			}
		}
	}()
	return func() { close(done) }
}
