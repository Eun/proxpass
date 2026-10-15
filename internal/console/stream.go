package console

import (
	"errors"
	"fmt"
	"io"

	gossh "golang.org/x/crypto/ssh"
)

// Stream is a command running on the node with its streams held open.
//
// Run and Exec both block until their command exits, which suits a transfer
// built from one command per operation. A long-lived helper is the opposite
// shape: it starts once, then reads requests and writes replies for as long
// as the session lasts. That needs Start/Wait rather than Run, and pipes the
// caller keeps hold of -- which is what this provides.
//
// It deliberately does NOT request a PTY, for the reason given on Run: a
// terminal line discipline rewrites "\n" as "\r\n" and would corrupt every
// binary payload on the wire.
type Stream struct {
	session *gossh.Session
	stdin   io.WriteCloser
	stdout  io.Reader
}

// Stream starts cmd on the node and returns its streams.
//
// stderr is drained into the supplied writer, if any. Leaving it nil discards
// it: the helper writes diagnostics there, and a caller that does not want
// them in its own log should say so explicitly rather than have them vanish
// into a full pipe, which would block the remote process.
func (r *NodeRunner) Stream(cmd string, stderr io.Writer) (*Stream, error) {
	return r.stream(stderr, func(s *gossh.Session) error {
		if err := s.Start(cmd); err != nil {
			return fmt.Errorf("starting remote command: %w", err)
		}
		return nil
	})
}

// Subsystem starts a named SSH subsystem on the node and returns its
// streams.
//
// This is what makes `scp' and `sftp' work against a NODE: the node runs
// its own sftp-server, so proxpass asks for it by name and pumps bytes
// between it and the client. Nothing is staged and nothing is entered --
// compare the guest path, which pushes a helper binary into the container
// through nsenter because there is no server in there to ask.
//
// A subsystem is requested rather than `exec sftp-server' because that is
// what the protocol is for, and because the remote path differs between
// distributions -- asking by name lets the node's own sshd resolve it.
//
// No PTY, like Stream, and for the reason given there: a line discipline
// would rewrite "\n" as "\r\n" and corrupt every binary payload. Real
// OpenSSH never allocates one for a subsystem either.
func (r *NodeRunner) Subsystem(name string, stderr io.Writer) (*Stream, error) {
	return r.stream(stderr, func(s *gossh.Session) error {
		if err := s.RequestSubsystem(name); err != nil {
			return fmt.Errorf("requesting the %q subsystem: %w", name, err)
		}
		return nil
	})
}

// stream opens a session, wires its pipes and hands it to start.
//
// Shared by Stream and Subsystem, which differ only in how the remote end
// is kicked off. The pipe wiring and the no-PTY rule are the parts that
// must not vary between them.
func (r *NodeRunner) stream(stderr io.Writer, start func(*gossh.Session) error) (*Stream, error) {
	r.mu.Lock()
	client := r.client
	r.mu.Unlock()
	if client == nil {
		return nil, errors.New("connection to the proxmox host is closed")
	}

	session, err := client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("opening remote session: %w", err)
	}

	stdin, err := session.StdinPipe()
	if err != nil {
		_ = session.Close()
		return nil, fmt.Errorf("stdin pipe: %w", err)
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		_ = session.Close()
		return nil, fmt.Errorf("stdout pipe: %w", err)
	}
	if stderr != nil {
		session.Stderr = stderr
	} else {
		session.Stderr = io.Discard
	}

	if err := start(session); err != nil {
		_ = session.Close()
		return nil, err
	}
	return &Stream{session: session, stdin: stdin, stdout: stdout}, nil
}

// Read reads from the command's stdout.
func (s *Stream) Read(p []byte) (int, error) { return s.stdout.Read(p) }

// Write writes to the command's stdin.
func (s *Stream) Write(p []byte) (int, error) { return s.stdin.Write(p) }

// Close ends the session.
//
// stdin is closed first so a helper that is waiting for a request sees EOF
// and exits of its own accord, rather than being killed mid-write. The
// session is then closed regardless, because a helper that ignores EOF must
// not be able to hold the connection open.
func (s *Stream) Close() error {
	_ = s.stdin.Close()
	err := s.session.Close()
	// A session that has already ended reports io.EOF from Close, which is
	// the normal case here and not a failure worth reporting upward.
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}
