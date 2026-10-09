package guesthelper

import (
	"errors"
	"fmt"
	"io"
	"log"
	"strings"
	"time"
)

// DefaultIdleTimeout is how long a helper waits for a request before
// deciding its peer has gone and exiting.
//
// It must be longer than any gap a live transfer produces and short enough
// that an abandoned process does not sit on a Proxmox node. Sixty seconds
// satisfies both: SFTP clients pipeline, so even an interactive session
// rarely pauses that long, and a leaked helper is gone within a minute.
const DefaultIdleTimeout = 60 * time.Second

// Node runs commands on a Proxmox node.
//
// This is the subset of console.NodeRunner the helper needs, declared here
// so the package does not depend on console -- and so tests can supply a
// fake without an SSH server.
type Node interface {
	// Run executes a one-shot command, as the shell path does.
	Run(cmd string, stdin io.Reader, stdout io.Writer) (exitCode int, stderr string, err error)
	// Stream starts a command and keeps its streams open.
	Stream(cmd string, stderr io.Writer) (Stream, error)
}

// Stream is a command running on the node with its streams held open.
type Stream interface {
	io.ReadWriter
	// Close ends the command.
	Close() error
}

// Session is a helper running inside one container, with the node resources
// that keep it alive.
type Session struct {
	*Client
	stream Stream
	logger *log.Logger
}

// Close shuts the helper down and releases the session.
func (s *Session) Close() error {
	// Tell the helper to quit before dropping the stream, so it exits on
	// its own rather than being killed. Either way it is gone: the stream
	// close sends EOF, and the idle timeout is the backstop if even that
	// does not arrive.
	_ = s.Client.Close()
	return s.stream.Close()
}

// Start stages the helper on the node if it is not already there, launches
// it inside the container, and completes the handshake.
//
// Every failure before the handshake wraps ErrUnsupported, because the
// correct response to all of them is to fall back to the shell path: a node
// whose architecture we do not build for, a /var/tmp that is noexec, an
// nsenter without -p. A failure AFTER the handshake is a real error, because
// by then a transfer may have started and retrying it by another route could
// duplicate work.
func Start(node Node, vmid int, unprivileged bool, logger *log.Logger) (*Session, error) {
	arch, err := detectArch(node)
	if err != nil {
		return nil, err
	}
	if err := stage(node, arch); err != nil {
		return nil, err
	}

	// The helper's own diagnostics, including the idle-timeout notice,
	// arrive on stderr. They go to the log so an operator can see why a
	// session ended.
	stderr := &logWriter{logger: logger, prefix: fmt.Sprintf("helper ct%d", vmid)}

	stream, err := node.Stream(LaunchCommand(vmid, arch, unprivileged), stderr)
	if err != nil {
		return nil, fmt.Errorf("%w: launching: %w", ErrUnsupported, err)
	}

	client, err := NewClient(stream, DefaultIdleTimeout)
	if err != nil {
		_ = stream.Close()
		return nil, err
	}
	return &Session{Client: client, stream: stream, logger: logger}, nil
}

// detectArch asks the node what it is.
func detectArch(node Node) (Arch, error) {
	var out strings.Builder
	code, stderr, err := node.Run(ArchCommand, nil, &out)
	if err != nil {
		return "", fmt.Errorf("%w: detecting architecture: %w", ErrUnsupported, err)
	}
	if code != 0 {
		return "", fmt.Errorf("%w: detecting architecture: %s", ErrUnsupported, strings.TrimSpace(stderr))
	}
	arch, err := ParseArch(out.String())
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrUnsupported, err)
	}
	return arch, nil
}

// stage pushes the helper to the node unless it is already there.
//
// The binary is piped into the staging command rather than written by it, so
// nothing has to be encoded for a shell and a two-megabyte argument list is
// never constructed.
func stage(node Node, arch Arch) error {
	bin, _, err := BinaryReader(arch)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrUnsupported, err)
	}
	code, stderr, err := node.Run(StageCommand(arch), bin, nil)
	if err != nil {
		return fmt.Errorf("%w: staging: %w", ErrUnsupported, err)
	}
	if code != 0 {
		return fmt.Errorf("%w: staging: %s", ErrUnsupported, strings.TrimSpace(stderr))
	}
	return nil
}

// IsUnsupported reports whether the caller should fall back to the shell
// path rather than failing the transfer.
func IsUnsupported(err error) bool { return errors.Is(err, ErrUnsupported) }

// logWriter forwards a helper's stderr to a logger, one line at a time.
type logWriter struct {
	logger *log.Logger
	prefix string
	buf    []byte
}

func (w *logWriter) Write(p []byte) (int, error) {
	if w.logger == nil {
		return len(p), nil
	}
	w.buf = append(w.buf, p...)
	for {
		i := strings.IndexByte(string(w.buf), '\n')
		if i < 0 {
			break
		}
		line := strings.TrimSpace(string(w.buf[:i]))
		w.buf = w.buf[i+1:]
		if line != "" {
			w.logger.Printf("%s: %s", w.prefix, line)
		}
	}
	return len(p), nil
}
