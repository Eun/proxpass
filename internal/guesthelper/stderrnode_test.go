package guesthelper_test

import (
	"errors"
	"io"
	"strings"

	"proxpass/internal/guesthelper"
)

// stderrNode is a node whose launch writes to stderr and then closes,
// exactly as a failing nsenter does.
type stderrNode struct {
	arch   string
	stderr string
}

func (n *stderrNode) Run(cmd string, stdin io.Reader, stdout io.Writer) (exitCode int, stderr string, err error) {
	if strings.Contains(cmd, "uname") {
		if stdout != nil {
			_, _ = io.WriteString(stdout, n.arch)
		}
		return 0, "", nil
	}
	if stdin != nil {
		_, _ = io.Copy(io.Discard, stdin)
	}
	return 0, "", nil
}

func (n *stderrNode) Stream(_ string, stderr io.Writer) (guesthelper.Stream, error) {
	// No trailing newline: this is the shape that was being discarded.
	if stderr != nil {
		_, _ = io.WriteString(stderr, n.stderr)
	}
	return &deadStream{}, nil
}

// deadStream is a stream whose process has already gone.
type deadStream struct{}

func (*deadStream) Read([]byte) (int, error)  { return 0, io.EOF }
func (*deadStream) Write([]byte) (int, error) { return 0, errors.New("process gone") }
func (*deadStream) Close() error              { return nil }
