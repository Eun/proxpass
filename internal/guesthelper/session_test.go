package guesthelper_test

import (
	"context"
	"errors"
	"io"
	"log"
	"os/exec"
	"strings"
	"testing"

	"proxpass/internal/guesthelper"
)

// fakeNode stands in for a Proxmox node, so the fallback paths can be
// exercised without an SSH server or a container.
type fakeNode struct {
	arch       string
	archCode   int
	archErr    error
	stageCode  int
	stageErr   error
	streamErr  error
	staged     []byte
	launchCmd  string
	helperPath string
}

func (n *fakeNode) Run(cmd string, stdin io.Reader, stdout io.Writer) (exitCode int, stderr string, err error) {
	switch {
	case strings.Contains(cmd, "uname"):
		if n.archErr != nil {
			return 0, "", n.archErr
		}
		if stdout != nil {
			_, _ = io.WriteString(stdout, n.arch)
		}
		return n.archCode, "uname failed", nil
	default: // staging
		if stdin != nil {
			b, _ := io.ReadAll(stdin)
			n.staged = b
		}
		if n.stageErr != nil {
			return 0, "", n.stageErr
		}
		return n.stageCode, "staging failed", nil
	}
}

func (n *fakeNode) Stream(cmd string, stderr io.Writer) (guesthelper.Stream, error) {
	return n.stream(context.Background(), cmd, stderr)
}

func (n *fakeNode) stream(ctx context.Context, cmd string, stderr io.Writer) (guesthelper.Stream, error) {
	n.launchCmd = cmd
	if n.streamErr != nil {
		return nil, n.streamErr
	}
	// Run the real helper locally. The nsenter wrapper cannot work here --
	// there is no container -- so only the protocol end is exercised.
	c := exec.CommandContext(ctx, n.helperPath, "serve") //nolint:gosec // helperPath is built by this test.
	in, err := c.StdinPipe()
	if err != nil {
		return nil, err
	}
	out, err := c.StdoutPipe()
	if err != nil {
		return nil, err
	}
	c.Stderr = stderr
	if err := c.Start(); err != nil {
		return nil, err
	}
	return &fakeStream{in: in, out: out, cmd: c}, nil
}

type fakeStream struct {
	in  io.WriteCloser
	out io.Reader
	cmd *exec.Cmd
}

func (s *fakeStream) Read(p []byte) (int, error)  { return s.out.Read(p) }
func (s *fakeStream) Write(p []byte) (int, error) { return s.in.Write(p) }
func (s *fakeStream) Close() error {
	_ = s.in.Close()
	return s.cmd.Wait()
}

// archAMD64Uname is what `uname -m' prints on a 64-bit x86 node.
const archAMD64Uname = "x86_64\n"

func testLogger() *log.Logger { return log.New(io.Discard, "", 0) }

// TestStartSucceeds walks the happy path and checks the helper was actually
// pushed and launched with the right flags.
func TestStartSucceeds(t *testing.T) {
	if _, err := guesthelper.Binary(guesthelper.ArchAMD64); errors.Is(err, guesthelper.ErrNoBinary) {
		t.Skip("no real binary staged: run `mise run helpers'")
	}
	n := &fakeNode{arch: archAMD64Uname, helperPath: buildHelper(t)}
	sess, err := guesthelper.Start(n, 127, true, testLogger())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = sess.Close() }()

	if len(n.staged) == 0 {
		t.Error("nothing was pushed to the node")
	}
	if !strings.Contains(n.launchCmd, " -p ") {
		t.Errorf("launch command lacks -p, which makes the exec ENOENT:\n%s", n.launchCmd)
	}
	// The session must actually work, not merely start.
	if _, err := sess.Stat("/"); err != nil {
		t.Errorf("stat through the session: %v", err)
	}
}

// TestUnsupportedArchFallsBack is the property that keeps a transfer working
// on hardware proxpass does not build for: it must be reported as
// unsupported, so the caller uses the shell path, rather than as a failure.
func TestUnsupportedArchFallsBack(t *testing.T) {
	for _, arch := range []string{"riscv64\n", "armv7l\n", "mips64\n"} {
		n := &fakeNode{arch: arch, helperPath: buildHelper(t)}
		_, err := guesthelper.Start(n, 127, true, testLogger())
		if err == nil {
			t.Fatalf("arch %q was accepted", strings.TrimSpace(arch))
		}
		if !guesthelper.IsUnsupported(err) {
			t.Errorf("arch %q: err = %v, want an unsupported error so the "+
				"caller falls back", strings.TrimSpace(arch), err)
		}
	}
}

// TestStagingFailureFallsBack covers a node that will not accept the binary
// -- a read-only or noexec /var/tmp, most likely.
func TestStagingFailureFallsBack(t *testing.T) {
	n := &fakeNode{arch: archAMD64Uname, stageCode: 1, helperPath: buildHelper(t)}
	_, err := guesthelper.Start(n, 127, true, testLogger())
	if err == nil {
		t.Fatal("a failed staging was accepted")
	}
	if !guesthelper.IsUnsupported(err) {
		t.Errorf("err = %v, want an unsupported error", err)
	}
}

// TestLaunchFailureFallsBack covers a node whose nsenter is too old for -p,
// or any other reason the process will not start.
func TestLaunchFailureFallsBack(t *testing.T) {
	n := &fakeNode{
		arch:       "x86_64\n",
		streamErr:  errors.New("nsenter: unrecognized option '-p'"),
		helperPath: buildHelper(t),
	}
	_, err := guesthelper.Start(n, 127, true, testLogger())
	if err == nil {
		t.Fatal("a failed launch was accepted")
	}
	if !guesthelper.IsUnsupported(err) {
		t.Errorf("err = %v, want an unsupported error", err)
	}
}

// TestArchProbeFailureFallsBack covers a node that cannot be reached at all
// for the probe.
func TestArchProbeFailureFallsBack(t *testing.T) {
	n := &fakeNode{archErr: errors.New("connection lost"), helperPath: buildHelper(t)}
	_, err := guesthelper.Start(n, 127, true, testLogger())
	if !guesthelper.IsUnsupported(err) {
		t.Errorf("err = %v, want an unsupported error", err)
	}
}
