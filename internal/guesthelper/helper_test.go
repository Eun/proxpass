package guesthelper_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
)

// buildHelper compiles the real helper once per test binary.
//
// Testing against the actual binary rather than calling its functions
// directly is deliberate: the helper is shipped as a separate executable and
// driven over pipes, so the framing and the process lifecycle are part of
// what has to work.
var buildOnce struct {
	sync.Once
	path string
	err  error
}

func buildHelper(t *testing.T) string {
	t.Helper()
	buildOnce.Do(func() {
		// Not t.TempDir(): that is removed when the FIRST test ends,
		// and the binary is shared by every test in the package.
		dir, err := os.MkdirTemp("", "proxpass-helper-build")
		if err != nil {
			buildOnce.err = &buildError{err: err}
			return
		}
		out := filepath.Join(dir, "proxpass-helper")
		cmd := exec.CommandContext(context.Background(), //nolint:usetesting // shared across tests, not scoped to one.
			"go", "build", "-o", out, "proxpass/cmd/proxpass-helper")
		if b, err := cmd.CombinedOutput(); err != nil {
			buildOnce.err = &buildError{out: string(b), err: err}
			return
		}
		buildOnce.path = out
	})
	if buildOnce.err != nil {
		t.Fatalf("building the helper: %v", buildOnce.err)
	}
	return buildOnce.path
}

type buildError struct {
	out string
	err error
}

func (e *buildError) Error() string { return e.err.Error() + ": " + e.out }

// helperCommand returns the helper ready to run.
//
// root is unused by the helper itself -- it operates on absolute paths -- but
// the tests pass it so the signature documents which directory the test is
// working in.
func helperCommand(t *testing.T, bin, root string) *exec.Cmd {
	t.Helper()
	_ = root
	cmd := exec.CommandContext(t.Context(), bin, "serve")
	return cmd
}
