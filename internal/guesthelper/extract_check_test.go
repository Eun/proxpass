package guesthelper_test

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"proxpass/internal/guesthelper"
)

// TestEmbeddedHelperRuns extracts the embedded binary for THIS machine's
// architecture and executes it, which is the only check that proves the
// embedded bytes are a working program rather than merely ELF-shaped.
func TestEmbeddedHelperRuns(t *testing.T) {
	arch, err := guesthelper.ParseArch(hostUname(t))
	if err != nil {
		t.Skipf("host architecture is not one we embed: %v", err)
	}
	b, err := guesthelper.Binary(arch)
	if errors.Is(err, guesthelper.ErrNoBinary) {
		t.Skipf("no real binary staged: run `mise run helpers'")
	}
	if err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(t.TempDir(), "helper")
	if err := os.WriteFile(path, b, 0o700); err != nil { //nolint:gosec // it must be executable.
		t.Fatal(err)
	}
	out, err := exec.CommandContext(t.Context(), path, "version").CombinedOutput()
	if err != nil {
		t.Fatalf("the embedded helper did not run: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "proxpass-helper") {
		t.Errorf("unexpected version output: %q", out)
	}
	t.Logf("embedded %s helper reports: %s", arch, strings.TrimSpace(string(out)))
}

func hostUname(t *testing.T) string {
	t.Helper()
	out, err := exec.CommandContext(t.Context(), "uname", "-m").Output()
	if err != nil {
		t.Skipf("uname: %v", err)
	}
	return string(out)
}
