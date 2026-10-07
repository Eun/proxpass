package guestfs

import (
	"os/exec"
	"testing"
)

// requireShell skips a test that needs a POSIX shell, which only a
// stripped-down build environment would lack: CI is Linux only.
func requireShell(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh available")
	}
}
