package guestfs

import (
	"os/exec"
	"runtime"
	"testing"
)

// requireShell skips a test that needs a POSIX shell.
//
// The quoting these tests check is only ever interpreted by a shell on a
// Proxmox node, which is Linux. Windows has no POSIX shell, and verifying the
// quoting against something else would not say anything about the platform
// that matters.
func requireShell(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("no POSIX shell on windows; these commands only run on a Proxmox node")
	}
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh available")
	}
}
