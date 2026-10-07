package sftpserver_test

import (
	"os/exec"
	"testing"
)

// requireShellTools skips a test that executes the generated commands for
// real, when the tools it needs are missing.
//
// There is no platform check: CI is Linux only, because that is what proxpass
// runs on and what a Proxmox node is. The guard is for a stripped-down
// environment -- a minimal build container -- rather than for another OS.
func requireShellTools(t *testing.T) {
	t.Helper()
	for _, bin := range []string{"sh", "stat", "dd"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s is not available", bin)
		}
	}
}
