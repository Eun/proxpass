package sftpserver_test

import (
	"os/exec"
	"runtime"
	"testing"
)

// requireLinuxShellTools skips a test that executes the generated commands
// for real.
//
// The commands target a Proxmox node, which is always Linux, and they use GNU
// coreutils behavior the harness cannot fake: `stat -c' (BSD stat spells it
// -f) and `dd iflag=skip_bytes' (BSD dd has no such flag). Windows has no
// POSIX shell at all.
//
// So these tests assert something true of the only platform the commands ever
// run on, and are skipped on the others rather than weakened to the lowest
// common denominator -- which would have meant not testing the real commands
// at all. The pure-Go parts (path handling, the protocol, mode translation)
// have their own tests and run everywhere.
func requireLinuxShellTools(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skipf("the generated commands use GNU coreutils and a POSIX shell, "+
			"which %s does not provide; they only ever run on a Proxmox node",
			runtime.GOOS)
	}
	for _, bin := range []string{"sh", "stat", "dd"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s is not available", bin)
		}
	}
}
