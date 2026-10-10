package guesthelper_test

import (
	"os"
	"os/exec"
	"testing"

	"proxpass/internal/guesthelper"
)

// TestACommandReturnsOnlyItsOwnOutput reproduces the defect that `sh -lc'
// caused, at the level the user sees it.
//
// A login shell sources /etc/profile.d, and the community-scripts Proxmox
// templates install a script there that prints an ANSI banner to STDOUT. The
// banner then prefixes whatever the command itself wrote, so
// `ssh ct100@host cat /etc/hostname > out' put 332 bytes in out where 5 were
// asked for, and legacy scp -- which multiplexes its protocol over the same
// stdout -- failed with "Connection closed".
//
// The container is simulated because the real one needs a Proxmox node: the
// nsenter stub sources a banner when it is handed -lc, which is precisely
// what a login shell inside a templated container does. Against the shipped
// code this test reports 51 bytes instead of 5.
func TestACommandReturnsOnlyItsOwnOutput(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh available")
	}
	// A login shell gets the banner a templated container's profile would
	// print; a plain -c does not, because no profile is ever read.
	bin := stubNode(t, `
if [ "$1" = "-lc" ]; then
  shift
  printf '\033[1;32m === WELCOME TO THE CONTAINER === \033[0m\n'
  exec /bin/sh -c "$1"
fi
if [ "$1" = "-c" ]; then shift; exec /bin/sh -c "$1"; fi
exec /bin/sh "$@"
`)

	//nolint:gosec // G204: running the generated line is the test.
	c := exec.CommandContext(t.Context(), "sh", "-c",
		guesthelper.ShellCommand(127, true, "echo DATA"))
	c.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"))

	// Output(), not CombinedOutput(): a shell redirect captures stdout
	// alone, and that is the stream the banner must stay off.
	stdout, err := c.Output()
	if err != nil {
		t.Fatalf("the generated command did not run: %v", err)
	}
	if string(stdout) != "DATA\n" {
		t.Fatalf("stdout carries more than the command's own output "+
			"(%d bytes, want 5):\n%q", len(stdout), stdout)
	}
}
