package guesthelper_test

import (
	"os/exec"
	"strings"
	"testing"

	"proxpass/internal/guesthelper"
)

// TestExecCommandEntersTheRightNamespaces pins the flags. Each was settled
// against a real PVE 9.2 node and a silent removal would reintroduce a bug
// that is expensive to rediscover.
func TestExecCommandEntersTheRightNamespaces(t *testing.T) {
	cmd := guesthelper.ExecCommand(127, true, "/bin/sh", "-lc", "whoami")

	for flag, why := range map[string]string{
		" -m ": "mount namespace: paths must resolve inside the container",
		" -r ": "root: an absolute symlink must not escape to the node",
		" -p ": "pid namespace: a command must see the container's processes",
		" -u ": "uts namespace: hostname must report the container's",
		" -i ": "ipc namespace",
		" -U ": "user namespace",
		"-S 0": "uid 0 inside",
		"-G 0": "gid 0 inside",
	} {
		if !strings.Contains(cmd, flag) {
			t.Errorf("missing %q (%s) in:\n%s", flag, why, cmd)
		}
	}

	// lxc-attach must NOT appear: it has no flag to refuse a terminal and
	// decides from its own descriptors, which corrupts binary output.
	if strings.Contains(cmd, "lxc-attach") {
		t.Errorf("lxc-attach reintroduced, which breaks the no-PTY guarantee:\n%s", cmd)
	}

	// -r and -w take OPTIONAL arguments, so a separated value becomes the
	// program. "nsenter -r /" once failed every operation with
	// "failed to execute /: Permission denied".
	for _, bad := range []string{"-r /", "-w /"} {
		if strings.Contains(cmd, bad) {
			t.Errorf("found %q, which makes / the program:\n%s", bad, cmd)
		}
	}
}

// TestExecCommandPrivileged pins that a privileged container does not get the
// user-namespace flags: entering it fails because the caller is already a
// member.
func TestExecCommandPrivileged(t *testing.T) {
	cmd := guesthelper.ExecCommand(100, false, "/bin/sh", "-l")
	if strings.Contains(cmd, " -U ") {
		t.Errorf("privileged container got -U:\n%s", cmd)
	}
	if !strings.Contains(cmd, " -m ") || !strings.Contains(cmd, " -p ") {
		t.Errorf("privileged container lost -m or -p:\n%s", cmd)
	}
}

// TestShellCommandUsesALoginShell pins -l, without which anything outside the
// default PATH is "command not found".
func TestShellCommandUsesALoginShell(t *testing.T) {
	withCmd := guesthelper.ShellCommand(127, true, "whoami")
	if !strings.Contains(withCmd, "-lc") {
		t.Errorf("a command is not run through a login shell:\n%s", withCmd)
	}
	if !strings.Contains(withCmd, "whoami") {
		t.Errorf("the command is missing:\n%s", withCmd)
	}

	// No command means an interactive login shell, not `sh -lc ""'.
	interactive := guesthelper.ShellCommand(127, true, "   ")
	if strings.Contains(interactive, "-lc") {
		t.Errorf("an empty command became a -c invocation:\n%s", interactive)
	}
	if !strings.Contains(interactive, "-l") {
		t.Errorf("the interactive shell is not a login shell:\n%s", interactive)
	}
}

// TestShellCommandQuotesAHostileCommand is the injection test: the command
// line comes from the client and becomes argv on the node.
func TestShellCommandQuotesAHostileCommand(t *testing.T) {
	got := guesthelper.ShellCommand(127, true, "$(touch /tmp/pwned)")
	if strings.Contains(got, "$(touch") && !strings.Contains(got, `'$(touch /tmp/pwned)'`) {
		t.Fatalf("a command substitution reached the command unquoted:\n%s", got)
	}

	// A single quote in the command must not end the quoting.
	hostile := guesthelper.ShellCommand(127, true, "it's; rm -rf /")
	if strings.Contains(hostile, "; rm -rf /'") && !strings.Contains(hostile, `'\''`) {
		t.Fatalf("an embedded quote broke out:\n%s", hostile)
	}
}

// TestExecCommandReportsAStoppedContainer pins the guard: nsenter given a
// missing pid says something unhelpful, so the command checks first and uses
// a status outside the range a guest command is likely to return.
func TestExecCommandReportsAStoppedContainer(t *testing.T) {
	cmd := guesthelper.ExecCommand(127, true, "/bin/true")
	if !strings.Contains(cmd, "lxc-info") {
		t.Errorf("no running check:\n%s", cmd)
	}
	if !strings.Contains(cmd, "is not running") {
		t.Errorf("no diagnostic for a stopped container:\n%s", cmd)
	}
	if !strings.Contains(cmd, "125") {
		t.Errorf("the not-running status is not 125:\n%s", cmd)
	}
}

// TestGeneratedExecCommandsAreValidShell runs them through `sh -n', which
// catches a quoting mistake that would otherwise only appear against a live
// node.
func TestGeneratedExecCommandsAreValidShell(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh available")
	}
	hostile := "it's a/file name;with$stuff"
	for name, cmd := range map[string]string{
		"exec":        guesthelper.ExecCommand(127, true, "/bin/sh", "-lc", hostile),
		"exec-unpriv": guesthelper.ExecCommand(127, false, "/bin/ls", hostile),
		"shell":       guesthelper.ShellCommand(127, true, hostile),
		"interactive": guesthelper.ShellCommand(127, true, ""),
	} {
		c := exec.CommandContext(t.Context(), "sh", "-n")
		c.Stdin = strings.NewReader(cmd)
		if out, err := c.CombinedOutput(); err != nil {
			t.Errorf("%s is not valid shell: %v\n%s\n%s", name, err, out, cmd)
		}
	}
}
