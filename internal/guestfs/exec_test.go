package guestfs

import (
	"os/exec"
	"strings"
	"testing"
)

// TestExecUsesLxcAttach pins the choice of tool.
//
// nsenter would be enough to make paths and process ids look right, and is
// what the file operations use. A command needs more: lxc-attach also applies
// the container's cgroup, its LSM profile and its capability set, so a
// long-running command stays inside the container's memory and CPU limits.
// Switching this to nsenter would silently let commands escape them.
func TestExecUsesLxcAttach(t *testing.T) {
	got := Container{VMID: 101}.ExecCmd("whoami")
	if !strings.Contains(got, "lxc-attach") {
		t.Fatalf("expected lxc-attach:\n%s", got)
	}
	if strings.Contains(got, "nsenter") {
		t.Fatalf("a command must not use nsenter, which leaves the host cgroup:\n%s", got)
	}
}

// TestExecClearsTheEnvironment keeps proxpass's own SSH session on the NODE
// from leaking into the container.
//
// The lxc-attach default is --keep-env, which would hand the container
// SSH_CONNECTION, SSH_CLIENT and anything else the node's sshd set. None of
// it describes the container.
func TestExecClearsTheEnvironment(t *testing.T) {
	got := Container{VMID: 101}.ExecCmd("whoami")
	if !strings.Contains(got, "--clear-env") {
		t.Fatalf("expected --clear-env:\n%s", got)
	}
}

// TestExecRefusesAStoppedContainer checks the early exit, so that a stopped
// container is reported as such rather than as whatever lxc-attach prints.
func TestExecRefusesAStoppedContainer(t *testing.T) {
	got := Container{VMID: 101}.ExecCmd("whoami")
	if !strings.Contains(got, "lxc-info") || !strings.Contains(got, "RUNNING") {
		t.Fatalf("expected a running check:\n%s", got)
	}
	if !strings.Contains(got, "exit 125") {
		t.Fatalf("expected the not-running status:\n%s", got)
	}
}

// TestShellCmdQuotesTheWholeCommand is the injection test.
//
// The command arrives from the client as one string and is passed to sh -lc
// INSIDE the container, so it is meant to be interpreted there -- but it must
// reach there as a single argument rather than being interpreted on the NODE
// on the way.
func TestShellCmdQuotesTheWholeCommand(t *testing.T) {
	got := Container{VMID: 101}.ShellCmd("echo hi; touch /tmp/pwned")

	// The whole command is one quoted word, so the node's shell sees it as
	// data. The semicolon must not end a command at this level.
	if !strings.Contains(got, `'echo hi; touch /tmp/pwned'`) {
		t.Fatalf("the command was not passed as a single quoted word:\n%s", got)
	}
}

// TestShellCmdWithoutACommandOpensALoginShell covers "ssh ct100@host" with a
// PTY and no command.
func TestShellCmdWithoutACommandOpensALoginShell(t *testing.T) {
	got := Container{VMID: 101}.ShellCmd("")
	if !strings.Contains(got, `'/bin/sh' '-l'`) {
		t.Fatalf("expected an interactive login shell:\n%s", got)
	}
	if strings.Contains(got, "-lc") {
		t.Fatalf("an empty command must not become `sh -lc \"\"`:\n%s", got)
	}
}

// TestShellCmdUsesALoginShell checks the -l, without which the container's
// profile is never read and PATH is whatever --clear-env left.
func TestShellCmdUsesALoginShell(t *testing.T) {
	got := Container{VMID: 101}.ShellCmd("whoami")
	if !strings.Contains(got, `'-lc'`) {
		t.Fatalf("expected a login shell:\n%s", got)
	}
}

// TestExecCommandsAreValidShell runs every generated form through a parser,
// which a quoting mistake would break.
func TestExecCommandsAreValidShell(t *testing.T) {
	requireShell(t)
	c := Container{VMID: 101}
	for name, cmd := range map[string]string{
		"exec":      c.ExecCmd("ls", "-la", "/tmp"),
		"shell":     c.ShellCmd("echo 'quoted' && ls | wc -l"),
		"loginOnly": c.ShellCmd(""),
		"hostile":   c.ShellCmd(`it's; $(touch /tmp/x); ` + "`id`"),
	} {
		if err := exec.CommandContext(t.Context(), "sh", "-n", "-c", cmd).Run(); err != nil {
			t.Errorf("%s produced invalid shell: %v\n%s", name, err, cmd)
		}
	}
}

// TestShellCmdCarriesAHostileCommandAsData is the end-to-end quoting check:
// the node's shell must treat the whole thing as one argument.
func TestShellCmdCarriesAHostileCommandAsData(t *testing.T) {
	requireShell(t)

	// Stand in for lxc-attach: print the arguments it would have received,
	// one per line, so the test can see where the boundaries fell.
	cmd := Container{VMID: 101}.ShellCmd("a; b && c")
	i := strings.Index(cmd, "lxc-attach")
	if i < 0 {
		t.Fatalf("no lxc-attach in:\n%s", cmd)
	}
	// Replace the binary with a printer, keeping its arguments intact.
	probe := "set -- " + cmd[i+len("lxc-attach"):] + `; for a in "$@"; do printf '[%s]' "$a"; done`

	out, err := exec.CommandContext(t.Context(), "sh", "-c", probe).Output()
	if err != nil {
		t.Fatalf("probe failed: %v", err)
	}
	// The command must arrive as ONE argument, semicolons and all.
	if !strings.Contains(string(out), "[a; b && c]") {
		t.Fatalf("the command did not arrive as a single argument: %s", out)
	}
}
