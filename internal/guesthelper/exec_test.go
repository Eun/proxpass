package guesthelper_test

import (
	"os"
	"os/exec"
	"path/filepath"
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

// TestShellCommandDoesNotUseALoginShell is the regression test for the banner
// on stdout.
//
// A login shell sources /etc/profile.d, and the community-scripts Proxmox
// templates write an ANSI banner there -- onto STDOUT, where it corrupts the
// output of any non-interactive command and breaks legacy scp outright. This
// is also what sshd does: session.c prepends the login-shell '-' only
// `if (!command)'.
//
// The test the old behavior had asserted "-lc" was present, so it passed
// while the bug shipped. This asserts the opposite.
func TestShellCommandDoesNotUseALoginShell(t *testing.T) {
	withCmd := guesthelper.ShellCommand(127, true, "whoami")
	if strings.Contains(withCmd, "-lc") {
		t.Errorf("a command is run through a login shell, which puts the\n"+
			"container's /etc/profile.d banner on stdout:\n%s", withCmd)
	}
	if !strings.Contains(withCmd, "'-c'") {
		t.Errorf("a command is not run with -c:\n%s", withCmd)
	}
	if !strings.Contains(withCmd, "whoami") {
		t.Errorf("the command is missing:\n%s", withCmd)
	}

	// No command is the other case: ssh gives an interactive LOGIN shell
	// there, profile and banner included, and so must this.
	interactive := guesthelper.ShellCommand(127, true, "   ")
	if strings.Contains(interactive, "-lc") {
		t.Errorf("an empty command became a -c invocation:\n%s", interactive)
	}
	if !strings.Contains(interactive, "'-l'") {
		t.Errorf("the interactive shell is not a login shell:\n%s", interactive)
	}
}

// TestShellCommandSetsPathAndNothingElse pins what replaced -l, and pins the
// boundary of it.
//
// Dropping -l removes the banner but also removes the PATH the profile set,
// which would make anything outside the namespace-entry default "command not
// found". So PATH is restored.
//
// Nothing else is, and that is the point of the second half of this test. A
// login shell never set HOME, USER or LOGNAME either -- /etc/profile does not
// set them, login(1) and sshd do, and neither runs here. Setting them would
// not restore behavior but invent it, and would be WRONG for a container
// whose uid 0 is not called root or whose home is not /root. Entering as
// uid 0 says nothing about what the container's own passwd calls that user.
func TestShellCommandSetsPathAndNothingElse(t *testing.T) {
	cmd := guesthelper.ShellCommand(127, true, "whoami")

	// sshd's SUPERUSER_PATH, which is also what the stock /etc/profile in
	// alpine and debian produces -- the same value by either route.
	const wantPath = "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	if !strings.Contains(cmd, wantPath) {
		t.Errorf("missing %q, which the profile used to provide:\n%s", wantPath, cmd)
	}
	if !strings.Contains(cmd, "export PATH") {
		t.Errorf("PATH is not exported, so the command would not see it:\n%s", cmd)
	}

	// Identity must NOT be guessed. A container is free to call uid 0
	// something other than root and to put its home somewhere other than
	// /root; the container's passwd is the only authority and a command
	// that needs these can read it.
	for _, guessed := range []string{"HOME=", "USER=", "LOGNAME=", "SHELL=", "cd "} {
		if strings.Contains(cmd, guessed) {
			t.Errorf("the prelude guesses %q, which a container need not agree with:\n%s",
				guessed, cmd)
		}
	}

	// The interactive shell sources the profile itself, so the prelude
	// would be redundant there.
	interactive := guesthelper.ShellCommand(127, true, "")
	if strings.Contains(interactive, wantPath) {
		t.Errorf("the interactive login shell got the prelude as well:\n%s", interactive)
	}
}

// TestShellCommandPreludeCannotBeEscapedByTheCommand guards the new adjacency:
// the prelude is now immediately before attacker-controlled text inside the
// same -c string, so the quoting that keeps them one argument matters more
// than it did.
func TestShellCommandPreludeCannotBeEscapedByTheCommand(t *testing.T) {
	// A command that tries to close the -c quoting and append its own.
	got := guesthelper.ShellCommand(127, true, `'; echo pwned; :'`)

	// Every embedded quote must be neutralized; none may survive to end the
	// literal early.
	if !strings.Contains(got, `'\''`) {
		t.Fatalf("an embedded quote was not escaped:\n%s", got)
	}

	// The prelude and the command must remain in ONE quoted argument: the
	// -c string opens once and closes once.
	body := got[strings.Index(got, "'-c'")+len("'-c'"):]
	if strings.Count(body, "'")%2 != 0 {
		t.Fatalf("unbalanced quoting after -c:\n%s", got)
	}
}

// TestShellCommandQuotesAHostileCommand is the injection test: the command
// line comes from the client and becomes argv on the node.
//
// The property is checked by EXECUTION rather than by substring. The command
// is no longer the whole -c string -- envPrelude precedes it -- so a test
// that pinned "the argument is exactly '<command>'" would fail on a correctly
// quoted command line. What has to hold is that the shell on the node expands
// nothing it was given, which only running it can show.
func TestShellCommandQuotesAHostileCommand(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh available")
	}
	marker := filepath.Join(t.TempDir(), "pwned")

	// The node's shell parses the generated line; the stub prints the argv
	// it was handed instead of entering a namespace, so any expansion
	// happens exactly where it would in production.
	stub := stubNode(t, "printf '%s\\n' \"$@\"\n")

	for name, command := range map[string]string{
		"substitution": "$(touch " + marker + ")",
		"backtick":     "`touch " + marker + "`",
		"quote-break":  "it's; touch " + marker,
		"closing":      "'; touch " + marker + "; :'",
	} {
		t.Run(name, func(t *testing.T) {
			// The command IS the thing under test: it must be run to
			// show the node's shell does not expand it.
			//nolint:gosec // G204: running the generated line is the test.
			c := exec.CommandContext(t.Context(), "sh", "-c",
				guesthelper.ShellCommand(127, true, command))
			c.Env = append(os.Environ(), "PATH="+stub+":"+os.Getenv("PATH"))
			out, err := c.CombinedOutput()
			if err != nil {
				t.Fatalf("generated command did not run: %v\n%s", err, out)
			}
			if _, err := os.Stat(marker); err == nil {
				t.Fatalf("the command was EXECUTED by the node's shell:\n%s", out)
			}
			// It must still have arrived, as one argument, intact.
			if !strings.Contains(string(out), command) {
				t.Fatalf("the command did not reach the container intact:\n%s", out)
			}
		})
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
