package guesthelper_test

import (
	"errors"
	"strings"
	"testing"

	"proxpass/internal/guesthelper"
)

// TestLaunchNeverHandsTheAttachANodePath is the regression test for the bug
// that shipped in v0.0.15 and broke every transfer.
//
// The program to exec is resolved AFTER the switch into the container's
// root, so a path on the node does not exist by the time it is used:
//
//	failed to execute /var/tmp/proxpass-helper-1-amd64:
//	No such file or directory
//
// The staged path may appear only as a REDIRECTION TARGET, which the shell
// opens before the attach runs. It must never be the program.
//
// This outlived the switch from nsenter to lxc-attach: both resolve the
// program inside the container, so the failure mode is identical.
func TestLaunchNeverHandsTheAttachANodePath(t *testing.T) {
	for _, arch := range []guesthelper.Arch{guesthelper.ArchAMD64, guesthelper.ArchARM64} {
		cmd := guesthelper.LaunchCommand(110, arch, true)
		staged := guesthelper.StagePath(arch)

		// Everything after the "--" separator is the program and its
		// arguments. The staged path must not be in there.
		i := strings.Index(cmd, " -- ")
		if i < 0 {
			t.Fatalf("%s: no -- separator in:\n%s", arch, cmd)
		}
		program := cmd[i+len(" -- "):]
		// Trim the redirection, which is legitimately where the path goes.
		if j := strings.Index(program, " 3< "); j >= 0 {
			program = program[:j]
		}
		if strings.Contains(program, staged) {
			t.Errorf("%s: the staged NODE path is the program nsenter must exec,"+
				" which is ENOENT inside the container:\n  program: %s\n  full: %s",
				arch, program, cmd)
		}
		if !strings.Contains(program, "/proc/self/fd/") {
			t.Errorf("%s: the program is not an inherited descriptor:\n  %s", arch, program)
		}
		// The descriptor has to be opened, or the exec has nothing to run.
		if !strings.Contains(cmd, "3< "+shQuote(staged)) {
			t.Errorf("%s: the staged binary is never opened on the node:\n%s", arch, cmd)
		}
		// /proc/self must be the CONTAINER's, or the descriptor path is
		// ENOENT. nsenter needed -p for that; lxc-attach enters the pid
		// namespace itself, so there is no flag to lose -- but there is
		// also no flag to assert, and searching the whole command for
		// " -p " would match the `lxc-info -n <id> -p' guard and pass no
		// matter what. Assert the attach instead.
		if !strings.Contains(cmd, "lxc-attach") {
			t.Errorf("%s: nothing enters the container's pid namespace, so"+
				" /proc/self/fd/3 is ENOENT:\n%s", arch, cmd)
		}
	}
}

// TestStagedHelperIsExecutableAfterIdmap is the regression test for the
// second half of the same failure.
//
// After entering the user namespace the process is uid 0 INSIDE the
// container, which an unprivileged container maps to a high uid on the node
// -- 100000 by default. The staged file belongs to the node's real root, so
// owner-only permissions deny the exec:
//
//	nsenter: failed to execute ...: Permission denied
//
// Verified on a live node: 0700 fails, 0755 runs.
func TestStagedHelperIsExecutableAfterIdmap(t *testing.T) {
	cmd := guesthelper.StageCommand(guesthelper.ArchAMD64)
	if strings.Contains(cmd, "chmod 0700") {
		t.Errorf("the staged helper is owner-only, which a user-namespaced"+
			" process cannot execute:\n%s", cmd)
	}
	if !strings.Contains(cmd, "chmod 0755") {
		t.Errorf("the staged helper is not made executable for others:\n%s", cmd)
	}
}

// shQuote mirrors the package's quoting so the test can look for a quoted
// path without exporting the helper.
func shQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// TestLaunchFailureCarriesTheReason is the regression test for the SILENCE
// that let v0.0.15 ship.
//
// nsenter writes its refusal without a trailing newline. The first version of
// the stderr writer only emitted complete lines, so that message was
// discarded: the client saw "Connection closed" and the log held nothing.
// Whatever the helper said must reach the error.
func TestLaunchFailureCarriesTheReason(t *testing.T) {
	// Needs a real staged binary: without one Start fails at the embed
	// check, before it ever launches, and the test would pass for the
	// wrong reason.
	if _, err := guesthelper.Binary(guesthelper.ArchAMD64); errors.Is(err, guesthelper.ErrNoBinary) {
		t.Skip("no real binary staged: run `mise run helpers'")
	}

	const refusal = "nsenter: failed to execute /proc/self/fd/3: No such file or directory"

	n := &stderrNode{arch: archAMD64Uname, stderr: refusal}
	_, err := guesthelper.Start(n, 110, true, nil)
	if err == nil {
		t.Fatal("a helper that never answered was accepted")
	}
	if !strings.Contains(err.Error(), "No such file or directory") {
		t.Errorf("the error does not carry what the helper said, so an operator"+
			" sees a dead session and no reason:\n  %v", err)
	}
}
