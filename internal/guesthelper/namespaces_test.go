package guesthelper_test

import (
	"strings"
	"testing"

	"proxpass/internal/guesthelper"
)

// A command must run in EVERY namespace the container has.
//
// `ssh ct100@host ip addr' reported the Proxmox node's vmbr0 while
// `hostname' in the same command reported the container's name: -u was
// passed and -n was not, so the command sat half inside the container. The
// kernel view on the live deployment was unambiguous --
//
//	mnt  4026534092   the container's
//	uts  4026534093   the container's
//	net  4026531833   the NODE's initial namespace
//
// -- and the container's own eth0 (192.168.0.225) was simply invisible,
// while the node's bridge (192.168.0.33) was not.
//
// The interactive console never had this: it runs `pct enter', which is
// Proxmox's own tool and attaches to everything. Only the hand-rolled
// nsenter used for commands and transfers was short a flag, which is why
// the two paths disagreed.
//
// This pins the whole set rather than just the missing one. A namespace
// omitted here is not a crash -- it is a command quietly reporting the
// node's state as though it were the container's, which is the kind of
// wrong answer that gets believed.
func TestEveryNamespaceIsEntered(t *testing.T) {
	// The COMMAND path only. A transfer no longer uses nsenter at all --
	// it attaches with lxc-attach, which derives the namespace set from
	// the container's own config. See LaunchCommand.
	for _, tc := range []struct {
		name string
		cmd  string
	}{
		{"command", guesthelper.ShellCommand(110, true, "ip addr")},
		{"interactive", guesthelper.ShellCommand(110, true, "")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Against the nsenter invocation ONLY. The surrounding shell
			// contains `lxc-info -n' and `[ -n "$pid" ]', so a search of
			// the whole string finds " -n " whether or not nsenter was
			// given it -- which is exactly how the missing flag went
			// unnoticed by a test that claimed to pin the set.
			args := nsenterArgs(t, tc.cmd)
			for _, ns := range []struct{ flag, why string }{
				{"-m", "mount: paths must resolve inside the container"},
				{"-r", "root: an absolute symlink must not escape to the node"},
				{"-n", "network: `ip addr' must show the container's stack, not the node's"},
				{"-p", "pid: /proc/self must be the container's"},
				{"-u", "uts: `hostname' must report the container's"},
				{"-i", "ipc"},
				{"-U", "user: writes must land as the container's root"},
			} {
				if !args[ns.flag] {
					t.Errorf("nsenter is missing %s (%s) in:\n%s",
						ns.flag, ns.why, tc.cmd)
				}
			}
		})
	}
}

// The namespaces a container usually does NOT have must not be requested.
//
// nsenter fails outright when asked for a namespace the target is not in,
// so requesting these would break every ordinary container rather than
// improving anything. `pct enter' leaves them alone too.
func TestUnavailableNamespacesAreNotRequested(t *testing.T) {
	cmd := guesthelper.ShellCommand(110, true, "true")
	args := nsenterArgs(t, cmd)
	for _, bad := range []struct{ flag, why string }{
		{"-C", "cgroup: only changes /proc/self/cgroup, which nothing here reads"},
		{"-T", "time: lxc does not create one, so this would always fail"},
	} {
		if args[bad.flag] {
			t.Errorf("nsenter was given %s (%s) in:\n%s", bad.flag, bad.why, cmd)
		}
	}
}

// nsenterArgs returns the flags passed to nsenter, as a set.
//
// It slices from "nsenter" to the "--" that ends its options, so the shell
// around it -- which legitimately contains "-n" and "-p" of its own, in
// `lxc-info -n' and `[ -n "$pid" ]' -- cannot satisfy an assertion about
// what nsenter received.
func nsenterArgs(t *testing.T, cmd string) map[string]bool {
	t.Helper()
	// From the EXEC, not the first "nsenter" in the string: the capability
	// probe runs `nsenter --help' earlier on the same line, and slicing
	// from that would read the probe's arguments instead of the real
	// invocation's -- reporting every namespace as missing.
	start := strings.Index(cmd, "exec nsenter ")
	if start < 0 {
		t.Fatalf("no `exec nsenter' invocation in:\n%s", cmd)
	}
	rest := cmd[start:]
	end := strings.Index(rest, " -- ")
	if end < 0 {
		t.Fatalf("nsenter invocation has no \" -- \" terminator in:\n%s", cmd)
	}
	out := map[string]bool{}
	for _, f := range strings.Fields(rest[:end]) {
		out[f] = true
	}
	return out
}

// The flags stay in their bare form.
//
// -n takes no argument at all, but -r and -w take OPTIONAL ones, so a
// separated value is read as the program to run. Adding a flag to the
// middle of that list is exactly when this gets broken again.
// The mistake these guard against: a flag whose argument is OPTIONAL given
// a separated value, which nsenter then reads as the program to run.
const (
	rootArgSep = "-r /"
	wdArgSep   = "-w /"
)

// cgroupFlag is the shell variable nsenter's --join-cgroup flag arrives in.
const cgroupFlag = "$ppcg"

func TestNamespaceFlagsTakeNoSeparatedArgument(t *testing.T) {
	for _, cmd := range []string{
		guesthelper.ShellCommand(110, true, "true"),
		guesthelper.LaunchCommand(110, guesthelper.ArchAMD64, true),
	} {
		for _, bad := range []string{rootArgSep, wdArgSep, "-n /"} {
			if strings.Contains(cmd, bad) {
				t.Errorf("found %q, which makes / the program:\n%s", bad, cmd)
			}
		}
	}
}

// A command must be accounted to the container's cgroup, not the node's.
//
// Without --join-cgroup the process stays in the cgroup of whatever
// invoked it -- the node's sshd session -- so the container's memory and
// CPU limits do not apply to it. Measured on a live one-CPU container
// before the fix:
//
//	ssh ct@host nproc            -> 24      (the node's CPUs)
//	pct enter, then nproc        -> 1       (the container's limit)
//	ssh ct@host cat /proc/self/cgroup
//	    -> 0::/user.slice/user-0.slice/session-152681.scope
//
// A runaway command therefore billed its memory to the node and the
// container's OOM killer never fired.
//
// This is NOT -C. That enters the cgroup namespace and only changes the
// path /proc/self/cgroup reports; the two were confused, which is how the
// escape came to be documented as an accepted cost of using nsenter.
//
// The shell variable is spelled out rather than imported: these tests read
// the command line as the node receives it, so a rename should make them
// fail and be re-read, not quietly follow along.
func TestTheContainersCgroupIsJoined(t *testing.T) {
	for _, tc := range []struct {
		name string
		cmd  string
	}{
		{"command", guesthelper.ShellCommand(110, true, "nproc")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// The flag reaches nsenter...
			if args := nsenterArgs(t, tc.cmd); !args[cgroupFlag] {
				t.Errorf("nsenter is not given %s, so the command keeps the "+
					"node's cgroup and escapes the container's limits:\n%s",
					cgroupFlag, tc.cmd)
			}
			// ...and something defines it, or it expands to nothing and
			// the flag silently does not exist.
			if !strings.Contains(tc.cmd, "ppcg=") {
				t.Errorf("%s is never assigned, so it always expands to "+
					"nothing:\n%s", cgroupFlag, tc.cmd)
			}
		})
	}
}

// A transfer gets the container's limits WITHOUT the cgroup flag.
//
// This is the other half of TestTheContainersCgroupIsJoined. The command
// path has to ask nsenter for the cgroup and settle for whatever the node's
// util-linux will give it; a transfer sidesteps the question by attaching
// with lxc-attach, which asks the running LXC monitor for the container's
// actual cgroup fds and loads its seccomp profile before exec.
//
// Measured on a live one-CPU container:
//
//	                  lxc-attach    nsenter (no -c)
//	cgroup            0::/.lxc      the node's sshd session
//	nproc             1             24
//	Seccomp           2             0
//
// So the transfer path must NOT grow a cgroup probe: having one would mean
// it had been switched back to nsenter and silently lost seccomp too.
func TestATransferIsContainedWithoutTheCgroupFlag(t *testing.T) {
	cmd := guesthelper.LaunchCommand(110, guesthelper.ArchAMD64, true)

	if !strings.Contains(cmd, "lxc-attach") {
		t.Errorf("a transfer does not use lxc-attach, so it runs in the node's "+
			"cgroup with no seccomp profile:\n%s", cmd)
	}
	// The CVE-2026-78408 probe belongs to the command path alone. Here it
	// would be dead weight at best, and a sign of a regression at worst.
	for _, bad := range []string{"ppcg", "--join-cgroup", "nsenter"} {
		if strings.Contains(cmd, bad) {
			t.Errorf("found %q on the transfer path, which should not need "+
				"nsenter at all:\n%s", bad, cmd)
		}
	}
}

// A transfer must not depend on anything inside the container.
//
// This is the distroless contract. The helper is a static binary staged on
// the NODE and executed through an inherited descriptor, so a container
// holding nothing but its own application -- no shell, no coreutils, no
// libc, no ld.so -- is still servable. Verified live: a container's /etc
// was listed this way.
//
// Two things keep it true, and both are easy to break by accident:
//
//   - the program is /proc/self/fd/N, never a path. lxc-attach execs the
//     argument as given (execvp skips the PATH search once it contains a
//     slash), so a container-side path would have to exist inside.
//   - nothing is wrapped in a shell. `pct enter' is the cautionary case:
//     it passes no command and so ends in execlp("/bin/sh"), which is
//     exactly why it cannot serve a distroless container.
func TestATransferNeedsNothingInsideTheContainer(t *testing.T) {
	cmd := guesthelper.LaunchCommand(110, guesthelper.ArchAMD64, true)

	at := strings.Index(cmd, " -- ")
	if at < 0 {
		t.Fatalf("no -- separator in:\n%s", cmd)
	}
	program := cmd[at+len(" -- "):]
	if j := strings.Index(program, " 3< "); j >= 0 {
		program = program[:j] // the redirection is node-side and legitimate
	}

	if !strings.HasPrefix(strings.TrimSpace(program), "/proc/self/fd/") {
		t.Errorf("the program is not an inherited descriptor, so it must exist "+
			"inside the container:\n  program: %s", program)
	}
	// No shell, and no container-side interpreter of any kind.
	for _, bad := range []string{"/bin/sh", "sh -c", "/bin/bash", "env "} {
		if strings.Contains(program, bad) {
			t.Errorf("the transfer runs %q inside the container, which a "+
				"distroless image does not have:\n  program: %s", bad, program)
		}
	}
}

// The cgroup flag is probed, not assumed.
//
// --join-cgroup needs a new enough util-linux and a unified cgroup v2
// hierarchy. An nsenter without it exits with a usage error before running
// anything, which would turn every command and every transfer into a hard
// failure on an older node -- worse than the escape the flag closes. So
// the generated shell asks first and leaves the flag out when the answer
// is no.
func TestTheCgroupFlagIsProbedBeforeUse(t *testing.T) {
	cmd := guesthelper.ShellCommand(110, true, "true")

	if !strings.Contains(cmd, "--join-cgroup") {
		t.Errorf("no probe for --join-cgroup in:\n%s", cmd)
	}
	// The probe must come BEFORE the invocation that uses its result.
	probeAt := strings.Index(cmd, "ppcg=")
	useAt := strings.Index(cmd, "nsenter "+cgroupFlag)
	if probeAt < 0 || useAt < 0 || probeAt > useAt {
		t.Errorf("the probe does not precede the use (probe=%d use=%d):\n%s",
			probeAt, useAt, cmd)
	}
	// Unquoted, so an empty result disappears from argv rather than
	// becoming an empty argument -- which nsenter reads as the program.
	for _, quoted := range []string{`"` + cgroupFlag + `"`, `'` + cgroupFlag + `'`} {
		if strings.Contains(cmd, quoted) {
			t.Errorf("%s is quoted, so an empty value becomes an empty "+
				"argument:\n%s", quoted, cmd)
		}
	}
}

// probePart returns everything the generated script does BEFORE the exec.
//
// The split matters: the exec line carries "$ppcg", so a test that searched
// the whole command for the flag would pass on the strength of the USE and
// never notice that the probe setting it had been weakened.
func probePart(t *testing.T, cmd string) string {
	t.Helper()
	at := strings.Index(cmd, "exec ")
	if at < 0 {
		t.Fatalf("no exec in the generated command:\n%s", cmd)
	}
	return cmd[:at]
}

// The probe must RUN --join-cgroup, not merely ask whether it exists.
//
// util-linux ships a bug -- CVE-2026-78408 -- in which --join-cgroup
// closes the caller's stdin and reopens /proc/<pid>/cgroup onto the freed
// descriptor, because sys-utils/nsenter.c initializes its cgroup fd to 0
// instead of -1 and open_target_fd() closes any fd >= 0 before opening.
// On such a node the flag is present and advertised by --help, and
// silently destroys standard input.
//
// Every release that has the flag is affected -- it arrived in 2.40 and
// 2.42.4 is the first carrying the complete fix -- so this is not a probe
// that can be deleted once the fleet is upgraded.
//
// That was not hypothetical. It shipped: every file transfer failed (the
// helper read the cgroup file instead of the protocol stream, so the
// handshake hit EOF) and every command reading stdin returned nothing,
// while commands that ignore stdin kept working -- which is exactly why a
// presence check let it through.
//
// So the probe has to execute the flag and confirm a byte survives the
// round trip. This test pins that it does, by requiring the probe to both
// pass -c to a real nsenter and compare the result against what was fed
// in; a presence-only probe fails here.
func TestTheCgroupProbeChecksThatStdinSurvives(t *testing.T) {
	cmd := guesthelper.ShellCommand(110, true, "true")
	probe := probePart(t, cmd)

	// It must actually invoke nsenter WITH the flag, not just grep --help.
	if !strings.Contains(probe, "nsenter -c ") {
		t.Errorf("the probe never runs `nsenter -c', so an nsenter that "+
			"advertises --join-cgroup and then eats stdin is accepted:\n%s",
			probe)
	}
	// ...and it must feed something in and check it comes back out. Without
	// the comparison, running the flag proves only that it does not crash.
	if !strings.Contains(probe, "printf pp") || !strings.Contains(probe, "= pp") {
		t.Errorf("the probe does not round-trip a byte through stdin, so it "+
			"cannot tell a working --join-cgroup from one that closes fd 0:\n%s",
			probe)
	}
	// The test runs inside the target's namespace, so it needs the pid --
	// which means it must come after the lookup that sets it.
	pidAt := strings.Index(cmd, "pid=$(")
	probeAt := strings.Index(cmd, "ppcg=")
	if pidAt < 0 || probeAt < pidAt {
		t.Errorf("the probe does not follow the pid lookup it depends on "+
			"(pid=%d probe=%d):\n%s", pidAt, probeAt, cmd)
	}
}

// A failing probe must be an answer, not an abort.
//
// The generated script runs under `set -e', and the probe is expected to
// fail on any node that is too old or affected by the stdin bug. If that
// failure propagated, the flag's absence would stop the command rather
// than merely leaving $ppcg empty -- turning a graceful degradation into
// a hard failure on exactly the nodes the probe exists to protect.
func TestAFailingCgroupProbeDoesNotAbortTheScript(t *testing.T) {
	cmd := guesthelper.ShellCommand(110, true, "true")
	probe := probePart(t, cmd)

	// `if' makes the whole thing a condition, which `set -e' never acts on.
	start := strings.Index(probe, "ppcg=")
	if start < 0 {
		t.Fatalf("no probe at all in:\n%s", cmd)
	}
	if !strings.HasPrefix(strings.TrimSpace(probe[start:]), "ppcg=; if ") {
		t.Errorf("the probe is not guarded by `if', so a node without a "+
			"working --join-cgroup aborts under `set -e' instead of running "+
			"the command without the flag:\n%s", probe)
	}
}
