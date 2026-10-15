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
	// Both builders share enterArgs, so both are checked: a transfer that
	// entered a different set from a command would be its own bug.
	for _, tc := range []struct {
		name string
		cmd  string
	}{
		{"command", guesthelper.ShellCommand(110, true, "ip addr")},
		{"helper launch", guesthelper.LaunchCommand(110, guesthelper.ArchAMD64, true)},
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
		{"helper launch", guesthelper.LaunchCommand(110, guesthelper.ArchAMD64, true)},
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
