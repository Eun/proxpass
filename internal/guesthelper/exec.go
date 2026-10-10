package guesthelper

import (
	"fmt"
	"strings"
)

// ExecCommand returns the command that runs argv inside a container.
//
// # Why this is not a protocol op
//
// Every other operation is a framed request on a shared channel. A command
// cannot be: it owns stdin, stdout and stderr for its whole lifetime, needs a
// PTY on the session carrying it, and its exit status has to come back as the
// session's. Multiplexing that through the same channel as a file transfer
// would mean reimplementing what SSH already does -- so a command gets its
// own session, and this builds the command line for it.
//
// # Why nsenter rather than lxc-attach
//
// lxc-attach applies the container's cgroup, LSM profile and capability set,
// which nsenter does not. That sounds like the safer choice and was the
// original one, but it carries a defect that is fatal here: lxc-attach has NO
// flag to request or refuse a terminal. It decides by inspecting its own
// descriptors (lxc_attach.c, stdfd_is_pty) and allocates one inside if ANY of
// the three is a tty.
//
// Measured over a real ssh, the same output is 12 bytes without a PTY -- LF
// line endings, stderr separate -- and 27 bytes with one, because the line
// discipline rewrites "\n" as "\r\n" and folds stderr into stdout. Since
// proxpass must mirror whatever terminal the CLIENT asked for, and sshd gives
// this process a PTY exactly when the client wanted one, lxc-attach's
// inspection of our descriptors is not a decision we can make independently.
// `ssh ct100@host cat f.bin > out' therefore corrupts every 0x0a byte.
//
// nsenter takes no view of the terminal, so the PTY is requested on the SSH
// session and nowhere else, which is the only place that knows what the
// client asked for.
//
// The cost is real and accepted: a command runs in the HOST cgroup and
// outside the container's AppArmor profile, so it is not bound by the
// container's memory or CPU limits. Verified on a live node:
// /proc/self/cgroup reads "0::/user.slice/..." and /proc/self/attr/current
// reads "unconfined", where lxc-attach gives "0::/.lxc". A correct transfer
// was judged to matter more than a limit that only binds a command the
// administrator already chose to allow.
func ExecCommand(vmid int, unprivileged bool, argv ...string) string {
	args := append([]string{}, enterArgs(unprivileged)...)
	args = append(args, "--")
	return containerCommand(vmid, strings.Join(args, " ")+" "+shellQuoteAll(argv...))
}

// envPrelude replaces what the login shell was there to provide.
//
// It is prepended to the command inside the already-quoted -c string, so the
// client's own command remains one literal argument and the injection
// boundary does not move -- see shellQuote.
//
// # Why PATH only
//
// Only PATH, because PATH is all `-l' ever actually set. Measured by running
// a login shell with an empty environment in stock images:
//
//	alpine:3   PATH=/usr/local/sbin:...:/bin  HOME=UNSET  USER=UNSET
//	debian:13  PATH=/usr/local/sbin:...:/bin  HOME=UNSET  USER=UNSET
//
// /etc/profile sets PATH and nothing else of interest; HOME, USER and LOGNAME
// come from login(1) or sshd, neither of which is in this path. So a command
// here never had them, and inventing values would not restore behavior --
// it would change it, and be WRONG for any container whose uid 0 is not
// named root or whose home is not /root. The namespace is entered as uid 0
// (-S 0), but that says nothing about what the container's passwd calls it.
//
// A command that wants them can read the container's own passwd, which is
// the only authority on the question. Nothing here has to guess.
//
// The value is sshd's SUPERUSER_PATH, which is also exactly what the three
// profiles above produce, so this is the same PATH by both routes.
//
// # Why no cd
//
// nsenter -r chroots and then restores the cwd it saved beforehand, so the
// working directory is a node directory that is no longer reachable under
// the new root. Verified: pwd returns empty and `cat ./secret' cannot reach
// the node file that is really in that directory -- the cwd is already
// severed from the filesystem, which is the containment the chroot exists to
// provide. A `cd' would only paper over a dangling cwd that is harmless, and
// `cd "$HOME"' would land somewhere a container need not even have.
const envPrelude = `PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; export PATH; `

// ShellCommand returns the command that opens a shell inside a container, or
// runs one command line in it.
//
// # Why a command does NOT get a login shell
//
// It used to. `sh -lc' was chosen so the profile would set PATH and HOME,
// without which anything outside the default PATH is "command not found".
// That fixed the environment and broke the output: a login shell sources
// /etc/profile.d, and a container whose template writes a banner there -- the
// community-scripts Proxmox templates do -- puts that banner on STDOUT.
// `ssh ct100@host cat /etc/hostname > out' returned 332 bytes where 5 were
// asked for, and legacy scp, which multiplexes its protocol over the same
// stdout, failed outright.
//
// sshd itself has the same problem to solve and does not solve it with a
// login shell. session.c, do_child(): the '-' that marks argv[0] as a login
// shell is prepended only `if (!command)', and the command path is
//
//	argv[0] = (char *) shell0;   /* bare basename, no '-' */
//	argv[1] = "-c";
//	argv[2] = (char *) command;
//
// The environment comes from do_setup_env() instead, which sets PATH, HOME
// and the rest explicitly and unconditionally -- so a non-login `sh -c' under
// real sshd still has a usable PATH. OpenSSH made this exact move for this
// exact reason: configure.ac appends $bindir to USER_PATH with the comment
// "make sure $bindir is in USER_PATH so scp will work".
//
// So -l goes, envPrelude takes over its job, and the banner cannot reach
// stdout because no profile is read. This also makes proxpass match ssh,
// which is the contract: `ssh ct100@host cmd' should behave as `ssh host cmd'
// does anywhere else. Note that the PTY makes no difference to this -- sshd
// branches on the tty only to choose do_exec_pty, and passes the same command
// to the same do_child -- so `ssh -t' is a non-login shell too.
//
// An empty command is the other case, and there a login shell IS what ssh
// does: no command means do_exec(ssh, s, NULL), the '-' is prepended, the
// profile is read and the banner is wanted.
func ShellCommand(vmid int, unprivileged bool, command string) string {
	if strings.TrimSpace(command) == "" {
		return ExecCommand(vmid, unprivileged, "/bin/sh", "-l")
	}
	return ExecCommand(vmid, unprivileged, "/bin/sh", "-c", envPrelude+command)
}

// shellQuoteAll quotes each argument and joins them with spaces.
func shellQuoteAll(args ...string) string {
	quoted := make([]string, 0, len(args))
	for _, a := range args {
		quoted = append(quoted, shellQuote(a))
	}
	return strings.Join(quoted, " ")
}

// enterArgs returns the nsenter prefix shared by the helper launch and a
// command.
//
// Each flag is load-bearing and was settled against a real PVE 9.2 node:
//
//	-m  the container's mount namespace, so paths resolve inside it
//	-r  its ROOT, so an absolute symlink cannot name anything outside.
//	    Without this a container holding "/data/x -> /etc" makes a write
//	    land on the NODE's /etc, which is a container escape.
//	-p  its PID namespace. Needed so /proc/self resolves against the
//	    container's own /proc -- which is how the streamed helper binary is
//	    executed -- and so a command sees the container's processes rather
//	    than the node's.
//	-u  its UTS namespace, so `hostname' reports the container's.
//	-i  its IPC namespace, for the same reason.
//	-U -S 0 -G 0  its user namespace as uid 0, so writes into an
//	    unprivileged container land as its root rather than nobody:nogroup.
//
// -r and -w are passed in their BARE form. Their arguments are OPTIONAL
// (-r[=<dir>]), so a separated value is taken as the program to run:
// "nsenter -r / -- cmd" once failed every transfer with
//
//	nsenter: failed to execute /: Permission denied
func enterArgs(unprivileged bool) []string {
	args := []string{"nsenter", "-t", `"$pid"`, "-m", "-r", "-p", "-u", "-i"}
	if unprivileged {
		args = append(args, "-U", "-S", "0", "-G", "0")
	}
	return args
}

// shellQuote wraps a string so a shell takes it as one literal argument.
//
// This is the injection boundary: a command line arrives from the client and
// becomes argv on the node. Single-quoting with '\” for an embedded quote is
// the only form that needs no knowledge of what else is in the string.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// containerCommand wraps cmd with the pid lookup and the restart guard.
//
// The pid is resolved on the node, because nsenter needs one and lxc-info is
// the only thing that knows it. A container that is not running is reported
// as such with ErrNotRunningStatus rather than as whatever nsenter says
// about a pid that does not exist.
func containerCommand(vmid int, cmd string) string {
	id := shellQuote(fmt.Sprint(vmid))
	pidOf := "lxc-info -n " + id + " -p 2>/dev/null | " +
		`sed -n 's/^PID:[[:space:]]*\([0-9]\{1,\}\)$/\1/p'`
	return strings.Join([]string{
		"set -e",
		"pid=$(" + pidOf + ")",
		`[ -n "$pid" ] || { echo "container ` + fmt.Sprint(vmid) +
			` is not running" >&2; exit ` + fmt.Sprint(ErrNotRunningStatus) + "; }",
		"exec " + cmd,
	}, "; ")
}

// ErrNotRunningStatus is the exit status used for "this container is not
// running".
//
// 125 is outside the range a transferred command is likely to return on its
// own: 1-124 are ordinary failures and 126/127 are the shell's own
// "not executable" and "not found".
const ErrNotRunningStatus = 125
