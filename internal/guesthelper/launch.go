package guesthelper

import (
	"fmt"
	"strings"
)

// Arch is a Proxmox node's CPU architecture, in Go's GOARCH spelling.
//
// Only the two architectures proxpass itself is built for are supported,
// because the helper ships inside the proxpass image and cannot exist for a
// platform the image was never built on.
type Arch string

// The supported architectures.
const (
	ArchAMD64 Arch = "amd64"
	ArchARM64 Arch = "arm64"
)

// ArchCommand prints the node's machine name.
//
// `uname -m' rather than anything Proxmox-specific because this runs on the
// NODE, not in the container, and every Proxmox node is a Debian host with
// coreutils. The container's architecture is not consulted: the helper runs
// in the container's namespaces but executes on the node's CPU, so it is the
// node's architecture that decides which binary can run.
const ArchCommand = "uname -m"

// ParseArch maps the output of ArchCommand to a GOARCH.
//
// Proxmox runs on x86_64 and aarch64; the aliases are accepted because
// `uname -m' is not consistent across kernels and an unexpected spelling
// should not be mistaken for an unsupported platform.
func ParseArch(unameM string) (Arch, error) {
	switch strings.ToLower(strings.TrimSpace(unameM)) {
	case "x86_64", "amd64":
		return ArchAMD64, nil
	case "aarch64", "arm64", "armv8l":
		return ArchARM64, nil
	default:
		return "", fmt.Errorf("unsupported node architecture %q", strings.TrimSpace(unameM))
	}
}

// StageDir is where the helper is written on the node.
//
// /var/tmp rather than /tmp: a transfer can outlive a tmpfs cleanup and,
// more importantly, some hardened nodes mount /tmp noexec, which would make
// the staged binary unrunnable for a reason that is tedious to diagnose.
// Checked at run time all the same -- see ErrStageNoExec.
const StageDir = "/var/tmp"

// StagePath returns the path the helper is written to on the node.
//
// The name carries the protocol version AND the architecture, so a node that
// serves containers for two proxpass versions keeps one file per version
// rather than racing over a single name.
func StagePath(arch Arch) string {
	return fmt.Sprintf("%s/proxpass-helper-%d-%s", StageDir, Version, arch)
}

// StageCommand returns a command that writes the helper from stdin, but only
// when the node does not already have that exact version.
//
// The check matters: pushing two megabytes over SSH on every transfer would
// cost more than the per-operation sessions the helper exists to remove. The
// first transfer to a node pays it; the rest do not.
//
// The write goes to a temporary name and is then renamed, so a concurrent
// transfer either sees no file or sees a complete one. rename(2) within a
// directory is atomic, which is why both paths are in StageDir.
func StageCommand(arch Arch) string {
	final := StagePath(arch)
	tmp := final + ".$$"
	return strings.Join([]string{
		"set -e",
		"mkdir -p " + shellQuote(StageDir),
		// Already present and executable: consume stdin so the writer
		// does not block on a pipe nobody reads, then stop.
		"if [ -x " + shellQuote(final) + " ]; then cat > /dev/null; exit 0; fi",
		"cat > " + shellQuote(tmp),
		"chmod 0700 " + shellQuote(tmp),
		"mv -f " + shellQuote(tmp) + " " + shellQuote(final),
	}, "; ")
}

// LaunchCommand returns the command that starts the helper inside a
// container.
//
// The flags are not interchangeable, and each was settled by running it
// against a real PVE 9.2 node:
//
//	-m        the container's mount namespace, so paths resolve inside it
//	-r        its root, so an ABSOLUTE SYMLINK cannot escape to the node.
//	          Without this a container holding "/data/x -> /etc" makes a
//	          write land on the NODE's /etc, which is a container escape.
//	-p        its PID namespace. Required, and the least obvious: the
//	          helper is executed by a path under the container's /proc,
//	          and without -p this process has no entry there, so the exec
//	          fails with ENOENT.
//	-U -S -G  its user namespace as uid 0, so writes into an unprivileged
//	          container land as its root rather than as nobody:nogroup.
//
// The pid is resolved and then re-checked by the caller, as the shell path
// does, because a container that restarts between the lookup and the use
// would have different namespaces.
func LaunchCommand(vmid int, arch Arch, unprivileged bool) string {
	args := []string{"nsenter", "-t", `"$pid"`, "-m", "-r", "-p"}
	if unprivileged {
		args = append(args, "-U", "-S", "0", "-G", "0")
	}
	args = append(args, "--", shellQuote(StagePath(arch)), "serve")
	return containerCommand(vmid, strings.Join(args, " "))
}

// containerCommand wraps cmd with the pid lookup and the restart guard.
//
// This mirrors guestfs.Container.Command rather than calling it: that method
// also appends the exit-status plumbing a one-shot command needs, which a
// long-lived process must not have -- the helper's stdin has to stay
// connected to the session, and a trailing "rc=$?" would run only after it
// exits, too late to be of use.
func containerCommand(vmid int, cmd string) string {
	id := shellQuote(fmt.Sprint(vmid))
	pidOf := "lxc-info -n " + id + " -p 2>/dev/null | " +
		`sed -n 's/^PID:[[:space:]]*\([0-9]\{1,\}\)$/\1/p'`
	return strings.Join([]string{
		"set -e",
		"pid=$(" + pidOf + ")",
		`[ -n "$pid" ] || { echo "container ` + fmt.Sprint(vmid) +
			` is not running" >&2; exit 125; }`,
		"exec " + cmd,
	}, "; ")
}

// shellQuote wraps a string so a shell takes it as one literal argument.
//
// The same single-quote escaping internal/guestfs uses: every path here is
// built by proxpass rather than supplied by a client, but the helper's path
// still travels through a shell and the quoting is what keeps that true.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
