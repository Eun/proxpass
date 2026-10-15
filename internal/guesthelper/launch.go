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
		shellPrelude,
		"mkdir -p " + shellQuote(StageDir),
		// Already present and executable: consume stdin so the writer
		// does not block on a pipe nobody reads, then stop.
		"if [ -x " + shellQuote(final) + " ]; then cat > /dev/null; exit 0; fi",
		"cat > " + shellQuote(tmp),
		// 0755, NOT 0700. After entering the user namespace the process
		// is uid 0 INSIDE the container, which maps to a high uid on the
		// node -- 100000 by default. The staged file is owned by the
		// node's real root, so owner-only permissions deny it and the
		// exec fails with EACCES. Verified on a live node: 0700 gives
		// "failed to execute ...: Permission denied", 0755 runs.
		//
		// The file is not secret: it is the same binary that is already
		// readable inside the proxpass image.
		"chmod 0755 " + shellQuote(tmp),
		"mv -f " + shellQuote(tmp) + " " + shellQuote(final),
	}, "; ")
}

// shellPrelude aborts the generated script on the first failing command.
//
// Every command proxpass builds starts with it, so a failing guard -- a
// container that is not running, a staging write that could not land --
// stops there rather than carrying on to run something against the wrong
// target.
const shellPrelude = "set -e"

// helperFD is the descriptor the staged helper is opened on before the
// namespace entry, and the number the exec path inside the container refers
// to.
//
// 3 is the first free descriptor after stdin, stdout and stderr, all three of
// which carry the protocol and must be left alone.
const helperFD = 3

// LaunchCommand returns the command that starts the helper inside a
// container.
//
// # Why the binary is executed through /proc/self/fd
//
// The program to exec is resolved AFTER the switch into the container's
// root, so a path on the NODE does not exist by the time it is used.
// Handing over StagePath(arch) fails with
//
//	failed to execute /var/tmp/proxpass-helper-1-amd64:
//	No such file or directory
//
// which is what shipped in v0.0.15 and broke every transfer. The regression
// is easy to make because the command LOOKS right and the staged file really
// is there -- just not in the namespace that matters.
//
// Opening the file on the node first and executing /proc/self/fd/3 avoids
// the problem entirely: the descriptor is inherited across the attach, so no
// path is resolved inside the container at all. This also means nothing has
// to be copied into the container, which would need cleanup and would be
// visible to its processes.
//
// It is what makes a DISTROLESS container servable. The helper is a static
// binary living on the node, and lxc-attach execs the absolute path given to
// it without consulting PATH (execvp skips the search when the argument
// contains a slash), so a container holding nothing but its own application
// -- no shell, no coreutils, no libc -- can still be listed and written to.
// Verified live against a container whose /etc was served this way.
//
// # Why lxc-attach rather than nsenter
//
// This is the opposite choice to ExecCommand's, for a reason that does not
// apply here. nsenter is used there because lxc-attach has NO flag to
// request or refuse a terminal: it inspects its own descriptors
// (tools/lxc_attach.c, stdfd_is_pty) and allocates a PTY inside if ANY of
// the three is a tty, which would rewrite "\n" as "\r\n" in a command's
// output. A command may legitimately run with a PTY, so that decision
// cannot be delegated.
//
// A TRANSFER never has one. scp and sftp arrive as an sshd SUBSYSTEM, and a
// client does not request a terminal for one, so stdfd_is_pty is false and
// no PTY is allocated. Measured: a helper launched under script(1) -- a
// deliberately hostile case with a real tty on all three descriptors --
// still returned its 32-byte reply byte-for-byte intact.
//
// What that buys is everything nsenter could not give us:
//
//	                  lxc-attach    nsenter
//	cgroup            0::/.lxc      the node's sshd session
//	nproc (1-CPU ct)  1             24
//	Seccomp           2             0
//
// lxc-attach asks the running LXC monitor for the container's actual cgroup
// directory fds (cgroups/cgfsng.c, cgroup_attach) rather than parsing
// /proc/<pid>/cgroup and guessing, and it loads the container's seccomp
// profile before exec. nsenter does neither: --join-cgroup is the closest
// equivalent and it is unusable, see cgroupProbe.
//
// This is also what `pct exec' does -- it is a thin wrapper that execs
// lxc-attach with the argv passed straight through, no shell:
//
//	my @lxc_attach_cmd = ('lxc-attach', '-n', $vmid);
//	push @lxc_attach_cmd, $keep_env ? '--keep-env' : '--clear-env';
//	push @lxc_attach_cmd, '--', @{ $param->{'extra-args'} };
//
// so this path now matches Proxmox's own tool. (`pct enter', by contrast,
// passes no command and ends in execlp("/bin/sh"), which is why it cannot
// serve a distroless container at all.)
//
// -e is NOT passed. It looks like it only elevates privileges, but
// attach.c's fetch_seccomp() is gated behind attach_lsm(), so dropping the
// LSM flag silently discards the seccomp profile too. Measured: a bare -e
// gives Seccomp 0, nproc 24 and the node's cgroup -- all three protections
// at once.
func LaunchCommand(vmid int, arch Arch, unprivileged bool) string {
	// unprivileged is unused: lxc-attach reads the container's own config
	// for the idmap, so there is no -U/-S/-G to decide. It stays in the
	// signature because the caller does not know which transport is used
	// and ExecCommand still needs it.
	_ = unprivileged

	args := []string{
		"lxc-attach", "-n", shellQuote(fmt.Sprint(vmid)),
		// The environment a transfer gets must not depend on the node's.
		// This matches `pct exec --keep-env=0', which is the PVE 9
		// default-to-be. The protocol is self-describing, so the helper
		// needs nothing from it.
		"--clear-env",
		"--", fmt.Sprintf("/proc/self/fd/%d", helperFD), "serve",
	}
	// The redirection opens the staged binary on the node, BEFORE the
	// attach changes what paths mean. It must come AFTER the command, not
	// before: "exec 3< f lxc-attach ..." makes the shell treat lxc-attach
	// as a redirect operand rather than the program.
	//
	// It also must stay a SHELL redirection rather than anything Go opens:
	// Go sets O_CLOEXEC on every descriptor it creates, which would close
	// the binary across the exec.
	return attachCommand(vmid, fmt.Sprintf("%s %d< %s",
		strings.Join(args, " "), helperFD, shellQuote(StagePath(arch))))
}

// attachCommand wraps an lxc-attach invocation with the restart guard.
//
// Unlike containerCommand this does NOT look up a pid: lxc-attach takes the
// container by name. The guard stays so that a stopped container is reported
// as ErrNotRunningStatus rather than as whatever lxc-attach says about a
// container it cannot find, which is what the session layer matches on.
func attachCommand(vmid int, cmd string) string {
	id := shellQuote(fmt.Sprint(vmid))
	return strings.Join([]string{
		shellPrelude,
		"lxc-info -n " + id + " -p >/dev/null 2>&1 || " +
			`{ echo "container ` + fmt.Sprint(vmid) +
			` is not running" >&2; exit ` + fmt.Sprint(ErrNotRunningStatus) + "; }",
		"exec " + cmd,
	}, "; ")
}
