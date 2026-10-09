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
// nsenter resolves the program to exec AFTER it has switched root, so a path
// on the NODE does not exist by the time it is used. Handing it
// StagePath(arch) fails with
//
//	nsenter: failed to execute /var/tmp/proxpass-helper-1-amd64:
//	No such file or directory
//
// which is what shipped in v0.0.15 and broke every transfer. The regression
// is easy to make because the command LOOKS right and the staged file really
// is there -- just not in the namespace that matters.
//
// Opening the file on the node first and executing /proc/self/fd/3 avoids
// the problem entirely: the descriptor is inherited across the namespace
// entry, so no path is resolved inside the container at all. This also means
// nothing has to be copied into the container, which would need cleanup and
// would be visible to its processes.
//
// -p is load-bearing for this: /proc/self is the container's own /proc, and
// without its PID namespace this process has no entry there. See enterArgs.
func LaunchCommand(vmid int, arch Arch, unprivileged bool) string {
	args := append([]string{}, enterArgs(unprivileged)...)
	args = append(args,
		"--", fmt.Sprintf("/proc/self/fd/%d", helperFD), "serve")
	// The redirection opens the staged binary on the node, BEFORE nsenter
	// changes what paths mean. It must come AFTER the command, not before:
	// "exec 3< f nsenter ..." makes the shell treat nsenter as a redirect
	// operand rather than the program.
	return containerCommand(vmid, fmt.Sprintf("%s %d< %s",
		strings.Join(args, " "), helperFD, shellQuote(StagePath(arch))))
}
