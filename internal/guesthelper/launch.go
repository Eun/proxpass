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
// The helper is executed by its path under the container's /proc rather than
// by its path on the node: nsenter resolves the program AFTER switching root,
// so a node path is ENOENT. See enterArgs in exec.go for why each flag is
// there.
func LaunchCommand(vmid int, arch Arch, unprivileged bool) string {
	args := append([]string{}, enterArgs(unprivileged)...)
	args = append(args, "--", shellQuote(StagePath(arch)), "serve")
	return containerCommand(vmid, strings.Join(args, " "))
}
