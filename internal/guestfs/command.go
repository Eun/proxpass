// Package guestfs runs filesystem operations inside a Proxmox LXC container.
//
// Every operation is a command run on the Proxmox NODE over SSH, entering the
// container's namespaces with nsenter(1). Nothing is staged on the node: file
// content streams through the command's stdin or stdout, so a transfer costs
// no node disk IO and leaves nothing behind.
//
// # Why nsenter rather than a path prefix
//
// The container's root is visible on the node at /proc/<pid>/root, so it is
// tempting to prefix it onto the user's path and operate from the node. That
// is unsafe, and the reason is worth stating because the bug it causes is
// silent and severe.
//
// Path resolution restarts at the CALLING process's root whenever it meets an
// absolute symlink (path_resolution(7), step 1). The kernel rewrites only the
// /proc/<pid>/root prefix, not the targets of symlinks found along the way. So
// a container that contains
//
//	/root/.ssh -> /etc
//
// turns a write to "/proc/<pid>/root/root/.ssh/authorized_keys" into a write
// to the NODE's /etc/authorized_keys. proxpass is root on the node, so an
// unprivileged user inside the container -- anyone who can create a symlink in
// a directory a transfer will touch -- can have the node write arbitrary files
// anywhere. That is a container escape, and it needs no race.
//
// Entering the mount namespace fixes it at the source: resolution starts from
// the container's root, so an absolute symlink cannot name anything outside.
// This is what `pct push' does for the same reason, and its comment says so.
//
// # Why the user namespace too
//
// An unprivileged container -- the Proxmox default -- maps container uid 0 to
// a high host uid, typically 100000. A file written as host root therefore
// appears inside as nobody:nogroup, unreadable at mode 0600 and impossible for
// the container's own root to chown. Entering the user namespace and dropping
// to uid 0 inside makes writes land as container root, which is what the user
// asked for.
package guestfs

import (
	"fmt"
	"strconv"
	"strings"
)

// Container identifies one LXC container on one Proxmox node.
type Container struct {
	// VMID is the Proxmox numeric id.
	VMID int
	// Unprivileged reports whether the container maps its root to a
	// different host uid, which decides whether we enter the user
	// namespace. Entering it for a PRIVILEGED container fails: the caller
	// is already a member, and setns refuses with EINVAL.
	Unprivileged bool
}

// shellQuote renders s as a single POSIX shell word.
//
// Every path in an SFTP request is chosen by the client, and each operation
// becomes a command line on the node, so quoting is the boundary that keeps a
// path from becoming code. Single quotes are used because the shell treats
// everything inside them literally, including $, `, \ and newline; the only
// character needing care is the single quote itself, which is closed, escaped
// and reopened.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// shellQuoteAll quotes each argument and joins them with spaces.
func shellQuoteAll(args ...string) string {
	out := make([]string, len(args))
	for i, a := range args {
		out[i] = shellQuote(a)
	}
	return strings.Join(out, " ")
}

// enterArgs returns the nsenter prefix for this container.
//
// The pieces, each load-bearing:
//
//	-t <pid>  the container's init process, whose namespaces we join
//	-m        its mount namespace, so paths resolve against its filesystem
//	-r        its ROOT directory. Without this, nsenter keeps the node's
//	          root and a container-absolute path such as /etc is read from
//	          the NODE -- the command appears to work and reads the wrong
//	          file. -m alone is not enough.
//	-w        its working directory, so a relative path cannot resolve
//	          against the node's cwd.
//	-U -S 0 -G 0  for an unprivileged container: join the user namespace
//	          and become its root, so writes are owned correctly.
//
// -r and -w are passed in their BARE form, which means "the target's". Their
// arguments are OPTIONAL (-r[=<dir>]), so a separated value is not parsed as
// one: `-w /' makes "/" the PROGRAM to execute and fails with
//
//	nsenter: failed to execute /: Permission denied
//
// An explicit directory would have to be written as -w=/ or --wd=/.
func enterArgs(pidVar string, unprivileged bool) string {
	args := []string{"nsenter", "-t", pidVar, "-m", "-r", "-w"}
	if unprivileged {
		args = append(args, "-U", "-S", "0", "-G", "0")
	}
	return strings.Join(args, " ")
}

// Command returns the shell command to run on the Proxmox node, which runs
// argv inside the container.
//
// The container's init pid is resolved and used within a SINGLE command, and
// re-checked afterwards. A pid can be reused between two SSH round trips, and
// acting on a reused pid would mean acting on an unrelated process's
// namespaces -- in the worst case the node's own. Proxmox guards the same race
// the same way in PVE::LXC::open_lxc_pid.
//
// `lxc-info -n <vmid> -p' is how Proxmox itself finds the pid
// (PVE::LXC::find_lxc_pid), and is used here rather than reading a pidfile
// because no pidfile exists: pve-container runs lxc-start without --pidfile.
func (c Container) Command(argv ...string) string {
	vmid := strconv.Itoa(c.VMID)
	pidOf := "lxc-info -n " + shellQuote(vmid) + " -p 2>/dev/null | " +
		`sed -n 's/^PID:[[:space:]]*\([0-9]\{1,\}\)$/\1/p'`

	var b strings.Builder
	b.WriteString("set -e; ")
	b.WriteString("pid=$(" + pidOf + "); ")
	// A container that is not running has no namespaces to enter. Report it
	// as such rather than letting nsenter fail with something about /proc.
	b.WriteString(`[ -n "$pid" ] || { echo "container ` + vmid +
		` is not running" >&2; exit 125; }; `)
	b.WriteString(enterArgs(`"$pid"`, c.Unprivileged) + " -- " + shellQuoteAll(argv...) + "; ")
	b.WriteString("rc=$?; ")
	// Re-check: if the pid changed under us, the namespaces we entered were
	// not necessarily this container's, so the result cannot be trusted.
	b.WriteString("pid2=$(" + pidOf + "); ")
	b.WriteString(`[ "$pid" = "$pid2" ] || { echo "container ` + vmid +
		` restarted during the operation" >&2; exit 125; }; `)
	b.WriteString("exit $rc")
	return b.String()
}

// ErrNotRunning is the exit status Command uses for "this container is not
// running" and for "it restarted underneath us".
//
// 125 is chosen because it is outside the range a transferred command is
// likely to return on its own: 1-124 are ordinary failures and 126/127 are the
// shell's own "not executable"/"not found".
const ErrNotRunning = 125

// WriteFileCmd returns a command that writes stdin to path inside the
// container, creating or truncating it.
//
// `cat > path' rather than a dedicated tool because it exists everywhere,
// including BusyBox, and because the redirection is what performs the create
// and the truncate. The path is quoted inside a shell command, so it cannot
// break out of the redirection target.
func (c Container) WriteFileCmd(path string) string {
	return c.Command("sh", "-c", "cat > "+shellQuote(path))
}

// ddBlock is the transfer block size for a ranged read or write.
//
// dd counts seek=, skip= and count= in BLOCKS, so reaching an arbitrary byte
// offset would ordinarily force bs=1 -- one syscall per byte, unusable over a
// network. iflag/oflag=skip_bytes,seek_bytes,count_bytes reinterpret those
// counts as BYTES while leaving the block size alone, which gives an exact
// offset at a sensible transfer size.
//
// Verified present in both GNU coreutils dd and BusyBox dd, so this does not
// cost the BusyBox compatibility the rest of this file preserves.
const ddBlock = 65536

// AppendFileCmd returns a command that writes stdin to path at a byte offset,
// which is how SFTP writes a file that does not arrive in one pass.
//
// conv=notrunc keeps what an earlier chunk wrote; without it each chunk would
// discard the file and only the last would survive. oflag=seek_bytes makes
// seek= a byte count rather than a block count, so an offset that is not a
// multiple of the block size still lands exactly.
func (c Container) AppendFileCmd(path string, offset int64) string {
	return c.Command("sh", "-c", fmt.Sprintf(
		"dd of=%s bs=%d seek=%d oflag=seek_bytes conv=notrunc status=none",
		shellQuote(path), ddBlock, offset))
}

// ReadFileCmd returns a command that writes path's contents to stdout.
func (c Container) ReadFileCmd(path string) string {
	return c.Command("cat", path)
}

// ReadRangeCmd returns a command that writes length bytes of path starting at
// offset to stdout, which is how SFTP reads a large file.
//
// iflag=skip_bytes,count_bytes make both counts byte-exact at the full block
// size, so neither the seek nor the length forces a bs=1 read.
func (c Container) ReadRangeCmd(path string, offset, length int64) string {
	return c.Command("sh", "-c", fmt.Sprintf(
		"dd if=%s bs=%d skip=%d count=%d iflag=skip_bytes,count_bytes status=none",
		shellQuote(path), ddBlock, offset, length))
}

// StatCmd returns a command that prints one line of attributes for each path.
//
// The format is chosen to be parseable without ambiguity:
//
//	<mode-octal> <size> <uid> <gid> <mtime-epoch> <name>
//
// The name is LAST because it is the only field that may contain a space.
// %f is the raw mode in hex -- including the file-type bits, which is how the
// caller tells a directory from a file -- and is supported by both GNU
// coreutils and BusyBox stat.
func (c Container) StatCmd(paths ...string) string {
	argv := append([]string{"stat", "-c", "%f %s %u %g %Y %n"}, paths...)
	return c.Command(argv...)
}

// ListCmd returns a command that prints one attribute line per entry in dir.
//
// Implemented as a stat over a glob rather than `find -printf' because
// BusyBox find -- what Alpine ships, and Alpine is a common container
// template -- does not support -printf. The shell expands the globs, so the
// entry names never pass through this process.
//
// Two globs are needed to include dotfiles, and the "." and ".." entries are
// excluded: SFTP clients supply them and a directory listing that repeats
// them confuses some of them.
func (c Container) ListCmd(dir string) string {
	q := shellQuote(strings.TrimSuffix(dir, "/"))
	return c.Command("sh", "-c",
		"cd "+q+" && "+
			`for e in * .[!.]* ..?*; do `+
			`[ -e "$e" ] || [ -L "$e" ] || continue; `+
			`stat -c '%f %s %u %g %Y %n' -- "$e"; `+
			"done")
}
