package guestfs

import "strings"

// ExecCmd returns the command to run argv inside the container, as a shell
// there would see it.
//
// # Why lxc-attach rather than the nsenter used for file operations
//
// The file operations in this package enter only the mount and user
// namespaces, because that is all a path needs to mean the right thing. A
// COMMAND is different: it should see the container as its own processes do.
//
// nsenter can join the remaining namespaces, but it stops there. lxc-attach
// additionally applies the container's cgroup, its LSM (AppArmor/SELinux)
// profile and its capability set. Without those a command runs outside the
// container's memory and CPU limits -- measurable as /proc/self/cgroup
// reading "0::/" under nsenter -- and with capabilities the container itself
// does not have. For a transfer that writes a file and exits, that is a
// theoretical difference; for `ssh ct100@host top' it is a process escaping
// its container's limits, which is not acceptable.
//
// # The terminal
//
// lxc-attach has NO flag to request or refuse a terminal. It decides by
// looking at its OWN stdin, stdout and stderr: if any of them is a tty it
// allocates one inside (lxc_attach.c, stdfd_is_pty), and otherwise it does
// not. So the decision is made by whether the SSH session carrying this
// command has a PTY, which is in turn decided by whether the client asked for
// one. That is exactly the behavior wanted -- the client's request is
// mirrored -- but it means the choice lives in the transport, not here. See
// console.NodeRunner.
//
// --clear-env is passed deliberately. The default is --keep-env, which would
// hand the container the environment of proxpass's own SSH session on the
// NODE: SSH_CONNECTION, SSH_CLIENT, and anything else the node's sshd set.
// None of it describes the container, and some of it describes proxpass's
// internals.
func (c Container) ExecCmd(argv ...string) string {
	attach := []string{
		"lxc-attach",
		"-n", shellQuote(itoa(c.VMID)),
		"--clear-env",
		"--",
	}
	return c.nodeCommand(strings.Join(attach, " ") + " " + shellQuoteAll(argv...))
}

// ShellCmd returns the command to open the container's login shell.
//
// `sh -lc' rather than a bare shell so the profile is read and PATH, HOME and
// the rest are what a login would give. Without -l a command runs with
// whatever minimal environment --clear-env left, and "command not found" for
// anything outside the default PATH.
func (c Container) ShellCmd(command string) string {
	if strings.TrimSpace(command) == "" {
		// No command: an interactive login shell.
		return c.ExecCmd("/bin/sh", "-l")
	}
	return c.ExecCmd("/bin/sh", "-lc", command)
}
