package session

import (
	"context"
	"io"
	"strings"

	"proxpass/internal/console"
	"proxpass/internal/guestfs"
	"proxpass/internal/guesthelper"
	"proxpass/internal/models"
	"proxpass/internal/sftpserver"
)

// sftpSubsystem is the command sshd hands a ForceCommand when the client asks
// for the sftp subsystem.
//
// sshd replaces a subsystem request with ForceCommand and puts the configured
// subsystem path in SSH_ORIGINAL_COMMAND, so this is how a transfer announces
// itself. The value is whatever the main sshd_config declares -- Debian ships
// /usr/lib/openssh/sftp-server -- so the test is on the basename rather than
// the whole path.
const sftpSubsystem = "sftp-server"

// isSFTPRequest reports whether cmd is sshd asking for a file transfer.
//
// Matching on the basename covers every distribution's path, and also the
// "internal-sftp" form, without the drop-in having to agree on one.
func isSFTPRequest(cmd string) bool {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return false
	}
	// The subsystem arrives as a bare path with no arguments.
	fields := strings.Fields(cmd)
	if len(fields) != 1 {
		return false
	}
	base := fields[0]
	if i := strings.LastIndex(base, "/"); i >= 0 {
		base = base[i+1:]
	}
	return base == sftpSubsystem || base == "internal-sftp"
}

// runSFTP serves a file transfer for the guest named by the login name.
//
// # Why the login name
//
// A subsystem request carries no arguments, so there is nowhere to put a
// guest identifier: "sftp alice@host ct100" is not a thing a client can send.
// The login name is the only channel, which makes
//
//	scp file.txt ct100@host:/tmp/
//
// the natural syntax -- and it is the same resolution the console already
// uses for "ssh ct100@host", scoped to the guests this session may reach. The
// identity still comes from the KEY, so naming a guest grants nothing.
//
// # Errors
//
// sshd sets CHAN_EXTENDED_IGNORE for a subsystem session, so anything written
// to stderr is DISCARDED: a client shows "Connection closed" and no reason.
// Errors before the protocol starts are therefore logged here, where an
// administrator can see them, and the client is left to report the close. Once
// the protocol is running, failures travel as SFTP status packets instead.
func (d *Deps) runSFTP(ctx context.Context) int {
	name := strings.TrimSpace(d.LoginName)
	if name == "" {
		d.Logger.Printf("%s: sftp without a guest name", d.IdentityName)
		return 1
	}

	// A reserved name means "browse", which a transfer cannot do: there is
	// no guest to transfer to.
	reserved, err := d.isReservedLoginName(ctx, name)
	if err != nil {
		d.Logger.Printf("%s: sftp: %v", d.IdentityName, err)
		return 1
	}
	if reserved {
		d.Logger.Printf("%s: sftp: %q names no guest", d.IdentityName, name)
		return 1
	}

	guest, err := d.resolveLoginNameGuest(ctx, name)
	if err != nil {
		d.Logger.Printf("%s: sftp: %v", d.IdentityName, err)
		return 1
	}

	// Asking for the connection IS the access check, exactly as the console
	// does, so a transfer cannot reach a guest a console could not.
	info, err := d.Dir.Connect(ctx, guest.ID)
	if err != nil {
		d.Logger.Printf("%s: sftp: connect %s: %v",
			d.IdentityName, guest.Name, err)
		return 1
	}
	return d.serveSFTP(info)
}

// serveSFTP opens the transport to the Proxmox node and serves the protocol.
func (d *Deps) serveSFTP(info *ConnectInfo) int {
	guest, inst := info.Guest, info.Instance

	// Only containers. A VM has no namespace to enter: reaching its disk
	// means the guest agent, whose write endpoint truncates at 60 KiB and
	// cannot append, so a transfer built on it would fail on any real file.
	if guest.Type != models.GuestTypeCT {
		d.Logger.Printf("%s: sftp: %s is a VM, which has no container filesystem",
			d.IdentityName, guest.Name)
		return 1
	}
	// Note there is NO check on the console transport. How a terminal is
	// attached says nothing about whether the node answers SSH, and gating
	// on it refused transfers for instances whose node is perfectly
	// reachable. What matters is the node address and the key, both checked
	// below by failing to connect.
	if inst.SSHHost == "" {
		d.Logger.Printf(
			"%s: sftp: instance %s has no ssh host configured",
			d.IdentityName, inst.Name)
		return 1
	}

	runner, err := console.DialNode(inst, info.SSHKey, d.Logger)
	if err != nil {
		d.Logger.Printf("%s: sftp: %v", d.IdentityName, err)
		return 1
	}
	defer func() { _ = runner.Close() }()

	d.Logger.Printf("%s: sftp to %s (%s%d) on %s",
		d.IdentityName, guest.Name, guest.Type, guest.ProxmoxID, inst.Name)

	// Assume unprivileged, which is the Proxmox default and the safe
	// assumption: entering the user namespace when the container is
	// privileged would fail, so this is checked at run time by the command
	// itself rather than guessed here.
	const unprivileged = true

	backend, closeBackend := d.openBackend(runner, guest.ProxmoxID, unprivileged)
	defer closeBackend()

	// The SFTP protocol runs over this session's stdin/stdout, which is
	// what sshd connected to the client's channel. Terminal carries them;
	// no PTY was allocated for a subsystem request, which is exactly what
	// a binary transfer needs.
	if err := sftpserver.Serve(sessionStream(d.Terminal), backend); err != nil {
		d.Logger.Printf("%s: sftp: %v", d.IdentityName, err)
		return 1
	}
	return 0
}

// sessionStream adapts the session's terminal streams to the
// io.ReadWriteCloser the SFTP server wants.
//
// Closing is a no-op: stdin and stdout belong to sshd, and closing them here
// would tear down the channel underneath the protocol's own shutdown.
type stream struct {
	io.Reader
	io.Writer
}

func (stream) Close() error { return nil }

func sessionStream(t *console.Terminal) io.ReadWriteCloser {
	return stream{Reader: t.In, Writer: t.Out}
}

// openBackend picks how this session reaches the container's filesystem.
//
// The helper is tried first: it costs one SSH session for the whole
// transfer rather than one per operation, and it works in a container that
// ships no shell. When it cannot be used -- an architecture proxpass is not
// built for, a node that will not run it -- the shell path still can, so the
// failure is logged and the transfer proceeds rather than being refused.
//
// Anything that is NOT a support problem is also handled by falling back,
// because at this point no bytes have moved: Start fails before the first
// request, so there is nothing a second attempt could duplicate.
func (d *Deps) openBackend(runner *console.NodeRunner, vmid int, unprivileged bool) (backend sftpserver.FS, cleanup func()) {
	sess, err := guesthelper.Start(nodeAdapter{runner}, vmid, unprivileged, d.Logger)
	if err == nil {
		d.Logger.Printf("%s: sftp: using the guest helper", d.IdentityName)
		return sess, func() { _ = sess.Close() }
	}

	// Worth a line in the log either way: a deployment that silently never
	// uses the helper would otherwise look like one that does.
	if guesthelper.IsUnsupported(err) {
		d.Logger.Printf("%s: sftp: helper unavailable, using shell commands: %v",
			d.IdentityName, err)
	} else {
		d.Logger.Printf("%s: sftp: helper failed to start, using shell commands: %v",
			d.IdentityName, err)
	}
	return &guestfs.FS{
		Container: guestfs.Container{VMID: vmid, Unprivileged: unprivileged},
		Runner:    runner,
	}, func() {}
}

// nodeAdapter lets a console.NodeRunner satisfy guesthelper.Node.
//
// The adapter exists because Stream returns a concrete *console.Stream while
// the interface wants its own Stream type; Go does not convert a return type
// for us. It is three lines, and it keeps guesthelper free of a dependency
// on console.
type nodeAdapter struct{ *console.NodeRunner }

func (a nodeAdapter) Stream(cmd string, stderr io.Writer) (guesthelper.Stream, error) {
	s, err := a.NodeRunner.Stream(cmd, stderr)
	if err != nil {
		return nil, err
	}
	return s, nil
}
