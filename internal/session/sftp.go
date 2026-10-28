package session

import (
	"context"
	"errors"
	"io"
	"strings"

	"proxpass/internal/console"
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

// runSFTP serves a file transfer for the guest or node named by the login
// name.
//
// # Why the login name
//
// A subsystem request carries no arguments, so there is nowhere to put a
// target identifier: "sftp alice@host ct100" is not a thing a client can send.
// The login name is the only channel, which makes
//
//	scp file.txt ct100@host:/tmp/
//
// the natural syntax -- and it is the same resolution the console already
// uses for "ssh ct100@host", scoped to what this session may reach. The
// identity still comes from the KEY, so naming a target grants nothing.
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
	// nothing to transfer to.
	if isReservedLoginName(name) {
		d.Logger.Printf("%s: sftp: %q names no target", d.IdentityName, name)
		return 1
	}

	// A node, before a guest, in the same order `ssh' and `ssh ... <cmd>'
	// use -- so `scp f rome@host:' and `ssh rome@host' reach the same
	// place. A node that shares its name with a guest wins here too, and
	// the guest stays reachable as <guest>@<instance>.
	if inst, ok := d.namesANode(ctx, name); ok {
		return d.serveNodeSFTP(ctx, inst)
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
	// Record WHERE: an SFTP transfer into info.Guest on host info.Instance.
	d.reportSFTP(ctx, info.Instance.Name, info.Guest.Name)
	return d.serveSFTP(info)
}

// serveNodeSFTP pumps a file transfer to and from the Proxmox node itself.
//
// Quite unlike the guest path below, and much shorter. A node runs its own
// sftp-server, so there is nothing to stage and nothing to enter: proxpass
// asks the node's sshd for the subsystem and copies bytes between it and
// the client. The whole guesthelper and sftpserver stack is bypassed --
// it exists because a container has no server to ask, which is not a
// problem a node has.
//
// `scp' needs no separate handling. Since OpenSSH 9.0 it speaks SFTP by
// default, so serving the subsystem serves both commands.
func (d *Deps) serveNodeSFTP(ctx context.Context, inst *models.ProxmoxInstance) int {
	// Asking for the credentials IS the access check, exactly as the
	// console does, so a transfer cannot reach a node a shell could not.
	info, err := d.Dir.ConnectNode(ctx, inst.ID)
	if err != nil {
		d.Logger.Printf("%s: sftp: connect node %s: %v",
			d.IdentityName, inst.Name, err)
		return 1
	}

	runner, err := console.DialNode(info.Instance, info.SSHKey, d.Logger)
	if err != nil {
		d.Logger.Printf("%s: sftp: %v", d.IdentityName, err)
		return 1
	}
	defer func() { _ = runner.Close() }()

	d.Logger.Printf("%s: sftp to node %s", d.IdentityName, info.Instance.Name)
	// Record WHERE: an SFTP transfer to the node itself (host, no guest).
	d.reportSFTP(ctx, info.Instance.Name, "")

	// The node's stderr is discarded rather than forwarded. sshd sets
	// CHAN_EXTENDED_IGNORE for a subsystem session, so the client would
	// never see it, and a real sftp-server reports its failures as SFTP
	// status packets on the channel itself -- which the pump below
	// carries through unchanged.
	remote, err := runner.Subsystem(nodeSFTPSubsystem, nil)
	if err != nil {
		d.Logger.Printf("%s: sftp: %v", d.IdentityName, err)
		return 1
	}
	defer func() { _ = remote.Close() }()

	return d.pumpSFTP(remote)
}

// nodeSFTPSubsystem is the subsystem name every sshd registers for SFTP.
//
// Not the path in SSH_ORIGINAL_COMMAND: that is what OUR sshd was asked
// for, and the node's own path may differ. Asking by name lets the node
// resolve it.
const nodeSFTPSubsystem = "sftp"

// pumpSFTP copies between the client and the node until either end stops.
//
// Both directions run, and the first one to finish ends the transfer. A
// client that has sent its last request closes the channel, which is the
// ordinary end of a transfer; a node whose sftp-server exits ends it the
// other way. Waiting for both would hang on whichever side is still
// waiting to be read.
func (d *Deps) pumpSFTP(remote io.ReadWriter) int {
	done := make(chan error, 2)
	go func() {
		_, err := io.Copy(remote, d.Terminal.In)
		done <- err
	}()
	go func() {
		_, err := io.Copy(d.Terminal.Out, remote)
		done <- err
	}()

	if err := <-done; err != nil && !errors.Is(err, io.EOF) {
		d.Logger.Printf("%s: sftp: %v", d.IdentityName, err)
		return 1
	}
	return 0
}

// serveSFTP serves a transfer for one GUEST, through the node hosting it.
//
// Unlike the node path above, this stages a helper inside the container and
// serves proxpass's own SFTP implementation against it, because a container
// has no sftp-server to ask for.
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

	// Assume unprivileged, the Proxmox default: entering the user
	// namespace of a privileged container fails, and that is reported by
	// the command itself at run time rather than guessed here.
	const unprivileged = true

	sess, err := guesthelper.Start(nodeAdapter{runner}, guest.ProxmoxID, unprivileged, d.Logger)
	if err != nil {
		d.Logger.Printf("%s: sftp: %v", d.IdentityName, err)
		return 1
	}
	defer func() { _ = sess.Close() }()

	// The SFTP protocol runs over this session's stdin/stdout, which is
	// what sshd connected to the client's channel. Terminal carries them;
	// no PTY was allocated for a subsystem request, which is exactly what
	// a binary transfer needs.
	if err := sftpserver.Serve(sessionStream(d.Terminal), sess); err != nil {
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
