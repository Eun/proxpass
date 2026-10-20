package cli

import (
	"context"
	"fmt"

	"proxpass/internal/models"
)

// SSHKeyService resolves the deployment's SSH key material on behalf of the
// admin CLI.
//
// The CLI runs inside a non-root session (sshd starts it as the logged-in
// user), and the proxpass key is a root-owned 0600 file. The session cannot
// read it -- that is the whole point of locking it to root -- so it must not
// open the file itself. Instead it asks `proxpass serve', which runs as root,
// through this service. Only the PUBLIC half and a yes/no reachability answer
// come back; the private key never reaches the session.
//
// Implemented by session.AdminRepository over the loopback admin API.
type SSHKeyService interface {
	// SSHPublicKey returns the authorized_keys line for the deployment key,
	// the path it lives at (for messages), or an empty key when the
	// deployment has none (a termproxy-only setup).
	SSHPublicKey(ctx context.Context) (pub, path string, err error)
	// CheckInstanceSSHAccess reports whether the deployment key opens a
	// session on the instance's host. A nil error means reachable; a non-nil
	// error is the reason it is not, suitable for printing.
	CheckInstanceSSHAccess(ctx context.Context, inst *models.ProxmoxInstance) error
}

// authorizedKeysPath is where the administrator installs proxpass's public
// key on a Proxmox node.
//
// On a clustered node this is a symlink into /etc/pve/priv/authorized_keys,
// which pmxcfs replicates to every member, so installing the key once per
// CLUSTER covers all of its nodes. A standalone node has a real file and
// needs its own copy. Proxmox's own key merging only ever appends and
// de-duplicates, so a key added here is not removed by `pvecm updatecerts'
// or by a node join.
const authorizedKeysPath = "~/.ssh/authorized_keys"

// reportSSHKey prints which key an instance uses and whether it currently
// opens the host.
//
// The reachability check is re-run here rather than cached from `instance
// add', because the answer changes the moment the administrator installs the
// public key -- and this is how they confirm that it landed.
//
// Both the public key and the reachability check come from `proxpass serve'
// (root): the session cannot read the private key the check needs.
func reportSSHKey(ctx context.Context, deps *Deps, inst *models.ProxmoxInstance) {
	pub, path, err := deps.SSHKeys.SSHPublicKey(ctx)
	if err != nil {
		fmt.Fprintf(deps.Out, "SSH Key:          %v\n", err)
		return
	}
	if pub == "" {
		fmt.Fprintf(deps.Out, "SSH Key:          none at %s\n", path)
		return
	}

	fmt.Fprintf(deps.Out, "SSH Key:          %s\n", path)
	fmt.Fprintf(deps.Out, "SSH Public Key:   %s", pub)

	if err := deps.SSHKeys.CheckInstanceSSHAccess(ctx, inst); err != nil {
		fmt.Fprintf(deps.Out, "SSH Access:       UNAVAILABLE: %v\n", err)
		fmt.Fprintf(deps.Out, "                  install the public key above in %s on %s\n",
			authorizedKeysPath, inst.SSHHost)
		return
	}
	fmt.Fprintf(deps.Out, "SSH Access:       ok\n")
}

// warnMissingSSHHost prints a warning, to ErrOut, when an instance has no SSH
// host. Such an instance is valid -- its termproxy console works -- but node
// shell, SFTP and file transfer all reach the node over SSH and so are
// unavailable until a host is set. The warning also shows the public key the
// administrator has to install, because a host without the key is as unusable
// as no host at all, and this is the moment they learn they need both.
//
// It is a no-op when SSHHost is set, so callers can invoke it unconditionally.
func warnMissingSSHHost(ctx context.Context, deps *Deps, inst *models.ProxmoxInstance) {
	if inst.SSHHost != "" {
		return
	}

	fmt.Fprintf(deps.ErrOut,
		"Warning: instance %q has no SSH host, so node shell, SFTP and file "+
			"transfer are unavailable (the %s console still works).\n"+
			"Set one with: instance update --name %s --ssh-host <host>\n",
		inst.Name, inst.ConsoleTransport, inst.Name)

	// Show the key the administrator must install on the node, so they can do
	// it in the same step as setting the host.
	pub, _, err := deps.SSHKeys.SSHPublicKey(ctx)
	if err != nil || pub == "" {
		return
	}
	fmt.Fprintf(deps.ErrOut,
		"Then add proxpass's public key to %s on the node:\n%s",
		authorizedKeysPath, pub)
}
