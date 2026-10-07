package cli

import (
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"proxpass/internal/models"
)

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

// sshCheckTimeout bounds the reachability check.
//
// Short on purpose: this runs inside `instance add', which an administrator
// is watching, and the answer is almost always immediate. An unreachable
// host is reported as a warning rather than a failure, so erring towards a
// quick "no" costs nothing.
const sshCheckTimeout = 10 * time.Second

// checkSSHAccess reports whether proxpass can open an SSH session on the
// instance's host with keyPEM.
//
// The key is passed in rather than read from inst because an instance added
// after proxpass owned a key carries none of its own: the key it will
// actually connect with is the deployment-wide one.
//
// It authenticates and opens a session rather than only completing the
// handshake: a key can be accepted while the account is still unable to run
// anything (a forced command, a disabled shell), and `pct enter' would then
// fail at the first console connection instead of here.
//
// The host key is deliberately NOT verified, which matches how the console
// connects today. Proxmox publishes no SSH host key or fingerprint over its
// API -- every `fingerprint' field it exposes is a TLS certificate -- so
// there is nothing to check it against yet. Changing that needs its own
// change: pin the host key on first contact and store it per instance.
func checkSSHAccess(ctx context.Context, inst *models.ProxmoxInstance, keyPEM string) error {
	signer, err := gossh.ParsePrivateKey([]byte(keyPEM))
	if err != nil {
		return fmt.Errorf("parsing the proxpass key: %w", err)
	}

	addr := net.JoinHostPort(inst.SSHHost, strconv.Itoa(inst.SSHPort))
	dialer := net.Dialer{Timeout: sshCheckTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("connecting to %s: %w", addr, err)
	}
	defer func() { _ = conn.Close() }()

	// The deadline covers the handshake, which DialContext does not.
	if err := conn.SetDeadline(time.Now().Add(sshCheckTimeout)); err != nil {
		return fmt.Errorf("setting deadline: %w", err)
	}

	clientConn, chans, reqs, err := gossh.NewClientConn(conn, addr, &gossh.ClientConfig{
		User:            inst.SSHUser,
		Auth:            []gossh.AuthMethod{gossh.PublicKeys(signer)},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(), //nolint:gosec // see the doc comment: Proxmox publishes no SSH host key to check against.
		Timeout:         sshCheckTimeout,
	})
	if err != nil {
		return fmt.Errorf("authenticating as %s: %w", inst.SSHUser, err)
	}
	client := gossh.NewClient(clientConn, chans, reqs)
	defer func() { _ = client.Close() }()

	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("opening a session: %w", err)
	}
	defer func() { _ = session.Close() }()

	// Clear the deadline: the connection is healthy and the remaining calls
	// have their own bounds. Leaving it set would expire mid-session.
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return fmt.Errorf("clearing deadline: %w", err)
	}
	return nil
}

// reportSSHKey prints which key an instance uses and whether it currently
// opens the host.
//
// The reachability check is re-run here rather than cached from `instance
// add', because the answer changes the moment the administrator installs the
// public key -- and this is how they confirm that it landed.
func reportSSHKey(ctx context.Context, deps *Deps, inst *models.ProxmoxInstance) {
	key := inst.SSHKey
	source := "instance (set before proxpass owned a key)"

	switch {
	case key != "":
		// Keep the instance's own key: see instanceCredentials.
	case inst.SSHKeyPath != "":
		b, err := os.ReadFile(inst.SSHKeyPath)
		if err != nil {
			fmt.Fprintf(deps.Out, "SSH Key:          unreadable at %s: %v\n",
				inst.SSHKeyPath, err)
			return
		}
		key, source = string(b), "instance path "+inst.SSHKeyPath
	default:
		deployed, err := models.ReadSSHKey()
		if err != nil {
			fmt.Fprintf(deps.Out, "SSH Key:          %v\n", err)
			return
		}
		if deployed == "" {
			fmt.Fprintf(deps.Out, "SSH Key:          none at %s\n", models.SSHKeyPath())
			return
		}
		key, source = deployed, models.SSHKeyPath()
	}

	fmt.Fprintf(deps.Out, "SSH Key:          %s\n", source)
	if pub, err := publicKeyLine(key); err == nil {
		fmt.Fprintf(deps.Out, "SSH Public Key:   %s", pub)
	}

	if err := checkSSHAccess(ctx, inst, key); err != nil {
		fmt.Fprintf(deps.Out, "SSH Access:       UNAVAILABLE: %v\n", err)
		fmt.Fprintf(deps.Out, "                  install the public key above in %s on %s\n",
			authorizedKeysPath, inst.SSHHost)
		return
	}
	fmt.Fprintf(deps.Out, "SSH Access:       ok\n")
}

// publicKeyLine returns the authorized_keys line for a PEM private key, which
// is what the administrator has to install on the Proxmox host.
func publicKeyLine(pemKey string) (string, error) {
	signer, err := gossh.ParsePrivateKey([]byte(pemKey))
	if err != nil {
		return "", fmt.Errorf("parsing the proxpass key: %w", err)
	}
	return string(gossh.MarshalAuthorizedKey(signer.PublicKey())), nil
}
