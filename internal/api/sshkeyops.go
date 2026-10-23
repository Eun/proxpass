package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"proxpass/internal/models"
	"proxpass/internal/sshhostkey"
)

// The SSH key file surface.
//
// These two admin operations exist because the proxpass SSH key lives in a
// root-owned 0600 file, and an admin session is NOT root (see
// models.sshkey.go). The CLI used to open that file itself -- in the session
// process -- which failed with "permission denied" the moment the key was
// locked down to root. `proxpass serve' runs as root, so these operations
// read the key here, on the caller's behalf, and return only what the CLI
// actually needs: the PUBLIC half to print, and a yes/no reachability answer.
// The private key never leaves this process.
//
// They are NOT db.Repository methods, which is why they stayed on the slim
// /admin/rpc endpoint instead of becoming typed /v1 resources like the
// repository-backed admin ops (see adminhandlers.go): the key is a file, not a
// row, and storing it in the database is exactly what the design avoids.

// sshPublicKeyResult is the authorized_keys line for the deployment key, or an
// empty Key when the deployment has no key at all (a termproxy-only setup).
type sshPublicKeyResult struct {
	Key  string `json:"key"`
	Path string `json:"path"`
}

// getSSHPublicKey reads the deployment key as root and returns its public half.
//
// A missing key is not an error: ReadSSHKey already treats an absent file as
// "no key", and the CLI decides what to say about that. The private key is
// never returned -- only the authorized_keys line the administrator installs.
func getSSHPublicKey(context.Context, json.RawMessage) (json.RawMessage, error) {
	pem, err := models.ReadSSHKey()
	if err != nil {
		return nil, err
	}
	out := sshPublicKeyResult{Path: models.SSHKeyPath()}
	if pem != "" {
		pub, err := publicKeyLine(pem)
		if err != nil {
			return nil, err
		}
		out.Key = pub
	}
	return encodeResult(out)
}

// sshAccessResult reports whether the deployment key opens a session on an
// instance's host. Err carries the reason when it does not, so the CLI can
// print the same diagnostic it printed when it dialed the host itself.
//
// NoFingerprint is set, instead of Err, for the one failure the CLI treats as
// FATAL rather than a warning: the host key could not be verified because the
// instance has no pinned fingerprint and the host publishes no DNSSEC-validated
// SSHFP record. It is carried as structured data so the session can rebuild a
// *sshhostkey.ErrNoFingerprint on the far side and errors.As keeps working
// across the loopback API -- the private key, and the dial, stay here in root.
type sshAccessResult struct {
	OK            bool               `json:"ok"`
	Err           string             `json:"err,omitempty"`
	NoFingerprint *noFingerprintData `json:"no_fingerprint,omitempty"`
}

// noFingerprintData mirrors the fields of sshhostkey.ErrNoFingerprint so the
// CLI can reconstruct that typed error from the JSON response.
type noFingerprintData struct {
	Host        string `json:"host"`
	Fingerprint string `json:"fingerprint"`
}

// checkInstanceSSHAccess dials the instance's host with the deployment key, as
// root, and reports whether a session opens.
//
// It runs here rather than in the session because only root can read the
// private key the dial needs. The check itself matches what the CLI used to do
// in-process (see cli.checkSSHAccess before it moved here): authenticate and
// open a session, with the host key verified against the instance's pinned
// fingerprint or DNSSEC-validated SSHFP records (see internal/sshhostkey).
func checkInstanceSSHAccess(ctx context.Context, p json.RawMessage) (json.RawMessage, error) {
	var args struct {
		Instance *models.ProxmoxInstance `json:"instance"`
	}
	if err := decodeParams(p, &args); err != nil {
		return nil, err
	}
	if args.Instance == nil {
		return nil, fmt.Errorf("checking ssh access: no instance given")
	}

	pem, err := models.ReadSSHKey()
	if err != nil {
		return nil, err
	}
	if pem == "" {
		return nil, fmt.Errorf(
			"no ssh key at %s: the container entrypoint generates one at "+
				"startup, so this deployment is either running an older image "+
				"or has had the file removed", models.SSHKeyPath())
	}

	out := sshAccessResult{OK: true}
	if err := dialSSHSession(ctx, args.Instance, pem); err != nil {
		out.OK = false
		out.Err = err.Error()
		// Preserve the fatal/warning distinction: an unverifiable host key is
		// carried structured so the CLI can rebuild the typed error and refuse
		// the add, rather than treating it as a "not installed yet" warning.
		var noFP *sshhostkey.ErrNoFingerprint
		if errors.As(err, &noFP) {
			out.NoFingerprint = &noFingerprintData{
				Host:        noFP.Host,
				Fingerprint: noFP.Fingerprint,
			}
		}
	}
	return encodeResult(out)
}

// sshCheckTimeout bounds the reachability dial.
//
// Short on purpose: this runs inside an `instance add'/`instance update' an
// administrator is watching, and the answer is almost always immediate. An
// unreachable host is reported as a warning rather than a failure.
const sshCheckTimeout = 10 * time.Second

// dialSSHSession authenticates with keyPEM and opens a session on the
// instance's host. It is the server-side twin of cli.checkSSHAccess: it opens
// a session rather than only completing the handshake, because a key can be
// accepted while the account still cannot run anything (a forced command, a
// disabled shell), and that should be reported here rather than at the first
// console connection.
//
// The host key is verified exactly as every other SSH path verifies it: via
// sshhostkey.Callback against the instance's pinned fingerprint if it has one,
// else DNSSEC-validated SSHFP records, unless the instance opts out with
// --insecure-ssh. An unverifiable host key surfaces as *sshhostkey.ErrNoFingerprint,
// which the caller turns into a fatal, actionable error.
func dialSSHSession(ctx context.Context, inst *models.ProxmoxInstance, keyPEM string) error {
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

	if err := conn.SetDeadline(time.Now().Add(sshCheckTimeout)); err != nil {
		return fmt.Errorf("setting deadline: %w", err)
	}

	clientConn, chans, reqs, err := gossh.NewClientConn(conn, addr, &gossh.ClientConfig{
		User:            inst.SSHUser,
		Auth:            []gossh.AuthMethod{gossh.PublicKeys(signer)},
		HostKeyCallback: sshhostkey.Callback(inst.SSHHost, inst.SSHFingerprints, inst.InsecureSSH),
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
	return nil
}

// publicKeyLine returns the authorized_keys line for a PEM private key, which
// is what the administrator has to install on the Proxmox host. Only the
// public half is derived; the private key is not returned.
func publicKeyLine(pemKey string) (string, error) {
	signer, err := gossh.ParsePrivateKey([]byte(pemKey))
	if err != nil {
		return "", fmt.Errorf("parsing the proxpass key: %w", err)
	}
	return string(gossh.MarshalAuthorizedKey(signer.PublicKey())), nil
}
