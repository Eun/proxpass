package console

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"sync"

	gossh "golang.org/x/crypto/ssh"

	"proxpass/internal/models"
)

// NodeRunner runs commands on a Proxmox node over SSH.
//
// One TCP connection is held open and each command gets its own SSH session,
// because a session carries exactly one command. That keeps the cost of a
// multi-command operation -- which an SFTP transfer always is -- to one
// handshake rather than one per request.
//
// It deliberately does NOT request a PTY. See Run.
type NodeRunner struct {
	mu     sync.Mutex
	client *gossh.Client
	logger *log.Logger
}

// DialNode opens an SSH connection to the instance's Proxmox host.
//
// The host key is not verified, matching the console path. Proxmox publishes
// no SSH host key or fingerprint through its API -- every `fingerprint' field
// it exposes belongs to a TLS certificate -- so there is nothing to check
// against yet. Fixing that is its own change: pin on first contact and store
// the key per instance.
func DialNode(inst *models.ProxmoxInstance, sshKey string, logger *log.Logger) (*NodeRunner, error) {
	signer, err := gossh.ParsePrivateKey([]byte(sshKey))
	if err != nil {
		return nil, fmt.Errorf("parsing proxmox key: %w", err)
	}
	addr := net.JoinHostPort(inst.SSHHost, strconv.Itoa(inst.SSHPort))
	client, err := gossh.Dial("tcp", addr, &gossh.ClientConfig{
		User:            inst.SSHUser,
		Auth:            []gossh.AuthMethod{gossh.PublicKeys(signer)},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(), //nolint:gosec // see the doc comment.
	})
	if err != nil {
		return nil, fmt.Errorf("dialing proxmox %s: %w", addr, err)
	}
	return &NodeRunner{client: client, logger: logger}, nil
}

// Close drops the connection to the node.
func (r *NodeRunner) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.client == nil {
		return nil
	}
	err := r.client.Close()
	r.client = nil
	return err
}

// Run executes one command on the node and returns its exit status.
//
// No PTY is requested, and that is a correctness requirement rather than a
// preference. nsenter reaches lxc-attach, which turns on terminal handling
// when ANY of stdin, stdout or stderr is a terminal; the line discipline then
// rewrites "\n" as "\r\n", so every file containing a newline byte would
// arrive corrupted. The console path requests a PTY on purpose -- `pct enter'
// needs one -- which is exactly why transfers cannot share it.
//
// A non-zero exit is returned as a status, not an error: the commands here
// use the exit code to say "no such file", and the caller turns that into an
// SFTP status packet.
func (r *NodeRunner) Run(cmd string, stdin io.Reader, stdout io.Writer) (exitCode int, stderrOut string, err error) {
	r.mu.Lock()
	client := r.client
	r.mu.Unlock()
	if client == nil {
		return 0, "", errors.New("connection to the proxmox host is closed")
	}

	session, sessErr := client.NewSession()
	if sessErr != nil {
		return 0, "", fmt.Errorf("opening remote session: %w", sessErr)
	}
	defer func() { _ = session.Close() }()

	var stderr bytes.Buffer
	session.Stderr = &stderr
	if stdout != nil {
		session.Stdout = stdout
	}
	if stdin != nil {
		session.Stdin = stdin
	}

	runErr := session.Run(cmd)
	if runErr == nil {
		return 0, stderr.String(), nil
	}
	var exitErr *gossh.ExitError
	if errors.As(runErr, &exitErr) {
		return exitErr.ExitStatus(), stderr.String(), nil
	}
	// A signal or a transport failure, neither of which is an exit status
	// the caller can interpret.
	return 0, stderr.String(), fmt.Errorf("running remote command: %w", runErr)
}
