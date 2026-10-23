// Command nodescphelper serves one node file transfer on stdin/stdout.
//
// It exists so a test can drive the REAL scp client against the node
// transfer path. scp's -D flag points it at a program that speaks SFTP on
// stdio, which is exactly the shape sshd hands `proxpass session' for a
// subsystem request -- so this exercises the whole pump with an unmodified
// client, no sshd and no network.
//
// It is a test fixture and is never shipped: the ordinary path is
// `proxpass session' with SSH_ORIGINAL_COMMAND set.
package main

import (
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strconv"

	"proxpass/internal/console"
	"proxpass/internal/models"
)

func main() {
	// All the work is in run so the defers below it actually run: os.Exit
	// skips them, which would leak the SSH session on every error path.
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	// The 5th argument is the node's SSH host-key fingerprint (SHA256:...).
	// It is required because DialNode now verifies the host key, and a test
	// host publishes no SSHFP: the fixture pins the mock server's fingerprint.
	if len(args) != 5 {
		return errors.New("usage: nodescphelper <host> <port> <user> <keyfile> <ssh-fingerprint>")
	}
	port, err := strconv.Atoi(args[1])
	if err != nil {
		return fmt.Errorf("bad port: %w", err)
	}
	key, err := readKey(args[3])
	if err != nil {
		return err
	}

	logger := log.New(io.Discard, "", 0)
	runner, err := console.DialNode(nodeInstance(args[0], port, args[2], args[4]), key, logger)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer func() { _ = runner.Close() }()

	remote, err := runner.Subsystem("sftp", nil)
	if err != nil {
		return fmt.Errorf("subsystem: %w", err)
	}
	defer func() { _ = remote.Close() }()

	// The same two-way pump the session runs, ended by whichever side
	// finishes first.
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(remote, os.Stdin); done <- struct{}{} }()
	go func() { _, _ = io.Copy(os.Stdout, remote); done <- struct{}{} }()
	<-done
	return nil
}

// readKey reads the private key the test generated.
//
// The path comes from the test's own argv, not from anything untrusted, so
// it is opened as given -- there is no sandbox here to traverse out of.
func readKey(path string) (string, error) {
	b, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return "", fmt.Errorf("reading key: %w", err)
	}
	return string(b), nil
}

// nodeInstance builds the minimal instance DialNode needs, including the
// pinned host-key fingerprint so verification succeeds against the test host.
func nodeInstance(host string, port int, user, fingerprint string) *models.ProxmoxInstance {
	return &models.ProxmoxInstance{
		Name: "test-node", Node: "test-node",
		SSHHost: host, SSHPort: port, SSHUser: user,
		SSHFingerprints: []string{fingerprint},
	}
}
