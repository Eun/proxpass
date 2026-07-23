package ssh_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	proxssh "proxpass/internal/ssh"
	"proxpass/internal/testenv"

	gossh "golang.org/x/crypto/ssh"
)

// waitForSSH retries a TCP dial until the server accepts connections
// or the deadline passes. It does not authenticate — just checks reachability.
func waitForSSH(addr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	dialer := &net.Dialer{Timeout: 500 * time.Millisecond}
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		conn, err := dialer.DialContext(ctx, "tcp", addr)
		cancel()
		if err == nil {
			conn.Close()
			return nil
		}
		time.Sleep(10 * time.Millisecond)
	}
	return fmt.Errorf("server at %s did not become ready within %s", addr, timeout)
}

// setupAdminTest starts a proxpass Server backed by testenv, registers a fresh
// admin keypair, and returns the server address, admin signer, mock proxier,
// and a cancel func.
func setupAdminTest(t *testing.T) (
	addr string,
	adminSigner gossh.Signer,
	mp *testenv.MockProxier,
	cancel context.CancelFunc,
) {
	t.Helper()

	env := testenv.New(t)

	// Generate a fresh admin keypair and register it.
	adminPub, adminPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate admin key: %v", err)
	}
	adminSSHPub, err := gossh.NewPublicKey(adminPub)
	if err != nil {
		t.Fatalf("admin ssh pub: %v", err)
	}
	authorizedLine := strings.TrimSpace(string(gossh.MarshalAuthorizedKey(adminSSHPub)))
	if addErr := env.Repo.AddAdminKey(context.Background(), authorizedLine); addErr != nil {
		t.Fatalf("add admin key: %v", addErr)
	}

	pemBlock, err := gossh.MarshalPrivateKey(adminPriv, "")
	if err != nil {
		t.Fatalf("marshal admin key: %v", err)
	}
	adminSigner, err = gossh.ParsePrivateKey(pem.EncodeToMemory(pemBlock))
	if err != nil {
		t.Fatalf("parse admin signer: %v", err)
	}

	// Provide a path for the host key file that does NOT exist yet.
	hf, err := os.CreateTemp("", "proxpass-host-key-*")
	if err != nil {
		t.Fatalf("host key temp: %v", err)
	}
	hf.Close()
	hostKeyPath := hf.Name() + ".key" // non-existent sibling path
	os.Remove(hf.Name())              // remove the empty placeholder
	t.Cleanup(func() { os.Remove(hostKeyPath) })

	logger := log.New(io.Discard, "", 0)
	mp = &testenv.MockProxier{}

	adminHandler := proxssh.DefaultAdminHandler(mp, nil, logger)

	srv := proxssh.NewServer(
		"127.0.0.1:0", // not used; we pass an explicit listener
		hostKeyPath,
		env.Repo,
		adminHandler,
		mp,
		logger,
	)

	// Bind on a random port before starting so we know the address.
	lc := &net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr = ln.Addr().String()

	ctx, cancelCtx := context.WithCancel(context.Background())
	cancel = cancelCtx

	go func() {
		_ = srv.ListenAndServeOn(ctx, ln)
	}()

	// Wait for the server to be ready before returning.
	if err := waitForSSH(addr, 5*time.Second); err != nil {
		t.Fatalf("proxpass server not ready: %v", err)
	}

	return addr, adminSigner, mp, cancel
}

// sshShellOutput dials the proxpass server, opens a shell session with the
// given username, closes stdin after the first byte of output arrives,
// reads all output until the session closes, and returns it.
func sshShellOutput(t *testing.T, addr, username string, signer gossh.Signer) string {
	t.Helper()

	cfg := &gossh.ClientConfig{
		User:            username,
		Auth:            []gossh.AuthMethod{gossh.PublicKeys(signer)},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(), //nolint:gosec // test only
	}

	client, err := gossh.Dial("tcp", addr, cfg)
	if err != nil {
		t.Fatalf("dial proxpass (%s): %v", username, err)
	}
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("new session: %v", err)
	}

	// Pipe stdout and stderr so we can read them concurrently.
	stdoutPipe, err := sess.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	stderrPipe, err := sess.StderrPipe()
	if err != nil {
		t.Fatalf("stderr pipe: %v", err)
	}

	stdinPipe, err := sess.StdinPipe()
	if err != nil {
		t.Fatalf("stdin pipe: %v", err)
	}

	if err := sess.Shell(); err != nil {
		t.Fatalf("shell: %v", err)
	}

	var buf bytes.Buffer
	firstByte := make(chan struct{}, 1)
	var wg sync.WaitGroup

	copyWithSignal := func(r io.Reader) {
		defer wg.Done()
		b := make([]byte, 4096)
		for {
			n, err := r.Read(b)
			if n > 0 {
				buf.Write(b[:n])
				select {
				case firstByte <- struct{}{}:
				default:
				}
			}
			if err != nil {
				return
			}
		}
	}

	wg.Add(2)
	go copyWithSignal(stdoutPipe)
	go copyWithSignal(stderrPipe)

	select {
	case <-firstByte:
	case <-time.After(5 * time.Second):
	}

	stdinPipe.Close()

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		sess.Close()
		t.Fatalf("session did not finish within 10s for username %q; output so far: %q", username, buf.String())
	}

	_ = sess.Wait()

	return buf.String()
}

// sshExecOutput dials the proxpass server, runs the given command via SSH exec,
// collects stdout+stderr, and returns the combined output.
func sshExecOutput(t *testing.T, addr, username, command string, signer gossh.Signer) string {
	t.Helper()

	cfg := &gossh.ClientConfig{
		User:            username,
		Auth:            []gossh.AuthMethod{gossh.PublicKeys(signer)},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(), //nolint:gosec // test only
	}

	client, err := gossh.Dial("tcp", addr, cfg)
	if err != nil {
		t.Fatalf("dial proxpass (%s): %v", username, err)
	}
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("new session: %v", err)
	}

	var buf strings.Builder
	sess.Stdout = &buf
	sess.Stderr = &buf

	_ = sess.Run(command)
	return buf.String()
}

// sshExecErroutput dials the proxpass server, runs the given command via SSH exec,
// and returns combined stdout+stderr. It tolerates the server closing the
// channel early (e.g. when the guest is not found or access is denied).
func sshExecErroutput(t *testing.T, addr, username, command string, signer gossh.Signer) string {
	t.Helper()

	cfg := &gossh.ClientConfig{
		User:            username,
		Auth:            []gossh.AuthMethod{gossh.PublicKeys(signer)},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(), //nolint:gosec // test only
	}

	client, err := gossh.Dial("tcp", addr, cfg)
	if err != nil {
		t.Fatalf("dial proxpass (%s): %v", username, err)
	}
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		return ""
	}

	var outBuf, errBuf strings.Builder
	sess.Stdout = &outBuf
	sess.Stderr = &errBuf

	// Ignore error: the server may close the channel early.
	_ = sess.Run(command)
	return outBuf.String() + errBuf.String()
}

// sshShellStderrOutput dials the proxpass server, opens a shell session,
// and returns combined stdout+stderr. Tolerates the server closing early.
func sshShellStderrOutput(t *testing.T, addr, username string, signer gossh.Signer) string {
	t.Helper()

	cfg := &gossh.ClientConfig{
		User:            username,
		Auth:            []gossh.AuthMethod{gossh.PublicKeys(signer)},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(), //nolint:gosec // test only
	}

	client, err := gossh.Dial("tcp", addr, cfg)
	if err != nil {
		t.Fatalf("dial proxpass (%s): %v", username, err)
	}
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		return ""
	}

	var outBuf, errBuf strings.Builder
	sess.Stdout = &outBuf
	sess.Stderr = &errBuf

	// Ignore shell/Wait errors -- server may reject or close early.
	_ = sess.Shell()
	_ = sess.Wait()

	return outBuf.String() + errBuf.String()
}
