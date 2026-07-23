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

	// Provide a path for the host key file that does NOT exist yet;
	// loadOrGenerateHostKey will create and populate it on first use.
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
// given username, closes stdin immediately (triggering EOF on the server side),
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

	// Read stdout and stderr into a shared buffer concurrently.
	// We pipe through a buffered reader so we can detect when the first byte
	// arrives (indicating the server has written its initial response) before
	// closing stdin.
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

	// Wait for the first byte of output (the server's initial response)
	// before closing stdin, or fall back after 5s for servers that write nothing.
	select {
	case <-firstByte:
	case <-time.After(5 * time.Second):
	}

	// Close stdin so the server-side handler (CLI or proxy) sees EOF and exits.
	stdinPipe.Close()

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	// Wait for all output to be drained or timeout.
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		sess.Close()
		t.Fatalf("session did not finish within 10s for username %q; output so far: %q", username, buf.String())
	}

	_ = sess.Wait()

	return buf.String()
}

// TestAdminWithGuestUsernameProxiesDirectly verifies that an admin key with a
// username like "ct100" connects straight to the guest without showing the CLI.
func TestAdminWithGuestUsernameProxiesDirectly(t *testing.T) {
	addr, adminSigner, mp, cancel := setupAdminTest(t)
	defer cancel()

	// The seeded DB has CT "webserver" at ProxmoxID 100.
	// "ct100" should resolve to it and proxy directly.
	output := sshShellOutput(t, addr, "ct100", adminSigner)

	if !strings.Contains(output, "[mock proxy]") {
		t.Errorf("expected mock proxy banner in output, got: %q", output)
	}

	sessions := mp.RecordedSessions()
	if len(sessions) == 0 {
		t.Fatal("expected at least one proxy session to be recorded")
	}
	if sessions[0].ProxmoxID != 100 {
		t.Errorf("expected ProxmoxID 100, got %d", sessions[0].ProxmoxID)
	}
}

// TestAdminWithRootUsernameShowsCLI verifies that an admin using "root" as the
// SSH username still gets the admin CLI, not a guest proxy.
func TestAdminWithRootUsernameShowsCLI(t *testing.T) {
	addr, adminSigner, mp, cancel := setupAdminTest(t)
	defer cancel()

	output := sshShellOutput(t, addr, "root", adminSigner)

	if strings.Contains(output, "[mock proxy]") {
		t.Errorf("expected CLI output, got mock proxy banner; output: %q", output)
	}

	sessions := mp.RecordedSessions()
	if len(sessions) != 0 {
		t.Errorf("expected no proxy sessions for 'root', got %d", len(sessions))
	}
}

// TestAdminWithUnknownUsernameShowsError verifies that an admin using an
// unresolvable username gets a clear error message — not the admin CLI help and
// not a proxy session.
func TestAdminWithUnknownUsernameShowsError(t *testing.T) {
	addr, adminSigner, mp, cancel := setupAdminTest(t)
	defer cancel()

	// "zzz9999" matches no guest in the seeded database.
	output := sshShellOutput(t, addr, "zzz9999", adminSigner)

	if strings.Contains(output, "[mock proxy]") {
		t.Errorf("did not expect proxy banner for unknown guest; output: %q", output)
	}
	if strings.Contains(output, "USAGE:") || strings.Contains(output, "--help") {
		t.Errorf("expected error message, not CLI help; output: %q", output)
	}
	if !strings.Contains(output, "not found") && !strings.Contains(output, "Error") {
		t.Errorf("expected error text in output, got: %q", output)
	}

	sessions := mp.RecordedSessions()
	if len(sessions) != 0 {
		t.Errorf("expected no proxy sessions for unknown guest, got %d", len(sessions))
	}

	t.Logf("output for unknown username %q: %q", "zzz9999", output)
}
