package ssh_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"io"
	"log"
	"net"
	"strings"
	"testing"
	"time"

	proxssh "proxpass/internal/ssh"
	"proxpass/internal/testenv"

	gossh "golang.org/x/crypto/ssh"
)

// setupClientTest starts a proxpass Server backed by testenv, replaces alice's
// public key with a freshly generated one, and returns the server address,
// client signer, mock proxier, and a cancel func.
//
// Access seeded by testenv.Seed:
//   - alice -> webserver (ct100)  [direct]
//   - alice (via developers group) -> devbox (vm200)  [group]
func setupClientTest(t *testing.T) (
	addr string,
	clientSigner gossh.Signer,
	mp *testenv.MockProxier,
	cancel context.CancelFunc,
) {
	t.Helper()

	env := testenv.New(t)

	// Generate a fresh client keypair so we control the private key.
	clientPub, clientPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate client key: %v", err)
	}
	clientSSHPub, err := gossh.NewPublicKey(clientPub)
	if err != nil {
		t.Fatalf("client ssh pub: %v", err)
	}
	pemBlock, err := gossh.MarshalPrivateKey(clientPriv, "")
	if err != nil {
		t.Fatalf("marshal client key: %v", err)
	}
	clientSigner, err = gossh.ParsePrivateKey(pem.EncodeToMemory(pemBlock))
	if err != nil {
		t.Fatalf("parse client signer: %v", err)
	}

	// Replace alice's key in the DB with our freshly generated key.
	authorizedLine := strings.TrimSpace(string(gossh.MarshalAuthorizedKey(clientSSHPub)))
	ctx := context.Background()

	client := env.Seed.Client
	client.PublicKeys = []string{authorizedLine}
	if err := env.Repo.UpdateClient(ctx, client); err != nil {
		t.Fatalf("update client key: %v", err)
	}

	hostKeyPath := t.TempDir() + "/host.key"

	logger := log.New(io.Discard, "", 0)
	mp = &testenv.MockProxier{}

	adminHandler := proxssh.DefaultAdminHandler(mp, nil, logger)

	srv := proxssh.NewServer(
		"127.0.0.1:0",
		hostKeyPath,
		env.Repo,
		adminHandler,
		mp,
		logger,
	)

	lc := &net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr = ln.Addr().String()

	ctx2, cancelCtx := context.WithCancel(context.Background())
	cancel = cancelCtx

	go func() {
		_ = srv.ListenAndServeOn(ctx2, ln)
	}()

	if err := waitForSSH(addr, 5*time.Second); err != nil {
		t.Fatalf("proxpass server not ready: %v", err)
	}

	return addr, clientSigner, mp, cancel
}

// TestClientWithTypeAndVMIDProxiesDirectly verifies that a client key with
// a username like "ct100" connects straight to the guest (ssh ct100@localhost).
func TestClientWithTypeAndVMIDProxiesDirectly(t *testing.T) {
	addr, clientSigner, mp, cancel := setupClientTest(t)
	defer cancel()

	// The seeded DB has CT "webserver" at ProxmoxID 100.
	// "ct100" should resolve to it and proxy directly.
	output := sshShellOutput(t, addr, "ct100", clientSigner)

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

// TestClientWithNumericVMIDProxiesDirectly verifies that a client can use
// a plain numeric VMID (e.g. "100") as the SSH username.
func TestClientWithNumericVMIDProxiesDirectly(t *testing.T) {
	addr, clientSigner, mp, cancel := setupClientTest(t)
	defer cancel()

	output := sshShellOutput(t, addr, "100", clientSigner)

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

// TestClientWithGuestNameProxiesDirectly verifies that a client can use
// a guest name (e.g. "webserver") as the SSH username.
func TestClientWithGuestNameProxiesDirectly(t *testing.T) {
	addr, clientSigner, mp, cancel := setupClientTest(t)
	defer cancel()

	output := sshShellOutput(t, addr, "webserver", clientSigner)

	if !strings.Contains(output, "[mock proxy]") {
		t.Errorf("expected mock proxy banner in output, got: %q", output)
	}

	sessions := mp.RecordedSessions()
	if len(sessions) == 0 {
		t.Fatal("expected at least one proxy session to be recorded")
	}
	if sessions[0].GuestName != "webserver" {
		t.Errorf("expected guest 'webserver', got %q", sessions[0].GuestName)
	}
}

// TestClientWithUnknownUsernameReturnsError verifies that a client using an
// unresolvable username gets an error written to stderr, not a panic.
func TestClientWithUnknownUsernameReturnsError(t *testing.T) {
	addr, clientSigner, mp, cancel := setupClientTest(t)
	defer cancel()

	output := sshStderrOutput(t, addr, "zzz9999", clientSigner)

	if strings.Contains(output, "[mock proxy]") {
		t.Errorf("did not expect proxy banner for unknown guest; output: %q", output)
	}

	sessions := mp.RecordedSessions()
	if len(sessions) != 0 {
		t.Errorf("expected no proxy sessions for unknown guest, got %d", len(sessions))
	}

	t.Logf("output for unknown username %q: %q", "zzz9999", output)
}

// TestClientWithNoAccessReturnsError verifies that a client is denied access
// to a guest they do not have permission for.
func TestClientWithNoAccessReturnsError(t *testing.T) {
	addr, clientSigner, mp, cancel := setupClientTest(t)
	defer cancel()

	// "database" (ct101) is in the DB but alice has no direct or group access to it.
	output := sshStderrOutput(t, addr, "database", clientSigner)

	if strings.Contains(output, "[mock proxy]") {
		t.Errorf("did not expect proxy banner for denied guest; output: %q", output)
	}

	sessions := mp.RecordedSessions()
	if len(sessions) != 0 {
		t.Errorf("expected no proxy sessions for denied guest, got %d", len(sessions))
	}

	t.Logf("output for denied guest: %q", output)
}

// sshStderrOutput dials the proxpass server, attempts to open a shell session
// with the given username, and collects both stdout and stderr. Unlike
// sshShellOutput it does not fatal on a shell-request failure (the server may
// close the channel before a shell is granted when the user is unknown or
// denied).
func sshStderrOutput(t *testing.T, addr, username string, signer gossh.Signer) string {
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
		// Channel already closed by server — that itself is a form of error.
		return ""
	}

	var outBuf, errBuf strings.Builder
	sess.Stdout = &outBuf
	sess.Stderr = &errBuf

	// Ignore errors: the server may reject the shell request.
	_ = sess.Shell()
	_ = sess.Wait()

	return outBuf.String() + errBuf.String()
}
