package api

import (
	"net"
	"os"
	"strconv"
	"strings"
	"testing"

	"proxpass/internal/models"
	"proxpass/internal/testenv"
)

const (
	testInstanceName = "pve"
	testLoopback     = "127.0.0.1"
	testSSHUser      = "root"
	// testGuestName is a sample container name reused across activity and
	// discovery tests (named to satisfy goconst, which flags the repeated
	// literal once a third occurrence appears).
	testGuestName = "ct100"
)

// instanceFor builds an instance pointing at the mock Proxmox host.
func instanceFor(t *testing.T, srv *testenv.MockSSHServer) *models.ProxmoxInstance {
	t.Helper()
	return &models.ProxmoxInstance{
		Name:             testInstanceName,
		ConsoleTransport: models.ConsoleTransportSSH,
		SSHHost:          srv.Host,
		SSHPort:          srv.Port,
		SSHUser:          srv.User,
		// Pin the mock server's host key: a test host publishes no SSHFP, so
		// without a pin verification would fall back to a (failing) DNS lookup.
		SSHFingerprints: []string{srv.HostKeyFingerprint()},
	}
}

// readKey returns the PEM bytes written by a mock host.
func readKey(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading the key %s: %v", path, err)
	}
	return b
}

// keyFor returns the PEM key the mock host accepts.
func keyFor(t *testing.T, srv *testenv.MockSSHServer) string {
	t.Helper()
	return string(readKey(t, srv.KeyPath))
}

// dialSSHSessionFor runs the dial with the instance's own key.
func dialSSHSessionFor(t *testing.T, srv *testenv.MockSSHServer) error {
	t.Helper()
	return dialSSHSession(t.Context(), instanceFor(t, srv), keyFor(t, srv))
}

// TestDialSSHSessionAcceptsAWorkingKey is the case the administrator sees once
// the public key is installed.
func TestDialSSHSessionAcceptsAWorkingKey(t *testing.T) {
	srv, err := testenv.NewMockSSHServer()
	if err != nil {
		t.Fatalf("starting the mock host: %v", err)
	}
	defer srv.Close()

	if err := dialSSHSessionFor(t, srv); err != nil {
		t.Fatalf("expected the configured key to be accepted: %v", err)
	}
}

// TestDialSSHSessionRejectsAnUninstalledKey is the case BEFORE the
// administrator has installed the public key, which is the whole reason the
// check exists.
func TestDialSSHSessionRejectsAnUninstalledKey(t *testing.T) {
	srv, err := testenv.NewMockSSHServer()
	if err != nil {
		t.Fatalf("starting the mock host: %v", err)
	}
	defer srv.Close()

	other, err := testenv.NewMockSSHServer()
	if err != nil {
		t.Fatalf("starting the second host: %v", err)
	}
	defer other.Close()

	// A valid key that this host does not know.
	err = dialSSHSession(t.Context(), instanceFor(t, srv), string(readKey(t, other.KeyPath)))
	if err == nil {
		t.Fatal("expected a key the host does not know to be refused")
	}
	// The message has to name the user, because the usual cause is the key
	// being installed for a different account than --ssh-user.
	if !strings.Contains(err.Error(), srv.User) {
		t.Fatalf("the error should name the ssh user %q: %v", srv.User, err)
	}
}

// TestDialSSHSessionReportsAClosedPort covers the other common failure: the
// host is not listening, or a firewall is in the way.
func TestDialSSHSessionReportsAClosedPort(t *testing.T) {
	// Bind and release a port so it is almost certainly closed.
	l, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", testLoopback+":0")
	if err != nil {
		t.Fatalf("reserving a port: %v", err)
	}
	addr, ok := l.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("unexpected address type %T", l.Addr())
	}
	port := addr.Port
	if err := l.Close(); err != nil {
		t.Fatalf("closing the listener: %v", err)
	}

	inst := &models.ProxmoxInstance{
		Name:             testInstanceName,
		ConsoleTransport: models.ConsoleTransportSSH,
		SSHHost:          testLoopback,
		SSHPort:          port,
		SSHUser:          testSSHUser,
	}
	err = dialSSHSession(t.Context(), inst, testKeyPEM(t))
	if err == nil {
		t.Fatal("expected a closed port to be reported")
	}
	if !strings.Contains(err.Error(), strconv.Itoa(port)) {
		t.Fatalf("the error should name the address: %v", err)
	}
}

// TestDialSSHSessionRejectsAnUnparseableKey keeps a malformed key from
// reaching the dialer, where it would be reported as a connection problem.
func TestDialSSHSessionRejectsAnUnparseableKey(t *testing.T) {
	inst := &models.ProxmoxInstance{
		Name:             testInstanceName,
		ConsoleTransport: models.ConsoleTransportSSH,
		SSHHost:          testLoopback,
		SSHPort:          22,
		SSHUser:          testSSHUser,
	}
	err := dialSSHSession(t.Context(), inst, "not a key")
	if err == nil {
		t.Fatal("expected a malformed key to be refused")
	}
	if !strings.Contains(err.Error(), "parsing") {
		t.Fatalf("the error should say the key did not parse: %v", err)
	}
}

// TestPublicKeyLineIsASingleAuthorizedKeysEntry checks the text the
// administrator is told to paste.
func TestPublicKeyLineIsASingleAuthorizedKeysEntry(t *testing.T) {
	line, err := publicKeyLine(testKeyPEM(t))
	if err != nil {
		t.Fatalf("publicKeyLine: %v", err)
	}
	if !strings.HasPrefix(line, "ssh-") {
		t.Fatalf("expected an authorized_keys line, got %q", line)
	}
	// Exactly one entry: a value with an embedded newline pasted into
	// authorized_keys would install a second, unreviewed key.
	if n := strings.Count(strings.TrimRight(line, "\n"), "\n"); n != 0 {
		t.Fatalf("expected a single line, found %d embedded newlines: %q", n, line)
	}
}

// testKeyPEM returns a usable private key, borrowed from a mock host.
func testKeyPEM(t *testing.T) string {
	t.Helper()
	srv, err := testenv.NewMockSSHServer()
	if err != nil {
		t.Fatalf("starting a mock host for its key: %v", err)
	}
	defer srv.Close()
	return string(readKey(t, srv.KeyPath))
}
