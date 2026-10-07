package cli

import (
	"net"
	"os"
	"strconv"
	"strings"
	"testing"

	"proxpass/internal/models"
	"proxpass/internal/testenv"
)

// instanceFor builds an instance pointing at the mock Proxmox host.
func instanceFor(t *testing.T, srv *testenv.MockSSHServer) *models.ProxmoxInstance {
	t.Helper()
	key, err := os.ReadFile(srv.KeyPath)
	if err != nil {
		t.Fatalf("reading the mock server key: %v", err)
	}
	_ = key
	return &models.ProxmoxInstance{
		Name:           testInstanceName,
		ConnectionType: models.ConnectionTypeSSH,
		SSHHost:        srv.Host,
		SSHPort:        srv.Port,
		SSHUser:        srv.User,
	}
}

// keyFor returns the PEM key the mock host accepts.
func keyFor(t *testing.T, srv *testenv.MockSSHServer) string {
	t.Helper()
	return string(readKey(t, srv.KeyPath))
}

// checkSSHAccessFor runs the check with the instance's own key.
func checkSSHAccessFor(t *testing.T, srv *testenv.MockSSHServer) error {
	t.Helper()
	return checkSSHAccess(t.Context(), instanceFor(t, srv), keyFor(t, srv))
}

// TestCheckSSHAccessAcceptsAWorkingKey is the case the administrator sees
// once the public key is installed.
func TestCheckSSHAccessAcceptsAWorkingKey(t *testing.T) {
	srv, err := testenv.NewMockSSHServer()
	if err != nil {
		t.Fatalf("starting the mock host: %v", err)
	}
	defer srv.Close()

	if err := checkSSHAccessFor(t, srv); err != nil {
		t.Fatalf("expected the configured key to be accepted: %v", err)
	}
}

// TestCheckSSHAccessRejectsAnUninstalledKey is the case BEFORE the
// administrator has installed the public key, which is the whole reason the
// check exists.
func TestCheckSSHAccessRejectsAnUninstalledKey(t *testing.T) {
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
	err = checkSSHAccess(t.Context(), instanceFor(t, srv), string(readKey(t, other.KeyPath)))
	if err == nil {
		t.Fatal("expected a key the host does not know to be refused")
	}
	// The message has to name the user, because the usual cause is the key
	// being installed for a different account than --ssh-user.
	if !strings.Contains(err.Error(), srv.User) {
		t.Fatalf("the error should name the ssh user %q: %v", srv.User, err)
	}
}

// TestCheckSSHAccessReportsAClosedPort covers the other common failure: the
// host is not listening, or a firewall is in the way.
func TestCheckSSHAccessReportsAClosedPort(t *testing.T) {
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
		Name:           testInstanceName,
		ConnectionType: models.ConnectionTypeSSH,
		SSHHost:        testLoopback,
		SSHPort:        port,
		SSHUser:        testSSHUser,
	}
	err = checkSSHAccess(t.Context(), inst, testKeyPEM(t))
	if err == nil {
		t.Fatal("expected a closed port to be reported")
	}
	if !strings.Contains(err.Error(), strconv.Itoa(port)) {
		t.Fatalf("the error should name the address: %v", err)
	}
}

// TestCheckSSHAccessRejectsAnUnparseableKey keeps a malformed key from
// reaching the dialer, where it would be reported as a connection problem.
func TestCheckSSHAccessRejectsAnUnparseableKey(t *testing.T) {
	inst := &models.ProxmoxInstance{
		Name:           testInstanceName,
		ConnectionType: models.ConnectionTypeSSH,
		SSHHost:        testLoopback,
		SSHPort:        22,
		SSHUser:        testSSHUser,
	}
	err := checkSSHAccess(t.Context(), inst, "not a key")
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
	b, err := os.ReadFile(srv.KeyPath)
	if err != nil {
		t.Fatalf("reading the key: %v", err)
	}
	return string(b)
}
