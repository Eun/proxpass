package session_test

import (
	"errors"
	"io"
	"log"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"proxpass/internal/api"
	"proxpass/internal/models"
	"proxpass/internal/session"
	"proxpass/internal/sshhostkey"
	"proxpass/internal/testenv"
)

// newAdminSSHRepo returns the CONCRETE AdminRepository (not just db.Repository)
// so the SSH-key methods, which are not interface methods, can be exercised.
// It goes through the whole stack: mint, exchange, HTTP, admin check.
func newAdminSSHRepo(t *testing.T) *session.AdminRepository {
	t.Helper()
	direct := newRepo(t)
	srv := httptest.NewServer(
		api.NewServer(direct, log.New(io.Discard, "", 0)).Handler())
	t.Cleanup(srv.Close)

	identity := adminIdentity()
	minted := "minted-" + identity.IdentityName
	now := time.Now()
	if err := direct.MintSessionToken(
		t.Context(), api.HashToken(minted), identity, now, now.Add(time.Minute)); err != nil {
		t.Fatalf("mint: %v", err)
	}
	client := session.NewAPIClient(srv.URL)
	if _, err := client.Exchange(t.Context(), minted); err != nil {
		t.Fatalf("exchange: %v", err)
	}
	return session.NewAdminRepository(client)
}

// TestSSHPublicKeyIsResolvedServerSide is the fix for the reported bug: the
// admin session cannot read the root-owned key file, so it asks `proxpass
// serve' through the admin API. The server reads the file and returns only the
// public half.
func TestSSHPublicKeyIsResolvedServerSide(t *testing.T) {
	srv, err := testenv.NewMockSSHServer()
	if err != nil {
		t.Fatalf("starting the mock host: %v", err)
	}
	defer srv.Close()
	// Point the (server-side) key at a real key the entrypoint would have made.
	t.Setenv(models.SSHKeyPathEnv, srv.KeyPath)

	remote := newAdminSSHRepo(t)
	pub, path, err := remote.SSHPublicKey(t.Context())
	if err != nil {
		t.Fatalf("SSHPublicKey: %v", err)
	}
	if !strings.HasPrefix(pub, "ssh-") {
		t.Fatalf("expected an authorized_keys line, got %q", pub)
	}
	if path != srv.KeyPath {
		t.Fatalf("expected the key path %q, got %q", srv.KeyPath, path)
	}
	// A private key must NEVER cross the wire.
	if strings.Contains(pub, "PRIVATE KEY") {
		t.Fatalf("the private key leaked to the session: %q", pub)
	}
}

// TestSSHPublicKeyIsEmptyWithoutAKey keeps "no key" distinct from an error, so
// a termproxy-only deployment is handled rather than reported as broken.
func TestSSHPublicKeyIsEmptyWithoutAKey(t *testing.T) {
	t.Setenv(models.SSHKeyPathEnv, filepath.Join(t.TempDir(), "absent"))

	remote := newAdminSSHRepo(t)
	pub, path, err := remote.SSHPublicKey(t.Context())
	if err != nil {
		t.Fatalf("SSHPublicKey: %v", err)
	}
	if pub != "" {
		t.Fatalf("expected no key, got %q", pub)
	}
	if path == "" {
		t.Fatal("expected the key path to be reported even when absent")
	}
}

// TestCheckInstanceSSHAccessReachesTheHost confirms the reachability check runs
// server-side with the private key (which the session cannot read) and reports
// a reachable host.
func TestCheckInstanceSSHAccessReachesTheHost(t *testing.T) {
	srv, err := testenv.NewMockSSHServer()
	if err != nil {
		t.Fatalf("starting the mock host: %v", err)
	}
	defer srv.Close()
	t.Setenv(models.SSHKeyPathEnv, srv.KeyPath)

	remote := newAdminSSHRepo(t)
	inst := &models.ProxmoxInstance{
		Name:             instPVE,
		ConsoleTransport: models.ConsoleTransportSSH,
		SSHHost:          srv.Host,
		SSHPort:          srv.Port,
		SSHUser:          srv.User,
		// Pin the mock host key: a test host publishes no SSHFP, so without a
		// pin the server-side dial would fall back to a failing DNS lookup.
		SSHFingerprints: []string{srv.HostKeyFingerprint()},
	}
	if err := remote.CheckInstanceSSHAccess(t.Context(), inst); err != nil {
		t.Fatalf("expected the configured key to open the host: %v", err)
	}
}

// TestCheckInstanceSSHAccessCarriesTheNoFingerprintCase is the crux of the
// merge with the host-key-verification feature: when the host key cannot be
// verified (no pinned fingerprint, no SSHFP), the server-side dial fails with
// a *sshhostkey.ErrNoFingerprint, and that TYPED error must survive the
// loopback API so the CLI's errors.As check still treats the add as fatal. A
// plain string would lose the type, so the op carries the host + fingerprint
// as structured data and the client rebuilds the error.
func TestCheckInstanceSSHAccessCarriesTheNoFingerprintCase(t *testing.T) {
	// Require DNSSEC off is irrelevant here: 127.0.0.1 has no SSHFP record at
	// all, so the lookup returns "none" regardless and the callback produces
	// ErrNoFingerprint.
	srv, err := testenv.NewMockSSHServer()
	if err != nil {
		t.Fatalf("starting the mock host: %v", err)
	}
	defer srv.Close()
	t.Setenv(models.SSHKeyPathEnv, srv.KeyPath)

	remote := newAdminSSHRepo(t)
	inst := &models.ProxmoxInstance{
		Name:             instPVE,
		ConsoleTransport: models.ConsoleTransportSSH,
		SSHHost:          srv.Host,
		SSHPort:          srv.Port,
		SSHUser:          srv.User,
		// No SSHFingerprint and no InsecureSSH: force the unverifiable path.
	}
	err = remote.CheckInstanceSSHAccess(t.Context(), inst)
	if err == nil {
		t.Fatal("expected an unverifiable host key to be refused")
	}
	var noFP *sshhostkey.ErrNoFingerprint
	if !errors.As(err, &noFP) {
		t.Fatalf("expected a *sshhostkey.ErrNoFingerprint across the API, got %T: %v", err, err)
	}
	// The reconstructed error must still carry what the operator pins.
	if noFP.Host != srv.Host {
		t.Errorf("host not preserved: got %q, want %q", noFP.Host, srv.Host)
	}
	if !strings.HasPrefix(noFP.Fingerprint, "SHA256:") {
		t.Errorf("expected a SHA256 fingerprint to pin, got %q", noFP.Fingerprint)
	}
}

// TestCheckInstanceSSHAccessReportsAnUninstalledKey is the state before the
// administrator installs the public key: the error names the ssh user, because
// that is the usual cause.
func TestCheckInstanceSSHAccessReportsAnUninstalledKey(t *testing.T) {
	srv, err := testenv.NewMockSSHServer()
	if err != nil {
		t.Fatalf("starting the mock host: %v", err)
	}
	defer srv.Close()

	// The deployment key is a DIFFERENT key the host does not know.
	other, err := testenv.NewMockSSHServer()
	if err != nil {
		t.Fatalf("starting the second host: %v", err)
	}
	defer other.Close()
	t.Setenv(models.SSHKeyPathEnv, other.KeyPath)

	remote := newAdminSSHRepo(t)
	inst := &models.ProxmoxInstance{
		Name:             instPVE,
		ConsoleTransport: models.ConsoleTransportSSH,
		SSHHost:          srv.Host,
		SSHPort:          srv.Port,
		SSHUser:          srv.User,
		// Pin the host key so verification passes and the dial reaches the
		// auth step -- the failure under test is the uninstalled client key.
		SSHFingerprints: []string{srv.HostKeyFingerprint()},
	}
	err = remote.CheckInstanceSSHAccess(t.Context(), inst)
	if err == nil {
		t.Fatal("expected a key the host does not know to be refused")
	}
	if !strings.Contains(err.Error(), srv.User) {
		t.Fatalf("the error should name the ssh user %q: %v", srv.User, err)
	}
}

// TestCheckInstanceSSHAccessWithoutAKey reports the missing deployment key
// rather than a confusing connection error.
func TestCheckInstanceSSHAccessWithoutAKey(t *testing.T) {
	t.Setenv(models.SSHKeyPathEnv, filepath.Join(t.TempDir(), "absent"))

	remote := newAdminSSHRepo(t)
	inst := &models.ProxmoxInstance{
		Name:             instPVE,
		ConsoleTransport: models.ConsoleTransportSSH,
		SSHHost:          "127.0.0.1",
		SSHPort:          22,
		SSHUser:          nodeSSHUser,
	}
	err := remote.CheckInstanceSSHAccess(t.Context(), inst)
	if err == nil {
		t.Fatal("expected a missing key to be reported")
	}
	if !strings.Contains(err.Error(), "no ssh key") {
		t.Fatalf("the error should say the key is missing: %v", err)
	}
}

// TestSSHKeyOpsRefuseAClientCredential keeps the SSH key material behind the
// admin check, like every other admin operation: the refusal happens before
// any file is read.
func TestSSHKeyOpsRefuseAClientCredential(t *testing.T) {
	direct := newRepo(t)
	srv := httptest.NewServer(
		api.NewServer(direct, log.New(io.Discard, "", 0)).Handler())
	t.Cleanup(srv.Close)

	identity := &models.SessionIdentity{
		LoginName: userAlias, IdentityName: userAlice, ClientID: 1,
	}
	minted := "minted-client"
	now := time.Now()
	if err := direct.MintSessionToken(
		t.Context(), api.HashToken(minted), identity, now, now.Add(time.Minute)); err != nil {
		t.Fatalf("mint: %v", err)
	}
	client := session.NewAPIClient(srv.URL)
	if _, err := client.Exchange(t.Context(), minted); err != nil {
		t.Fatalf("exchange: %v", err)
	}
	remote := session.NewAdminRepository(client)

	if _, _, err := remote.SSHPublicKey(t.Context()); err == nil {
		t.Fatal("a client credential read the SSH public key")
	}
}
