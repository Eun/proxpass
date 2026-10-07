package cli

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"proxpass/internal/models"
	"proxpass/internal/testenv"
)

// reportFor runs reportSSHKey and returns what it printed.
func reportFor(t *testing.T, inst *models.ProxmoxInstance) string {
	t.Helper()
	var out bytes.Buffer
	reportSSHKey(t.Context(), &Deps{Out: &out, ErrOut: &out}, inst)
	return out.String()
}

// TestInspectReportsAccessOnceTheKeyIsInstalled is what the administrator
// runs to confirm the key landed, which is what the README tells them to do.
func TestInspectReportsAccessOnceTheKeyIsInstalled(t *testing.T) {
	srv, err := testenv.NewMockSSHServer()
	if err != nil {
		t.Fatalf("starting the mock host: %v", err)
	}
	defer srv.Close()

	// The deployment key is the one the host accepts.
	key := readKey(t, srv.KeyPath)
	keyPath := writeKeyFile(t, key)
	t.Setenv(models.SSHKeyPathEnv, keyPath)

	// An instance with no key of its own, as `instance add' stores them now.
	inst := &models.ProxmoxInstance{
		Name:           testInstanceName,
		ConnectionType: models.ConnectionTypeSSH,
		SSHHost:        srv.Host,
		SSHPort:        srv.Port,
		SSHUser:        srv.User,
	}

	got := reportFor(t, inst)
	if !strings.Contains(got, "SSH Access:       ok") {
		t.Fatalf("expected the deployment key to open the host:\n%s", got)
	}
	if !strings.Contains(got, keyPath) {
		t.Fatalf("expected the report to name the key file:\n%s", got)
	}
	if !strings.Contains(got, "SSH Public Key:   ssh-") {
		t.Fatalf("expected the public key to be printed for installation:\n%s", got)
	}
}

// TestInspectReportsTheKeyIsNotInstalledYet is the state between adding an
// instance and installing the key, and must say what to do about it.
func TestInspectReportsTheKeyIsNotInstalledYet(t *testing.T) {
	srv, err := testenv.NewMockSSHServer()
	if err != nil {
		t.Fatalf("starting the mock host: %v", err)
	}
	defer srv.Close()

	// A valid key this host does not know.
	other, err := testenv.NewMockSSHServer()
	if err != nil {
		t.Fatalf("starting the second host: %v", err)
	}
	defer other.Close()
	wrong := readKey(t, other.KeyPath)
	keyPath := writeKeyFile(t, wrong)
	t.Setenv(models.SSHKeyPathEnv, keyPath)

	got := reportFor(t, &models.ProxmoxInstance{
		Name:           testInstanceName,
		ConnectionType: models.ConnectionTypeSSH,
		SSHHost:        srv.Host,
		SSHPort:        srv.Port,
		SSHUser:        srv.User,
	})
	if !strings.Contains(got, "UNAVAILABLE") {
		t.Fatalf("expected the missing key to be reported:\n%s", got)
	}
	// Telling them it failed is useless without telling them what to do.
	if !strings.Contains(got, authorizedKeysPath) {
		t.Fatalf("expected the report to name authorized_keys:\n%s", got)
	}
	if !strings.Contains(got, "SSH Public Key:   ssh-") {
		t.Fatalf("expected the key to install to be printed:\n%s", got)
	}
}

// TestInspectReportsAMissingDeploymentKey covers a deployment whose key file
// has gone, which otherwise looks like an ordinary connection failure.
func TestInspectReportsAMissingDeploymentKey(t *testing.T) {
	t.Setenv(models.SSHKeyPathEnv, filepath.Join(t.TempDir(), "absent"))

	got := reportFor(t, &models.ProxmoxInstance{
		Name:           testInstanceName,
		ConnectionType: models.ConnectionTypeSSH,
		SSHHost:        testLoopback,
		SSHPort:        22,
		SSHUser:        testSSHUser,
	})
	if !strings.Contains(got, "none at") {
		t.Fatalf("expected the absent key to be named as such:\n%s", got)
	}
}
