package cli

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"proxpass/internal/models"
)

// reportFor runs reportSSHKey with the given key service and returns what it
// printed.
func reportFor(t *testing.T, svc SSHKeyService, inst *models.ProxmoxInstance) string {
	t.Helper()
	var out bytes.Buffer
	reportSSHKey(t.Context(), &Deps{Out: &out, ErrOut: &out, SSHKeys: svc}, inst)
	return out.String()
}

func sshInstance() *models.ProxmoxInstance {
	return &models.ProxmoxInstance{
		Name:             testInstanceName,
		ConsoleTransport: models.ConsoleTransportSSH,
		SSHHost:          testLoopback,
		SSHPort:          22,
		SSHUser:          testSSHUser,
	}
}

// TestInspectReportsAccessOnceTheKeyIsInstalled is what the administrator
// runs to confirm the key landed, which is what the README tells them to do.
func TestInspectReportsAccessOnceTheKeyIsInstalled(t *testing.T) {
	svc := &fakeSSHKeys{pub: testPubKey, path: testKeyPath}

	got := reportFor(t, svc, sshInstance())
	if !strings.Contains(got, "SSH Access:       ok") {
		t.Fatalf("expected the deployment key to open the host:\n%s", got)
	}
	if !strings.Contains(got, testKeyPath) {
		t.Fatalf("expected the report to name the key file:\n%s", got)
	}
	if !strings.Contains(got, "SSH Public Key:   ssh-") {
		t.Fatalf("expected the public key to be printed for installation:\n%s", got)
	}
}

// TestInspectReportsTheKeyIsNotInstalledYet is the state between adding an
// instance and installing the key, and must say what to do about it.
func TestInspectReportsTheKeyIsNotInstalledYet(t *testing.T) {
	svc := &fakeSSHKeys{
		pub:      testPubKey,
		path:     testKeyPath,
		reachErr: errors.New("authenticating as root: ssh: unable to authenticate"),
	}

	got := reportFor(t, svc, sshInstance())
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
	svc := &fakeSSHKeys{pub: "", path: testKeyPath}

	got := reportFor(t, svc, sshInstance())
	if !strings.Contains(got, "none at") {
		t.Fatalf("expected the absent key to be named as such:\n%s", got)
	}
}

// TestInspectReportsAKeyServiceError surfaces a failure to reach `proxpass
// serve' for the key, rather than silently claiming there is none.
func TestInspectReportsAKeyServiceError(t *testing.T) {
	svc := &fakeSSHKeys{err: errors.New("reaching the proxpass API")}

	got := reportFor(t, svc, sshInstance())
	if !strings.Contains(got, "SSH Key:") || !strings.Contains(got, "reaching the proxpass API") {
		t.Fatalf("expected the key service error to be reported:\n%s", got)
	}
}
