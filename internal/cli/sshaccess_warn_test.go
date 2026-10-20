package cli

import (
	"bytes"
	"strings"
	"testing"

	"proxpass/internal/models"
)

// warnFor runs warnMissingSSHHost with the given key service and returns what
// it printed to ErrOut.
func warnFor(t *testing.T, svc SSHKeyService, inst *models.ProxmoxInstance) string {
	t.Helper()
	var out bytes.Buffer
	warnMissingSSHHost(t.Context(), &Deps{Out: &out, ErrOut: &out, SSHKeys: svc}, inst)
	return out.String()
}

// TestWarnMissingSSHHostWarnsAndShowsTheKey covers the state an instance added
// without --ssh-host lands in: its console may work, but node shell, SFTP and
// file transfer cannot, and the administrator has to both set a host and
// install the key. The warning has to say all of that.
func TestWarnMissingSSHHostWarnsAndShowsTheKey(t *testing.T) {
	svc := &fakeSSHKeys{pub: testPubKey}

	got := warnFor(t, svc, &models.ProxmoxInstance{
		Name:             testInstanceName,
		ConsoleTransport: models.ConsoleTransportTermProxy,
		// SSHHost deliberately empty.
	})

	for _, want := range []string{
		"Warning:",
		"no SSH host",
		"SFTP",
		// The fix must tell them how to set a host...
		"instance update --name " + testInstanceName + " --ssh-host",
		// ...and show the key to install, with where it goes.
		authorizedKeysPath,
		"ssh-",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("warning missing %q:\n%s", want, got)
		}
	}
}

// TestWarnMissingSSHHostIsSilentWhenHostIsSet keeps the warning from firing on
// a perfectly configured instance, so callers can invoke it unconditionally.
func TestWarnMissingSSHHostIsSilentWhenHostIsSet(t *testing.T) {
	svc := &fakeSSHKeys{pub: testPubKey}

	got := warnFor(t, svc, &models.ProxmoxInstance{
		Name:             testInstanceName,
		ConsoleTransport: models.ConsoleTransportSSH,
		SSHHost:          testLoopback,
		SSHPort:          22,
		SSHUser:          testSSHUser,
	})
	if got != "" {
		t.Fatalf("expected no output when the SSH host is set, got:\n%s", got)
	}
}

// TestWarnMissingSSHHostStaysQuietWithoutAKey keeps the warning useful when the
// deployment has no key to show: the host warning still prints, but there is
// no key line to paste.
func TestWarnMissingSSHHostStaysQuietWithoutAKey(t *testing.T) {
	svc := &fakeSSHKeys{pub: ""}

	got := warnFor(t, svc, &models.ProxmoxInstance{
		Name:             testInstanceName,
		ConsoleTransport: models.ConsoleTransportTermProxy,
	})
	if !strings.Contains(got, "no SSH host") {
		t.Fatalf("expected the host warning to still print:\n%s", got)
	}
	if strings.Contains(got, "add proxpass's public key") {
		t.Fatalf("did not expect a key line when there is no key:\n%s", got)
	}
}
