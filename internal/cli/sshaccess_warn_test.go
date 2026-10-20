package cli

import (
	"bytes"
	"strings"
	"testing"

	"proxpass/internal/models"
	"proxpass/internal/testenv"
)

// warnFor runs warnMissingSSHHost and returns what it printed to ErrOut.
func warnFor(t *testing.T, inst *models.ProxmoxInstance) string {
	t.Helper()
	var out bytes.Buffer
	warnMissingSSHHost(&Deps{Out: &out, ErrOut: &out}, inst)
	return out.String()
}

// TestWarnMissingSSHHostWarnsAndShowsTheKey covers the state an instance added
// without --ssh-host lands in: its console may work, but node shell, SFTP and
// file transfer cannot, and the administrator has to both set a host and
// install the key. The warning has to say all of that.
func TestWarnMissingSSHHostWarnsAndShowsTheKey(t *testing.T) {
	// A real key so publicKeyLine has something to print.
	srv, err := testenv.NewMockSSHServer()
	if err != nil {
		t.Fatalf("starting the mock host: %v", err)
	}
	defer srv.Close()
	keyPath := writeKeyFile(t, readKey(t, srv.KeyPath))
	t.Setenv(models.SSHKeyPathEnv, keyPath)

	got := warnFor(t, &models.ProxmoxInstance{
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
	got := warnFor(t, &models.ProxmoxInstance{
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
