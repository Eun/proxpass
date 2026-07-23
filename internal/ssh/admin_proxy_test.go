package ssh_test

import (
	"strings"
	"testing"
)

// TestAdminProxyWithTypeAndVMID verifies that an admin passing "ct100"
// as the SSH command is proxied directly to CT 180 without showing the CLI.
func TestAdminProxyWithTypeAndVMID(t *testing.T) {
	addr, adminSigner, mp, cancel := setupAdminTest(t)
	defer cancel()

	// The seeded DB has CT "webserver" at ProxmoxID 100.
	// Pass "ct100" as the SSH exec command (not the username).
	output := sshExecOutput(t, addr, "root", "ct100", adminSigner)

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

// TestAdminProxyWithNumericVMID verifies that an admin passing a plain
// numeric VMID as the SSH command is proxied to the right guest.
func TestAdminProxyWithNumericVMID(t *testing.T) {
	addr, adminSigner, mp, cancel := setupAdminTest(t)
	defer cancel()

	// The seeded DB has CT "webserver" at ProxmoxID 100.
	// Pass "100" as the SSH exec command.
	output := sshExecOutput(t, addr, "root", "100", adminSigner)

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

// TestAdminProxyWithGuestName verifies that an admin passing a guest name
// as the SSH command is proxied correctly.
func TestAdminProxyWithGuestName(t *testing.T) {
	addr, adminSigner, mp, cancel := setupAdminTest(t)
	defer cancel()

	// The seeded DB has CT "webserver" at ProxmoxID 100.
	output := sshExecOutput(t, addr, "root", "webserver", adminSigner)

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

// TestAdminProxyWithInstancePrefix verifies that an admin can use
// the instance:identifier format (e.g. "test-pve:ct100").
func TestAdminProxyWithInstancePrefix(t *testing.T) {
	addr, adminSigner, mp, cancel := setupAdminTest(t)
	defer cancel()

	// Seeded instance is named "test-pve".
	// Use "test-pve:ct100" to target it explicitly.
	output := sshExecOutput(t, addr, "root", "test-pve:ct100", adminSigner)

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

// TestAdminProxyUnknownGuestReturnsError verifies that an admin passing
// an unresolvable single-word command receives an error (no CLI help).
func TestAdminProxyUnknownGuestReturnsError(t *testing.T) {
	addr, adminSigner, mp, cancel := setupAdminTest(t)
	defer cancel()

	// "zzz9999" is a single-token command that matches no guest.
	output := sshExecOutput(t, addr, "root", "zzz9999", adminSigner)

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
}

// TestAdminCLIShellShowsGuestList verifies that a plain shell session
// (no exec command) lists available guests instead of the generic --help.
func TestAdminCLIShellShowsGuestList(t *testing.T) {
	addr, adminSigner, mp, cancel := setupAdminTest(t)
	defer cancel()

	// No exec command -> plain shell -> should list guests (same as 'guest ls').
	// Use sshShellOutput which opens a shell session (not exec).
	output := sshShellOutput(t, addr, "admin", adminSigner)

	if strings.Contains(output, "[mock proxy]") {
		t.Errorf("expected guest list, got mock proxy banner; output: %q", output)
	}
	// Seeded guests: webserver, database, devbox, staging
	for _, name := range []string{"webserver", "database", "devbox", "staging"} {
		if !strings.Contains(output, name) {
			t.Errorf("expected guest %q in output, got: %q", name, output)
		}
	}

	sessions := mp.RecordedSessions()
	if len(sessions) != 0 {
		t.Errorf("expected no proxy sessions for plain shell, got %d", len(sessions))
	}
}

// TestAdminCLIMultiWordExecRunsCLI verifies that a multi-word exec command
// (e.g. "guest ls") always runs the CLI and never attempts a proxy.
func TestAdminCLIMultiWordExecRunsCLI(t *testing.T) {
	addr, adminSigner, mp, cancel := setupAdminTest(t)
	defer cancel()

	output := sshExecOutput(t, addr, "admin", "guest ls", adminSigner)

	if strings.Contains(output, "[mock proxy]") {
		t.Errorf("expected CLI output, got mock proxy banner; output: %q", output)
	}

	sessions := mp.RecordedSessions()
	if len(sessions) != 0 {
		t.Errorf("expected no proxy sessions when exec command is given, got %d", len(sessions))
	}

	// the CLI ran: "guest ls" should produce some output
	t.Logf("output for 'guest ls': %q", output)
}

// TestAdminCLIUsernameIsIgnored verifies that the SSH username has no
// effect on routing: the same exec command proxies regardless of username.
func TestAdminCLIUsernameIsIgnored(t *testing.T) {
	addr, adminSigner, mp, cancel := setupAdminTest(t)
	defer cancel()

	for _, username := range []string{"root", "admin", "manage", "ct100", "alice"} {
		username := username
		t.Run(username, func(t *testing.T) {
			output := sshExecOutput(t, addr, username, "ct100", adminSigner)
			if !strings.Contains(output, "[mock proxy]") {
				t.Errorf("username %q: expected proxy banner, got: %q", username, output)
			}
			sessions := mp.RecordedSessions()
			if len(sessions) == 0 {
				t.Errorf("username %q: expected proxy session", username)
			}
		})
	}
}
