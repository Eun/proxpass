package ssh_test

import (
	"strings"
	"testing"
)

// TestClientProxyWithTypeAndVMID verifies that a client passing "ct100"
// as the SSH command is proxied directly to CT 100.
func TestClientProxyWithTypeAndVMID(t *testing.T) {
	addr, clientSigner, mp, cancel := setupClientTest(t)
	defer cancel()

	// The seeded DB has CT "webserver" at ProxmoxID 100.
	// Pass "ct100" as the SSH exec command (username does not matter).
	output := sshExecOutput(t, addr, "alice", "ct100", clientSigner)

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

// TestClientProxyWithNumericVMID verifies that a client can use
// a plain numeric VMID as the SSH command.
func TestClientProxyWithNumericVMID(t *testing.T) {
	addr, clientSigner, mp, cancel := setupClientTest(t)
	defer cancel()

	output := sshExecOutput(t, addr, "alice", "100", clientSigner)

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

// TestClientProxyWithGuestName verifies that a client can use
// a guest name as the SSH command.
func TestClientProxyWithGuestName(t *testing.T) {
	addr, clientSigner, mp, cancel := setupClientTest(t)
	defer cancel()

	output := sshExecOutput(t, addr, "alice", "webserver", clientSigner)

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

// TestClientProxyWithInstancePrefix verifies that a client can use
// the instance:identifier format.
func TestClientProxyWithInstancePrefix(t *testing.T) {
	addr, clientSigner, mp, cancel := setupClientTest(t)
	defer cancel()

	// Seeded instance is named "test-pve".
	output := sshExecOutput(t, addr, "alice", "test-pve:ct100", clientSigner)

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

// TestClientUnknownGstReturnsError verifies that a client passing
// an unresolvable guest identifier gets an error, not a panic.
func TestClientUnknownGstReturnsError(t *testing.T) {
	addr, clientSigner, mp, cancel := setupClientTest(t)
	defer cancel()

	output := sshExecErroutput(t, addr, "alice", "zzz9999", clientSigner)

	if strings.Contains(output, "[mock proxy]") {
		t.Errorf("did not expect proxy banner for unknown guest; output: %q", output)
	}

	sessions := mp.RecordedSessions()
	if len(sessions) != 0 {
		t.Errorf("expected no proxy sessions for unknown guest, got %d", len(sessions))
	}
}

// TestClientNoAccessReturnsError verifies that a client is denied access
// to a guest they do not have permission for.
func TestClientNoAccessReturnsError(t *testing.T) {
	addr, clientSigner, mp, cancel := setupClientTest(t)
	defer cancel()

	// "database" (ct101) is in the DB but alice has no direct or group access to it.
	output := sshExecErroutput(t, addr, "alice", "database", clientSigner)

	if strings.Contains(output, "[mock proxy]") {
		t.Errorf("did not expect proxy banner for denied guest; output: %q", output)
	}

	sessions := mp.RecordedSessions()
	if len(sessions) != 0 {
		t.Errorf("expected no proxy sessions for denied guest, got %d", len(sessions))
	}
}

// TestClientShellWithoutCommandShowsHelp verifies that a plain shell
// session (no exec command) writes a usage message and exits.
func TestClientShellWithoutCommandShowsHelp(t *testing.T) {
	addr, clientSigner, mp, cancel := setupClientTest(t)
	defer cancel()

	// No exec command: plain shell. The client should receive a usage message.
	output := sshShellStderrOutput(t, addr, "alice", clientSigner)

	if strings.Contains(output, "[mock proxy]") {
		t.Errorf("did not expect proxy banner for plain shell; output: %q", output)
	}
	if !strings.Contains(output, "Usage:") && !strings.Contains(output, "identifier") {
		t.Errorf("expected usage message for plain shell, got: %q", output)
	}

	sessions := mp.RecordedSessions()
	if len(sessions) != 0 {
		t.Errorf("expected no proxy sessions for plain shell, got %d", len(sessions))
	}
}
