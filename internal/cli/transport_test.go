package cli

import (
	"testing"

	"proxpass/internal/models"
)

// TestSSHHostIsDerivedForEveryTransport pins the decision that the console
// transport no longer governs whether the node is reachable.
//
// It used to: `instance add' resolved the SSH host only for the ssh
// transport, so a termproxy instance was stored with an empty ssh_host and
// file transfer was refused on it -- even though the node answers SSH
// perfectly well, and is the same machine either way.
func TestSSHHostIsDerivedForEveryTransport(t *testing.T) {
	for _, transport := range []models.ConsoleTransport{
		models.ConsoleTransportTermProxy,
		models.ConsoleTransportSSH,
	} {
		host, port, err := resolveSSHHostPort("", "https://pve1.example.com:8006", false)
		if err != nil {
			t.Fatalf("%s: %v", transport, err)
		}
		if host != "pve1.example.com" {
			t.Errorf("%s: host = %q, want pve1.example.com", transport, host)
		}
		if port != 22 {
			t.Errorf("%s: port = %d, want 22", transport, port)
		}
	}
}

// TestExplicitSSHHostWins covers the override, including a non-default port.
func TestExplicitSSHHostWins(t *testing.T) {
	host, port, err := resolveSSHHostPort("mgmt.pve1:2222", "https://pve1:8006", false)
	if err != nil {
		t.Fatalf("resolveSSHHostPort: %v", err)
	}
	if host != "mgmt.pve1" || port != 2222 {
		t.Fatalf("got %s:%d, want mgmt.pve1:2222", host, port)
	}
}
