package cli

import (
	"testing"
)

// TestSSHHostIsNeverDerivedFromURL pins the decision that the SSH host is
// never derived from the API URL. An omitted --ssh-host leaves the instance
// with no SSH host (empty host, zero port) rather than guessing one from the
// URL hostname.
//
// It used to derive the host from --url, which broke whenever the API address
// was a bare IP or an alias that does not resolve from where proxpass runs.
func TestSSHHostIsNeverDerivedFromURL(t *testing.T) {
	host, port, err := parseExplicitSSHHost("")
	if err != nil {
		t.Fatalf("parseExplicitSSHHost: %v", err)
	}
	if host != "" {
		t.Errorf("host = %q, want empty", host)
	}
	if port != 0 {
		t.Errorf("port = %d, want 0", port)
	}
}

// TestExplicitSSHHost covers an explicit host without a port (defaults to 22).
func TestExplicitSSHHost(t *testing.T) {
	host, port, err := parseExplicitSSHHost("mgmt.pve1")
	if err != nil {
		t.Fatalf("parseExplicitSSHHost: %v", err)
	}
	if host != "mgmt.pve1" || port != 22 {
		t.Fatalf("got %s:%d, want mgmt.pve1:22", host, port)
	}
}

// TestExplicitSSHHostWithPort covers an explicit "host:port".
func TestExplicitSSHHostWithPort(t *testing.T) {
	host, port, err := parseExplicitSSHHost("mgmt.pve1:2222")
	if err != nil {
		t.Fatalf("parseExplicitSSHHost: %v", err)
	}
	if host != "mgmt.pve1" || port != 2222 {
		t.Fatalf("got %s:%d, want mgmt.pve1:2222", host, port)
	}
}
