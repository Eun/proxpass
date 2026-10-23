package cli

import (
	"strings"
	"testing"

	"proxpass/internal/db"
	"proxpass/internal/models"
	"proxpass/internal/testenv"
)

// TestConfiguredTLS covers the pure, no-network TLS summary shown by
// `instance ls`.
func TestConfiguredTLS(t *testing.T) {
	cases := []struct {
		name     string
		url      string
		insecure bool
		want     string
	}{
		{"https verified", "https://pve:8006", false, statusVerified},
		{"https insecure", "https://pve:8006", true, statusInsecure},
		{"plain http", "http://pve:8006", false, "off (http)"},
		{"uppercase scheme", "HTTPS://pve:8006", false, statusVerified},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := configuredTLS(&models.ProxmoxInstance{APIURL: tc.url, InsecureTLS: tc.insecure})
			if got != tc.want {
				t.Fatalf("configuredTLS = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestConfiguredSSH covers the pure, no-network SSH summary shown by
// `instance ls`.
func TestConfiguredSSH(t *testing.T) {
	cases := []struct {
		name string
		inst *models.ProxmoxInstance
		want string
	}{
		{"no host", &models.ProxmoxInstance{SSHHost: ""}, "SSH: not configured"},
		{"sshfp", &models.ProxmoxInstance{SSHHost: testInstanceName, SSHPort: 22}, "SSH: pve:22 (sshfp)"},
		{"pinned", &models.ProxmoxInstance{
			SSHHost: testInstanceName, SSHPort: 22,
			SSHFingerprints: []string{"SHA256:x"},
		}, "SSH: pve:22 (pinned)"},
		{"insecure", &models.ProxmoxInstance{SSHHost: testInstanceName, SSHPort: 2222, InsecureSSH: true}, "SSH: pve:2222 (insecure)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := configuredSSH(tc.inst); got != tc.want {
				t.Fatalf("configuredSSH = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestInstanceLsShowsConfiguredStatus drives the real `instance ls` command and
// checks it reports configured TLS + SSH without touching the network (the
// seeded host is unreachable, and ls must not try to reach it).
func TestInstanceLsShowsConfiguredStatus(t *testing.T) {
	repo, _ := seedInstance(t) // https://pve1:8006, SSHHost pve1:22, verified
	out, err := runCLI(t, repo, cmdInstance, "ls")
	if err != nil {
		t.Fatalf("ls: %v", err)
	}
	for _, want := range []string{testInstName, "TLS: verified", "SSH: pve1:22 (sshfp)"} {
		if !strings.Contains(out, want) {
			t.Fatalf("ls output missing %q:\n%s", want, out)
		}
	}
}

// TestInstanceInspectProbesTLS drives the real `instance inspect` command
// against a self-signed mock API and checks that the live TLS probe reports a
// working connection when the instance is insecure (so the self-signed cert is
// accepted).
func TestInstanceInspectProbesTLS(t *testing.T) {
	api := testenv.NewMockAPIServer(testAPITokenID, testAPITokenSecret)
	defer api.Close()
	api.AddLXC(testInstName, 100, "ct1", "running")

	repo, err := db.NewRepository(t.TempDir() + "/p.db")
	if err != nil {
		t.Fatalf("opening the repository: %v", err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	inst := &models.ProxmoxInstance{
		Name:             testInstName,
		APIURL:           api.URL(), // https, self-signed
		APITokenID:       testAPITokenID,
		APITokenSecret:   testAPITokenSecret,
		ConsoleTransport: models.ConsoleTransportTermProxy,
		Node:             testInstName,
		InsecureTLS:      true, // accept the self-signed mock cert
	}
	if err := repo.AddProxmoxInstance(t.Context(), inst); err != nil {
		t.Fatalf("seeding: %v", err)
	}

	out, err := runCLI(t, repo, cmdInstance, cmdInspect, testInstName)
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	if !strings.Contains(out, "TLS Connection:   ok") {
		t.Fatalf("expected a working TLS probe, got:\n%s", out)
	}
	// With no SSH host, inspect should say SSH is not configured.
	if !strings.Contains(out, "SSH:              not configured") {
		t.Fatalf("expected SSH not configured, got:\n%s", out)
	}
}

// TestInstanceInspectReportsCertFailure checks the live probe flags an
// untrusted certificate when the instance is NOT insecure.
func TestInstanceInspectReportsCertFailure(t *testing.T) {
	api := testenv.NewMockAPIServer(testAPITokenID, testAPITokenSecret)
	defer api.Close()

	repo, err := db.NewRepository(t.TempDir() + "/p.db")
	if err != nil {
		t.Fatalf("opening the repository: %v", err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	inst := &models.ProxmoxInstance{
		Name:             testInstName,
		APIURL:           api.URL(),
		APITokenID:       testAPITokenID,
		APITokenSecret:   testAPITokenSecret,
		ConsoleTransport: models.ConsoleTransportTermProxy,
		Node:             testInstName,
		InsecureTLS:      false, // verify -> self-signed cert must be flagged
	}
	if err := repo.AddProxmoxInstance(t.Context(), inst); err != nil {
		t.Fatalf("seeding: %v", err)
	}

	out, err := runCLI(t, repo, cmdInstance, cmdInspect, testInstName)
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	if !strings.Contains(out, "certificate not trusted") {
		t.Fatalf("expected a certificate failure, got:\n%s", out)
	}
}
