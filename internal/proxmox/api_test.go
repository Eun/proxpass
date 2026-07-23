package proxmox_test

import (
	"context"
	"testing"

	"proxpass/internal/models"
	"proxpass/internal/proxmox"
	"proxpass/internal/testenv"
)

const (
	testTokenSecret = "secret123"
	testNode1       = "node1"
)

func TestAPIClientDiscoverGuests(t *testing.T) {
	api := testenv.NewMockAPIServer(testTokenID, testTokenSecret)
	defer api.Close()

	// node1 has 2 CTs and 1 VM; node2 has 1 VM.
	// When SSHHost="node1", DiscoverGuests must only return node1's guests.
	api.AddLXC(testNode1, 100, "ct1", "running")
	api.AddLXC(testNode1, 101, "ct2", "stopped")
	api.AddQEMU(testNode1, 200, "vm1", "running")
	api.AddQEMU("node2", 300, "vm2", "running") // different node — must not appear

	inst := &models.ProxmoxInstance{
		APIURL:         api.URL(),
		APITokenID:     testTokenID,
		APITokenSecret: testTokenSecret,
		SSHHost:        testNode1, // scope discovery to node1 only
	}

	client, err := proxmox.NewAPIClient(inst)
	if err != nil {
		t.Fatalf("NewAPIClient: %v", err)
	}
	guests, err := client.DiscoverGuests(context.Background())
	if err != nil {
		t.Fatalf("DiscoverGuests: %v", err)
	}

	// Only node1 guests: 2 CTs + 1 VM = 3 total.
	// (node2's vm2 must not appear regardless of status)
	if len(guests) != 3 {
		t.Fatalf("expected 3 guests from node1, got %d", len(guests))
	}

	ctCount, vmCount := 0, 0
	for _, g := range guests {
		switch g.Type {
		case models.GuestTypeCT:
			ctCount++
		case models.GuestTypeVM:
			vmCount++
		}
	}
	if ctCount != 2 {
		t.Errorf("expected 2 CTs from node1, got %d", ctCount)
	}
	if vmCount != 1 {
		t.Errorf("expected 1 VM from node1, got %d", vmCount)
	}
}

// TestAPIClientDiscoverGuestsFQDN verifies that SSHHost as a FQDN resolves
// to the correct short Proxmox node name via FQDN-prefix matching.
func TestAPIClientDiscoverGuestsFQDN(t *testing.T) {
	api := testenv.NewMockAPIServer(testTokenID, testTokenSecret)
	defer api.Close()

	api.AddLXC("rome", 100, "ct1", "running")
	api.AddQEMU("london", 200, "vm1", "running") // different node — must not appear

	inst := &models.ProxmoxInstance{
		APIURL:         api.URL(),
		APITokenID:     testTokenID,
		APITokenSecret: testTokenSecret,
		// FQDN: should match node "rome" via prefix "rome."
		SSHHost: "rome.erika.salzmann.berlin",
	}

	client, err := proxmox.NewAPIClient(inst)
	if err != nil {
		t.Fatalf("NewAPIClient: %v", err)
	}
	guests, err := client.DiscoverGuests(context.Background())
	if err != nil {
		t.Fatalf("DiscoverGuests: %v", err)
	}

	if len(guests) != 1 {
		t.Fatalf("expected 1 guest from node rome, got %d", len(guests))
	}
	if guests[0].Name != "ct1" {
		t.Errorf("expected guest ct1, got %s", guests[0].Name)
	}
}

func TestAPIClientBadAuth(t *testing.T) {
	api := testenv.NewMockAPIServer(testTokenID, testTokenSecret)
	defer api.Close()

	api.AddLXC(testNode1, 100, "ct1", "running")

	inst := &models.ProxmoxInstance{
		APIURL:         api.URL(),
		APITokenID:     "wrong",
		APITokenSecret: "wrong",
		SSHHost:        testNode1,
	}

	client, err := proxmox.NewAPIClient(inst)
	if err != nil {
		t.Fatalf("NewAPIClient: %v", err)
	}
	_, err = client.DiscoverGuests(context.Background())
	if err == nil {
		t.Fatal("expected auth error, got nil")
	}
}

func TestNewAPIClientURLValidation(t *testing.T) {
	tests := []struct {
		name    string
		apiURL  string
		wantErr bool
	}{
		{"valid https with port", "https://pve:8006", false},
		{"valid http with port", "http://pve:8006", false},
		{"valid https trailing slash", "https://pve:8006/", false},
		{"missing scheme — port silently lost", "pve:8006", true},
		{"missing scheme no port", "pve", true},
		{"empty string", "", true},
		{"scheme-relative", "//pve:8006", true},
		{"ftp scheme", "ftp://pve:8006", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inst := &models.ProxmoxInstance{
				APIURL:         tt.apiURL,
				APITokenID:     testTokenID,
				APITokenSecret: "secret",
			}
			_, err := proxmox.NewAPIClient(inst)
			if tt.wantErr && err == nil {
				t.Errorf("expected error for api-url %q, got nil", tt.apiURL)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error for api-url %q: %v", tt.apiURL, err)
			}
		})
	}
}

// TestCreateTermProxyTicket verifies that CreateTermProxyTicket POSTs to the
// correct endpoint and correctly parses the ticket/port from the response.
func TestCreateTermProxyTicket(t *testing.T) {
	api := testenv.NewMockAPIServer(testTokenID, testTokenSecret)
	defer api.Close()
	api.AddLXC(testNode1, 100, "ct1", "running")
	// Register a termproxy response for vmid 100 on node1.
	api.AddTermProxy(testNode1, "lxc", 100, "TICKET123", 5900)

	inst := &models.ProxmoxInstance{
		APIURL:         api.URL(),
		APITokenID:     testTokenID,
		APITokenSecret: testTokenSecret,
		SSHHost:        testNode1,
		Node:           testNode1,
	}
	client, err := proxmox.NewAPIClient(inst)
	if err != nil {
		t.Fatalf("NewAPIClient: %v", err)
	}

	guest := &models.Guest{Type: models.GuestTypeCT, ProxmoxID: 100}
	ticket, err := client.CreateTermProxyTicket(context.Background(), "node1", guest)
	if err != nil {
		t.Fatalf("CreateTermProxyTicket: %v", err)
	}
	if ticket.Ticket != "TICKET123" {
		t.Errorf("ticket: got %q, want %q", ticket.Ticket, "TICKET123")
	}
	if ticket.Port != 5900 {
		t.Errorf("port: got %d, want %d", ticket.Port, 5900)
	}
}

// TestResolveNodeNameLocalNode verifies that ResolveNodeName with no sshHost
// returns the node marked local=1 in the cluster/status response — even when
// the cluster has multiple nodes.
func TestResolveNodeNameLocalNode(t *testing.T) {
	api := testenv.NewMockAPIServer(testTokenID, testTokenSecret)
	defer api.Close()
	api.AddLXC("oslo", 100, "ct1", "running")
	api.AddLXC("rome", 200, "ct2", "running")
	api.AddLXC("paris", 300, "ct3", "running")
	// Simulate --api-url pointing at "rome".
	api.SetLocalNode("rome")

	inst := &models.ProxmoxInstance{
		APIURL:         api.URL(),
		APITokenID:     testTokenID,
		APITokenSecret: testTokenSecret,
	}
	client, err := proxmox.NewAPIClient(inst)
	if err != nil {
		t.Fatalf("NewAPIClient: %v", err)
	}

	node, err := client.ResolveNodeName(context.Background(), "")
	if err != nil {
		t.Fatalf("ResolveNodeName: %v", err)
	}
	if node != "rome" {
		t.Errorf("node: got %q, want %q", node, "rome")
	}
}
