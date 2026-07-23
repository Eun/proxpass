package proxmox_test

import (
	"context"
	"testing"

	"proxpass/internal/models"
	"proxpass/internal/proxmox"
	"proxpass/internal/testenv"
)

func TestAPIClientDiscoverGuests(t *testing.T) {
	api := testenv.NewMockAPIServer(testTokenID, "secret123")
	defer api.Close()

	api.AddLXC("node1", 100, "ct1", "running")
	api.AddLXC("node1", 101, "ct2", "stopped")
	api.AddQEMU("node1", 200, "vm1", "running")
	api.AddQEMU("node2", 300, "vm2", "stopped")

	inst := &models.ProxmoxInstance{
		APIURL:         api.URL(),
		APITokenID:     testTokenID,
		APITokenSecret: "secret123",
	}

	client, err := proxmox.NewAPIClient(inst)
	if err != nil {
		t.Fatalf("NewAPIClient: %v", err)
	}
	guests, err := client.DiscoverGuests(context.Background())
	if err != nil {
		t.Fatalf("DiscoverGuests: %v", err)
	}

	if len(guests) != 4 {
		t.Fatalf("expected 4 guests, got %d", len(guests))
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
		t.Errorf("expected 2 CTs, got %d", ctCount)
	}
	if vmCount != 2 {
		t.Errorf("expected 2 VMs, got %d", vmCount)
	}
}

func TestAPIClientBadAuth(t *testing.T) {
	api := testenv.NewMockAPIServer(testTokenID, "secret123")
	defer api.Close()

	api.AddLXC("node1", 100, "ct1", "running")

	inst := &models.ProxmoxInstance{
		APIURL:         api.URL(),
		APITokenID:     "wrong",
		APITokenSecret: "wrong",
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
