package ssh

import (
	"strings"
	"testing"

	"proxpass/internal/models"
)

func makeGuests() []*models.Guest {
	return []*models.Guest{
		{ID: 1, Type: models.GuestTypeCT, Name: "webserver", ProxmoxID: 100, InstanceID: 1},
		{ID: 2, Type: models.GuestTypeCT, Name: "database", ProxmoxID: 101, InstanceID: 1},
		{ID: 3, Type: models.GuestTypeVM, Name: "devbox", ProxmoxID: 200, InstanceID: 1},
		{ID: 4, Type: models.GuestTypeVM, Name: "staging", ProxmoxID: 201, InstanceID: 1},
	}
}

func TestResolveGuestByVMID(t *testing.T) {
	guests := makeGuests()
	g, err := resolveGuest("100", guests)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if g.Name != "webserver" {
		t.Errorf("expected webserver, got %s", g.Name)
	}
}

func TestResolveGuestByTypeAndVMID(t *testing.T) {
	guests := makeGuests()

	g, err := resolveGuest("ct101", guests)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if g.Name != "database" {
		t.Errorf("expected database, got %s", g.Name)
	}

	g, err = resolveGuest("VM200", guests)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if g.Name != "devbox" {
		t.Errorf("expected devbox, got %s", g.Name)
	}
}

func TestResolveGuestByName(t *testing.T) {
	guests := makeGuests()

	g, err := resolveGuest("staging", guests)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if g.ProxmoxID != 201 {
		t.Errorf("expected VMID 201, got %d", g.ProxmoxID)
	}
}

func TestResolveGuestByNameCaseInsensitive(t *testing.T) {
	guests := makeGuests()

	g, err := resolveGuest("WebServer", guests)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if g.ID != 1 {
		t.Errorf("expected ID 1, got %d", g.ID)
	}
}

func TestResolveGuestAmbiguousVMID(t *testing.T) {
	guests := []*models.Guest{
		{ID: 1, Type: models.GuestTypeCT, Name: "ct-a", ProxmoxID: 100, InstanceID: 1},
		{ID: 2, Type: models.GuestTypeVM, Name: "vm-a", ProxmoxID: 100, InstanceID: 2},
	}

	_, err := resolveGuest("100", guests)
	if err == nil {
		t.Fatal("expected ambiguity error")
	}
	if !contains(err.Error(), "matches 2 guests") {
		t.Errorf("unexpected error: %v", err)
	}
}

const testAppName = "app"

func TestResolveGuestAmbiguousName(t *testing.T) {
	guests := []*models.Guest{
		{ID: 1, Type: models.GuestTypeCT, Name: testAppName, ProxmoxID: 100, InstanceID: 1},
		{ID: 2, Type: models.GuestTypeVM, Name: testAppName, ProxmoxID: 200, InstanceID: 2},
	}

	_, err := resolveGuest("app", guests)
	if err == nil {
		t.Fatal("expected ambiguity error")
	}
	if !contains(err.Error(), "matches 2 guests") {
		t.Errorf("unexpected error: %v", err)
	}
	if !contains(err.Error(), "ct100") ||
		!contains(err.Error(), "vm200") {
		t.Errorf("expected hints ct100, vm200 in: %v", err)
	}
}

func TestResolveGuestTypeIDDisambiguates(t *testing.T) {
	guests := []*models.Guest{
		{ID: 1, Type: models.GuestTypeCT, Name: testAppName, ProxmoxID: 100, InstanceID: 1},
		{ID: 2, Type: models.GuestTypeVM, Name: testAppName, ProxmoxID: 100, InstanceID: 2},
	}

	g, err := resolveGuest("ct100", guests)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if g.ID != 1 {
		t.Errorf("expected ID 1, got %d", g.ID)
	}

	g, err = resolveGuest("vm100", guests)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if g.ID != 2 {
		t.Errorf("expected ID 2, got %d", g.ID)
	}
}

func TestResolveGuestNotFound(t *testing.T) {
	guests := makeGuests()

	_, err := resolveGuest("nonexistent", guests)
	if err == nil {
		t.Fatal("expected not-found error")
	}
	if !contains(err.Error(), "not found") {
		t.Errorf("unexpected error: %v", err)
	}
}

func contains(s, sub string) bool {
	return strings.Contains(s, sub)
}
