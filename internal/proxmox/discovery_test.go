package proxmox_test

import (
	"context"
	"io"
	"log"
	"testing"
	"time"

	"proxpass/internal/models"
	"proxpass/internal/proxmox"
	"proxpass/internal/testenv"
)

func TestDiscoveryRunOnce(t *testing.T) {
	env := testenv.New(t)

	// Create a mock discoverer factory that returns static guests
	factory := func(_ *models.ProxmoxInstance) proxmox.GuestDiscoverer {
		return &staticDiscoverer{guests: []*models.Guest{
			{Type: models.GuestTypeCT, ProxmoxID: 300, Name: "newct", Status: models.StatusRunning},
			{Type: models.GuestTypeVM, ProxmoxID: 400, Name: "newvm", Status: models.StatusStopped},
		}}
	}

	d := proxmox.NewDiscovery(env.Repo, 5*time.Minute, log.New(io.Discard, "", 0), factory)

	if err := d.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}

	// Verify guests were upserted
	guests, err := env.Repo.ListGuests(context.Background())
	if err != nil {
		t.Fatalf("ListGuests: %v", err)
	}

	// Should have original 4 seeded + 2 new = 6
	if len(guests) != 6 {
		t.Fatalf("expected 6 guests, got %d", len(guests))
	}

	// Check the new ones exist
	found := 0
	for _, g := range guests {
		if g.Name == "newct" || g.Name == "newvm" {
			found++
		}
	}
	if found != 2 {
		t.Fatalf("expected 2 new guests, found %d", found)
	}
}

type staticDiscoverer struct {
	guests []*models.Guest
}

func (d *staticDiscoverer) DiscoverGuests(_ context.Context) ([]*models.Guest, error) {
	return d.guests, nil
}
