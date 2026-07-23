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

	// Create a mock discoverer factory that returns one running and one stopped guest.
	// Only the running guest must be upserted into the DB.
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

	// The seeded data has 3 running guests + 1 stopped guest (staging, proxmox_id=201).
	// Discovery adds 1 running (newct) and skips 1 stopped (newvm).
	// Stopped guests from the seed are NOT touched by this discovery pass.
	// Total in DB: 3 original running + 1 original stopped + 1 new running = 5.
	if len(guests) != 5 {
		t.Fatalf("expected 5 guests (3 seeded-running + 1 seeded-stopped + 1 new-running), got %d", len(guests))
	}

	// newct (running) must exist; newvm (stopped) must NOT exist
	var foundNewCT, foundNewVM bool
	for _, g := range guests {
		switch g.Name {
		case "newct":
			foundNewCT = true
		case "newvm":
			foundNewVM = true
		}
	}
	if !foundNewCT {
		t.Error("expected running guest 'newct' to be stored, but it was not found")
	}
	if foundNewVM {
		t.Error("expected stopped guest 'newvm' to be skipped, but it was stored")
	}
}

type staticDiscoverer struct {
	guests []*models.Guest
}

func (d *staticDiscoverer) DiscoverGuests(_ context.Context) ([]*models.Guest, error) {
	return d.guests, nil
}
