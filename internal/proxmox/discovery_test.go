package proxmox_test

import (
	"context"
	"errors"
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

	// A discovery pass reconciles rather than appends: the guest list is
	// whatever the host currently reports as running. The seeded guests all
	// belong to this same instance and none of them appear in the
	// discoverer's response, so they are pruned as destroyed. Only the new
	// running guest survives; the new stopped one is never stored.
	if len(guests) != 1 {
		t.Fatalf("expected the list to reconcile to 1 running guest, got %d: %v",
			len(guests), guestNames(t, env.Repo))
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

// Pruning must only ever act on a complete guest list. When the Proxmox API
// call fails, discovery must leave the existing guests alone rather than
// treat "no guests reported" as "every guest was destroyed", which would
// wipe the list on a transient network blip.
func TestDiscoveryDoesNotPruneWhenDiscoveryFails(t *testing.T) {
	env := testenv.New(t)

	before := guestNames(t, env.Repo)
	if len(before) == 0 {
		t.Fatal("seed data should contain guests")
	}

	factory := func(_ *models.ProxmoxInstance) proxmox.GuestDiscoverer {
		return &failingDiscoverer{}
	}
	d := proxmox.NewDiscovery(env.Repo, 5*time.Minute, log.New(io.Discard, "", 0), factory)

	// RunOnce surfaces the error...
	if err := d.RunOnce(context.Background()); err == nil {
		t.Fatal("RunOnce must report the discovery failure")
	}
	// ...and must not have touched the guest list.
	if after := guestNames(t, env.Repo); len(after) != len(before) {
		t.Errorf("guests changed from %v to %v after a failed pass", before, after)
	}
}

type failingDiscoverer struct{}

func (d *failingDiscoverer) DiscoverGuests(_ context.Context) ([]*models.Guest, error) {
	return nil, errDiscovery
}

var errDiscovery = errors.New("proxmox unreachable")

type staticDiscoverer struct {
	guests []*models.Guest
}

func (d *staticDiscoverer) DiscoverGuests(_ context.Context) ([]*models.Guest, error) {
	return d.guests, nil
}
