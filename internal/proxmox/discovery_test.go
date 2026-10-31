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

// blockingDiscoverer stands in for a down/black-holed node: it never returns
// until the context is canceled, exactly as an unbounded network call to a dead
// host would hang.
type blockingDiscoverer struct{}

func (d *blockingDiscoverer) DiscoverGuests(ctx context.Context) ([]*models.Guest, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

// A single down instance must not prevent discovery of the healthy ones. Before
// the fix, RunOnce iterated instances sequentially and the REST client had no
// timeout, so one black-holed node stalled the whole pass and left every node's
// guest cache stale. Now the instances are discovered concurrently, so the
// healthy node's guests are stored even while the dead one blocks until the
// context deadline.
func TestRunOnceOneDeadInstanceDoesNotBlockTheOthers(t *testing.T) {
	env := testenv.New(t)

	// Add a SECOND instance beside the seeded one. The seeded instance will be
	// the healthy one; this new instance will be the "dead" one that blocks.
	dead := &models.ProxmoxInstance{
		Name:       "dead-node",
		APIURL:     "https://dead.invalid:8006",
		APITokenID: "t", APITokenSecret: "s",
		Node: "dead", SSHHost: "dead.invalid", SSHPort: 22, SSHUser: "root",
	}
	if err := env.Repo.AddProxmoxInstance(context.Background(), dead); err != nil {
		t.Fatalf("add dead instance: %v", err)
	}
	healthyID := env.Seed.Instance.ID

	factory := func(inst *models.ProxmoxInstance) proxmox.GuestDiscoverer {
		if inst.ID == healthyID {
			return &staticDiscoverer{guests: []*models.Guest{
				{Type: models.GuestTypeCT, ProxmoxID: 500, Name: "alive", Status: models.StatusRunning},
			}}
		}
		return &blockingDiscoverer{}
	}

	d := proxmox.NewDiscovery(env.Repo, 5*time.Minute, log.New(io.Discard, "", 0), factory)

	// Bound the pass: the dead instance blocks until this deadline, the healthy
	// one must finish well within it. If discovery were still serial (and the
	// dead instance were iterated first), the healthy guest would never be
	// stored before the deadline and this test would fail.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	start := time.Now()
	_ = d.RunOnce(ctx) // returns the dead instance's ctx error; that is expected
	elapsed := time.Since(start)

	// The healthy instance's guest must be present despite the dead one.
	var foundAlive bool
	for _, g := range guestNames(t, env.Repo) {
		if g == "alive" {
			foundAlive = true
		}
	}
	if !foundAlive {
		t.Fatalf("healthy instance's guest 'alive' was not stored (a dead node blocked the pass); got %v",
			guestNames(t, env.Repo))
	}
	// Sanity: the pass should not have returned before the healthy work was done,
	// nor hung past the deadline.
	if elapsed > 3*time.Second {
		t.Errorf("RunOnce took %s, expected it to be bounded by the 2s context", elapsed)
	}
}
