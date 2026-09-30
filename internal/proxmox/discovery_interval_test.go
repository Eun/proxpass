package proxmox_test

import (
	"context"
	"io"
	"log"
	"sync"
	"testing"
	"time"

	"proxpass/internal/db"
	"proxpass/internal/models"
	"proxpass/internal/proxmox"
)

// fakeDiscoverer returns whatever guest list the test currently wants, and
// counts how many times it was polled.
type fakeDiscoverer struct {
	mu     sync.Mutex
	guests []*models.Guest
	calls  int
}

func (f *fakeDiscoverer) DiscoverGuests(_ context.Context) ([]*models.Guest, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	out := make([]*models.Guest, len(f.guests))
	for i, g := range f.guests {
		cp := *g
		out[i] = &cp
	}
	return out, nil
}

func (f *fakeDiscoverer) set(guests ...*models.Guest) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.guests = guests
}

func (f *fakeDiscoverer) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// pollInterval is short so the loop ticks several times per test.
const pollInterval = 50 * time.Millisecond

const (
	gWeb = "web"
	gDB  = "db"
	node = "pve"
)

func discoveryEnv(t *testing.T, fake *fakeDiscoverer) (db.Repository, *proxmox.Discovery) {
	t.Helper()
	repo, err := db.NewSQLiteRepository(t.TempDir() + "/d.db")
	if err != nil {
		t.Fatalf("open repository: %v", err)
	}
	t.Cleanup(func() { _ = repo.Close() })

	inst := &models.ProxmoxInstance{
		Name: node, APIURL: "https://pve:8006", Node: node,
		ConnectionType: models.ConnectionTypeTermProxy,
	}
	if err := repo.AddProxmoxInstance(t.Context(), inst); err != nil {
		t.Fatalf("add instance: %v", err)
	}

	d := proxmox.NewDiscovery(repo, pollInterval, log.New(io.Discard, "", 0),
		func(*models.ProxmoxInstance) proxmox.GuestDiscoverer { return fake })
	return repo, d
}

func guestNames(t *testing.T, repo db.Repository) []string {
	t.Helper()
	guests, err := repo.ListGuests(t.Context())
	if err != nil {
		t.Fatalf("list guests: %v", err)
	}
	names := make([]string, 0, len(guests))
	for _, g := range guests {
		names = append(names, g.Name)
	}
	return names
}

// The loop must poll repeatedly on its interval, not just once at startup.
func TestDiscoveryRunsOnInterval(t *testing.T) {
	fake := &fakeDiscoverer{}
	fake.set(&models.Guest{
		Type: models.GuestTypeCT, Name: gWeb,
		Status: models.StatusRunning, ProxmoxID: 100,
	})
	_, d := discoveryEnv(t, fake)

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { d.Run(ctx); close(done) }()

	// One immediate pass plus several ticks.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && fake.callCount() < 3 {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done

	if got := fake.callCount(); got < 3 {
		t.Errorf("discovery polled %d times, want at least 3 (an immediate pass plus ticks)", got)
	}
}

// A guest that appears on the host later must show up without a restart.
func TestDiscoveryPicksUpNewGuests(t *testing.T) {
	fake := &fakeDiscoverer{}
	fake.set(&models.Guest{
		Type: models.GuestTypeCT, Name: gWeb,
		Status: models.StatusRunning, ProxmoxID: 100,
	})
	repo, d := discoveryEnv(t, fake)

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { d.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()

	waitForGuestCount(t, repo, 1)

	// A new container is created on the Proxmox host.
	fake.set(
		&models.Guest{Type: models.GuestTypeCT, Name: gWeb, Status: models.StatusRunning, ProxmoxID: 100},
		&models.Guest{Type: models.GuestTypeCT, Name: gDB, Status: models.StatusRunning, ProxmoxID: 101},
	)
	waitForGuestCount(t, repo, 2)
}

// A guest that stops must not linger as connectable: pct enter and
// qm terminal both fail against a stopped guest, so offering it in the
// picker is a dead end.
func TestDiscoveryRemovesStoppedGuests(t *testing.T) {
	fake := &fakeDiscoverer{}
	fake.set(
		&models.Guest{Type: models.GuestTypeCT, Name: gWeb, Status: models.StatusRunning, ProxmoxID: 100},
		&models.Guest{Type: models.GuestTypeCT, Name: gDB, Status: models.StatusRunning, ProxmoxID: 101},
	)
	repo, d := discoveryEnv(t, fake)

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { d.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()

	waitForGuestCount(t, repo, 2)

	// "db" is shut down on the host.
	fake.set(
		&models.Guest{Type: models.GuestTypeCT, Name: gWeb, Status: models.StatusRunning, ProxmoxID: 100},
		&models.Guest{Type: models.GuestTypeCT, Name: gDB, Status: models.StatusStopped, ProxmoxID: 101},
	)
	waitForGuestCount(t, repo, 1)

	if names := guestNames(t, repo); len(names) != 1 || names[0] != gWeb {
		t.Errorf("guests = %v, want only [%s]", names, gWeb)
	}
}

// A guest destroyed on the host must disappear from the list.
func TestDiscoveryRemovesDeletedGuests(t *testing.T) {
	fake := &fakeDiscoverer{}
	fake.set(
		&models.Guest{Type: models.GuestTypeCT, Name: gWeb, Status: models.StatusRunning, ProxmoxID: 100},
		&models.Guest{Type: models.GuestTypeCT, Name: gDB, Status: models.StatusRunning, ProxmoxID: 101},
	)
	repo, d := discoveryEnv(t, fake)

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { d.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()

	waitForGuestCount(t, repo, 2)

	// "db" is destroyed: it is simply absent from the host's response.
	fake.set(&models.Guest{
		Type: models.GuestTypeCT, Name: gWeb,
		Status: models.StatusRunning, ProxmoxID: 100,
	})
	waitForGuestCount(t, repo, 1)

	if names := guestNames(t, repo); len(names) != 1 || names[0] != gWeb {
		t.Errorf("guests = %v, want only [%s]", names, gWeb)
	}
}

// A renamed guest must not appear twice.
func TestDiscoveryHandlesRename(t *testing.T) {
	fake := &fakeDiscoverer{}
	fake.set(&models.Guest{
		Type: models.GuestTypeCT, Name: gWeb,
		Status: models.StatusRunning, ProxmoxID: 100,
	})
	repo, d := discoveryEnv(t, fake)

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { d.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()

	waitForGuestCount(t, repo, 1)

	fake.set(&models.Guest{
		Type: models.GuestTypeCT, Name: "webserver",
		Status: models.StatusRunning, ProxmoxID: 100,
	})

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if names := guestNames(t, repo); len(names) == 1 && names[0] == "webserver" {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Errorf("guests = %v, want exactly [webserver] after a rename", guestNames(t, repo))
}

func waitForGuestCount(t *testing.T, repo db.Repository, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if len(guestNames(t, repo)) == want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("guests = %v, want %d of them", guestNames(t, repo), want)
}
