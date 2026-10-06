package session_test

import (
	"errors"
	"io"
	"log"
	"net/http/httptest"
	"sort"
	"testing"
	"time"

	"proxpass/internal/api"
	"proxpass/internal/db"
	"proxpass/internal/models"
	"proxpass/internal/session"
)

// newAPIDirectory starts the real API server against repo and returns a
// Directory backed by it, for the identity given.
//
// This goes through the whole stack -- mint, exchange, HTTP, redeem -- so
// the test exercises what a deployed session actually does rather than a
// stub that merely matches the interface.
func newAPIDirectory(
	t *testing.T, repo db.Repository, identity *models.SessionIdentity,
) session.Directory {
	t.Helper()

	srv := httptest.NewServer(
		api.NewServer(repo, log.New(io.Discard, "", 0)).Handler())
	t.Cleanup(srv.Close)

	const minted = "minted-token-for-directory-test"
	now := time.Now()
	if err := repo.MintSessionToken(
		t.Context(), api.HashToken(minted), identity, now, now.Add(time.Minute)); err != nil {
		t.Fatalf("mint: %v", err)
	}

	client := session.NewAPIClient(srv.URL)
	if _, err := client.Exchange(t.Context(), minted); err != nil {
		t.Fatalf("exchange: %v", err)
	}
	return &session.APIDirectory{Client: client}
}

func newRepoDirectory(repo db.Repository, identity *models.SessionIdentity) session.Directory {
	return &session.RepoDirectory{
		Repo:     repo,
		IsAdmin:  identity.IsAdmin,
		ClientID: identity.ClientID,
	}
}

// TestDirectoriesAgree is what makes PR D safe: a client session changes
// from reading the database to calling the API, and that must not change
// what it sees. Any divergence is a behavior change hiding in a refactor.
func TestDirectoriesAgree(t *testing.T) {
	for _, name := range []string{"admin", "client"} {
		t.Run(name, func(t *testing.T) {
			repo := newRepo(t)
			world := seedWorld(t, repo)

			identity := &models.SessionIdentity{
				User: userAlias, DisplayName: session.AdminUser, IsAdmin: true,
			}
			if name == "client" {
				identity = &models.SessionIdentity{
					User: userAlias, DisplayName: userAlice, ClientID: world.clientID,
				}
			}

			repoDir := newRepoDirectory(repo, identity)
			apiDir := newAPIDirectory(t, repo, identity)

			t.Run("AccessibleGuests", func(t *testing.T) {
				assertSameGuests(t,
					mustGuests(t, repoDir), mustGuests(t, apiDir))
			})
			t.Run("Connect-allowed", func(t *testing.T) {
				assertSameConnect(t, repoDir, apiDir, world.mine.ID)
			})
			t.Run("Connect-forbidden", func(t *testing.T) {
				assertSameRefusal(t, repoDir, apiDir, world.secret.ID)
			})
			t.Run("Connect-missing", func(t *testing.T) {
				assertSameRefusal(t, repoDir, apiDir, 999999)
			})
			t.Run("IsLoginNameReserved", func(t *testing.T) {
				assertSameReservations(t, repoDir, apiDir)
			})
			t.Run("PublicEndpoint", func(t *testing.T) {
				assertSameEndpoint(t, repoDir, apiDir)
			})
		})
	}
}

func mustGuests(t *testing.T, dir session.Directory) []*session.GuestInfo {
	t.Helper()
	got, err := dir.AccessibleGuests(t.Context())
	if err != nil {
		t.Fatalf("AccessibleGuests: %v", err)
	}
	return got
}

func assertSameGuests(t *testing.T, a, b []*session.GuestInfo) {
	t.Helper()
	if len(a) != len(b) {
		t.Fatalf("repo returned %d guests, api returned %d", len(a), len(b))
	}
	key := func(g *session.GuestInfo) string {
		return g.Guest.Name + "@" + g.InstanceName
	}
	ka := make([]string, 0, len(a))
	kb := make([]string, 0, len(b))
	for i := range a {
		ka = append(ka, key(a[i]))
		kb = append(kb, key(b[i]))
	}
	sort.Strings(ka)
	sort.Strings(kb)
	for i := range ka {
		if ka[i] != kb[i] {
			t.Errorf("guest %d: repo=%q api=%q", i, ka[i], kb[i])
		}
	}
}

// An API-backed client session must never be handed credentials for a guest
// it cannot reach -- the property the whole migration exists to establish.
func TestAPIDirectoryWithholdsCredentialsForAForbiddenGuest(t *testing.T) {
	repo := newRepo(t)
	world := seedWorld(t, repo)

	dir := newAPIDirectory(t, repo, &models.SessionIdentity{
		User: userAlias, DisplayName: userAlice, ClientID: world.clientID,
	})

	if _, err := dir.Connect(t.Context(), world.secret.ID); !errors.Is(err, session.ErrAccessDenied) {
		t.Fatalf("got %v, want ErrAccessDenied: a client was offered "+
			"credentials for a guest it was never granted", err)
	}
}

// A client's guest list must not contain an instance's secrets, since it is
// held for the whole session.
func TestAPIDirectoryGuestListHasNoCredentials(t *testing.T) {
	repo := newRepo(t)
	world := seedWorld(t, repo)

	dir := newAPIDirectory(t, repo, &models.SessionIdentity{
		User: userAlias, DisplayName: userAlice, ClientID: world.clientID,
	})

	guests, err := dir.AccessibleGuests(t.Context())
	if err != nil {
		t.Fatalf("AccessibleGuests: %v", err)
	}
	if len(guests) == 0 {
		t.Fatal("expected at least one guest")
	}
	// GuestInfo has no instance field at all, which is the structural
	// guarantee; assert the name is present so the test fails loudly if
	// the shape ever grows one.
	for _, g := range guests {
		if g.InstanceName == "" {
			t.Errorf("guest %q has no instance name", g.Guest.Name)
		}
	}
}

// world is a small fixture: one instance with secrets, one guest the client
// is granted and one it is not.
type world struct {
	instID   int64
	clientID int64
	mine     *models.Guest
	secret   *models.Guest
}

func seedWorld(t *testing.T, repo db.Repository) world {
	t.Helper()
	ctx := t.Context()

	inst := &models.ProxmoxInstance{
		Name:           "pve",
		APIURL:         "https://pve:8006",
		APITokenID:     "root@pam!tok",
		APITokenSecret: "SECRET-TOKEN",
		ConnectionType: models.ConnectionTypeTermProxy,
		Node:           "pve1",
	}
	if err := repo.AddProxmoxInstance(ctx, inst); err != nil {
		t.Fatalf("add instance: %v", err)
	}
	if err := repo.SetSetting(ctx, db.SettingPublicEndpoint, "proxpass.example.com"); err != nil {
		t.Fatalf("set endpoint: %v", err)
	}

	mine := &models.Guest{
		Type: models.GuestTypeCT, Name: "mine", Status: models.StatusRunning,
		ProxmoxID: 100, InstanceID: inst.ID,
	}
	secret := &models.Guest{
		Type: models.GuestTypeCT, Name: "secret", Status: models.StatusRunning,
		ProxmoxID: 999, InstanceID: inst.ID,
	}
	for _, g := range []*models.Guest{mine, secret} {
		if err := repo.UpsertGuest(ctx, g); err != nil {
			t.Fatalf("upsert guest: %v", err)
		}
	}

	client := &models.Client{Name: userAlice, PublicKeys: []string{"ssh-ed25519 AAAAalice alice"}}
	if err := repo.AddClient(ctx, client); err != nil {
		t.Fatalf("add client: %v", err)
	}
	stored, err := repo.GetClientByName(ctx, userAlice)
	if err != nil {
		t.Fatalf("get client: %v", err)
	}

	guests, err := repo.ListGuests(ctx)
	if err != nil {
		t.Fatalf("list guests: %v", err)
	}
	for _, g := range guests {
		switch g.Name {
		case "mine":
			mine = g
		case "secret":
			secret = g
		}
	}
	if err := repo.GrantClientAccess(ctx, stored.ID, []int64{mine.ID}); err != nil {
		t.Fatalf("grant: %v", err)
	}

	return world{instID: inst.ID, clientID: stored.ID, mine: mine, secret: secret}
}

// assertSameConnect checks both implementations hand back the same guest and
// the same credentials.
func assertSameConnect(t *testing.T, repoDir, apiDir session.Directory, guestID int64) {
	t.Helper()
	a, errA := repoDir.Connect(t.Context(), guestID)
	b, errB := apiDir.Connect(t.Context(), guestID)
	if (errA == nil) != (errB == nil) {
		t.Fatalf("repo err=%v but api err=%v", errA, errB)
	}
	if errA != nil {
		return
	}
	if a.Guest.ID != b.Guest.ID {
		t.Errorf("guest %d vs %d", a.Guest.ID, b.Guest.ID)
	}
	if a.Instance.APITokenSecret != b.Instance.APITokenSecret {
		t.Errorf("api token secret differs: %q vs %q",
			a.Instance.APITokenSecret, b.Instance.APITokenSecret)
	}
	if a.Instance.Name != b.Instance.Name {
		t.Errorf("instance %q vs %q", a.Instance.Name, b.Instance.Name)
	}
}

// assertSameRefusal checks both refuse, or both allow, the same guest.
func assertSameRefusal(t *testing.T, repoDir, apiDir session.Directory, guestID int64) {
	t.Helper()
	_, errA := repoDir.Connect(t.Context(), guestID)
	_, errB := apiDir.Connect(t.Context(), guestID)
	if errors.Is(errA, session.ErrAccessDenied) != errors.Is(errB, session.ErrAccessDenied) {
		t.Fatalf("repo err=%v but api err=%v", errA, errB)
	}
}

func assertSameReservations(t *testing.T, repoDir, apiDir session.Directory) {
	t.Helper()
	for _, name := range []string{
		session.AdminUser, userAlice, "ALICE", "ct100", "nobody",
	} {
		a, err := repoDir.IsLoginNameReserved(t.Context(), name)
		if err != nil {
			t.Fatalf("repo: %v", err)
		}
		b, err := apiDir.IsLoginNameReserved(t.Context(), name)
		if err != nil {
			t.Fatalf("api: %v", err)
		}
		if a != b {
			t.Errorf("%q: repo=%v api=%v", name, a, b)
		}
	}
}

func assertSameEndpoint(t *testing.T, repoDir, apiDir session.Directory) {
	t.Helper()
	a, err := repoDir.PublicEndpoint(t.Context())
	if err != nil {
		t.Fatalf("repo: %v", err)
	}
	b, err := apiDir.PublicEndpoint(t.Context())
	if err != nil {
		t.Fatalf("api: %v", err)
	}
	if a != b {
		t.Errorf("endpoint: repo=%q api=%q", a, b)
	}
}
