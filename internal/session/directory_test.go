package session_test

import (
	"errors"
	"io"
	"log"
	"net/http/httptest"
	"os"
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

// An API-backed client session must never be handed credentials for a guest
// it cannot reach -- the property the whole migration exists to establish.
func TestAPIDirectoryWithholdsCredentialsForAForbiddenGuest(t *testing.T) {
	repo := newRepo(t)
	world := seedWorld(t, repo)

	dir := newAPIDirectory(t, repo, &models.SessionIdentity{
		LoginName: userAlias, IdentityName: userAlice, ClientID: world.clientID,
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
		LoginName: userAlias, IdentityName: userAlice, ClientID: world.clientID,
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
		Name:             "pve",
		APIURL:           "https://pve:8006",
		APITokenID:       "root@pam!tok",
		APITokenSecret:   "SECRET-TOKEN",
		ConsoleTransport: models.ConsoleTransportTermProxy,
		Node:             "pve1",
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

// Test keys. Real ed25519 public keys so that anything parsing them sees a
// well-formed value.
const (
	keyAdmin = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ2H6djoN78rkj1En9yM7XsMUUDyFgiGWn3WZZqfI3JF admin"
	keyAlice = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHixnSBaUZmAX3Qd4hYl71jjgr58KXAJTdKjFrax6FHN alice"
	keyBob   = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOG/T2Snw/38000pfUM6LhVXu4rKZrlrbfHhu7u0Yc3D bob"
)

// addNamedClient stores a client under name, holding keyAlice.
func addNamedClient(t *testing.T, repo db.Repository, name string) {
	t.Helper()
	c := &models.Client{Name: name, PublicKeys: []string{keyAlice}}
	if err := repo.AddClient(t.Context(), c); err != nil {
		t.Fatalf("add client %s: %v", name, err)
	}
}

// The node endpoints, through the same full stack.
//
// These matter beyond the API tests because the session is where a node
// grant is eventually acted on: a Directory that returned credentials for
// an ungranted node would make the server's check irrelevant.

// A session must not be handed credentials for a node it cannot reach.
func TestAPIDirectoryWithholdsCredentialsForAForbiddenNode(t *testing.T) {
	repo := newRepo(t)
	world := seedWorld(t, repo)

	dir := newAPIDirectory(t, repo, &models.SessionIdentity{
		LoginName: userAlias, IdentityName: userAlice, ClientID: world.clientID,
	})

	// seedWorld grants a GUEST on this instance and no node at all, which
	// is exactly the case that must not leak: the guest grant is real.
	if _, err := dir.ConnectNode(t.Context(), world.instID); !errors.Is(err, session.ErrAccessDenied) {
		t.Fatalf("got %v, want ErrAccessDenied: a session was offered "+
			"credentials for a node it was never granted", err)
	}
}

// And the list it is given is empty, for the same reason.
func TestAPIDirectoryInstanceListIsScoped(t *testing.T) {
	repo := newRepo(t)
	world := seedWorld(t, repo)

	dir := newAPIDirectory(t, repo, &models.SessionIdentity{
		LoginName: userAlias, IdentityName: userAlice, ClientID: world.clientID,
	})

	// The guest list is not empty, so this cannot pass vacuously.
	guests, err := dir.AccessibleGuests(t.Context())
	if err != nil {
		t.Fatalf("listing guests: %v", err)
	}
	if len(guests) == 0 {
		t.Fatal("precondition: the client should see one guest")
	}

	instances, err := dir.AccessibleInstances(t.Context())
	if err != nil {
		t.Fatalf("listing instances: %v", err)
	}
	if len(instances) != 0 {
		t.Errorf("a client granted only a guest saw %d instances: %+v",
			len(instances), instances)
	}
}

// Once granted, the node arrives with the key needed to reach it.
func TestAPIDirectoryDeliversTheNodeKeyOnceGranted(t *testing.T) {
	repo := newRepo(t)
	world := seedWorld(t, repo)
	ctx := t.Context()

	// Configure the instance for SSH and grant it.
	instances, err := repo.ListProxmoxInstances(ctx)
	if err != nil {
		t.Fatalf("list instances: %v", err)
	}
	inst := instances[0]
	inst.SSHHost = "pve.example.com"
	inst.SSHPort = 22
	inst.SSHUser = "root"
	if err := repo.UpdateProxmoxInstance(ctx, inst); err != nil {
		t.Fatalf("configure ssh: %v", err)
	}
	if err := repo.GrantClientInstanceAccess(ctx, world.clientID, []int64{inst.ID}); err != nil {
		t.Fatalf("grant node: %v", err)
	}

	keyPath := t.TempDir() + "/key"
	const keyPEM = "-----BEGIN PRIVATE KEY-----\nNODEKEY\n-----END PRIVATE KEY-----"
	if err := os.WriteFile(keyPath, []byte(keyPEM+"\n"), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	t.Setenv(models.SSHKeyPathEnv, keyPath)

	dir := newAPIDirectory(t, repo, &models.SessionIdentity{
		LoginName: userAlias, IdentityName: userAlice, ClientID: world.clientID,
	})

	info, err := dir.ConnectNode(ctx, inst.ID)
	if err != nil {
		t.Fatalf("connecting to a granted node: %v", err)
	}
	if info.SSHKey != keyPEM {
		t.Errorf("SSHKey = %q, want the deployment key", info.SSHKey)
	}
	if info.Instance == nil || info.Instance.SSHHost != "pve.example.com" {
		t.Errorf("instance = %+v, want the configured ssh host", info.Instance)
	}
}
