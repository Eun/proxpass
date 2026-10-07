package session_test

import (
	"errors"
	"io"
	"log"
	"net/http/httptest"
	"testing"
	"time"

	"proxpass/internal/api"
	"proxpass/internal/db"
	"proxpass/internal/models"
	"proxpass/internal/session"
)

// newAdminRepo returns a db.Repository served by the API, for the identity
// given, alongside the real repository behind it.
//
// Goes through the whole stack: mint, exchange, HTTP, admin check.
func newAdminRepo(
	t *testing.T, identity *models.SessionIdentity,
) (remote, direct db.Repository) {
	t.Helper()

	direct = newRepo(t)
	srv := httptest.NewServer(
		api.NewServer(direct, log.New(io.Discard, "", 0)).Handler())
	t.Cleanup(srv.Close)

	minted := "minted-" + identity.IdentityName
	now := time.Now()
	if err := direct.MintSessionToken(
		t.Context(), api.HashToken(minted), identity, now, now.Add(time.Minute)); err != nil {
		t.Fatalf("mint: %v", err)
	}
	client := session.NewAPIClient(srv.URL)
	if _, err := client.Exchange(t.Context(), minted); err != nil {
		t.Fatalf("exchange: %v", err)
	}
	return session.NewAdminRepository(client), direct
}

const clientAliceName = "alice"

func adminIdentity() *models.SessionIdentity {
	return &models.SessionIdentity{
		LoginName: userAlias, IdentityName: session.AdminUser, IsAdmin: true,
	}
}

// A write through the API must land in the real database, and read back the
// same way. This is what makes it safe to hand the admin CLI an API-backed
// repository without touching a single command.
func TestAdminRepositoryWritesReachTheDatabase(t *testing.T) {
	remote, direct := newAdminRepo(t, adminIdentity())

	client := &models.Client{
		Name:       clientAliceName,
		PublicKeys: []string{"ssh-ed25519 AAAAalice alice"},
	}
	if err := remote.AddClient(t.Context(), client); err != nil {
		t.Fatalf("AddClient: %v", err)
	}
	if client.ID == 0 {
		t.Error("the database-assigned id was not returned to the caller")
	}

	// Visible through the real repository, so the write really happened.
	stored, err := direct.GetClientByName(t.Context(), clientAliceName)
	if err != nil {
		t.Fatalf("the client is not in the database: %v", err)
	}
	if stored.Name != clientAliceName || len(stored.PublicKeys) != 1 {
		t.Errorf("stored client differs: %+v", stored)
	}
}

// Every method the admin CLI uses must agree with the real repository.
func TestAdminRepositoryAgreesWithTheDatabase(t *testing.T) {
	remote, direct := newAdminRepo(t, adminIdentity())
	ctx := t.Context()

	inst := &models.ProxmoxInstance{
		Name: "pve", APIURL: "https://pve:8006", Node: "pve1",
		APITokenSecret: "SECRET", ConsoleTransport: models.ConsoleTransportTermProxy,
	}
	if err := remote.AddProxmoxInstance(ctx, inst); err != nil {
		t.Fatalf("AddProxmoxInstance: %v", err)
	}
	if inst.ID == 0 {
		t.Fatal("instance id was not returned")
	}

	guest := &models.Guest{
		Type: models.GuestTypeCT, Name: "web", Status: models.StatusRunning,
		ProxmoxID: 100, InstanceID: inst.ID,
	}
	if err := remote.UpsertGuest(ctx, guest); err != nil {
		t.Fatalf("UpsertGuest: %v", err)
	}

	client := &models.Client{Name: clientAliceName, PublicKeys: []string{"ssh-ed25519 AAAAa alice"}}
	if err := remote.AddClient(ctx, client); err != nil {
		t.Fatalf("AddClient: %v", err)
	}
	group := &models.Group{Name: "devs", ClientIDs: []int64{client.ID}}
	if err := remote.AddGroup(ctx, group); err != nil {
		t.Fatalf("AddGroup: %v", err)
	}
	if err := remote.AddAdminKey(ctx, "ssh-ed25519 AAAAadmin admin"); err != nil {
		t.Fatalf("AddAdminKey: %v", err)
	}

	guests, err := direct.ListGuests(ctx)
	if err != nil || len(guests) != 1 {
		t.Fatalf("guests: %v %d", err, len(guests))
	}
	if err := remote.GrantClientAccess(ctx, client.ID, []int64{guests[0].ID}); err != nil {
		t.Fatalf("GrantClientAccess: %v", err)
	}
	if err := remote.SetDefaultPolicy(ctx,
		&models.DefaultAccessPolicy{AuthorizedClientIDs: []int64{client.ID}}); err != nil {
		t.Fatalf("SetDefaultPolicy: %v", err)
	}
	if err := remote.SetSetting(ctx, db.SettingPublicEndpoint, "proxpass.example.com"); err != nil {
		t.Fatalf("SetSetting: %v", err)
	}

	// Now compare every read against the real repository.
	assertSameInstances(t, remote, direct)
	assertSameClients(t, remote, direct)
	assertSameGroups(t, remote, direct)
	assertSameRest(t, remote, direct, client.ID, guests[0].ID)
}

func assertSameInstances(t *testing.T, remote, direct db.Repository) {
	t.Helper()
	a, err := remote.ListProxmoxInstances(t.Context())
	if err != nil {
		t.Fatalf("remote instances: %v", err)
	}
	b, err := direct.ListProxmoxInstances(t.Context())
	if err != nil {
		t.Fatalf("direct instances: %v", err)
	}
	if len(a) != len(b) {
		t.Fatalf("instances: remote %d, real %d", len(a), len(b))
	}
	// The credentials must survive the round trip: the admin CLI prints
	// them, and `instance inspect' would otherwise show blanks.
	if a[0].APITokenSecret != b[0].APITokenSecret {
		t.Errorf("api token secret differs: %q vs %q",
			a[0].APITokenSecret, b[0].APITokenSecret)
	}
	if a[0].Name != b[0].Name || a[0].Node != b[0].Node {
		t.Errorf("instance differs: %+v vs %+v", a[0], b[0])
	}
}

func assertSameClients(t *testing.T, remote, direct db.Repository) {
	t.Helper()
	a, err := remote.ListClients(t.Context())
	if err != nil {
		t.Fatalf("remote clients: %v", err)
	}
	b, err := direct.ListClients(t.Context())
	if err != nil {
		t.Fatalf("direct clients: %v", err)
	}
	if len(a) != len(b) {
		t.Fatalf("clients: remote %d, real %d", len(a), len(b))
	}
	if a[0].Name != b[0].Name || len(a[0].PublicKeys) != len(b[0].PublicKeys) {
		t.Errorf("client differs: %+v vs %+v", a[0], b[0])
	}

	byName, err := remote.GetClientByName(t.Context(), b[0].Name)
	if err != nil {
		t.Fatalf("GetClientByName: %v", err)
	}
	if byName.ID != b[0].ID {
		t.Errorf("GetClientByName returned %d, want %d", byName.ID, b[0].ID)
	}
}

func assertSameGroups(t *testing.T, remote, direct db.Repository) {
	t.Helper()
	a, err := remote.ListGroups(t.Context())
	if err != nil {
		t.Fatalf("remote groups: %v", err)
	}
	b, err := direct.ListGroups(t.Context())
	if err != nil {
		t.Fatalf("direct groups: %v", err)
	}
	if len(a) != len(b) {
		t.Fatalf("groups: remote %d, real %d", len(a), len(b))
	}
	if a[0].Name != b[0].Name || len(a[0].ClientIDs) != len(b[0].ClientIDs) {
		t.Errorf("group differs: %+v vs %+v", a[0], b[0])
	}
}

func assertSameRest(t *testing.T, remote, direct db.Repository, clientID, guestID int64) {
	t.Helper()
	ctx := t.Context()

	rulesA, err := remote.ListAccessRules(ctx)
	if err != nil {
		t.Fatalf("remote rules: %v", err)
	}
	rulesB, err := direct.ListAccessRules(ctx)
	if err != nil {
		t.Fatalf("direct rules: %v", err)
	}
	if len(rulesA) != len(rulesB) {
		t.Errorf("access rules: remote %d, real %d", len(rulesA), len(rulesB))
	}

	// Check a GRANTED pair, so that a bug returning a constant false shows
	// up. An ungranted pair would agree by accident: both would say no.
	okA, err := remote.HasAccess(ctx, clientID, guestID)
	if err != nil {
		t.Fatalf("remote HasAccess: %v", err)
	}
	okB, err := direct.HasAccess(ctx, clientID, guestID)
	if err != nil {
		t.Fatalf("direct HasAccess: %v", err)
	}
	if okA != okB {
		t.Errorf("HasAccess: remote %v, direct %v", okA, okB)
	}
	if !okB {
		t.Fatal("the fixture does not grant this pair, so the comparison " +
			"above would pass even if both sides were broken")
	}

	keysA, err := remote.ListAdminKeys(ctx)
	if err != nil {
		t.Fatalf("remote keys: %v", err)
	}
	keysB, err := direct.ListAdminKeys(ctx)
	if err != nil {
		t.Fatalf("direct keys: %v", err)
	}
	if len(keysA) != len(keysB) {
		t.Errorf("admin keys: remote %d, real %d", len(keysA), len(keysB))
	}

	polA, err := remote.GetDefaultPolicy(ctx)
	if err != nil {
		t.Fatalf("remote policy: %v", err)
	}
	polB, err := direct.GetDefaultPolicy(ctx)
	if err != nil {
		t.Fatalf("direct policy: %v", err)
	}
	if len(polA.AuthorizedClientIDs) != len(polB.AuthorizedClientIDs) {
		t.Errorf("policy differs: %+v vs %+v", polA, polB)
	}

	endA, err := remote.GetSetting(ctx, db.SettingPublicEndpoint)
	if err != nil {
		t.Fatalf("remote setting: %v", err)
	}
	endB, err := direct.GetSetting(ctx, db.SettingPublicEndpoint)
	if err != nil {
		t.Fatalf("direct setting: %v", err)
	}
	if endA != endB {
		t.Errorf("setting: remote %q, real %q", endA, endB)
	}
}

// THE security property of this PR: a client credential must not reach the
// admin API. Without this check, every write in the system would be one HTTP
// call away from any client session.
func TestAClientCredentialCannotUseTheAdminAPI(t *testing.T) {
	remote, direct := newAdminRepo(t, &models.SessionIdentity{
		LoginName: userAlias, IdentityName: userAlice, ClientID: 1,
	})

	err := remote.AddClient(t.Context(),
		&models.Client{Name: "mallory", PublicKeys: []string{"ssh-ed25519 AAAAm m"}})
	if err == nil {
		t.Fatal("a client session created a client through the admin API")
	}
	if !errors.Is(err, session.ErrNotAdmin) {
		t.Errorf("got %v, want ErrNotAdmin", err)
	}

	// And nothing was written.
	clients, listErr := direct.ListClients(t.Context())
	if listErr != nil {
		t.Fatalf("list: %v", listErr)
	}
	for _, c := range clients {
		if c.Name == "mallory" {
			t.Fatal("the refused write landed in the database anyway")
		}
	}
}

// Reads are privileged too: the instance list carries credentials.
func TestAClientCredentialCannotReadThroughTheAdminAPI(t *testing.T) {
	remote, _ := newAdminRepo(t, &models.SessionIdentity{
		LoginName: userAlias, IdentityName: userAlice, ClientID: 1,
	})

	if _, err := remote.ListProxmoxInstances(t.Context()); !errors.Is(err, session.ErrNotAdmin) {
		t.Fatalf("got %v, want ErrNotAdmin: a client read the instance "+
			"list, which carries every Proxmox credential", err)
	}
}

// An operation that is not on the allowlist must be refused, so that adding
// a Repository method does not silently expose it.
func TestAnUnknownOperationIsRefused(t *testing.T) {
	remote, _ := newAdminRepo(t, adminIdentity())

	// GetGuestByID is a real Repository method that is deliberately NOT in
	// the allowlist; calling it panics client-side before reaching the
	// wire, which is the contract. Assert that contract here.
	defer func() {
		if recover() == nil {
			t.Fatal("an unsupported method did not panic")
		}
	}()
	_, _ = remote.GetGuestByID(t.Context(), 1)
}

// The session's own token methods must not be reachable: minting is how
// authentication works, and an admin credential must not be able to forge
// one for somebody else.
func TestTokenMethodsAreNotOnTheAdminAPI(t *testing.T) {
	remote, _ := newAdminRepo(t, adminIdentity())

	defer func() {
		if recover() == nil {
			t.Fatal("MintSessionToken was reachable through the admin API")
		}
	}()
	_ = remote.MintSessionToken(t.Context(), "h",
		&models.SessionIdentity{IsAdmin: true}, time.Now(), time.Now())
}
