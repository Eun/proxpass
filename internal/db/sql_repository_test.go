package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"proxpass/internal/models"
)

const (
	testKey         = "key"
	testClientName  = "alice"
	testTokenID     = "user@pam!token"
	testTokenSecret = "secret"
)

// newTestRepo returns a repository for the backend under test.
//
// Every test in this file goes through here, so pointing it at Postgres runs
// the entire suite against Postgres -- the behavior is asserted once and both
// backends must satisfy it. That matters more than it sounds: the failure mode
// of a two-backend port is a query that happens to work on the one the tests
// use, and a single shared suite is what makes that impossible.
//
// Postgres is used when PROXPASS_TEST_POSTGRES_DSN is set; otherwise SQLite,
// so the default `go test ./...` needs no server. CI and the release build
// both set it.
func newTestRepo(t *testing.T) Repository {
	t.Helper()
	if dsn := os.Getenv(testPostgresDSNEnv); dsn != "" {
		return newTestPostgresRepo(t, dsn)
	}

	f, err := os.CreateTemp("", "proxpass-test-*.db")
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	t.Cleanup(func() { _ = os.Remove(f.Name()) })

	repo, err := NewSQLiteRepository(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	return repo
}

// testPostgresDSNEnv names a Postgres server the tests may use.
const testPostgresDSNEnv = "PROXPASS_TEST_POSTGRES_DSN"

// newTestPostgresRepo gives each test its own schema on the shared server.
//
// A fresh schema rather than a fresh database: creating a database is slow and
// cannot run inside a transaction, while a schema is cheap and gives the same
// isolation. search_path makes the unqualified names in the migrations and
// queries resolve to it, so nothing in the production code needs to know.
func newTestPostgresRepo(t *testing.T, dsn string) Repository {
	t.Helper()
	schema := fmt.Sprintf("test_%d_%d", os.Getpid(), nextSchemaID.Add(1))

	admin, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("opening postgres: %v", err)
	}
	defer func() { _ = admin.Close() }()
	if _, err := admin.ExecContext(t.Context(), "CREATE SCHEMA "+schema); err != nil {
		t.Fatalf("creating schema %s: %v", schema, err)
	}
	t.Cleanup(func() {
		db, err := sql.Open("pgx", dsn)
		if err != nil {
			return
		}
		defer func() { _ = db.Close() }()
		_, _ = db.ExecContext(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
	})

	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	repo, err := NewRepository(dsn + sep + "search_path=" + schema)
	if err != nil {
		t.Fatalf("opening repository on schema %s: %v", schema, err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	return repo
}

// nextSchemaID keeps parallel tests from colliding on a schema name.
var nextSchemaID atomic.Int64

func TestProxmoxInstances(t *testing.T) {
	repo := newTestRepo(t)
	ctx := context.Background()

	inst := &models.ProxmoxInstance{
		Name:           "pve1",
		APIURL:         "https://pve1.local:8006",
		APITokenID:     testTokenID,
		APITokenSecret: testTokenSecret,
		SSHHost:        "pve1.local",
		SSHPort:        22,
		SSHUser:        "root",
		SSHKeyPath:     "/tmp/key",
	}
	if err := repo.AddProxmoxInstance(ctx, inst); err != nil {
		t.Fatal(err)
	}
	if inst.ID == 0 {
		t.Fatal("expected non-zero ID after insert")
	}

	list, err := repo.ListProxmoxInstances(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].Name != "pve1" {
		t.Fatalf("unexpected list: %+v", list)
	}

	inst.Name = "pve1-updated"
	if err := repo.UpdateProxmoxInstance(ctx, inst); err != nil {
		t.Fatal(err)
	}

	list, _ = repo.ListProxmoxInstances(ctx)
	if list[0].Name != "pve1-updated" {
		t.Fatalf("update failed: %+v", list[0])
	}

	if err := repo.RemoveProxmoxInstance(ctx, inst.ID); err != nil {
		t.Fatal(err)
	}
	list, _ = repo.ListProxmoxInstances(ctx)
	if len(list) != 0 {
		t.Fatal("expected empty list after remove")
	}
}

// Instances must come back ordered by id, so the listing is stable rather
// than whatever order SQLite happened to return.
//
// The names here are deliberately in the reverse of their id order: sorting
// by id and sorting by name would otherwise be indistinguishable, and a test
// that cannot tell them apart would pass against either.
//
// Honest limitation: this test cannot detect ORDER BY being dropped
// altogether, because SQLite returns rows in rowid order for a simple table
// scan and so happens to agree. It pins the order against a *wrong* order
// (by name, or descending), which is the realistic regression. The guarantee
// against no ORDER BY is the SQL itself: the order is unspecified without
// it, and a later index or query-plan change could expose that.
func TestListProxmoxInstancesIsOrderedByID(t *testing.T) {
	repo := newTestRepo(t)
	ctx := context.Background()

	for _, name := range []string{"zulu", "yankee", "xray", "whiskey"} {
		inst := &models.ProxmoxInstance{
			Name:           name,
			APIURL:         "https://" + name + ":8006",
			APITokenID:     testTokenID,
			APITokenSecret: testTokenSecret,
			Node:           name,
		}
		if err := repo.AddProxmoxInstance(ctx, inst); err != nil {
			t.Fatalf("add %s: %v", name, err)
		}
	}

	list, err := repo.ListProxmoxInstances(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 4 {
		t.Fatalf("got %d instances, want 4", len(list))
	}
	for i := 1; i < len(list); i++ {
		if list[i-1].ID >= list[i].ID {
			t.Errorf("not ordered by id: index %d has id %d, index %d has id %d",
				i-1, list[i-1].ID, i, list[i].ID)
		}
	}
	// Insertion order and id order coincide here, so the names pin down
	// which order was actually applied.
	want := []string{"zulu", "yankee", "xray", "whiskey"}
	for i, w := range want {
		if list[i].Name != w {
			t.Errorf("position %d = %q, want %q (full order: %s)",
				i, list[i].Name, w, instanceNames(list))
		}
	}
}

// Removing an instance must not disturb the order of the rest. SQLite can
// reuse a freed rowid for the next insert, which is the case where an
// unordered query visibly reorders itself.
func TestListProxmoxInstancesStaysOrderedAfterRemoval(t *testing.T) {
	repo := newTestRepo(t)
	ctx := context.Background()

	ids := make([]int64, 0, 3)
	for _, name := range []string{"alpha", "bravo", "charlie"} {
		inst := &models.ProxmoxInstance{
			Name: name, APIURL: "https://" + name + ":8006",
			APITokenID: testTokenID, APITokenSecret: testTokenSecret, Node: name,
		}
		if err := repo.AddProxmoxInstance(ctx, inst); err != nil {
			t.Fatalf("add %s: %v", name, err)
		}
		ids = append(ids, inst.ID)
	}

	// Drop the middle one and add another, which may take the freed rowid.
	if err := repo.RemoveProxmoxInstance(ctx, ids[1]); err != nil {
		t.Fatalf("remove: %v", err)
	}
	added := &models.ProxmoxInstance{
		Name: "delta", APIURL: "https://delta:8006",
		APITokenID: testTokenID, APITokenSecret: testTokenSecret, Node: "delta",
	}
	if err := repo.AddProxmoxInstance(ctx, added); err != nil {
		t.Fatalf("add delta: %v", err)
	}

	list, err := repo.ListProxmoxInstances(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i < len(list); i++ {
		if list[i-1].ID >= list[i].ID {
			t.Errorf("not ordered by id after removal (%s)", instanceNames(list))
		}
	}
}

func instanceNames(list []*models.ProxmoxInstance) string {
	names := make([]string, 0, len(list))
	for _, i := range list {
		names = append(names, fmt.Sprintf("%d:%s", i.ID, i.Name))
	}
	return strings.Join(names, " ")
}

func TestGuestUpsert(t *testing.T) {
	repo := newTestRepo(t)
	ctx := context.Background()

	g := &models.Guest{Type: models.GuestTypeCT, Name: "web1", Status: models.StatusRunning, ProxmoxID: 100, InstanceID: 1}
	if err := repo.UpsertGuest(ctx, g); err != nil {
		t.Fatal(err)
	}
	if g.ID == 0 {
		t.Fatal("expected non-zero ID")
	}

	// Upsert same proxmox_id+instance_id should update
	g2 := &models.Guest{Type: models.GuestTypeCT, Name: "web1-renamed", Status: models.StatusStopped, ProxmoxID: 100, InstanceID: 1}
	if err := repo.UpsertGuest(ctx, g2); err != nil {
		t.Fatal(err)
	}
	if g2.ID != g.ID {
		t.Fatalf("expected same ID on upsert, got %d vs %d", g2.ID, g.ID)
	}

	fetched, err := repo.GetGuestByID(ctx, g.ID)
	if err != nil {
		t.Fatal(err)
	}
	if fetched.Name != "web1-renamed" || fetched.Status != models.StatusStopped {
		t.Fatalf("upsert didn't update: %+v", fetched)
	}
}

func TestClients(t *testing.T) {
	repo := newTestRepo(t)
	ctx := context.Background()

	c := &models.Client{Name: testClientName, PublicKeys: []string{"ssh-ed25519 AAAA..."}, GroupIDs: []int64{1, 2}}
	if err := repo.AddClient(ctx, c); err != nil {
		t.Fatal(err)
	}
	if c.ID == 0 {
		t.Fatal("expected non-zero ID")
	}

	got, err := repo.GetClientByName(ctx, testClientName)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.PublicKeys) != 1 || len(got.GroupIDs) != 2 {
		t.Fatalf("unexpected client: %+v", got)
	}

	c.Name = testClientName + "-updated"
	if err := repo.UpdateClient(ctx, c); err != nil {
		t.Fatal(err)
	}
	got, _ = repo.GetClientByName(ctx, testClientName+"-updated")
	if got == nil {
		t.Fatal("expected to find updated client")
	}

	if err := repo.RemoveClient(ctx, c.ID); err != nil {
		t.Fatal(err)
	}
	_, err = repo.GetClientByName(ctx, testClientName+"-updated")
	if err == nil {
		t.Fatal("expected error after remove")
	}
}

func TestGroups(t *testing.T) {
	repo := newTestRepo(t)
	ctx := context.Background()

	g := &models.Group{Name: "devs", ClientIDs: []int64{10, 20}}
	if err := repo.AddGroup(ctx, g); err != nil {
		t.Fatal(err)
	}
	if g.ID == 0 {
		t.Fatal("expected non-zero ID")
	}

	g.Name = "developers"
	if err := repo.UpdateGroup(ctx, g); err != nil {
		t.Fatal(err)
	}

	if err := repo.RemoveGroup(ctx, g.ID); err != nil {
		t.Fatal(err)
	}
}

func TestAccessRules(t *testing.T) {
	repo := newTestRepo(t)
	ctx := context.Background()

	// Setup: client + guests
	c := &models.Client{Name: "bob", PublicKeys: []string{"key1"}, GroupIDs: []int64{}}
	if err := repo.AddClient(ctx, c); err != nil {
		t.Fatal(err)
	}

	g1 := &models.Guest{Type: models.GuestTypeVM, Name: "vm1", Status: models.StatusRunning, ProxmoxID: 200, InstanceID: 1}
	g2 := &models.Guest{Type: models.GuestTypeVM, Name: "vm2", Status: models.StatusRunning, ProxmoxID: 201, InstanceID: 1}
	if err := repo.UpsertGuest(ctx, g1); err != nil {
		t.Fatal(err)
	}
	if err := repo.UpsertGuest(ctx, g2); err != nil {
		t.Fatal(err)
	}

	// Grant client access to both guests
	if err := repo.GrantClientAccess(ctx, c.ID, []int64{g1.ID, g2.ID}); err != nil {
		t.Fatal(err)
	}

	ok, err := repo.HasAccess(ctx, c.ID, g1.ID)
	if err != nil || !ok {
		t.Fatal("expected access to g1")
	}

	// Revoke access to g1
	if err := repo.RevokeClientAccess(ctx, c.ID, g1.ID); err != nil {
		t.Fatal(err)
	}
	ok, _ = repo.HasAccess(ctx, c.ID, g1.ID)
	if ok {
		t.Fatal("expected no access to g1 after revoke")
	}

	// g2 should still be accessible
	ok, _ = repo.HasAccess(ctx, c.ID, g2.ID)
	if !ok {
		t.Fatal("expected access to g2")
	}
}

func TestGroupAccessRules(t *testing.T) {
	repo := newTestRepo(t)
	ctx := context.Background()

	// Create a group
	grp := &models.Group{Name: "ops", ClientIDs: []int64{}}
	if err := repo.AddGroup(ctx, grp); err != nil {
		t.Fatal(err)
	}

	// Create client in that group
	c := &models.Client{Name: "carol", PublicKeys: []string{testKey}, GroupIDs: []int64{grp.ID}}
	if err := repo.AddClient(ctx, c); err != nil {
		t.Fatal(err)
	}

	g := &models.Guest{Type: models.GuestTypeCT, Name: "ct1", Status: models.StatusRunning, ProxmoxID: 300, InstanceID: 1}
	if err := repo.UpsertGuest(ctx, g); err != nil {
		t.Fatal(err)
	}

	// No access yet
	ok, _ := repo.HasAccess(ctx, c.ID, g.ID)
	if ok {
		t.Fatal("expected no access before grant")
	}

	// Grant group access
	if err := repo.GrantGroupAccess(ctx, grp.ID, []int64{g.ID}); err != nil {
		t.Fatal(err)
	}

	ok, err := repo.HasAccess(ctx, c.ID, g.ID)
	if err != nil || !ok {
		t.Fatal("expected access via group")
	}

	// Revoke
	if err := repo.RevokeGroupAccess(ctx, grp.ID, g.ID); err != nil {
		t.Fatal(err)
	}
	ok, _ = repo.HasAccess(ctx, c.ID, g.ID)
	if ok {
		t.Fatal("expected no access after group revoke")
	}
}

func TestDefaultPolicy(t *testing.T) {
	repo := newTestRepo(t)
	ctx := context.Background()

	// Empty policy by default
	policy, err := repo.GetDefaultPolicy(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(policy.AuthorizedClientIDs) != 0 || len(policy.AuthorizedGroupIDs) != 0 {
		t.Fatal("expected empty default policy")
	}

	// Create client + guest
	c := &models.Client{Name: "dave", PublicKeys: []string{testKey}, GroupIDs: []int64{}}
	if err := repo.AddClient(ctx, c); err != nil {
		t.Fatal(err)
	}
	g := &models.Guest{Type: models.GuestTypeVM, Name: "vm5", Status: models.StatusRunning, ProxmoxID: 500, InstanceID: 1}
	if err := repo.UpsertGuest(ctx, g); err != nil {
		t.Fatal(err)
	}

	// No explicit rules, no default policy -> no access
	ok, _ := repo.HasAccess(ctx, c.ID, g.ID)
	if ok {
		t.Fatal("expected no access with empty policy")
	}

	// Set default policy to allow this client
	if err := repo.SetDefaultPolicy(ctx, &models.DefaultAccessPolicy{
		AuthorizedClientIDs: []int64{c.ID},
	}); err != nil {
		t.Fatal(err)
	}

	ok, _ = repo.HasAccess(ctx, c.ID, g.ID)
	if !ok {
		t.Fatal("expected access via default policy")
	}

	// Override policy to remove client
	if err := repo.SetDefaultPolicy(ctx, &models.DefaultAccessPolicy{}); err != nil {
		t.Fatal(err)
	}
	ok, _ = repo.HasAccess(ctx, c.ID, g.ID)
	if ok {
		t.Fatal("expected no access after policy cleared")
	}
}

func TestDefaultPolicyGroupAccess(t *testing.T) {
	repo := newTestRepo(t)
	ctx := context.Background()

	grp := &models.Group{Name: "team", ClientIDs: []int64{}}
	if err := repo.AddGroup(ctx, grp); err != nil {
		t.Fatal(err)
	}

	c := &models.Client{Name: "eve", PublicKeys: []string{testKey}, GroupIDs: []int64{grp.ID}}
	if err := repo.AddClient(ctx, c); err != nil {
		t.Fatal(err)
	}

	g := &models.Guest{Type: models.GuestTypeCT, Name: "ct9", Status: models.StatusRunning, ProxmoxID: 900, InstanceID: 1}
	if err := repo.UpsertGuest(ctx, g); err != nil {
		t.Fatal(err)
	}

	// Default policy grants group
	if err := repo.SetDefaultPolicy(ctx, &models.DefaultAccessPolicy{
		AuthorizedGroupIDs: []int64{grp.ID},
	}); err != nil {
		t.Fatal(err)
	}

	ok, err := repo.HasAccess(ctx, c.ID, g.ID)
	if err != nil || !ok {
		t.Fatal("expected access via default policy group")
	}
}

func TestAdminKeys(t *testing.T) {
	repo := newTestRepo(t)
	ctx := context.Background()

	if err := repo.AddAdminKey(ctx, "ssh-ed25519 ADMIN1"); err != nil {
		t.Fatal(err)
	}
	if err := repo.AddAdminKey(ctx, "ssh-ed25519 ADMIN2"); err != nil {
		t.Fatal(err)
	}
	// Duplicate insert should be ignored
	if err := repo.AddAdminKey(ctx, "ssh-ed25519 ADMIN1"); err != nil {
		t.Fatal(err)
	}

	keys, err := repo.ListAdminKeys(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(keys))
	}

	if err := repo.RemoveAdminKey(ctx, "ssh-ed25519 ADMIN1"); err != nil {
		t.Fatal(err)
	}
	keys, _ = repo.ListAdminKeys(ctx)
	if len(keys) != 1 {
		t.Fatalf("expected 1 key after remove, got %d", len(keys))
	}
}

// TestRemoveProxmoxInstanceCleansUpGuests verifies that deleting a Proxmox
// instance also removes all of its guests and any access rules that reference
// those guests.
func TestRemoveProxmoxInstanceCleansUpGuests(t *testing.T) {
	repo := newTestRepo(t)
	ctx := context.Background()

	// Add two instances.
	inst1 := &models.ProxmoxInstance{
		Name: "inst-a", APIURL: "https://inst-a.local:8006",
		APITokenID: "user@pam!t1", APITokenSecret: "s1",
	}
	inst2 := &models.ProxmoxInstance{
		Name: "inst-b", APIURL: "https://inst-b.local:8006",
		APITokenID: "user@pam!t2", APITokenSecret: "s2",
	}
	if err := repo.AddProxmoxInstance(ctx, inst1); err != nil {
		t.Fatal(err)
	}
	if err := repo.AddProxmoxInstance(ctx, inst2); err != nil {
		t.Fatal(err)
	}

	// Add a guest on each instance.
	g1 := &models.Guest{Type: models.GuestTypeVM, Name: "vm1", Status: models.StatusRunning, ProxmoxID: 100, InstanceID: inst1.ID}
	g2 := &models.Guest{Type: models.GuestTypeVM, Name: "vm2", Status: models.StatusRunning, ProxmoxID: 200, InstanceID: inst2.ID}
	if err := repo.UpsertGuest(ctx, g1); err != nil {
		t.Fatal(err)
	}
	if err := repo.UpsertGuest(ctx, g2); err != nil {
		t.Fatal(err)
	}

	// Add a client and grant access to both guests.
	c := &models.Client{Name: testClientName, PublicKeys: []string{"key"}, GroupIDs: []int64{}}
	if err := repo.AddClient(ctx, c); err != nil {
		t.Fatal(err)
	}
	if err := repo.GrantClientAccess(ctx, c.ID, []int64{g1.ID, g2.ID}); err != nil {
		t.Fatal(err)
	}

	// Sanity: both guests visible and accessible.
	guests, err := repo.ListGuests(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(guests) != 2 {
		t.Fatalf("expected 2 guests before remove, got %d", len(guests))
	}
	ok, _ := repo.HasAccess(ctx, c.ID, g1.ID)
	if !ok {
		t.Fatal("expected access to g1 before remove")
	}

	// Remove inst1 — g1 and its access rule must disappear.
	if err := repo.RemoveProxmoxInstance(ctx, inst1.ID); err != nil {
		t.Fatal(err)
	}

	// Only g2 should remain.
	guests, err = repo.ListGuests(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(guests) != 1 {
		t.Fatalf("expected 1 guest after remove, got %d", len(guests))
	}
	if guests[0].ID != g2.ID {
		t.Fatalf("expected surviving guest to be g2 (id %d), got %d", g2.ID, guests[0].ID)
	}

	// Access rule for g1 must be gone.
	ok, err = repo.HasAccess(ctx, c.ID, g1.ID)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("expected no access to g1 after instance removed")
	}

	// Access rule for g2 must still hold.
	ok, err = repo.HasAccess(ctx, c.ID, g2.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected access to g2 to be unaffected")
	}
}

// Compile-time interface check.
var _ Repository = (*sqlRepo)(nil)

func TestSettings(t *testing.T) {
	repo := newTestRepo(t)
	ctx := context.Background()

	// An unset key is not an error: a fresh database legitimately has none,
	// and every caller wants the same empty fallback.
	got, err := repo.GetSetting(ctx, SettingPublicEndpoint)
	if err != nil {
		t.Fatalf("reading an unset setting: %v", err)
	}
	if got != "" {
		t.Errorf("unset setting = %q, want empty", got)
	}

	if err := repo.SetSetting(ctx, SettingPublicEndpoint, "proxpass.example.com"); err != nil {
		t.Fatal(err)
	}
	if got, err = repo.GetSetting(ctx, SettingPublicEndpoint); err != nil {
		t.Fatal(err)
	} else if got != "proxpass.example.com" {
		t.Errorf("setting = %q, want %q", got, "proxpass.example.com")
	}

	// Setting it again replaces rather than failing on the primary key, so a
	// deployment can change its endpoint by restarting.
	if err := repo.SetSetting(ctx, SettingPublicEndpoint, "new.example.com"); err != nil {
		t.Fatal(err)
	}
	if got, err = repo.GetSetting(ctx, SettingPublicEndpoint); err != nil {
		t.Fatal(err)
	} else if got != "new.example.com" {
		t.Errorf("setting after replace = %q, want %q", got, "new.example.com")
	}

	// Keys are independent.
	if err := repo.SetSetting(ctx, "other", "value"); err != nil {
		t.Fatal(err)
	}
	if got, err = repo.GetSetting(ctx, SettingPublicEndpoint); err != nil {
		t.Fatal(err)
	} else if got != "new.example.com" {
		t.Errorf("setting changed by an unrelated key: %q", got)
	}
}

// --- Session Tokens ---
//
// These run against whichever backend newTestRepo picks, so the statements
// are exercised on Postgres in CI as well as on SQLite. DELETE ... RETURNING
// and the INTEGER-rather-than-BOOLEAN column are exactly the kind of thing
// that works on one backend and not the other.

func TestSessionTokenRoundTrip(t *testing.T) {
	repo := newTestRepo(t)
	ctx := t.Context()
	now := time.Now()

	want := &models.SessionIdentity{
		User: "tobias", DisplayName: "alice", ClientID: 42,
	}
	if err := repo.MintSessionToken(ctx, "hash-client", want, now, now.Add(time.Minute)); err != nil {
		t.Fatalf("mint: %v", err)
	}

	got, err := repo.RedeemSessionToken(ctx, "hash-client", now)
	if err != nil {
		t.Fatalf("redeem: %v", err)
	}
	if got.User != want.User || got.DisplayName != want.DisplayName ||
		got.ClientID != want.ClientID || got.IsAdmin {
		t.Errorf("round trip changed the identity: got %+v, want %+v", got, want)
	}
}

// bool has to survive a column that is INTEGER on both backends.
func TestSessionTokenKeepsTheAdminFlag(t *testing.T) {
	repo := newTestRepo(t)
	ctx := t.Context()
	now := time.Now()

	if err := repo.MintSessionToken(ctx, "hash-admin",
		&models.SessionIdentity{User: "u", DisplayName: "admin", IsAdmin: true},
		now, now.Add(time.Minute)); err != nil {
		t.Fatalf("mint: %v", err)
	}
	got, err := repo.RedeemSessionToken(ctx, "hash-admin", now)
	if err != nil {
		t.Fatalf("redeem: %v", err)
	}
	if !got.IsAdmin {
		t.Errorf("is_admin did not survive the round trip: %+v", got)
	}
}

func TestSessionTokenIsSingleUse(t *testing.T) {
	repo := newTestRepo(t)
	ctx := t.Context()
	now := time.Now()

	if err := repo.MintSessionToken(ctx, "hash",
		&models.SessionIdentity{User: "u", DisplayName: "d"},
		now, now.Add(time.Minute)); err != nil {
		t.Fatalf("mint: %v", err)
	}
	if _, err := repo.RedeemSessionToken(ctx, "hash", now); err != nil {
		t.Fatalf("first redeem: %v", err)
	}
	if _, err := repo.RedeemSessionToken(ctx, "hash", now); !errors.Is(err, ErrNoSuchToken) {
		t.Fatalf("second redeem = %v, want ErrNoSuchToken", err)
	}
}

func TestSessionTokenExpires(t *testing.T) {
	repo := newTestRepo(t)
	ctx := t.Context()
	now := time.Now()

	if err := repo.MintSessionToken(ctx, "hash",
		&models.SessionIdentity{User: "u", DisplayName: "d"},
		now, now.Add(time.Second)); err != nil {
		t.Fatalf("mint: %v", err)
	}
	if _, err := repo.RedeemSessionToken(ctx, "hash", now.Add(2*time.Second)); !errors.Is(err, ErrNoSuchToken) {
		t.Fatalf("expired redeem = %v, want ErrNoSuchToken", err)
	}
}

func TestRedeemingAnUnknownTokenIsNotAnError(t *testing.T) {
	repo := newTestRepo(t)

	_, err := repo.RedeemSessionToken(t.Context(), "never-minted", time.Now())
	if !errors.Is(err, ErrNoSuchToken) {
		t.Fatalf("got %v, want ErrNoSuchToken", err)
	}
}

// Minting sweeps expired rows, and the threshold is "now" -- not the new
// token's own expiry. Sweeping by the latter would delete every token due to
// expire before it, so two people logging in at once would lock each other
// out.
func TestMintingDoesNotSweepOtherLiveTokens(t *testing.T) {
	repo := newTestRepo(t)
	ctx := t.Context()
	now := time.Now()
	identity := &models.SessionIdentity{User: "u", DisplayName: "d"}

	// An older token that is still valid.
	if err := repo.MintSessionToken(ctx, "first", identity, now, now.Add(30*time.Second)); err != nil {
		t.Fatalf("mint first: %v", err)
	}
	// A newer one that outlives it.
	if err := repo.MintSessionToken(ctx, "second", identity, now, now.Add(90*time.Second)); err != nil {
		t.Fatalf("mint second: %v", err)
	}

	if _, err := repo.RedeemSessionToken(ctx, "first", now); err != nil {
		t.Fatalf("the first token was swept by the second mint: %v", err)
	}
}

// An expired row must not survive forever just because nobody redeemed it.
func TestMintingSweepsExpiredTokens(t *testing.T) {
	repo := newTestRepo(t)
	ctx := t.Context()
	now := time.Now()
	identity := &models.SessionIdentity{User: "u", DisplayName: "d"}

	if err := repo.MintSessionToken(ctx, "stale", identity, now, now.Add(time.Second)); err != nil {
		t.Fatalf("mint stale: %v", err)
	}
	later := now.Add(time.Minute)
	if err := repo.MintSessionToken(ctx, "fresh", identity, later, later.Add(time.Minute)); err != nil {
		t.Fatalf("mint fresh: %v", err)
	}

	var n int
	if err := repo.(*sqlRepo).queryRow(ctx,
		"SELECT COUNT(*) FROM session_tokens WHERE token_hash = ?", "stale").
		Scan(&n); err != nil {
		t.Fatalf("counting: %v", err)
	}
	if n != 0 {
		t.Errorf("the expired token was not swept: %d rows remain", n)
	}
}
