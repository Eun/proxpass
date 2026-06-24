package db

import (
	"context"
	"os"
	"testing"

	"proxpass/internal/models"
)

func newTestRepo(t *testing.T) *sqliteRepo {
	t.Helper()
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

func TestProxmoxInstances(t *testing.T) {
	repo := newTestRepo(t)
	ctx := context.Background()

	inst := &models.ProxmoxInstance{Hostname: "pve1.local", Port: 8006, APIKey: "secret"}
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
	if len(list) != 1 || list[0].Hostname != "pve1.local" {
		t.Fatalf("unexpected list: %+v", list)
	}

	inst.Hostname = "pve1-updated.local"
	if err := repo.UpdateProxmoxInstance(ctx, inst); err != nil {
		t.Fatal(err)
	}

	list, _ = repo.ListProxmoxInstances(ctx)
	if list[0].Hostname != "pve1-updated.local" {
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

	c := &models.Client{Name: "alice", PublicKeys: []string{"ssh-ed25519 AAAA..."}, GroupIDs: []int64{1, 2}}
	if err := repo.AddClient(ctx, c); err != nil {
		t.Fatal(err)
	}
	if c.ID == 0 {
		t.Fatal("expected non-zero ID")
	}

	got, err := repo.GetClientByName(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.PublicKeys) != 1 || len(got.GroupIDs) != 2 {
		t.Fatalf("unexpected client: %+v", got)
	}

	c.Name = "alice-updated"
	if err := repo.UpdateClient(ctx, c); err != nil {
		t.Fatal(err)
	}
	got, _ = repo.GetClientByName(ctx, "alice-updated")
	if got == nil {
		t.Fatal("expected to find updated client")
	}

	if err := repo.RemoveClient(ctx, c.ID); err != nil {
		t.Fatal(err)
	}
	_, err = repo.GetClientByName(ctx, "alice-updated")
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
	c := &models.Client{Name: "carol", PublicKeys: []string{"key"}, GroupIDs: []int64{grp.ID}}
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
	c := &models.Client{Name: "dave", PublicKeys: []string{"key"}, GroupIDs: []int64{}}
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

	c := &models.Client{Name: "eve", PublicKeys: []string{"key"}, GroupIDs: []int64{grp.ID}}
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

// Compile-time interface check
var _ Repository = (*sqliteRepo)(nil)
