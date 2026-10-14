package db

import (
	"context"
	"testing"

	"proxpass/internal/models"
)

// Access rules whose target is a Proxmox node rather than a guest.
//
// The two kinds are deliberately independent: granting a node does not grant
// its guests, and granting every guest does not grant the node. An
// administrator granting a node is understood to know that a shell there can
// reach the guests on it by other means -- that is a property of the node,
// not something proxpass models.

// addInstance is a Proxmox node to grant access to.
func addInstance(t *testing.T, repo Repository, name string) *models.ProxmoxInstance {
	t.Helper()
	inst := &models.ProxmoxInstance{
		Name:             name,
		APIURL:           "https://" + name + ":8006",
		Node:             name,
		ConsoleTransport: models.ConsoleTransportTermProxy,
		SSHHost:          name,
		SSHPort:          22,
		SSHUser:          "root",
	}
	if err := repo.AddProxmoxInstance(t.Context(), inst); err != nil {
		t.Fatalf("add instance %q: %v", name, err)
	}
	return inst
}

func TestInstanceAccessRules(t *testing.T) {
	repo := newTestRepo(t)
	ctx := context.Background()

	c := &models.Client{Name: testGrantee, PublicKeys: []string{testKey}, GroupIDs: []int64{}}
	if err := repo.AddClient(ctx, c); err != nil {
		t.Fatal(err)
	}
	rome := addInstance(t, repo, "rome")
	paris := addInstance(t, repo, "paris")

	if err := repo.GrantClientInstanceAccess(ctx, c.ID, []int64{rome.ID}); err != nil {
		t.Fatal(err)
	}

	ok, err := repo.HasInstanceAccess(ctx, c.ID, rome.ID)
	if err != nil {
		t.Fatalf("HasInstanceAccess: %v", err)
	}
	if !ok {
		t.Error("granted instance is not reachable")
	}

	// A grant names one instance, not all of them.
	ok, err = repo.HasInstanceAccess(ctx, c.ID, paris.ID)
	if err != nil {
		t.Fatalf("HasInstanceAccess: %v", err)
	}
	if ok {
		t.Error("a grant on one instance reached another")
	}

	if err := repo.RevokeClientInstanceAccess(ctx, c.ID, rome.ID); err != nil {
		t.Fatal(err)
	}
	ok, _ = repo.HasInstanceAccess(ctx, c.ID, rome.ID)
	if ok {
		t.Error("instance still reachable after revoke")
	}
}

// Granting twice is not an error and does not duplicate the rule, which the
// ON CONFLICT clause is there for.
func TestGrantingAnInstanceTwiceIsIdempotent(t *testing.T) {
	repo := newTestRepo(t)
	ctx := context.Background()

	c := &models.Client{Name: testGrantee, PublicKeys: []string{testKey}, GroupIDs: []int64{}}
	if err := repo.AddClient(ctx, c); err != nil {
		t.Fatal(err)
	}
	rome := addInstance(t, repo, "rome")

	for range 2 {
		if err := repo.GrantClientInstanceAccess(ctx, c.ID, []int64{rome.ID}); err != nil {
			t.Fatalf("grant: %v", err)
		}
	}

	rules, err := repo.ListInstanceAccessRules(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rules) != 1 {
		t.Errorf("granting twice produced %d rules, want 1", len(rules))
	}
}

// A group grant reaches every member, like the guest side.
func TestGroupInstanceAccessRules(t *testing.T) {
	repo := newTestRepo(t)
	ctx := context.Background()

	g := &models.Group{Name: testGroupName, ClientIDs: []int64{}}
	if err := repo.AddGroup(ctx, g); err != nil {
		t.Fatal(err)
	}
	c := &models.Client{Name: testGrantee, PublicKeys: []string{testKey}, GroupIDs: []int64{g.ID}}
	if err := repo.AddClient(ctx, c); err != nil {
		t.Fatal(err)
	}
	rome := addInstance(t, repo, "rome")

	if err := repo.GrantGroupInstanceAccess(ctx, g.ID, []int64{rome.ID}); err != nil {
		t.Fatal(err)
	}
	ok, err := repo.HasInstanceAccess(ctx, c.ID, rome.ID)
	if err != nil {
		t.Fatalf("HasInstanceAccess: %v", err)
	}
	if !ok {
		t.Error("a member of a granted group cannot reach the instance")
	}

	if err := repo.RevokeGroupInstanceAccess(ctx, g.ID, rome.ID); err != nil {
		t.Fatal(err)
	}
	ok, _ = repo.HasInstanceAccess(ctx, c.ID, rome.ID)
	if ok {
		t.Error("instance still reachable after the group grant was revoked")
	}
}

// --- the two properties that must not regress ---

// The default policy must NOT reach instances.
//
// HasAccess has a third tier where a client named in default_policy reaches
// anything, and that tier does not look at its target at all. Extending it
// here would hand a shell on every node to every policy-covered client the
// moment this table existed -- and a policy set months ago, when guests were
// the only possible target, is not consent to that.
//
// So this is the test that keeps node access explicit.
func TestTheDefaultPolicyDoesNotReachInstances(t *testing.T) {
	repo := newTestRepo(t)
	ctx := context.Background()

	c := &models.Client{Name: testGrantee, PublicKeys: []string{testKey}, GroupIDs: []int64{}}
	if err := repo.AddClient(ctx, c); err != nil {
		t.Fatal(err)
	}
	rome := addInstance(t, repo, "rome")

	// A policy that reaches every GUEST.
	if err := repo.SetDefaultPolicy(ctx, &models.DefaultAccessPolicy{
		AuthorizedClientIDs: []int64{c.ID},
	}); err != nil {
		t.Fatal(err)
	}

	// It does, so the policy is really in force...
	guest := &models.Guest{
		Type: models.GuestTypeCT, Name: "web", Status: models.StatusRunning,
		ProxmoxID: 100, InstanceID: rome.ID,
	}
	if err := repo.UpsertGuest(ctx, guest); err != nil {
		t.Fatal(err)
	}
	ok, err := repo.HasAccess(ctx, c.ID, guest.ID)
	if err != nil {
		t.Fatalf("HasAccess: %v", err)
	}
	if !ok {
		t.Fatal("the default policy does not reach a guest; the test proves nothing")
	}

	// ...and it still must not reach the node.
	ok, err = repo.HasInstanceAccess(ctx, c.ID, rome.ID)
	if err != nil {
		t.Fatalf("HasInstanceAccess: %v", err)
	}
	if ok {
		t.Error("the default policy reached a Proxmox node: node access must " +
			"be granted explicitly, never inherited from a policy that " +
			"predates instance grants")
	}
}

// Removing an instance must delete the rules that named it.
//
// instance_access_rules has no foreign key -- the same deliberate omission
// as access_rules -- and proxmox_instances.id is AUTOINCREMENT. A rule left
// behind would therefore start granting a node shell to whatever instance
// later occupied that row id.
func TestRemovingAnInstanceDeletesItsAccessRules(t *testing.T) {
	repo := newTestRepo(t)
	ctx := context.Background()

	c := &models.Client{Name: testGrantee, PublicKeys: []string{testKey}, GroupIDs: []int64{}}
	if err := repo.AddClient(ctx, c); err != nil {
		t.Fatal(err)
	}
	rome := addInstance(t, repo, "rome")
	if err := repo.GrantClientInstanceAccess(ctx, c.ID, []int64{rome.ID}); err != nil {
		t.Fatal(err)
	}

	if err := repo.RemoveProxmoxInstance(ctx, rome.ID); err != nil {
		t.Fatalf("remove instance: %v", err)
	}

	rules, err := repo.ListInstanceAccessRules(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rules) != 0 {
		t.Fatalf("removing an instance left %d rule(s) behind; the next "+
			"instance to take that row id would inherit them", len(rules))
	}

	// Demonstrate the consequence that cleanup prevents: a new instance
	// reusing the id must not be reachable.
	reused := addInstance(t, repo, "paris")
	ok, err := repo.HasInstanceAccess(ctx, c.ID, reused.ID)
	if err != nil {
		t.Fatalf("HasInstanceAccess: %v", err)
	}
	if ok {
		t.Error("a new instance inherited a removed instance's grant")
	}
}
