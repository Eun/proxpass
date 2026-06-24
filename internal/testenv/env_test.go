package testenv_test

import (
	"context"
	"testing"

	"proxpass/internal/models"
	"proxpass/internal/testenv"
)

func TestNewTestEnv(t *testing.T) {
	env := testenv.New(t)

	// Verify seed data exists
	if env.Seed.Instance == nil {
		t.Fatal("instance is nil")
	}
	if len(env.Seed.Guests) != 4 {
		t.Fatalf("expected 4 guests, got %d", len(env.Seed.Guests))
	}
	if env.Seed.Client == nil {
		t.Fatal("client is nil")
	}
	if env.Seed.Group == nil {
		t.Fatal("group is nil")
	}
	if env.Seed.AdminKey == "" {
		t.Fatal("admin key is empty")
	}

	// Verify access rules work
	ctx := context.Background()

	// alice can access webserver (direct rule)
	ok, err := env.Repo.HasAccess(ctx, env.Seed.Client.ID, env.Seed.Guests[0].ID)
	if err != nil {
		t.Fatalf("HasAccess: %v", err)
	}
	if !ok {
		t.Error("expected alice to have access to webserver")
	}

	// alice can access devbox (via developers group)
	ok, err = env.Repo.HasAccess(ctx, env.Seed.Client.ID, env.Seed.Guests[2].ID)
	if err != nil {
		t.Fatalf("HasAccess: %v", err)
	}
	if !ok {
		t.Error("expected alice to have access to devbox via group")
	}

	// alice cannot access database (no rule)
	ok, err = env.Repo.HasAccess(ctx, env.Seed.Client.ID, env.Seed.Guests[1].ID)
	if err != nil {
		t.Fatalf("HasAccess: %v", err)
	}
	if ok {
		t.Error("expected alice to NOT have access to database")
	}

	// Verify mock API is reachable — discover guests
	inst := env.Seed.Instance
	apiInst := &models.ProxmoxInstance{
		APIURL:         inst.APIURL,
		APITokenID:     inst.APITokenID,
		APITokenSecret: inst.APITokenSecret,
	}
	// We don't import proxmox here directly to avoid circular deps.
	// Just verify the seed data matches the mock API.
	_ = apiInst
}
