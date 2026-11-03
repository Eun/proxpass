package db

import (
	"context"
	"errors"
	"strconv"
	"testing"

	"proxpass/internal/filter"
	"proxpass/internal/models"
)

func strp(s string) *string { return &s }

// TestListAccessRulesFilter verifies the guest access-rule list honors the
// JSON filter at the SQL layer, returning only matching rows.
func TestListAccessRulesFilter(t *testing.T) {
	repo := newTestRepo(t)
	ctx := context.Background()

	c := &models.Client{Name: testGrantee, PublicKeys: []string{testKey}, GroupIDs: []int64{}}
	if err := repo.AddClient(ctx, c); err != nil {
		t.Fatal(err)
	}
	g1 := &models.Guest{Type: models.GuestTypeVM, Name: "fvm1", Status: models.StatusRunning, ProxmoxID: 200, InstanceID: 1}
	g2 := &models.Guest{Type: models.GuestTypeVM, Name: "fvm2", Status: models.StatusRunning, ProxmoxID: 201, InstanceID: 1}
	if err := repo.UpsertGuest(ctx, g1); err != nil {
		t.Fatal(err)
	}
	if err := repo.UpsertGuest(ctx, g2); err != nil {
		t.Fatal(err)
	}
	if err := repo.GrantClientAccess(ctx, c.ID, []int64{g1.ID, g2.ID}); err != nil {
		t.Fatal(err)
	}

	// No filter -> both rules.
	all, err := repo.ListAccessRules(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 {
		t.Fatalf("unfiltered list = %d rules, want 2", len(all))
	}

	// Filter by guest_id -> exactly the one rule for g2.
	filtered, err := repo.ListAccessRules(ctx, jsonGuestFilter(g2.ID))
	if err != nil {
		t.Fatalf("filtered list: %v", err)
	}
	if len(filtered) != 1 {
		t.Fatalf("filtered list = %d rules, want 1", len(filtered))
	}
	if filtered[0].GuestID != g2.ID {
		t.Errorf("filtered rule guest_id = %d, want %d", filtered[0].GuestID, g2.ID)
	}

	// Filtering on a non-existent guest yields no rows (not an error).
	none, err := repo.ListAccessRules(ctx, jsonGuestFilter(99999))
	if err != nil {
		t.Fatal(err)
	}
	if len(none) != 0 {
		t.Errorf("filter for absent guest returned %d rules, want 0", len(none))
	}
}

// TestListInstanceAccessRulesFilter mirrors the above for node rules.
func TestListInstanceAccessRulesFilter(t *testing.T) {
	repo := newTestRepo(t)
	ctx := context.Background()

	c := &models.Client{Name: testGrantee, PublicKeys: []string{testKey}, GroupIDs: []int64{}}
	if err := repo.AddClient(ctx, c); err != nil {
		t.Fatal(err)
	}
	rome := addInstance(t, repo, "rome")
	paris := addInstance(t, repo, "paris")
	if err := repo.GrantClientInstanceAccess(ctx, c.ID, []int64{rome.ID, paris.ID}); err != nil {
		t.Fatal(err)
	}

	filtered, err := repo.ListInstanceAccessRules(ctx, strp(`{"instance_id":{"$eq":"`+strconv.FormatInt(paris.ID, 10)+`"}}`))
	if err != nil {
		t.Fatalf("filtered list: %v", err)
	}
	if len(filtered) != 1 || filtered[0].InstanceID != paris.ID {
		t.Fatalf("instance filter = %+v, want one rule for instance %d", filtered, paris.ID)
	}
}

// TestListAccessRulesBadFilter: a malformed or unknown-field filter surfaces
// ErrInvalidFilter so the handler can answer 400.
func TestListAccessRulesBadFilter(t *testing.T) {
	repo := newTestRepo(t)
	ctx := context.Background()
	for _, raw := range []string{
		`{not json`,
		`{"password":{"$eq":"x"}}`,
	} {
		_, err := repo.ListAccessRules(ctx, strp(raw))
		if err == nil || !errors.Is(err, filter.ErrInvalidFilter) {
			t.Errorf("filter %q: err = %v, want ErrInvalidFilter", raw, err)
		}
	}
}

func jsonGuestFilter(id int64) *string {
	return strp(`{"guest_id":{"$eq":"` + strconv.FormatInt(id, 10) + `"}}`)
}
