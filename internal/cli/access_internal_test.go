package cli

import (
	"testing"

	"proxpass/internal/db"
	"proxpass/internal/models"
)

// newAccessRepo seeds two instances that both host ct200, so the bare VMID
// is ambiguous and only the qualified form can name one.
func newAccessRepo(t *testing.T) (repo db.Repository, romeID, parisID int64) {
	t.Helper()
	repo, err := db.NewSQLiteRepository(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatalf("open repository: %v", err)
	}
	t.Cleanup(func() { _ = repo.Close() })

	rome := &models.ProxmoxInstance{
		Name: "rome", APIURL: "https://rome:8006", Node: "rome",
		ConnectionType: models.ConnectionTypeTermProxy,
	}
	paris := &models.ProxmoxInstance{
		Name: "paris", APIURL: "https://paris:8006", Node: "paris",
		ConnectionType: models.ConnectionTypeTermProxy,
	}
	for _, i := range []*models.ProxmoxInstance{rome, paris} {
		if err := repo.AddProxmoxInstance(t.Context(), i); err != nil {
			t.Fatalf("add instance: %v", err)
		}
	}
	for _, id := range []int64{rome.ID, paris.ID} {
		if err := repo.UpsertGuest(t.Context(), &models.Guest{
			Type: models.GuestTypeCT, Name: "shared",
			Status: models.StatusRunning, ProxmoxID: 200, InstanceID: id,
		}); err != nil {
			t.Fatalf("upsert guest: %v", err)
		}
	}
	return repo, rome.ID, paris.ID
}

// `access grant --guest ct200@rome` must work.
//
// This path resolved a RAW identifier and never parsed "@", so a VMID
// present on two instances could not be granted at all: ambiguous
// unqualified, and unqualifiable here. Covered through
// resolveGuestIdentifiers itself rather than its helpers, because the bug
// was the missing call.
func TestResolveGuestIdentifiersAcceptsTheQualifiedForm(t *testing.T) {
	repo, romeID, parisID := newAccessRepo(t)
	deps := &Deps{Repo: repo}

	for _, tc := range []struct {
		ident string
		want  int64
	}{
		{"ct200@rome", romeID},
		{"ct200@paris", parisID},
		{"shared@rome", romeID},
		{"200@paris", parisID},
	} {
		ids, names, err := resolveGuestIdentifiers(t.Context(), deps, []string{tc.ident})
		if err != nil {
			t.Errorf("%s: %v", tc.ident, err)
			continue
		}
		if len(ids) != 1 || len(names) != 1 {
			t.Errorf("%s: got %d ids, want 1", tc.ident, len(ids))
			continue
		}
		guests, _ := repo.ListGuests(t.Context())
		var gotInstance int64
		for _, g := range guests {
			if g.ID == ids[0] {
				gotInstance = g.InstanceID
			}
		}
		if gotInstance != tc.want {
			t.Errorf("%s resolved to instance %d, want %d",
				tc.ident, gotInstance, tc.want)
		}
	}
}

// The bare form must still be refused as ambiguous rather than guessed.
func TestResolveGuestIdentifiersStillRefusesAmbiguity(t *testing.T) {
	repo, _, _ := newAccessRepo(t)
	deps := &Deps{Repo: repo}

	if _, _, err := resolveGuestIdentifiers(
		t.Context(), deps, []string{"ct200"}); err == nil {
		t.Error("an unqualified colliding VMID must be refused")
	}
}
