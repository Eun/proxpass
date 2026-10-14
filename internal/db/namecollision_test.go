package db

import (
	"context"
	"strings"
	"testing"

	"proxpass/internal/models"
)

// Names are unique ignoring case.
//
// Lookups were already case-insensitive in most places while the constraint
// underneath was not, so testClientName and testClientUpper could both exist and a
// case-insensitive lookup would match two rows -- returning whichever the
// scan yielded first. For a client that decides a uid; for a group it
// decides the subject_id written into an access rule. Migration 00010 closes
// that by indexing lower(name).

func TestNamesAreUniqueIgnoringCase(t *testing.T) {
	repo := newTestRepo(t)
	ctx := context.Background()

	t.Run("client", func(t *testing.T) {
		if err := repo.AddClient(ctx, &models.Client{
			Name: testClientName, PublicKeys: []string{testKey}, GroupIDs: []int64{},
		}); err != nil {
			t.Fatalf("first add: %v", err)
		}
		if err := repo.AddClient(ctx, &models.Client{
			Name: testClientUpper, PublicKeys: []string{testKey}, GroupIDs: []int64{},
		}); err == nil {
			t.Error(`testClientUpper was accepted alongside testClientName`)
		}
	})

	t.Run("group", func(t *testing.T) {
		if err := repo.AddGroup(ctx, &models.Group{
			Name: testGroupName, ClientIDs: []int64{},
		}); err != nil {
			t.Fatalf("first add: %v", err)
		}
		if err := repo.AddGroup(ctx, &models.Group{
			Name: strings.ToUpper(testGroupName), ClientIDs: []int64{},
		}); err == nil {
			t.Error(`strings.ToUpper(testGroupName) was accepted alongside testGroupName`)
		}
	})

	t.Run("instance", func(t *testing.T) {
		if err := repo.AddProxmoxInstance(ctx, &models.ProxmoxInstance{
			Name: testNodeName, APIURL: "https://rome:8006", Node: testNodeName,
			ConsoleTransport: models.ConsoleTransportTermProxy,
		}); err != nil {
			t.Fatalf("first add: %v", err)
		}
		if err := repo.AddProxmoxInstance(ctx, &models.ProxmoxInstance{
			Name: "Rome", APIURL: "https://rome2:8006", Node: testNodeName,
			ConsoleTransport: models.ConsoleTransportTermProxy,
		}); err == nil {
			t.Error(`"Rome" was accepted alongside "rome"`)
		}
	})
}

// A client is found by whatever case the caller typed, and the stored
// spelling comes back unchanged.
func TestGetClientByNameIgnoresCase(t *testing.T) {
	repo := newTestRepo(t)
	ctx := context.Background()

	if err := repo.AddClient(ctx, &models.Client{
		Name: testClientName, PublicKeys: []string{testKey}, GroupIDs: []int64{},
	}); err != nil {
		t.Fatal(err)
	}

	for _, typed := range []string{testClientName, "ALICE", testClientUpper, "aLiCe"} {
		c, err := repo.GetClientByName(ctx, typed)
		if err != nil {
			t.Errorf("%s: %v", typed, err)
			continue
		}
		if c.Name != testClientName {
			t.Errorf("%s: Name = %q, want the stored spelling %q",
				typed, c.Name, testClientName)
		}
	}
}

// A database that already holds a case-collision is refused, and the error
// names the pair rather than reporting a bare constraint failure.
//
// Such a database is reachable: every build before migration 00010 accepted
// both spellings. The collision is not resolved automatically because there
// is no correct row to discard -- access_rules.subject_id has no foreign key
// to either, so deleting one would leave rules pointing at an id a later row
// will occupy.
func TestAMigrationRefusesACaseCollisionAndNamesIt(t *testing.T) {
	// Build a database at the schema version BEFORE the index, so both
	// spellings can be inserted, then migrate it.
	path := t.TempDir() + "/collide.db"
	repo, err := NewSQLiteRepository(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	ctx := context.Background()
	if err := repo.AddClient(ctx, &models.Client{
		Name: testClientName, PublicKeys: []string{testKey}, GroupIDs: []int64{},
	}); err != nil {
		t.Fatal(err)
	}
	// Insert the colliding row behind the repository's back: the index now
	// forbids it, which is the point -- this reproduces a database written
	// by an older build.
	sqlDB := repo.(*sqlRepo).db
	if _, err := sqlDB.ExecContext(ctx,
		"DROP INDEX IF EXISTS idx_clients_name_lower"); err != nil {
		t.Fatalf("drop index: %v", err)
	}
	if _, err := sqlDB.ExecContext(ctx,
		`INSERT INTO clients (name, public_keys, group_ids)
		 VALUES ('Alice', '[]', '[]')`); err != nil {
		t.Fatalf("seed collision: %v", err)
	}
	if err := repo.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// Reopening runs the migrations again, which must refuse.
	_, err = NewSQLiteRepository(path)
	if err == nil {
		t.Fatal("a database with a case-collision was migrated anyway")
	}
	for _, want := range []string{testClientName, testClientUpper, "client"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error does not mention %q: %v", want, err)
		}
	}
}

// A database with no collisions migrates cleanly, including one that already
// holds names differing in more than case.
func TestMigrationAcceptsNamesThatDifferBeyondCase(t *testing.T) {
	path := t.TempDir() + "/fine.db"
	repo, err := NewSQLiteRepository(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	ctx := context.Background()
	for _, n := range []string{testClientName, "bob", "Carol"} {
		if err := repo.AddClient(ctx, &models.Client{
			Name: n, PublicKeys: []string{testKey}, GroupIDs: []int64{},
		}); err != nil {
			t.Fatalf("add %s: %v", n, err)
		}
	}
	if err := repo.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	reopened, err := NewSQLiteRepository(path)
	if err != nil {
		t.Fatalf("reopening a clean database failed: %v", err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
}
