package db

import (
	"context"
	"strings"
	"testing"

	"proxpass/internal/models"
)

// An accented name, in both spellings. SQLite's lower() folds neither to the
// other -- it is ASCII-only -- which is the difference these pin.
const (
	testAccentedName  = "alicé"
	testAccentedUpper = "ALICÉ"
)

// Names are folded in Go on the way into the database (models.FoldName), so
// the plain UNIQUE(name) constraint that has existed since the initial schema
// is what makes them unique ignoring case. Nothing in SQL knows about case.

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

// A name is stored folded, and the caller's struct is updated to say so.
//
// The write-back is not cosmetic: `instance add' re-finds the row it just
// created by matching inst.Name against the listed rows, to get the id
// discovery needs. A struct left holding the typed spelling would not match.
func TestAddingAnInstanceFoldsTheNameInTheCallersStruct(t *testing.T) {
	repo := newTestRepo(t)
	ctx := context.Background()

	inst := &models.ProxmoxInstance{
		Name: "ROME", APIURL: "https://rome:8006", Node: testNodeName,
		ConsoleTransport: models.ConsoleTransportTermProxy,
	}
	if err := repo.AddProxmoxInstance(ctx, inst); err != nil {
		t.Fatal(err)
	}
	if inst.Name != testNodeName {
		t.Errorf("inst.Name = %q, want the folded %q", inst.Name, testNodeName)
	}

	listed, err := repo.ListProxmoxInstances(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 1 || listed[0].Name != testNodeName {
		t.Fatalf("stored %v, want one instance named %q", listed, testNodeName)
	}
	// The match `instance add' performs, against the struct it passed in.
	if listed[0].Name != inst.Name {
		t.Errorf("the stored name %q does not match the caller's struct %q",
			listed[0].Name, inst.Name)
	}
}

func TestAddingAClientFoldsTheName(t *testing.T) {
	repo := newTestRepo(t)
	ctx := context.Background()

	c := &models.Client{
		Name: testClientUpper, PublicKeys: []string{testKey}, GroupIDs: []int64{},
	}
	if err := repo.AddClient(ctx, c); err != nil {
		t.Fatal(err)
	}
	if c.Name != testClientName {
		t.Errorf("client.Name = %q, want the folded %q", c.Name, testClientName)
	}
}

// A client is found by whatever case the caller typed.
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
			t.Errorf("%s: Name = %q, want %q", typed, c.Name, testClientName)
		}
	}
}

// Folding is Unicode-aware, which SQL's lower() is not.
//
// SQLite's lower() is ASCII-only -- it folds "ALICÉ" to "alicÉ" -- so a
// database-side rule would have treated these as two different clients while
// models.FoldName treats them as one. Postgres' lower() is locale-dependent
// and would have disagreed with BOTH. This is the behavior that moving the
// rule into Go buys: the same answer on every backend.
func TestFoldingIsUnicodeAwareUnlikeSQLLower(t *testing.T) {
	repo := newTestRepo(t)
	ctx := context.Background()

	if err := repo.AddClient(ctx, &models.Client{
		Name: testAccentedName, PublicKeys: []string{testKey}, GroupIDs: []int64{},
	}); err != nil {
		t.Fatal(err)
	}
	if err := repo.AddClient(ctx, &models.Client{
		Name: testAccentedUpper, PublicKeys: []string{testKey}, GroupIDs: []int64{},
	}); err == nil {
		t.Error("the upper-case accented name was accepted alongside the lower")
	}
	c, err := repo.GetClientByName(ctx, testAccentedUpper)
	if err != nil {
		t.Fatalf("looking up %q: %v", testAccentedUpper, err)
	}
	if c.Name != testAccentedName {
		t.Errorf("Name = %q, want %q", c.Name, testAccentedName)
	}
}

// Names written by an older build are folded when the database is opened.
//
// Without this an unfolded row is not merely untidy: GetClientByName matches
// `name = ?' against a folded argument, so a client stored as "Alice" would
// stop being found at all.
func TestOpeningFoldsNamesWrittenByAnOlderBuild(t *testing.T) {
	path := t.TempDir() + "/legacy.db"
	repo, err := NewSQLiteRepository(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	ctx := context.Background()

	// Write the unfolded spellings behind the repository's back, reproducing
	// a database written before names were folded.
	sqlDB := repo.(*sqlRepo).db
	for _, stmt := range []string{
		`INSERT INTO clients (name, public_keys, group_ids) VALUES ('Alice', '[]', '[]')`,
		`INSERT INTO groups (name, client_ids) VALUES ('OPS', '[]')`,
	} {
		if _, err := sqlDB.ExecContext(ctx, stmt); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	if err := repo.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	reopened, err := NewSQLiteRepository(path)
	if err != nil {
		t.Fatalf("reopening: %v", err)
	}
	t.Cleanup(func() { _ = reopened.Close() })

	c, err := reopened.GetClientByName(ctx, testClientUpper)
	if err != nil {
		t.Fatalf("the legacy client was not found after folding: %v", err)
	}
	if c.Name != testClientName {
		t.Errorf("client name = %q, want the folded %q", c.Name, testClientName)
	}

	groups, err := reopened.ListGroups(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 1 || groups[0].Name != testGroupName {
		t.Errorf("groups = %v, want one named %q", groups, testGroupName)
	}
}

// A database holding two names that fold together is refused, and the error
// names the pair rather than reporting a bare constraint failure.
//
// Such a database is reachable: every build before names were folded accepted
// both spellings. The collision is not resolved automatically because there
// is no correct row to discard -- access_rules.subject_id has no foreign key
// to either, so deleting one would leave rules pointing at an id a later row
// will occupy.
func TestOpeningRefusesACaseCollisionAndNamesIt(t *testing.T) {
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
	sqlDB := repo.(*sqlRepo).db
	if _, err := sqlDB.ExecContext(ctx,
		`INSERT INTO clients (name, public_keys, group_ids)
		 VALUES ('Alice', '[]', '[]')`); err != nil {
		t.Fatalf("seed collision: %v", err)
	}
	if err := repo.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	_, err = NewSQLiteRepository(path)
	if err == nil {
		t.Fatal("a database with a case-collision was opened anyway")
	}
	for _, want := range []string{testClientName, testClientUpper, "client"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error does not mention %q: %v", want, err)
		}
	}
}

// The refusal must be driven by the SAME folding the write uses.
//
// Asking the database for lower(name) would report no collision here --
// SQLite's lower() leaves "ALICÉ" as "alicÉ" -- and the fold that follows
// would then hit the UNIQUE constraint with a bare error. The check has to
// predict exactly what the write will do.
func TestTheRefusalUsesGoFoldingNotSQLLower(t *testing.T) {
	path := t.TempDir() + "/unicode-collide.db"
	repo, err := NewSQLiteRepository(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	ctx := context.Background()
	sqlDB := repo.(*sqlRepo).db
	for _, n := range []string{testAccentedName, testAccentedUpper} {
		if _, err := sqlDB.ExecContext(ctx,
			`INSERT INTO clients (name, public_keys, group_ids) VALUES (?, '[]', '[]')`,
			n); err != nil {
			t.Fatalf("seed %q: %v", n, err)
		}
	}
	if err := repo.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	_, err = NewSQLiteRepository(path)
	if err == nil {
		t.Fatal("a database with a non-ASCII case-collision was opened anyway")
	}
	if !strings.Contains(err.Error(), "differ only by case") {
		t.Errorf("want a named collision, got: %v", err)
	}
}

// A database with no collisions opens cleanly, including one that already
// holds names differing in more than case.
func TestOpeningAcceptsNamesThatDifferBeyondCase(t *testing.T) {
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
