package main

import (
	"context"
	"errors"
	"io"
	"log"
	"path/filepath"
	"strings"
	"testing"

	"proxpass/internal/db"
	"proxpass/internal/session"
)

func testRepo(t *testing.T) db.Repository {
	t.Helper()
	repo, err := db.NewSQLiteRepository(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("opening the test database: %v", err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	return repo
}

// The public endpoint has to survive the trip from `proxpass serve' to a
// session, and the database is the only thing both processes share: sshd
// hands the session a fresh environment, so the variable that configured
// serve is not set there.
func TestStorePublicEndpointRoundTrip(t *testing.T) {
	repo := testRepo(t)
	ctx := context.Background()
	logger := log.New(io.Discard, "", 0)

	if err := storePublicEndpoint(ctx, repo, "proxpass.example.com", logger); err != nil {
		t.Fatalf("storing: %v", err)
	}
	got, err := repo.GetSetting(ctx, db.SettingPublicEndpoint)
	if err != nil {
		t.Fatal(err)
	}
	if got != "proxpass.example.com" {
		t.Errorf("stored endpoint = %q, want %q", got, "proxpass.example.com")
	}
}

// It describes the deployment rather than granting anything, so unlike the
// admin key it is updated in place: changing the compose file and restarting
// must change what sessions display.
func TestStorePublicEndpointReplaces(t *testing.T) {
	repo := testRepo(t)
	ctx := context.Background()
	logger := log.New(io.Discard, "", 0)

	for _, v := range []string{"old.example.com", "new.example.com"} {
		if err := storePublicEndpoint(ctx, repo, v, logger); err != nil {
			t.Fatalf("storing %q: %v", v, err)
		}
	}
	got, err := repo.GetSetting(ctx, db.SettingPublicEndpoint)
	if err != nil {
		t.Fatal(err)
	}
	if got != "new.example.com" {
		t.Errorf("endpoint = %q, want the newer %q", got, "new.example.com")
	}
}

// Removing the variable must remove the endpoint, not leave the previous one
// behind: a stale hostname in the status bar is worse than none, because it
// tells the user to connect somewhere that may no longer work.
func TestStorePublicEndpointClears(t *testing.T) {
	repo := testRepo(t)
	ctx := context.Background()
	logger := log.New(io.Discard, "", 0)

	if err := storePublicEndpoint(ctx, repo, "proxpass.example.com", logger); err != nil {
		t.Fatal(err)
	}
	if err := storePublicEndpoint(ctx, repo, "", logger); err != nil {
		t.Fatalf("clearing: %v", err)
	}
	got, err := repo.GetSetting(ctx, db.SettingPublicEndpoint)
	if err != nil {
		t.Fatal(err)
	}
	if got != "" {
		t.Errorf("endpoint = %q after clearing, want empty", got)
	}
}

// Surrounding whitespace in a compose file is easy to introduce and would
// otherwise end up rendered in the bar.
func TestStorePublicEndpointTrimsWhitespace(t *testing.T) {
	repo := testRepo(t)
	ctx := context.Background()
	logger := log.New(io.Discard, "", 0)

	if err := storePublicEndpoint(ctx, repo, "  proxpass.example.com\n", logger); err != nil {
		t.Fatal(err)
	}
	got, err := repo.GetSetting(ctx, db.SettingPublicEndpoint)
	if err != nil {
		t.Fatal(err)
	}
	if got != "proxpass.example.com" {
		t.Errorf("endpoint = %q, want it trimmed", got)
	}
}

// --- client database fallback ---

// testLoginName is the alias a session arrives with.
const testLoginName = "tobias"

// A client whose API exchange failed must not continue with a database
// handle. Before this check the only thing stopping it was the file mode,
// which is a property of the shipped image rather than of the program.
func TestAClientIsRefusedTheDatabaseFallback(t *testing.T) {
	err := refuseClientDatabaseFallback(
		&session.Identity{User: testLoginName, DisplayName: "alice", ClientID: 7},
		errors.New("no session token in the environment"))
	if err == nil {
		t.Fatal("a client session was allowed to fall back to the database")
	}
	// The message has to name the likely cause: when this fires, the
	// session is dead and the operator needs to know why.
	if !strings.Contains(err.Error(), session.TokenEnv) {
		t.Errorf("the error does not name %s: %v", session.TokenEnv, err)
	}
}

// The administrator still needs it: the admin CLI writes, and nothing
// serves it yet.
func TestAnAdminMayStillUseTheDatabase(t *testing.T) {
	if err := refuseClientDatabaseFallback(
		&session.Identity{User: testLoginName, DisplayName: "admin", IsAdmin: true},
		errors.New("no session token")); err != nil {
		t.Fatalf("the administrator was refused the database: %v", err)
	}
}

// The reason the API failed must survive, so the log says what to fix.
func TestTheFallbackRefusalKeepsTheAPIError(t *testing.T) {
	apiErr := errors.New("connection refused")
	err := refuseClientDatabaseFallback(
		&session.Identity{User: testLoginName, DisplayName: "alice", ClientID: 1}, apiErr)
	if !errors.Is(err, apiErr) {
		t.Fatalf("the API error was lost: %v", err)
	}
}
