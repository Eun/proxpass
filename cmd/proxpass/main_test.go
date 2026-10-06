package main

import (
	"context"
	"io"
	"log"
	"path/filepath"
	"testing"

	"proxpass/internal/db"
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
