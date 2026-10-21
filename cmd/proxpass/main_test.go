package main

import (
	"context"
	"io"
	"log"
	"path/filepath"
	"strings"
	"testing"
	"time"

	ucli "github.com/urfave/cli/v3"

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

// serve must refuse to start without a non-empty PROXPASS_NSS_TOKEN: an empty
// token leaves the NSS directory fail-closed, so the process would come up but
// every login lookup would 401. Failing fast turns that silent, login-breaking
// misconfiguration into an obvious startup error. The guard runs before the
// listener blocks, so a short timeout here only matters if it ever regresses.
func TestServeRequiresAnNSSToken(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	data := filepath.Join(t.TempDir(), "proxpass.db")
	cmd := rootCommandForTest()

	for _, tok := range []string{"", "   "} {
		err := cmd.Run(ctx, []string{
			progName, "--data", data, "serve",
			"--listen", "127.0.0.1:0", "--nss-token", tok,
		})
		if err == nil {
			t.Fatalf("serve with nss-token %q: want a startup error, got nil", tok)
		}
		if !strings.Contains(err.Error(), "PROXPASS_NSS_TOKEN") {
			t.Errorf("serve with nss-token %q: error = %v, want it to mention PROXPASS_NSS_TOKEN", tok, err)
		}
		if ctx.Err() != nil {
			t.Fatalf("serve with nss-token %q blocked past the guard (ctx: %v)", tok, ctx.Err())
		}
	}
}

const progName = "proxpass"

// rootCommandForTest mirrors the command wiring in run(): runServe reads both
// root flags (data, admin-key, log-level, public-endpoint) and serve flags, so
// the guard can only be exercised through the assembled command tree.
func rootCommandForTest() *ucli.Command {
	return &ucli.Command{
		Name: progName,
		Flags: []ucli.Flag{
			&ucli.StringFlag{Name: "data"},
			&ucli.StringFlag{Name: "log-level", Value: "info"},
			&ucli.StringFlag{Name: "admin-key"},
			&ucli.StringFlag{Name: "public-endpoint"},
		},
		Commands: []*ucli.Command{serveCommand()},
	}
}
