package api

// Tests for GetLatestVersion: the GitHub latest-release comparison. Internal
// (package api) so the handler is called directly with a credential on the
// context and the injectable fetcher/clock are reachable.

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"proxpass/internal/models"
)

// fakeFetcher returns a fixed release and counts how many times it ran, so a
// test can assert the cache suppresses repeat GitHub calls.
func fakeFetcher(tag, url string, calls *int32) func(context.Context) (latestRelease, error) {
	return func(context.Context) (latestRelease, error) {
		atomic.AddInt32(calls, 1)
		return latestRelease{TagName: tag, HTMLURL: url}, nil
	}
}

// adminHandlerFor returns a handler at a known build version with the given
// fetcher and update-check setting, plus an admin context.
//
// The admin session is seeded with a far-future expiry so tests that advance
// h.now across the cache TTL (hours ahead) do not accidentally expire the
// credential and hit the 401 gate -- they are testing the cache, not auth.
func adminHandlerFor(t *testing.T, version string, enabled bool,
	fetch func(context.Context) (latestRelease, error),
) (*SessionHandler, context.Context) {
	t.Helper()
	h, repo, _ := newAdminHandler(t)
	h.WithVersion(version).WithUpdateCheck(enabled).WithLatestFetcher(fetch)

	const token = "long-lived-admin" // fake test credential
	now := time.Now()
	identity := &models.SessionIdentity{LoginName: AdminUser, IdentityName: AdminUser, IsAdmin: true}
	if err := repo.CreateAPISession(
		t.Context(), HashToken(token), identity, now, now.Add(365*24*time.Hour)); err != nil {
		t.Fatalf("create long-lived api session: %v", err)
	}
	ctx := context.WithValue(t.Context(), bearerTokenKey, token)
	return h, ctx
}

func getLatest(ctx context.Context, t *testing.T, h *SessionHandler) LatestVersion {
	t.Helper()
	resp, err := h.GetLatestVersion(ctx, GetLatestVersionRequestObject{})
	if err != nil {
		t.Fatalf("GetLatestVersion: %v", err)
	}
	ok, is := resp.(GetLatestVersion200JSONResponse)
	if !is {
		t.Fatalf("expected 200, got %T", resp)
	}
	return LatestVersion(ok)
}

// TestLatestVersionReportsAnUpdate is the case the UI shows a hint for: a newer
// tag exists on GitHub.
func TestLatestVersionReportsAnUpdate(t *testing.T) {
	var calls int32
	h, ctx := adminHandlerFor(t, "v0.0.30", true,
		fakeFetcher("v0.0.31", "https://github.com/Eun/proxpass/releases/tag/v0.0.31", &calls))

	got := getLatest(ctx, t, h)
	if !got.UpdateAvailable {
		t.Fatal("expected update_available=true when latest > current")
	}
	if got.Current != "v0.0.30" || got.Latest != "v0.0.31" {
		t.Fatalf("current/latest = %q/%q", got.Current, got.Latest)
	}
	if got.HTMLURL == "" {
		t.Fatal("expected the release URL to be reported")
	}
}

// TestLatestVersionUpToDate: current equals latest, so no update.
func TestLatestVersionUpToDate(t *testing.T) {
	var calls int32
	h, ctx := adminHandlerFor(t, "v0.0.31", true, fakeFetcher("v0.0.31", "u", &calls))
	if getLatest(ctx, t, h).UpdateAvailable {
		t.Fatal("expected update_available=false when current == latest")
	}
}

// TestLatestVersionNormalizesVPrefix is the production case: goreleaser injects
// the build version WITHOUT the leading "v" (0.0.33) while GitHub's tag keeps it
// (v0.0.34). The compare must normalize both, or no update is ever offered.
func TestLatestVersionNormalizesVPrefix(t *testing.T) {
	var calls int32
	// current "0.0.33" (no v, as in prod) vs latest "v0.0.34" -> update.
	h, ctx := adminHandlerFor(t, "0.0.33", true, fakeFetcher("v0.0.34", "u", &calls))
	if !getLatest(ctx, t, h).UpdateAvailable {
		t.Fatal("expected an update when current lacks the v prefix but latest is newer")
	}
	// Same version, differing only by the prefix -> NOT an update.
	h2, ctx2 := adminHandlerFor(t, "0.0.33", true, fakeFetcher("v0.0.33", "u", &calls))
	if getLatest(ctx2, t, h2).UpdateAvailable {
		t.Fatal("0.0.33 and v0.0.33 are the same release; expected no update")
	}
}

// TestLatestVersionDevBuildNeverUpdates: a "dev" build has no comparable
// version, so it never claims an update even if GitHub has a release.
func TestLatestVersionDevBuildNeverUpdates(t *testing.T) {
	var calls int32
	h, ctx := adminHandlerFor(t, devVersion, true, fakeFetcher("v9.9.9", "u", &calls))
	got := getLatest(ctx, t, h)
	if got.UpdateAvailable {
		t.Fatal("a dev build must never report update_available")
	}
	if got.Current != devVersion {
		t.Fatalf("current = %q, want %q", got.Current, devVersion)
	}
}

// TestLatestVersionDisabledSkipsGitHub: with the check off, the fetcher is
// never called and latest is empty.
func TestLatestVersionDisabledSkipsGitHub(t *testing.T) {
	var calls int32
	h, ctx := adminHandlerFor(t, "v0.0.30", false, fakeFetcher("v0.0.31", "u", &calls))
	got := getLatest(ctx, t, h)
	if got.UpdateAvailable || got.Latest != "" {
		t.Fatalf("disabled check must not report a latest; got %+v", got)
	}
	if atomic.LoadInt32(&calls) != 0 {
		t.Fatalf("disabled check must not call GitHub; calls=%d", calls)
	}
}

// TestLatestVersionCachesWithinTTL: repeat calls within the TTL hit the cache,
// so GitHub is asked only once.
func TestLatestVersionCachesWithinTTL(t *testing.T) {
	var calls int32
	h, ctx := adminHandlerFor(t, "v0.0.30", true, fakeFetcher("v0.0.31", "u", &calls))

	for i := 0; i < 5; i++ {
		getLatest(ctx, t, h)
	}
	if n := atomic.LoadInt32(&calls); n != 1 {
		t.Fatalf("expected 1 GitHub call within the TTL, got %d", n)
	}
}

// TestLatestVersionRefetchesAfterTTL: once the cache is older than the TTL, the
// next call fetches again. The clock is advanced via h.now.
func TestLatestVersionRefetchesAfterTTL(t *testing.T) {
	var calls int32
	h, ctx := adminHandlerFor(t, "v0.0.30", true, fakeFetcher("v0.0.31", "u", &calls))

	base := time.Now()
	h.now = func() time.Time { return base }
	getLatest(ctx, t, h) // fetch #1, cached at base

	h.now = func() time.Time { return base.Add(latestVersionTTL + time.Minute) }
	getLatest(ctx, t, h) // cache stale -> fetch #2

	if n := atomic.LoadInt32(&calls); n != 2 {
		t.Fatalf("expected a refetch after the TTL, got %d calls", n)
	}
}

// TestLatestVersionKeepsStaleOnError: when a refetch fails, the last good
// answer is kept rather than wiped.
func TestLatestVersionKeepsStaleOnError(t *testing.T) {
	var calls int32
	good := fakeFetcher("v0.0.31", "u", &calls)
	h, ctx := adminHandlerFor(t, "v0.0.30", true, good)

	base := time.Now()
	h.now = func() time.Time { return base }
	getLatest(ctx, t, h) // caches v0.0.31

	// Now make the fetcher fail and advance past the TTL.
	h.fetchLatest = func(context.Context) (latestRelease, error) {
		return latestRelease{}, errors.New("github unreachable")
	}
	h.now = func() time.Time { return base.Add(latestVersionTTL + time.Minute) }
	got := getLatest(ctx, t, h)
	if got.Latest != "v0.0.31" {
		t.Fatalf("expected the stale good answer to be kept, got latest=%q", got.Latest)
	}
}

// TestLatestVersionEmptyOnErrorWithNoCache: a fetch failure with nothing cached
// degrades to "no update", not an error.
func TestLatestVersionEmptyOnErrorWithNoCache(t *testing.T) {
	h, ctx := adminHandlerFor(t, "v0.0.30", true,
		func(context.Context) (latestRelease, error) {
			return latestRelease{}, errors.New("github unreachable")
		})
	got := getLatest(ctx, t, h)
	if got.UpdateAvailable || got.Latest != "" {
		t.Fatalf("a failed fetch with no cache must report no update; got %+v", got)
	}
}

// TestLatestVersionRefusesAClient: the endpoint is admin-only.
func TestLatestVersionRefusesAClient(t *testing.T) {
	var calls int32
	h, _, _ := newAdminHandler(t)
	h.WithVersion("v0.0.30").WithUpdateCheck(true).WithLatestFetcher(fakeFetcher("v0.0.31", "u", &calls))
	repo := h.repo
	resp, err := h.GetLatestVersion(clientCtx(t, repo), GetLatestVersionRequestObject{})
	if err != nil {
		t.Fatalf("GetLatestVersion: %v", err)
	}
	if _, is := resp.(GetLatestVersion403JSONResponse); !is {
		t.Fatalf("expected 403 for a client, got %T", resp)
	}
}
