package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"golang.org/x/mod/semver"
)

// The latest-release check.
//
// proxpass asks GitHub, at most once every latestVersionTTL, for the latest
// release of the repository and compares its tag against the running build.
// The admin UI polls GetLatestVersion so it can show an "update available"
// hint without every browser calling GitHub itself -- one cached answer serves
// the whole deployment, and the call is skipped entirely when PROXPASS_UPDATE_CHECK
// is off (an air-gapped deployment that must not reach out).
//
// The check is best-effort: a disabled check, a "dev" build, an unreachable
// GitHub, or a tag that is not a valid semver all resolve to "no update", with
// an empty latest, so the UI simply shows nothing rather than an error.

const (
	// latestVersionTTL is how long a fetched result is reused before GitHub is
	// asked again. A few hours keeps the UI current without hammering GitHub's
	// unauthenticated rate limit (60/hr/IP).
	latestVersionTTL = 6 * time.Hour

	// latestReleaseURL is the GitHub REST endpoint for the newest, non-draft,
	// non-prerelease release of the proxpass repository.
	latestReleaseURL = "https://api.github.com/repos/Eun/proxpass/releases/latest"

	// githubFetchTimeout bounds the outbound call so a slow or black-holed
	// GitHub never blocks the handler for long.
	githubFetchTimeout = 5 * time.Second

	// devVersion is the build version a plain `go build' reports -- it has no
	// comparable release, so the update check always reports "no update" for it.
	devVersion = "dev"
)

// latestRelease is the slice of the GitHub release payload proxpass needs.
type latestRelease struct {
	TagName string `json:"tag_name"`
	HTMLURL string `json:"html_url"`
}

// fetchLatestReleaseFromGitHub is the default fetcher: it asks GitHub for the
// latest release. Tests inject a fake fetcher instead (WithLatestFetcher).
func fetchLatestReleaseFromGitHub(ctx context.Context) (latestRelease, error) {
	ctx, cancel := context.WithTimeout(ctx, githubFetchTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, latestReleaseURL, http.NoBody)
	if err != nil {
		return latestRelease{}, fmt.Errorf("building the GitHub request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return latestRelease{}, fmt.Errorf("fetching the latest release: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return latestRelease{}, fmt.Errorf("GitHub returned %s", resp.Status)
	}

	var out latestRelease
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return latestRelease{}, fmt.Errorf("decoding the GitHub response: %w", err)
	}
	return out, nil
}

// latestResult returns the cached latest-release answer, refreshing it from the
// fetcher when the cache is empty or older than latestVersionTTL. A fetch error
// is swallowed: the stale value is kept if there is one, otherwise an empty
// release is returned, so the caller degrades to "no update".
//
// The mutex serializes the refresh so a burst of UI polls makes at most one
// GitHub call per TTL.
func (h *SessionHandler) latestResult(ctx context.Context) latestRelease {
	h.latestMu.Lock()
	defer h.latestMu.Unlock()

	if h.latestCache != nil && h.now().Sub(h.latestFetched) < latestVersionTTL {
		return *h.latestCache
	}

	fetch := h.fetchLatest
	if fetch == nil {
		fetch = fetchLatestReleaseFromGitHub
	}
	rel, err := fetch(ctx)
	if err != nil {
		h.logger.Printf("update check: %v", err)
		if h.latestCache != nil {
			return *h.latestCache // keep the last good answer
		}
		return latestRelease{}
	}
	h.latestCache = &rel
	h.latestFetched = h.now()
	return rel
}

// compareVersions reports whether latest is a newer release than current.
//
// Both are expected to be "vX.Y.Z" tags. A "dev" (or otherwise non-semver)
// current, or a non-semver latest, yields false: there is nothing meaningful to
// compare, so no update is offered.
func updateAvailable(current, latest string) bool {
	if !semver.IsValid(current) || !semver.IsValid(latest) {
		return false
	}
	return semver.Compare(latest, current) > 0
}
