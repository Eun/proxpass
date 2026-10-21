package api_test

import (
	"net/http"
	"strings"
	"testing"
)

// TestWebUIServedAtRoot asserts the admin SPA is served at "/" on the loopback
// handler, so an operator who opens the listener in a browser gets the UI.
func TestWebUIServedAtRoot(t *testing.T) {
	h, _ := newTestServer(t)

	rec := get(t, h, "/")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET / = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("GET / content-type = %q, want text/html", ct)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "ProxPass") {
		t.Fatalf("GET / body does not look like the admin UI: %.120q", body)
	}
	// A placeholder stub must never be what ships. The committed dist is a
	// real build, so the marker must be absent.
	if strings.Contains(body, "PROXPASS_WEBUI_PLACEHOLDER") {
		t.Fatal("GET / served the placeholder UI; run `mise run frontend`")
	}
}

// TestWebUIAssetsServed asserts the built CSS and vendored JS resolve, so the
// page the browser loads is complete rather than referencing missing files.
func TestWebUIAssetsServed(t *testing.T) {
	h, _ := newTestServer(t)

	for _, tc := range []struct {
		path  string
		ctHas string
	}{
		{"/assets/app.css", "text/css"},
		{"/assets/js/alpine.min.js", "javascript"},
		{"/assets/js/chart.min.js", "javascript"},
	} {
		rec := get(t, h, tc.path)
		if rec.Code != http.StatusOK {
			t.Errorf("GET %s = %d, want 200", tc.path, rec.Code)
			continue
		}
		if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, tc.ctHas) {
			t.Errorf("GET %s content-type = %q, want it to contain %q", tc.path, ct, tc.ctHas)
		}
	}
}

// TestOpenAPISpecServed asserts /openapi.json returns the embedded spec as
// JSON, unauthenticated, so the UI (or any client) can fetch it.
func TestOpenAPISpecServed(t *testing.T) {
	h, _ := newTestServer(t)

	rec := get(t, h, "/openapi.json")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /openapi.json = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("GET /openapi.json content-type = %q, want application/json", ct)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "/v1/instances") {
		t.Fatalf("GET /openapi.json does not contain the /v1 paths: %.160q", body)
	}
}

// TestWebUIDoesNotShadowAPI asserts the SPA catch-all does not intercept API
// routes: an API path still reaches the API (here, an auth error), not the UI.
func TestWebUIDoesNotShadowAPI(t *testing.T) {
	h, _ := newTestServer(t)

	rec := get(t, h, "/v1/instances")
	// No credential -> the admin gate answers (401/403), definitely not the
	// SPA's 200 text/html.
	if rec.Code == http.StatusOK {
		t.Fatalf("GET /v1/instances = 200; the SPA catch-all shadowed the API")
	}
	if ct := rec.Header().Get("Content-Type"); strings.HasPrefix(ct, "text/html") {
		t.Fatalf("GET /v1/instances served HTML (%q); the SPA shadowed the API", ct)
	}
}
