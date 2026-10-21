package webui

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestNotPlaceholder asserts the committed dist is a real build, not the
// build-time placeholder. If this fails, someone committed the stub.
func TestNotPlaceholder(t *testing.T) {
	if IsPlaceholder() {
		t.Fatal("embedded UI is the placeholder; run `mise run frontend` and commit internal/webui/dist")
	}
}

// TestHandlerServesIndex asserts the handler serves index.html for "/" and the
// real assets for their paths.
func TestHandlerServesIndex(t *testing.T) {
	h := Handler()

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", http.NoBody))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET / = %d, want 200", rec.Code)
	}
	body, _ := io.ReadAll(rec.Body)
	if !strings.Contains(string(body), "ProxPass") {
		t.Fatalf("index.html missing expected content: %.80q", body)
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/assets/app.css", http.NoBody))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /assets/app.css = %d, want 200", rec.Code)
	}
}

// TestHandlerMissingFile asserts a genuinely missing asset is a 404, not a
// silent index fallback (the SPA uses in-page views, so no history rewrite).
func TestHandlerMissingFile(t *testing.T) {
	h := Handler()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/assets/does-not-exist.js", http.NoBody))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("GET missing asset = %d, want 404", rec.Code)
	}
}
