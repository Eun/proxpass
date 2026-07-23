package proxmox_test

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"proxpass/internal/models"
	"proxpass/internal/proxmox"
)

const testTokenID = "user@pam!tok"

// TestAPIURLPortPreserved verifies that a URL with a non-default port
// is actually used when making HTTP requests -- the request must reach
// the server on its specific port, not port 80 or 443.
func TestAPIURLPortPreserved(t *testing.T) {
	var gotHost string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Host
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[]}`))
	}))
	defer srv.Close()

	// srv.URL is e.g. "http://127.0.0.1:54321" -- a non-standard port.
	inst := &models.ProxmoxInstance{
		APIURL:         srv.URL,
		APITokenID:     testTokenID,
		APITokenSecret: "secret",
	}

	client, err := proxmox.NewAPIClient(inst)
	if err != nil {
		t.Fatalf("NewAPIClient: %v", err)
	}
	// DiscoverGuests will fail (empty node list is fine), but the
	// request must have been sent to the right host:port.
	_, _ = client.DiscoverGuests(context.Background())

	port := srv.Listener.Addr().(*net.TCPAddr).Port
	want := fmt.Sprintf("127.0.0.1:%d", port)
	if gotHost != want {
		t.Errorf("request Host header = %q, want %q -- port was not preserved", gotHost, want)
	} else {
		t.Logf("OK: request reached correct host:port %q", gotHost)
	}
}
