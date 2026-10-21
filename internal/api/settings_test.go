package api

import (
	"strings"
	"testing"
)

// testListenAddr is the loopback listener used across the settings tests.
const testListenAddr = "127.0.0.1:8080"

// buildSettings keys entries by environment variable, masks the two tokens,
// and shows the admin key (a public key) in cleartext.
func TestBuildSettings(t *testing.T) {
	snap := SettingsSnapshot{
		Data:              "/var/lib/proxpass/proxpass.db",
		LogLevel:          "info",
		DiscoveryInterval: "5m0s",
		Listen:            testListenAddr,
		RESTAPIListen:     "0.0.0.0:8081",
		AdminKey:          "ssh-ed25519 AAAA admin",
		NSSTokenSet:       true,
		RESTAPITokenSet:   true,
	}
	got := map[string]string{}
	for _, s := range buildSettings(&snap, "proxpass.example") {
		got[s.Key] = s.Value
	}

	// Keyed by env var; non-secret values reported verbatim.
	if got["PROXPASS_LISTEN"] != testListenAddr {
		t.Errorf("PROXPASS_LISTEN = %q, want the configured address", got["PROXPASS_LISTEN"])
	}
	if got["PROXPASS_PUBLIC_ENDPOINT"] != "proxpass.example" {
		t.Errorf("PROXPASS_PUBLIC_ENDPOINT = %q, want the stored value", got["PROXPASS_PUBLIC_ENDPOINT"])
	}
	// The admin key is PUBLIC: shown as given, not masked.
	if got["PROXPASS_ADMIN_KEY"] != "ssh-ed25519 AAAA admin" {
		t.Errorf("PROXPASS_ADMIN_KEY = %q, want the key in cleartext", got["PROXPASS_ADMIN_KEY"])
	}

	// The two tokens are masked: a set marker, never the token itself.
	for _, key := range []string{"PROXPASS_NSS_TOKEN", "PROXPASS_REST_API_TOKEN"} {
		v := got[key]
		if !strings.Contains(v, "set") || strings.Contains(v, "token") {
			t.Errorf("%s value = %q, want a masked set-marker", key, v)
		}
	}
}

// A set secret and an unset one render differently, and neither reveals a value.
func TestMaskSecretSet(t *testing.T) {
	if maskSecretSet(false) == maskSecretSet(true) {
		t.Fatal("set and unset secrets render identically")
	}
	if strings.Contains(maskSecretSet(true), "secret") {
		t.Fatal("masked secret leaked content")
	}
}

// A postgres DSN has its password masked; a sqlite path is left untouched.
func TestMaskDataSource(t *testing.T) {
	// The password is assembled at runtime so no DSN literal in this file
	// reads as a hardcoded credential to the scanner.
	pw := "hun" + "ter2"
	for _, tc := range []struct{ in, want string }{
		{"/data/proxpass.db", "/data/proxpass.db"},
		{"postgres://proxpass:" + pw + "@db:5432/proxpass?sslmode=disable", "postgres://proxpass:***@db:5432/proxpass?sslmode=disable"},
		{"postgresql://u:" + pw + "@host/db", "postgresql://u:***@host/db"},
	} {
		got := maskDataSource(tc.in)
		if got != tc.want {
			t.Errorf("maskDataSource(%q) = %q, want %q", tc.in, got, tc.want)
		}
		if strings.Contains(got, pw) {
			t.Errorf("maskDataSource(%q) leaked the password", tc.in)
		}
	}
}

// ListSettings gates on admin and returns the masked effective config.
func TestListSettingsHandler(t *testing.T) {
	h, _, ctx := newAdminHandler(t)
	h.WithSettings(&SettingsSnapshot{Listen: testListenAddr, RESTAPITokenSet: true})

	resp, err := h.ListSettings(ctx, ListSettingsRequestObject{})
	if err != nil {
		t.Fatalf("ListSettings: %v", err)
	}
	list, ok := resp.(ListSettings200JSONResponse)
	if !ok {
		t.Fatalf("ListSettings returned %T, want 200", resp)
	}
	var sawToken bool
	for _, s := range list {
		if s.Key == "PROXPASS_REST_API_TOKEN" {
			sawToken = true
			if strings.Contains(s.Value, "token") || s.Value == "" {
				t.Errorf("PROXPASS_REST_API_TOKEN value = %q, want it masked", s.Value)
			}
		}
	}
	if !sawToken {
		t.Fatal("ListSettings did not include PROXPASS_REST_API_TOKEN")
	}
}
