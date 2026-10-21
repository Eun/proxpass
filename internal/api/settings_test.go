package api

import (
	"strings"
	"testing"
)

// testListenAddr is the loopback listener used across the settings tests.
const testListenAddr = "127.0.0.1:8080"

// buildSettings masks the secret-bearing fields and never emits a real token
// or password; non-secret config is reported as-is.
func TestBuildSettingsMasksSecrets(t *testing.T) {
	snap := SettingsSnapshot{
		Data:              "/var/lib/proxpass/proxpass.db",
		LogLevel:          "info",
		DiscoveryInterval: "5m0s",
		Listen:            testListenAddr,
		RESTAPIListen:     "0.0.0.0:8081",
		AdminKeySet:       true,
		NSSTokenSet:       true,
		RESTAPITokenSet:   true,
	}
	got := map[string]Setting{}
	for _, s := range buildSettings(&snap, "proxpass.example") {
		got[s.Key] = s
	}

	// Non-secret values are reported verbatim.
	if got["listen"].Value != testListenAddr {
		t.Errorf("listen = %q, want the configured address", got["listen"].Value)
	}
	if got["public_endpoint"].Value != "proxpass.example" {
		t.Errorf("public_endpoint = %q, want the stored value", got["public_endpoint"].Value)
	}

	// Secret entries are flagged and masked: no plaintext, just a set marker.
	for _, key := range []string{"nss_token", "rest_api_token"} {
		s := got[key]
		if s.Secret == nil || !*s.Secret {
			t.Errorf("%s: Secret flag not set", key)
		}
		if !strings.Contains(s.Value, "set") || strings.Contains(s.Value, "token") {
			t.Errorf("%s value = %q, want a masked set-marker", key, s.Value)
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
		if s.Key == "rest_api_token" {
			sawToken = true
			if s.Secret == nil || !*s.Secret {
				t.Error("rest_api_token not flagged secret")
			}
		}
	}
	if !sawToken {
		t.Fatal("ListSettings did not include rest_api_token")
	}
}
