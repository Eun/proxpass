package api

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// WriteNSSConfig must render a config whose bearer token is exactly the token
// passed (the whole point: serve writes the token it validates), whose URLs
// point at loopback on the listener's port, and which is valid JSON written
// atomically with a login-readable mode.
func TestWriteNSSConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nss_http.json")

	const token = "tok3n-abc123"
	if err := WriteNSSConfig(path, "0.0.0.0:8080", token); err != nil {
		t.Fatalf("WriteNSSConfig: %v", err)
	}

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}

	// Valid JSON.
	var cfg map[string]any
	if err := json.Unmarshal(b, &cfg); err != nil {
		t.Fatalf("config is not valid JSON: %v\n%s", err, b)
	}

	s := string(b)
	// The exact token, in the Bearer header.
	if !strings.Contains(s, `"Bearer `+token+`"`) {
		t.Errorf("config does not carry the exact bearer token %q:\n%s", token, s)
	}
	// Loopback host on the listener's port, NOT the 0.0.0.0 bind address: the
	// NSS module runs in the same container and must reach the directory locally.
	if !strings.Contains(s, "http://127.0.0.1:8080/users") {
		t.Errorf("config URLs are not loopback:port:\n%s", s)
	}
	if strings.Contains(s, "0.0.0.0") {
		t.Errorf("config leaked the bind address 0.0.0.0 into a URL:\n%s", s)
	}
	// All six routes present.
	for _, route := range []string{"/users", "/user/uid/", "/user/name/", "/groups", "/group/gid/", "/group/name/"} {
		if !strings.Contains(s, route) {
			t.Errorf("config is missing the %q route:\n%s", route, s)
		}
	}
	// Login-readable.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Errorf("config mode = %o, want 0644 (NSS module in sshd/sessions must read it)", info.Mode().Perm())
	}
}

// A bind address without a port (unusual, but defend against it) must not crash
// and must fall back to a bare loopback host.
func TestWriteNSSConfigHandlesPortlessListen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nss_http.json")
	if err := WriteNSSConfig(path, "garbage-no-port", "t"); err != nil {
		t.Fatalf("WriteNSSConfig: %v", err)
	}
	b, _ := os.ReadFile(path)
	if !strings.Contains(string(b), "http://127.0.0.1/users") {
		t.Errorf("portless listen did not fall back to bare loopback:\n%s", b)
	}
}
