package cli

import (
	"os"
	"path/filepath"
	"testing"
)

// Fixture values shared by the SSH access tests.
const (
	testInstanceName = "pve"
	testLoopback     = "127.0.0.1"
	testSSHUser      = "root"
)

// writeKeyFile writes a key into a temp dir and returns its path.
//
// Takes the directory from t.TempDir() rather than building a path from a
// variable, which gosec reads as a traversal risk.
func writeKeyFile(t *testing.T, key []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "proxpass_key")
	if err := os.WriteFile(path, key, 0o600); err != nil {
		t.Fatalf("writing the key: %v", err)
	}
	return path
}

// readKey returns the contents of a mock host's client key.
func readKey(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("reading the key: %v", err)
	}
	return b
}
