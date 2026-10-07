package models_test

import (
	"os"
	"path/filepath"
	"testing"

	"proxpass/internal/models"
)

// TestReadSSHKeyIsEmptyWhenAbsent pins the decision that a missing key file is
// not an error.
//
// A deployment that only uses termproxy never needs this key. Returning an
// error here would break those connections over a file they do not use, so
// the absence has to be reported as "no key" and judged by the caller.
func TestReadSSHKeyIsEmptyWhenAbsent(t *testing.T) {
	t.Setenv(models.SSHKeyPathEnv, filepath.Join(t.TempDir(), "absent"))

	key, err := models.ReadSSHKey()
	if err != nil {
		t.Fatalf("ReadSSHKey: %v", err)
	}
	if key != "" {
		t.Fatalf("expected no key, got %q", key)
	}
}

// TestReadSSHKeyTrimsTheFile checks that the trailing newline ssh-keygen
// writes does not reach the PEM parser.
func TestReadSSHKeyTrimsTheFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(path, []byte("PEM BODY\n"), 0o600); err != nil {
		t.Fatalf("writing key: %v", err)
	}
	t.Setenv(models.SSHKeyPathEnv, path)

	key, err := models.ReadSSHKey()
	if err != nil {
		t.Fatalf("ReadSSHKey: %v", err)
	}
	if key != "PEM BODY" {
		t.Fatalf("expected the trimmed body, got %q", key)
	}
}

// TestReadSSHKeyReportsAnUnreadableFile distinguishes "no key configured"
// from "the key is there but we cannot read it". The first is ordinary, the
// second is a misconfiguration the administrator has to see.
//
// A directory stands in for the unreadable file rather than a 0o000 mode:
// Windows does not enforce that mode, so the read would succeed there and the
// test would fail on a platform where the distinction still matters. Opening
// a directory fails everywhere.
func TestReadSSHKeyReportsAnUnreadableFile(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "key")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("creating the directory: %v", err)
	}
	t.Setenv(models.SSHKeyPathEnv, dir)

	if _, err := models.ReadSSHKey(); err == nil {
		t.Fatal("expected an unreadable key to be reported, got nil")
	}
}

// TestSSHKeyPathPrefersTheEnvironment covers the override a deployment uses
// to mount its own key.
func TestSSHKeyPathPrefersTheEnvironment(t *testing.T) {
	if got := models.SSHKeyPath(); got != models.DefaultSSHKeyPath {
		t.Fatalf("unset: expected %q, got %q", models.DefaultSSHKeyPath, got)
	}

	t.Setenv(models.SSHKeyPathEnv, "/mnt/secrets/proxmox")
	if got := models.SSHKeyPath(); got != "/mnt/secrets/proxmox" {
		t.Fatalf("set: expected the override, got %q", got)
	}
}
