package cli_test

import (
	"strings"
	"testing"

	"proxpass/internal/api"
	"proxpass/internal/cli"
)

func TestValidateClientName(t *testing.T) {
	// proxpass serves users over NSS rather than from /etc/passwd, so it is
	// not bound by the base image's useradd policy and accepts more than
	// useradd would: mixed case, a leading digit, dots and non-ASCII.
	valid := []string{
		"alice", "bob2", "deploy-bot", "_svc", "a", strings.Repeat("a", api.MaxLoginNameLen),
		"Alice", "1alice", "alice.b", "alicé", "alice@host", "alice+tag",
	}
	for _, name := range valid {
		if err := cli.ValidateClientName(name); err != nil {
			t.Errorf("ValidateClientName(%q) = %v, want nil", name, err)
		}
	}

	invalid := map[string]string{
		"dot":            ".",
		"dotdot":         "..",
		"percent":        "alice%",
		"hash":           "alice#b",
		"empty":          "",
		"reserved admin": "admin",
		"reserved upper": "ADMIN",
		"reserved mixed": "Admin",
		"leading hyphen": "-alice",
		"space":          "al ice",
		"slash":          "al/ice",
		"path traversal": "../root",
		"colon":          "al:ice",
		"newline":        "alice\nbob",
		"url escape":     "alice%2f",
		"too long":       strings.Repeat("a", api.MaxLoginNameLen+1),
		// A shell metacharacter is safe on its own -- the wrappers quote
		// "$@" and nothing interpolates the name into a shell -- but a
		// client name is also written into the access-rule output, so keep
		// the CLI's own surface conservative.
		"query string":     "alice?x=1",
		"trailing newline": "alice\n",
	}
	for what, name := range invalid {
		if err := cli.ValidateClientName(name); err == nil {
			t.Errorf("%s: ValidateClientName(%q) = nil, want an error", what, name)
		}
	}
}

// A single --key must never be able to install more than one credential.
// gossh.ParseAuthorizedKey stops at the first line, and the stored value is
// later printed verbatim into sshd's AuthorizedKeysCommand output, so a
// multi-line value would add keys that the admin never reviewed and that
// "client ls" would still count as one.
func TestValidatePublicKeyRejectsMultipleEntries(t *testing.T) {
	const keyA = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ2H6djoN78rkj1En9yM7XsMUUDyFgiGWn3WZZqfI3JF a"
	const keyB = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHcw94QjFaGcfUXy3J5bAS7hCzn51cUeiIMxJCDd90fZ b"

	if _, err := cli.ValidatePublicKey(keyA); err != nil {
		t.Fatalf("a single valid key must be accepted, got %v", err)
	}

	for what, raw := range map[string]string{
		"newline separated":    keyA + "\n" + keyB,
		"crlf separated":       keyA + "\r\n" + keyB,
		"trailing newline+key": keyA + "\n" + keyB + "\n",
		"bare cr":              keyA + "\r" + keyB,
		"nul byte":             keyA + "\x00" + keyB,
	} {
		if _, err := cli.ValidatePublicKey(raw); err == nil {
			t.Errorf("%s: a multi-entry key must be rejected", what)
		}
	}
}

// authorized_keys options such as command= or environment= would let a key
// change what the session does. proxpass decides that, not the key.
func TestValidatePublicKeyRejectsOptions(t *testing.T) {
	const key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ2H6djoN78rkj1En9yM7XsMUUDyFgiGWn3WZZqfI3JF a"
	for _, raw := range []string{
		`command="/bin/sh" ` + key,
		"no-pty " + key,
		`environment="PATH=/tmp" ` + key,
	} {
		if _, err := cli.ValidatePublicKey(raw); err == nil {
			t.Errorf("key with options must be rejected: %q", raw)
		}
	}
}

// "admin" is the administrator login; a client holding it would be routed as
// an administrator inside a session.
func TestValidateClientNameRejectsAdmin(t *testing.T) {
	err := cli.ValidateClientName(cli.ReservedAdminName)
	if err == nil {
		t.Fatal("the reserved admin name must be rejected")
	}
	if !strings.Contains(err.Error(), "reserved") {
		t.Errorf("error = %q, want it to explain the name is reserved", err)
	}
}
