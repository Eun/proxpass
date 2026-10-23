package api

// Tests for the typed /v1 GetSSHPublicKey handler. Internal (package api) so
// the handler can be called directly with a credential on the context, like
// the other admin-handler tests.

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	gossh "golang.org/x/crypto/ssh"

	"proxpass/internal/models"
)

// writeTestSSHKey generates an ed25519 private key, writes it in OpenSSH PEM
// form to a temp file, points SSHKeyPathEnv at it, and returns the expected
// authorized_keys line for its public half.
func writeTestSSHKey(t *testing.T) (wantLine string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	block, err := gossh.MarshalPrivateKey(priv, "proxpass")
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	path := filepath.Join(t.TempDir(), "proxpass_key")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	t.Setenv(models.SSHKeyPathEnv, path)

	sshPub, err := gossh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("ssh public key: %v", err)
	}
	// publicKeyLine returns MarshalAuthorizedKey's output verbatim, which
	// ends in a newline; the endpoint mirrors the /admin/rpc op byte for byte.
	return string(gossh.MarshalAuthorizedKey(sshPub))
}

// TestGetSSHPublicKeyReturnsTheInstalledKey is the case the UI relies on: an
// admin caller gets the authorized_keys line. The response carries only the
// key -- the key file's path on the server is deliberately not exposed.
func TestGetSSHPublicKeyReturnsTheInstalledKey(t *testing.T) {
	wantLine := writeTestSSHKey(t)
	h, _, ctx := newAdminHandler(t)

	resp, err := h.GetProxpassSSHPublicKey(ctx, GetProxpassSSHPublicKeyRequestObject{})
	if err != nil {
		t.Fatalf("GetProxpassSSHPublicKey: %v", err)
	}
	ok, is := resp.(GetProxpassSSHPublicKey200JSONResponse)
	if !is {
		t.Fatalf("expected 200, got %T", resp)
	}
	if ok.Key != wantLine {
		t.Fatalf("key = %q, want %q", ok.Key, wantLine)
	}
}

// TestGetSSHPublicKeyEmptyWhenNoKey pins that a termproxy-only deployment (no
// key file) gets a 200 with an empty key, not an error.
func TestGetSSHPublicKeyEmptyWhenNoKey(t *testing.T) {
	t.Setenv(models.SSHKeyPathEnv, filepath.Join(t.TempDir(), "absent"))
	h, _, ctx := newAdminHandler(t)

	resp, err := h.GetProxpassSSHPublicKey(ctx, GetProxpassSSHPublicKeyRequestObject{})
	if err != nil {
		t.Fatalf("GetProxpassSSHPublicKey: %v", err)
	}
	ok, is := resp.(GetProxpassSSHPublicKey200JSONResponse)
	if !is {
		t.Fatalf("expected 200, got %T", resp)
	}
	if ok.Key != "" {
		t.Fatalf("expected an empty key, got %q", ok.Key)
	}
}

// TestGetSSHPublicKeyRefusesAClient asserts gateAdmin returns 403 for a
// non-admin caller: the key is an admin-only read.
func TestGetSSHPublicKeyRefusesAClient(t *testing.T) {
	writeTestSSHKey(t)
	h, repo, _ := newAdminHandler(t)

	resp, err := h.GetProxpassSSHPublicKey(clientCtx(t, repo), GetProxpassSSHPublicKeyRequestObject{})
	if err != nil {
		t.Fatalf("GetProxpassSSHPublicKey: %v", err)
	}
	if _, is := resp.(GetProxpassSSHPublicKey403JSONResponse); !is {
		t.Fatalf("expected 403 for a client, got %T", resp)
	}
}

// TestGetSSHPublicKeyRequiresACredential asserts a caller with no credential
// gets 401, not the key.
func TestGetSSHPublicKeyRequiresACredential(t *testing.T) {
	writeTestSSHKey(t)
	h, _, _ := newAdminHandler(t)

	resp, err := h.GetProxpassSSHPublicKey(t.Context(), GetProxpassSSHPublicKeyRequestObject{})
	if err != nil {
		t.Fatalf("GetProxpassSSHPublicKey: %v", err)
	}
	if _, is := resp.(GetProxpassSSHPublicKey401JSONResponse); !is {
		t.Fatalf("expected 401 without a credential, got %T", resp)
	}
}
