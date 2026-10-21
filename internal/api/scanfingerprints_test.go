package api

import (
	"testing"

	"proxpass/internal/testenv"
)

// ScanSSHFingerprints returns, over the handler, the fingerprint a host
// actually presents.
func TestScanSSHFingerprintsHandler(t *testing.T) {
	srv, err := testenv.NewMockSSHServer()
	if err != nil {
		t.Fatalf("mock ssh server: %v", err)
	}
	t.Cleanup(srv.Close)

	h, _, ctx := newAdminHandler(t)
	body := ScanSSHFingerprintsJSONRequestBody{SSHHost: srv.Host, SSHPort: srv.Port}
	resp, err := h.ScanSSHFingerprints(ctx, ScanSSHFingerprintsRequestObject{Body: &body})
	if err != nil {
		t.Fatalf("ScanSSHFingerprints: %v", err)
	}
	list, ok := resp.(ScanSSHFingerprints200JSONResponse)
	if !ok {
		t.Fatalf("ScanSSHFingerprints returned %T, want 200", resp)
	}
	want := srv.HostKeyFingerprint()
	var found bool
	for _, k := range list {
		if k.Fingerprint == want {
			found = true
		}
	}
	if !found {
		t.Fatalf("ScanSSHFingerprints = %+v, want one matching %s", list, want)
	}
}

// An unreachable host is a 502 (bad upstream), not a 500 or a panic.
func TestScanSSHFingerprintsUnreachable(t *testing.T) {
	h, _, ctx := newAdminHandler(t)
	body := ScanSSHFingerprintsJSONRequestBody{SSHHost: "127.0.0.1", SSHPort: 1}
	resp, err := h.ScanSSHFingerprints(ctx, ScanSSHFingerprintsRequestObject{Body: &body})
	if err != nil {
		t.Fatalf("ScanSSHFingerprints: %v", err)
	}
	if _, ok := resp.(ScanSSHFingerprints502JSONResponse); !ok {
		t.Fatalf("ScanSSHFingerprints(unreachable) returned %T, want 502", resp)
	}
}

// A non-admin credential is refused.
func TestScanSSHFingerprintsRequiresAdmin(t *testing.T) {
	h, repo, _ := newAdminHandler(t)
	ctx := clientCtx(t, repo)
	body := ScanSSHFingerprintsJSONRequestBody{SSHHost: "h", SSHPort: 22}
	resp, err := h.ScanSSHFingerprints(ctx, ScanSSHFingerprintsRequestObject{Body: &body})
	if err != nil {
		t.Fatalf("ScanSSHFingerprints: %v", err)
	}
	if _, ok := resp.(ScanSSHFingerprints403JSONResponse); !ok {
		t.Fatalf("ScanSSHFingerprints(non-admin) returned %T, want 403", resp)
	}
}
