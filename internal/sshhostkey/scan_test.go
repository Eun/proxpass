package sshhostkey_test

import (
	"strings"
	"testing"

	"proxpass/internal/sshhostkey"
	"proxpass/internal/testenv"
)

// ScanFingerprints returns the exact host-key fingerprint a server presents,
// in the "SHA256:<base64>" form pinning expects.
func TestScanFingerprintsReturnsHostKey(t *testing.T) {
	srv, err := testenv.NewMockSSHServer()
	if err != nil {
		t.Fatalf("mock ssh server: %v", err)
	}
	t.Cleanup(srv.Close)

	keys, err := sshhostkey.ScanFingerprints(t.Context(), srv.Host, srv.Port)
	if err != nil {
		t.Fatalf("ScanFingerprints: %v", err)
	}
	if len(keys) == 0 {
		t.Fatal("ScanFingerprints returned no keys")
	}

	want := srv.HostKeyFingerprint()
	var found bool
	for _, k := range keys {
		if k.Fingerprint == want {
			found = true
		}
		if !strings.HasPrefix(k.Fingerprint, "SHA256:") {
			t.Errorf("fingerprint %q is not in SHA256: form", k.Fingerprint)
		}
		if k.KeyType == "" {
			t.Error("scanned key has no key type")
		}
	}
	if !found {
		t.Fatalf("ScanFingerprints = %+v, want one matching %s", keys, want)
	}
}

// A closed/unreachable port fails rather than hanging or returning an empty
// success.
func TestScanFingerprintsUnreachable(t *testing.T) {
	// Port 1 on loopback: nothing listens, so the dial is refused fast.
	if _, err := sshhostkey.ScanFingerprints(t.Context(), "127.0.0.1", 1); err == nil {
		t.Fatal("ScanFingerprints to a dead port returned no error")
	}
}

// Input validation rejects an empty host and an out-of-range port before any
// network call.
func TestScanFingerprintsValidation(t *testing.T) {
	if _, err := sshhostkey.ScanFingerprints(t.Context(), "", 22); err == nil {
		t.Error("empty host accepted")
	}
	if _, err := sshhostkey.ScanFingerprints(t.Context(), "host", 0); err == nil {
		t.Error("port 0 accepted")
	}
	if _, err := sshhostkey.ScanFingerprints(t.Context(), "host", 70000); err == nil {
		t.Error("port 70000 accepted")
	}
}
