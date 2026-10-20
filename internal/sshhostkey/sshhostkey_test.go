package sshhostkey

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/miekg/dns"
	gossh "golang.org/x/crypto/ssh"
)

// newHostKey returns a fresh ed25519 SSH public key for tests.
func newHostKey(t *testing.T) gossh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	key, err := gossh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("public key: %v", err)
	}
	return key
}

// fakeResolver returns canned SSHFP answers.
type fakeResolver struct {
	records       []*dns.SSHFP
	authenticated bool
	err           error
}

func (f fakeResolver) lookupSSHFP(string) ([]*dns.SSHFP, bool, error) {
	return f.records, f.authenticated, f.err
}

// sshfpRecordFor builds a SHA-256 SSHFP record matching key.
func sshfpRecordFor(key gossh.PublicKey) *dns.SSHFP {
	digest := sha256.Sum256(key.Marshal())
	return &dns.SSHFP{
		Algorithm:   sshfpAlgorithm(key.Type()),
		Type:        sshfpTypeSHA256,
		FingerPrint: fmt.Sprintf("%x", digest[:]),
	}
}

func callNoAddr(cb gossh.HostKeyCallback, key gossh.PublicKey) error {
	return cb("host:22", &net.TCPAddr{}, key)
}

// TestPinnedFingerprintMatches accepts the key whose fingerprint was pinned.
func TestPinnedFingerprintMatches(t *testing.T) {
	key := newHostKey(t)
	cb := callbackWithResolver("pve", FingerprintSHA256(key), false, fakeResolver{})
	if err := callNoAddr(cb, key); err != nil {
		t.Fatalf("pinned key should be accepted: %v", err)
	}
}

// TestPinnedFingerprintMismatchIsRejected refuses a different key.
func TestPinnedFingerprintMismatchIsRejected(t *testing.T) {
	pinned := FingerprintSHA256(newHostKey(t))
	other := newHostKey(t)
	cb := callbackWithResolver("pve", pinned, false, fakeResolver{})
	err := callNoAddr(cb, other)
	if err == nil || !strings.Contains(err.Error(), "mismatch") {
		t.Fatalf("expected a mismatch error, got: %v", err)
	}
}

// TestSSHFPMatchAccepts accepts a key whose SSHFP record is published and
// DNSSEC-validated.
func TestSSHFPMatchAccepts(t *testing.T) {
	key := newHostKey(t)
	res := fakeResolver{records: []*dns.SSHFP{sshfpRecordFor(key)}, authenticated: true}
	cb := callbackWithResolver("pve", "", false, res)
	if err := callNoAddr(cb, key); err != nil {
		t.Fatalf("matching SSHFP should be accepted: %v", err)
	}
}

// TestSSHFPMismatchIsRejected refuses a key whose SSHFP record is for a
// different key (a possible MITM) -- and does NOT fall through to the prompt.
func TestSSHFPMismatchIsRejected(t *testing.T) {
	published := newHostKey(t)
	presented := newHostKey(t)
	res := fakeResolver{records: []*dns.SSHFP{sshfpRecordFor(published)}, authenticated: true}
	cb := callbackWithResolver("pve", "", false, res)
	err := callNoAddr(cb, presented)
	var noFP *ErrNoFingerprint
	if errors.As(err, &noFP) {
		t.Fatalf("a mismatch must not become a no-fingerprint prompt: %v", err)
	}
	if err == nil {
		t.Fatal("expected the mismatched key to be rejected")
	}
}

// TestUnauthenticatedSSHFPIsIgnoredByDefault treats a non-DNSSEC answer as no
// records, so the caller is prompted for a fingerprint rather than trusting a
// spoofable answer.
func TestUnauthenticatedSSHFPIsIgnoredByDefault(t *testing.T) {
	t.Setenv(RequireDNSSECEnv, "") // default: require DNSSEC
	key := newHostKey(t)
	res := fakeResolver{records: []*dns.SSHFP{sshfpRecordFor(key)}, authenticated: false}
	cb := callbackWithResolver("pve", "", false, res)
	err := callNoAddr(cb, key)
	var noFP *ErrNoFingerprint
	if !errors.As(err, &noFP) {
		t.Fatalf("an unauthenticated SSHFP should prompt for a fingerprint, got: %v", err)
	}
}

// TestUnauthenticatedSSHFPAcceptedWhenRelaxed honors the env override.
func TestUnauthenticatedSSHFPAcceptedWhenRelaxed(t *testing.T) {
	t.Setenv(RequireDNSSECEnv, "0")
	key := newHostKey(t)
	res := fakeResolver{records: []*dns.SSHFP{sshfpRecordFor(key)}, authenticated: false}
	cb := callbackWithResolver("pve", "", false, res)
	if err := callNoAddr(cb, key); err != nil {
		t.Fatalf("with DNSSEC relaxed, a matching SSHFP should be accepted: %v", err)
	}
}

// TestNoSSHFPPromptsForFingerprint names the presented fingerprint so the
// operator can pin it.
func TestNoSSHFPPromptsForFingerprint(t *testing.T) {
	key := newHostKey(t)
	cb := callbackWithResolver("pve", "", false, fakeResolver{}) // no records
	err := callNoAddr(cb, key)
	var noFP *ErrNoFingerprint
	if !errors.As(err, &noFP) {
		t.Fatalf("no SSHFP should prompt for a fingerprint, got: %v", err)
	}
	if noFP.Fingerprint != FingerprintSHA256(key) {
		t.Fatalf("prompt names %q, want %q", noFP.Fingerprint, FingerprintSHA256(key))
	}
	if !strings.Contains(noFP.Error(), "--ssh-fingerprint") {
		t.Fatalf("prompt should tell the operator how to pin: %s", noFP.Error())
	}
}

// TestLookupErrorPromptsRatherThanFailing treats a DNS error (timeout, no
// resolver) as "unverifiable", prompting for a fingerprint.
func TestLookupErrorPromptsRatherThanFailing(t *testing.T) {
	key := newHostKey(t)
	res := fakeResolver{err: errors.New("i/o timeout")}
	cb := callbackWithResolver("pve", "", false, res)
	err := callNoAddr(cb, key)
	var noFP *ErrNoFingerprint
	if !errors.As(err, &noFP) {
		t.Fatalf("a DNS error should prompt, not surface the error: %v", err)
	}
}

// TestInsecureAcceptsAnyKey covers --insecure-ssh: with insecure set, any host
// key is accepted without a pin or an SSHFP record.
func TestInsecureAcceptsAnyKey(t *testing.T) {
	// A resolver that would fail if consulted, to prove insecure short-circuits
	// before any SSHFP lookup.
	res := fakeResolver{err: errors.New("resolver must not be consulted")}
	cb := callbackWithResolver("pve", "", true, res)
	if err := callNoAddr(cb, newHostKey(t)); err != nil {
		t.Fatalf("insecure should accept any key: %v", err)
	}
}

func TestNormalizeFingerprint(t *testing.T) {
	good := "SHA256:abc123+/ABC"
	got, err := NormalizeFingerprint(good)
	if err != nil || got != good {
		t.Fatalf("valid fingerprint: got %q err %v", got, err)
	}
	for _, bad := range []string{"", "SHA256:", "md5:xyz", "abc123", "SHA1:deadbeef"} {
		if _, err := NormalizeFingerprint(bad); err == nil {
			t.Errorf("expected %q to be rejected", bad)
		}
	}
}
