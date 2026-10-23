package sshhostkey

import (
	"errors"
	"fmt"
	"net"
	"strings"

	gossh "golang.org/x/crypto/ssh"
)

// ErrNoFingerprint is returned by a callback when a host key cannot be verified
// because the instance has no pinned fingerprint and the host publishes no
// (DNSSEC-validated) SSHFP record. The error names the host key's actual
// fingerprint so an operator can inspect it and pin it with --ssh-fingerprint.
type ErrNoFingerprint struct {
	Host        string
	Fingerprint string // the presented key's SHA256:... fingerprint
}

func (e *ErrNoFingerprint) Error() string {
	return fmt.Sprintf(
		"cannot verify the SSH host key of %q: no pinned fingerprint and no "+
			"DNSSEC-validated SSHFP record. Re-add with --ssh-fingerprint %s "+
			"after confirming it out of band",
		e.Host, e.Fingerprint)
}

// Callback builds a gossh.HostKeyCallback for one instance. When insecure is
// true it accepts any host key (no verification) -- the SSH equivalent of
// adding the instance with --insecure-ssh. Otherwise it verifies, in order:
//
//  1. pinnedFingerprints ("SHA256:<base64>" each), when non-empty: the
//     presented key must match ANY one of them. A node answers with a
//     different host key per algorithm and may be re-keyed, so more than one
//     may be pinned.
//  2. DNS SSHFP records for sshHost (DNSSEC-validated unless relaxed by env).
//
// When neither verifies the key it returns an *ErrNoFingerprint carrying the
// presented key's fingerprint, so the caller can tell the operator exactly
// what to pin. It never silently accepts a key unless insecure is set.
func Callback(sshHost string, pinnedFingerprints []string, insecure bool) gossh.HostKeyCallback {
	return callbackWithResolver(sshHost, pinnedFingerprints, insecure, dnsResolver{})
}

func callbackWithResolver(sshHost string, pinnedFingerprints []string, insecure bool, res resolver) gossh.HostKeyCallback {
	return func(_ string, _ net.Addr, key gossh.PublicKey) error {
		// 0. Insecure: accept whatever the node presents. Chosen per instance
		// via --insecure-ssh; use only on a trusted path.
		if insecure {
			return nil
		}

		got := FingerprintSHA256(key)

		// 1. Pinned fingerprints win and are self-contained: no DNS needed.
		// The presented key matches if it equals any pinned entry.
		if len(pinnedFingerprints) > 0 {
			for _, fp := range pinnedFingerprints {
				if got == fp {
					return nil
				}
			}
			return fmt.Errorf(
				"SSH host key mismatch for %q: host presented %s, which matches "+
					"none of the pinned fingerprints %s",
				sshHost, got, strings.Join(pinnedFingerprints, ", "))
		}

		// 2. Fall back to SSHFP. A real mismatch is fatal; only "no records"
		// turns into the actionable prompt.
		err := verifyAgainstSSHFP(res, sshHost, key)
		if err == nil {
			return nil
		}
		if errors.Is(err, errNoSSHFP) {
			return &ErrNoFingerprint{Host: sshHost, Fingerprint: got}
		}
		return err
	}
}

// NormalizeFingerprint validates and canonicalizes a user-supplied
// fingerprint. It accepts the "SHA256:<base64>" form OpenSSH and ssh-keyscan
// print and returns it unchanged; anything else is rejected with a message
// showing the expected form.
func NormalizeFingerprint(fp string) (string, error) {
	const prefix = "SHA256:"
	if len(fp) <= len(prefix) || fp[:len(prefix)] != prefix {
		return "", fmt.Errorf(
			"invalid --ssh-fingerprint %q: expected the \"SHA256:<base64>\" form "+
				"printed by ssh-keyscan", fp)
	}
	return fp, nil
}

// NormalizeFingerprints validates and canonicalizes a list of user-supplied
// fingerprints, dropping blank entries. Each is run through
// NormalizeFingerprint, so one malformed value rejects the whole list. The
// result preserves order and may be empty (no pin -> SSHFP fallback).
func NormalizeFingerprints(fps []string) ([]string, error) {
	out := make([]string, 0, len(fps))
	for _, fp := range fps {
		fp = strings.TrimSpace(fp)
		if fp == "" {
			continue
		}
		norm, err := NormalizeFingerprint(fp)
		if err != nil {
			return nil, err
		}
		out = append(out, norm)
	}
	return out, nil
}
