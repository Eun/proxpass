package sshhostkey

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	gossh "golang.org/x/crypto/ssh"
)

// scanTimeout bounds one host-key scan: the dial, and each per-algorithm
// handshake. A node that does not answer should fail fast rather than hang the
// admin request that triggered the scan.
const scanTimeout = 10 * time.Second

// ScannedKey is one host key a server presented during a scan.
type ScannedKey struct {
	// KeyType is the key's algorithm name, e.g. "ssh-ed25519" or "rsa-sha2-512".
	KeyType string
	// Fingerprint is the "SHA256:<base64>" form, exactly what --ssh-fingerprint
	// pins and what sshhostkey.Callback compares against.
	Fingerprint string
}

// scanAlgorithms is the set of host-key algorithms a scan probes for, newest
// and strongest first. A server offers a subset; one connection negotiates one
// algorithm, so the scan dials once per entry and records whatever key the
// server returned, de-duplicating by fingerprint. Matches the common set
// ssh-keyscan reports.
var scanAlgorithms = []string{
	gossh.KeyAlgoED25519,
	gossh.KeyAlgoECDSA256,
	gossh.KeyAlgoECDSA384,
	gossh.KeyAlgoECDSA521,
	gossh.KeyAlgoRSASHA512,
	gossh.KeyAlgoRSASHA256,
	gossh.KeyAlgoRSA,
}

// errKeyCaptured stops the handshake once the host key is in hand: a scan needs
// the key, not a session, so there is no reason to authenticate. The SSH
// library surfaces this as the HostKeyCallback's error, which we then discard.
var errKeyCaptured = errors.New("host key captured")

// ScanFingerprints connects to host:port and returns the SSH host-key
// fingerprints it presents, one per distinct host key -- the server-side
// equivalent of ssh-keyscan. No authentication is attempted and no session is
// opened: the handshake is aborted the moment the host key is read.
//
// It is used by the admin API so an operator adding a node can fetch the real
// fingerprints and pick one to pin, instead of having to run ssh-keyscan by
// hand. The caller must still confirm the chosen fingerprint out of band --
// scanning only reports what the host currently presents, it does not vouch for
// it.
func ScanFingerprints(ctx context.Context, host string, port int) ([]ScannedKey, error) {
	if host == "" {
		return nil, errors.New("ssh host is required")
	}
	if port <= 0 || port > 65535 {
		return nil, fmt.Errorf("invalid ssh port %d", port)
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))

	var out []ScannedKey
	seen := map[string]bool{}
	var lastErr error

	for _, alg := range scanAlgorithms {
		key, err := scanOne(ctx, addr, alg)
		if err != nil {
			lastErr = err
			continue
		}
		fp := FingerprintSHA256(key)
		if seen[fp] {
			continue
		}
		seen[fp] = true
		out = append(out, ScannedKey{KeyType: key.Type(), Fingerprint: fp})
	}

	if len(out) == 0 {
		if lastErr != nil {
			return nil, fmt.Errorf("scanning %s: %w", addr, lastErr)
		}
		return nil, fmt.Errorf("scanning %s: no host key presented", addr)
	}
	return out, nil
}

// scanOne dials addr once, offering only the given host-key algorithm, and
// returns the key the server presents for it. A server that does not offer the
// algorithm fails the handshake, which the caller treats as "not this one".
func scanOne(ctx context.Context, addr, alg string) (gossh.PublicKey, error) {
	dialer := net.Dialer{Timeout: scanTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(time.Now().Add(scanTimeout)); err != nil {
		return nil, err
	}

	var captured gossh.PublicKey
	cfg := &gossh.ClientConfig{
		// No real user/auth: the handshake is aborted in the host-key callback
		// before authentication, so these are never used.
		User:              "proxpass-scan",
		HostKeyAlgorithms: []string{alg},
		HostKeyCallback: func(_ string, _ net.Addr, key gossh.PublicKey) error {
			captured = key
			return errKeyCaptured
		},
		Timeout: scanTimeout,
	}
	// The host-key callback captures the key and aborts, so the handshake
	// never completes and the returned connection/channels are always nil --
	// only the error matters, and only when nothing was captured.
	if clientConn, _, _, dialErr := gossh.NewClientConn(conn, addr, cfg); clientConn != nil {
		_ = clientConn.Close()
	} else {
		err = dialErr
	}
	if captured != nil {
		// Expected: the callback aborted with errKeyCaptured after reading the
		// key. Any other wrapped error still means we got the key.
		return captured, nil
	}
	if err != nil {
		return nil, err
	}
	return nil, errors.New("no host key presented")
}
