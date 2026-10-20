package sshhostkey

import (
	"crypto/sha256"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
	gossh "golang.org/x/crypto/ssh"
)

// sshfpAlgorithm maps an SSH host-key type to the SSHFP algorithm number from
// the IANA registry (RFC 4255 and successors). Only key types proxmox nodes
// actually present are listed; an unlisted type yields 0 and is treated as "no
// SSHFP can match", which fails closed.
func sshfpAlgorithm(keyType string) uint8 {
	switch keyType {
	case gossh.KeyAlgoRSA:
		return 1
	case gossh.KeyAlgoDSA: //nolint:staticcheck // SA1019: still a valid SSHFP algorithm number even though ssh-dss is deprecated.
		return 2
	case gossh.KeyAlgoECDSA256, gossh.KeyAlgoECDSA384, gossh.KeyAlgoECDSA521:
		return 3
	case gossh.KeyAlgoED25519:
		return 4
	default:
		return 0
	}
}

const (
	// sshfpTypeSHA256 is the SSHFP fingerprint-type number for SHA-256.
	sshfpTypeSHA256 = 2

	// sshfpLookupTimeout bounds a single SSHFP DNS lookup so an unreachable or
	// slow resolver cannot stall a connection.
	sshfpLookupTimeout = 5 * time.Second
)

// errNoSSHFP is returned when a host has no SSHFP records (or none usable).
// Callers turn this into the "supply --ssh-fingerprint" prompt.
var errNoSSHFP = fmt.Errorf("no SSHFP records")

// resolver is the DNS entry point, swappable in tests.
type resolver interface {
	lookupSSHFP(host string) (records []*dns.SSHFP, authenticated bool, err error)
}

// verifyAgainstSSHFP checks a presented host key against the host's SSHFP
// records. It returns nil when a record matches, errNoSSHFP when the host
// publishes none, or a descriptive error when records exist but none match (a
// genuine mismatch -- a possible man-in-the-middle -- which must not fall
// through to the fingerprint prompt).
//
// When DNSSEC is required (the default) an unauthenticated answer is treated
// as no records: an attacker who can forge DNS could otherwise publish an
// SSHFP for their own key.
func verifyAgainstSSHFP(res resolver, host string, key gossh.PublicKey) error {
	records, authenticated, err := res.lookupSSHFP(host)
	if err != nil {
		// A lookup failure (timeout, no resolver, SERVFAIL) means we could not
		// verify via SSHFP -- not that the host key is wrong. Treat it as "no
		// records" so the caller falls back to requiring an explicit pinned
		// fingerprint rather than surfacing a DNS error.
		return errNoSSHFP
	}
	if len(records) == 0 {
		return errNoSSHFP
	}
	if requireDNSSEC() && !authenticated {
		// Records exist but are not DNSSEC-validated; do not trust them. Treat
		// as absent so the caller falls back to an explicit fingerprint rather
		// than trusting a spoofable answer.
		return errNoSSHFP
	}

	wantAlgo := sshfpAlgorithm(key.Type())
	if wantAlgo == 0 {
		return fmt.Errorf("unsupported host key type %q for SSHFP", key.Type())
	}
	digest := sha256.Sum256(key.Marshal())

	sawAlgo := false
	for _, rr := range records {
		if rr.Algorithm != wantAlgo {
			continue
		}
		if rr.Type != sshfpTypeSHA256 {
			continue // only SHA-256 fingerprints are compared; SHA-1 is not trusted.
		}
		sawAlgo = true
		if strings.EqualFold(rr.FingerPrint, fmt.Sprintf("%x", digest[:])) {
			return nil
		}
	}
	if sawAlgo {
		return fmt.Errorf(
			"host key for %q does not match any SSHFP record (possible man-in-the-middle)", host)
	}
	// Records exist but none for this key's algorithm/SHA-256. Fail closed
	// rather than silently accepting; the operator can pin a fingerprint.
	return fmt.Errorf("no SHA-256 SSHFP record for the %q host key of %q", key.Type(), host)
}

// dnsResolver is the production resolver. It queries SSHFP records and reports
// whether the answer was DNSSEC-authenticated (the AD bit set by a validating
// resolver).
type dnsResolver struct {
	// server is "host:port" of the DNS resolver; empty means read the system
	// resolver from /etc/resolv.conf.
	server string
}

func (d dnsResolver) lookupSSHFP(host string) ([]*dns.SSHFP, bool, error) {
	server := d.server
	if server == "" {
		conf, err := dns.ClientConfigFromFile("/etc/resolv.conf")
		if err != nil || len(conf.Servers) == 0 {
			return nil, false, fmt.Errorf("reading system resolver: %w", err)
		}
		server = net.JoinHostPort(conf.Servers[0], conf.Port)
	}

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(host), dns.TypeSSHFP)
	// Request DNSSEC: set the DO bit so the resolver validates and sets AD.
	m.SetEdns0(4096, true)
	m.AuthenticatedData = true

	// Bound the lookup so a slow or unreachable resolver cannot hang a
	// connection attempt. SSHFP is best-effort: on timeout we report "no
	// records" and the caller falls back to an explicit fingerprint.
	c := &dns.Client{Timeout: sshfpLookupTimeout}
	resp, _, err := c.Exchange(m, server)
	if err != nil {
		return nil, false, err
	}
	var records []*dns.SSHFP
	for _, ans := range resp.Answer {
		if fp, ok := ans.(*dns.SSHFP); ok {
			records = append(records, fp)
		}
	}
	return records, resp.AuthenticatedData, nil
}
