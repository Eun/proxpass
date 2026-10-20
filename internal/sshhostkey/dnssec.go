package sshhostkey

import "os"

// RequireDNSSECEnv names the environment variable that relaxes the
// DNSSEC requirement for SSHFP verification.
//
// SSHFP records are only trustworthy when the DNS answer is authenticated:
// without DNSSEC an attacker who can spoof DNS can also serve an SSHFP for
// their own host key, defeating the check. So by default proxpass only
// accepts SSHFP records from a DNSSEC-validated answer (the resolver's AD
// bit), exactly as OpenSSH's "VerifyHostKeyDNS=yes" does.
//
// Set PROXPASS_SSHFP_REQUIRE_DNSSEC=0 (or false/no) to accept SSHFP records
// without DNSSEC validation -- weaker, for networks with a trusted resolver
// path but no DNSSEC. Any other value, or an unset variable, keeps the secure
// default.
const RequireDNSSECEnv = "PROXPASS_SSHFP_REQUIRE_DNSSEC"

// requireDNSSEC reports whether SSHFP answers must be DNSSEC-validated. It is
// true unless the env var is explicitly set to a falsey value.
func requireDNSSEC() bool {
	switch os.Getenv(RequireDNSSECEnv) {
	case "0", "false", "FALSE", "no", "NO":
		return false
	default:
		return true
	}
}
