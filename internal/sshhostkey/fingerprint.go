// Package sshhostkey verifies Proxmox node SSH host keys.
//
// Proxmox publishes no SSH host key or fingerprint through its REST API, so
// there is nothing to pin on first contact from the API itself. Verification
// therefore has two sources, in order:
//
//  1. A fingerprint pinned on the instance (models.ProxmoxInstance.SSHFingerprint),
//     a "SHA256:<base64>" the presented host key must match exactly. This is
//     what --ssh-fingerprint sets.
//  2. DNS SSHFP records (RFC 4255) for the node, which must be DNSSEC-validated
//     unless that requirement is explicitly relaxed.
//
// When neither is available the connection fails and the caller is told to
// supply a fingerprint, which is then pinned and used from then on.
package sshhostkey

import (
	gossh "golang.org/x/crypto/ssh"
)

// FingerprintSHA256 returns the "SHA256:<base64>" fingerprint of a host key,
// the exact form ssh-keyscan and OpenSSH print and the form stored in
// ProxmoxInstance.SSHFingerprint.
func FingerprintSHA256(key gossh.PublicKey) string {
	return gossh.FingerprintSHA256(key)
}
