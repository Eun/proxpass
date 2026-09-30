package cli

import (
	"fmt"
	"strings"
)

// ReservedAdminName is the login name that identifies an administrator. It
// must never be taken by a client.
//
// Declared here rather than imported from internal/session to keep the CLI
// free of a dependency on the session package; session.AdminUser and
// api.AdminUser carry the same value and api_test asserts they agree.
const ReservedAdminName = "admin"

// maxClientNameLen bounds the login name. NSS and sshd both handle long
// names, but a login this long is a mistake rather than an intent.
const maxClientNameLen = 32

// ValidateClientName rejects names that cannot safely be used as a login.
//
// A client name becomes a Unix login name served over NSS, so it has to be a
// valid one. Most importantly it must not be "admin": that name resolves to
// the administrator identity, so a client holding it would be granted admin
// routing in a session. The key lookup would still refuse to offer that
// client's keys for the admin login, so this is not currently exploitable,
// but the collision is a trap worth closing at the source.
func ValidateClientName(name string) error {
	if name == "" {
		return fmt.Errorf("client name must not be empty")
	}
	if strings.EqualFold(name, ReservedAdminName) {
		return fmt.Errorf("client name %q is reserved for administrators", name)
	}
	if len(name) > maxClientNameLen {
		return fmt.Errorf("client name must be at most %d characters", maxClientNameLen)
	}

	// Restrict to a conservative portable login name: start with a letter or
	// underscore, then letters, digits, underscore or hyphen. This keeps the
	// name safe in /etc/passwd-style output, in a URL path segment (the
	// directory API builds its routes by concatenation and does not escape),
	// and in the shell wrappers sshd invokes.
	for i, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r == '_':
		case i > 0 && (r >= '0' && r <= '9' || r == '-'):
		default:
			return fmt.Errorf(
				"client name %q is invalid: use letters, digits, '_' and '-', starting with a letter",
				name)
		}
	}
	return nil
}
