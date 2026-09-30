package cli

import (
	"fmt"
	"strings"

	"proxpass/internal/api"
)

// ReservedAdminName is the login name that identifies an administrator. It
// must never be taken by a client.
//
// Declared here rather than imported from internal/session to keep the CLI
// free of a dependency on the session package; session.AdminUser and
// api.AdminUser carry the same value and api_test asserts they agree.
const ReservedAdminName = "admin"

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
	if len(name) > api.MaxLoginNameLen {
		return fmt.Errorf("client name must be at most %d characters", api.MaxLoginNameLen)
	}
	// The syntax rules live in the api package because the directory server
	// applies the same ones when it decides whether to serve an unknown name
	// as an administrator alias.
	if !api.ValidLoginName(name) {
		return fmt.Errorf(
			"client name %q is invalid: use letters, digits, '_' and '-', starting with a letter",
			name)
	}
	return nil
}
