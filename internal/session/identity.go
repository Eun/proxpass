package session

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"proxpass/internal/api"
	"proxpass/internal/db"
)

// AdminUser is the reserved login name for administrators. It is not a
// proxpass client and has no database row; it is authorized purely by the
// admin key list.
//
// It is an alias of api.AdminUser so the directory API and the session agree
// on the name: the API must publish a matching NSS entry, or sshd rejects the
// login as an invalid user before authentication is even attempted.
const AdminUser = api.AdminUser

// Identity is the resolved identity behind an authenticated login name.
type Identity struct {
	User     string
	IsAdmin  bool
	ClientID int64
}

// ResolveIdentity maps the login name sshd authenticated to a proxpass
// identity.
//
// Authentication itself already happened: sshd verified the client's key
// against the authorized-keys command, so reaching this point means the login
// name is legitimate. This only decides what the session is allowed to do.
func ResolveIdentity(ctx context.Context, repo db.Repository, user string) (*Identity, error) {
	user = strings.TrimSpace(user)
	if user == "" {
		return nil, fmt.Errorf("empty user name")
	}
	if user == AdminUser {
		// Defense in depth: "admin" is reserved, and cli.ValidateClientName
		// refuses to create a client with that name. If one exists anyway
		// (for example from a database predating that check), refuse the
		// login rather than silently granting it admin routing.
		existing, err := repo.GetClientByName(ctx, user)
		if err == nil && existing != nil {
			return nil, fmt.Errorf(
				"a client named %q exists and shadows the administrator login; rename or remove it",
				user)
		}
		return &Identity{User: user, IsAdmin: true}, nil
	}

	client, err := repo.GetClientByName(ctx, user)
	if err == nil && client != nil {
		return &Identity{User: user, ClientID: client.ID}, nil
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		// A real storage fault must not be mistaken for "not a client",
		// which would silently promote the login to an administrator.
		return nil, fmt.Errorf("looking up client %q: %w", user, err)
	}

	// Not a client. Reaching this point means sshd already authenticated the
	// login against the admin key list (WriteAuthorizedKeys offers only
	// those for a name that is not a client), so this is the administrator
	// logging in under a login name of their choosing.
	return &Identity{User: user, IsAdmin: true}, nil
}
