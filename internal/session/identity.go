package session

import "proxpass/internal/api"

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
	// User is the login name sshd authenticated. For an administrator this
	// is whatever name they chose, since any unused name resolves to the
	// admin; it is kept for the log, where the name that actually came in
	// is the audit record.
	User string
	// DisplayName is the configured name of the identity behind User, as
	// opposed to the name the client typed: AdminUser for an
	// administrator, and the client's stored name for a client.
	//
	// These differ because a login name is not a configured account. Any
	// unused name is served as an administrator alias, so "ssh
	// whatever@host" with an admin key logs in as the administrator --
	// showing "whatever" back would present a name that nothing was ever
	// defined under.
	DisplayName string
	IsAdmin     bool
	ClientID    int64
}
