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

// Identity is who a session turned out to be, as resolved from the key that
// authenticated it.
type Identity struct {
	// LoginName is what the caller typed in `ssh <name>@host'.
	//
	// It is a REQUEST PARAMETER, not an identity. Any name the directory
	// does not already serve resolves to an alias, so anybody can pick
	// anybody else's. Its one legitimate use is as a guest target: "ssh
	// ct100@host" names a guest rather than a person. Never log it as the
	// actor and never authorize from it -- use IdentityName, IsAdmin and
	// ClientID.
	LoginName string

	// IdentityName is WHO THE CALLER IS: the client's stored name, or
	// AdminUser for an administrator.
	//
	// Resolved by `proxpass authorized-keys', which runs as root before
	// the session exists and so knows which key authenticated; the session
	// cannot influence it. This is the name to log and the name to show.
	//
	// It differs from LoginName because a login name is not a configured
	// account: "ssh whatever@host" with an admin key logs in as the
	// administrator, and echoing "whatever" back would present a name
	// nothing was ever defined under.
	IdentityName string

	IsAdmin  bool
	ClientID int64
}
