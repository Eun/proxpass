package api

import (
	"fmt"
	"strconv"
)

// Default id layout. Every value stays below DefaultMaxID so that proxpass
// works on a user-namespaced Docker daemon out of the box; see IDLayout.
const (
	DefaultAdminGroupGID  = 19001
	DefaultSharedGroupGID = 19000
	DefaultUIDBase        = 20000
	DefaultGIDBase        = 40000

	// DefaultMaxID is the highest id proxpass will hand out.
	//
	// A userns-remapped or rootless Docker daemon maps only the 65536
	// subordinate ids from /etc/subuid into the container, so an id above
	// 65535 does not exist inside the namespace. sshd accepts the public key
	// and only then fails the login with
	//
	//	setresuid 99999: Invalid argument
	//
	// which reads like a broken account rather than a range limit.
	DefaultMaxID = 65535
)

// IDLayout describes how proxpass derives Unix ids for the users and groups
// it serves to NSS.
//
// It is configurable because the usable id range is a property of the
// deployment, not of proxpass: a userns-remapped daemon, a different
// /etc/subuid allocation, or a base image whose own accounts occupy part of
// the range all change what is safe. Hardcoding these caused logins to fail
// with "setresuid ...: Invalid argument" on a user-namespaced daemon.
type IDLayout struct {
	// AdminUID is the uid of the reserved admin login.
	AdminUID uint
	// AliasUID is the uid of a login name that names no configured account.
	//
	// Aliases are what make "the key is the identity" work: the directory
	// serves any unused name so that sshd gets as far as checking a key.
	// They all share this uid, because NSS is asked only for a name and has
	// no way to tell one alias session from another.
	//
	// It is deliberately NOT AdminUID. Sharing a uid means sharing an
	// identity to everything that keys off one -- process ownership, and
	// anything that later hands a session a credential -- so an alias
	// session must not be indistinguishable from the administrator's. The
	// gids already differ; this makes the uids differ too.
	AliasUID uint
	// AdminGroupGID is the admin's primary group: the only group permitted
	// to write the database.
	AdminGroupGID uint
	// SharedGroupGID is every client's primary group, granting read access.
	SharedGroupGID uint
	// UIDBase is added to a client's database id to derive its uid.
	UIDBase uint
	// GIDBase is added to a group's database id to derive its gid.
	GIDBase uint
	// MaxID is the highest id that may be served.
	MaxID uint
}

// DefaultIDLayout returns the built-in layout.
func DefaultIDLayout() IDLayout {
	return IDLayout{
		AdminUID:       DefaultUIDBase - 1,
		AliasUID:       DefaultUIDBase - 2,
		AdminGroupGID:  DefaultAdminGroupGID,
		SharedGroupGID: DefaultSharedGroupGID,
		UIDBase:        DefaultUIDBase,
		GIDBase:        DefaultGIDBase,
		MaxID:          DefaultMaxID,
	}
}

// idEnv maps each field to the environment variable that overrides it.
// Exposed for documentation and for the container entrypoint, which must
// agree with these values when it chowns the state directory.
const (
	EnvAdminUID       = "PROXPASS_ADMIN_UID"
	EnvAliasUID       = "PROXPASS_ALIAS_UID"
	EnvAdminGroupGID  = "PROXPASS_ADMIN_GID"
	EnvSharedGroupGID = "PROXPASS_GID"
	EnvUIDBase        = "PROXPASS_UID_BASE"
	EnvGIDBase        = "PROXPASS_GID_BASE"
	EnvMaxID          = "PROXPASS_MAX_ID"
)

// LoadIDLayout builds a layout from the defaults, overridden by whichever of
// the PROXPASS_* id variables are set. lookup is usually os.LookupEnv.
//
// The result is validated: an invalid layout is rejected at startup rather
// than producing logins that fail after the key has already been accepted.
func LoadIDLayout(lookup func(string) (string, bool)) (IDLayout, error) {
	l := DefaultIDLayout()

	// Read MaxID first: it bounds the validation of everything else.
	for _, f := range []struct {
		env string
		dst *uint
	}{
		{EnvMaxID, &l.MaxID},
		{EnvAdminUID, &l.AdminUID},
		{EnvAliasUID, &l.AliasUID},
		{EnvAdminGroupGID, &l.AdminGroupGID},
		{EnvSharedGroupGID, &l.SharedGroupGID},
		{EnvUIDBase, &l.UIDBase},
		{EnvGIDBase, &l.GIDBase},
	} {
		raw, ok := lookup(f.env)
		if !ok || raw == "" {
			continue
		}
		v, err := strconv.ParseUint(raw, 10, 32)
		if err != nil {
			return IDLayout{}, fmt.Errorf("%s=%q: not an unsigned integer", f.env, raw)
		}
		*f.dst = uint(v)
	}

	if err := l.Validate(); err != nil {
		return IDLayout{}, err
	}
	return l, nil
}

// Validate reports whether the layout can actually be served.
func (l IDLayout) Validate() error {
	if l.MaxID == 0 {
		return fmt.Errorf("%s must be greater than 0", EnvMaxID)
	}

	// Nothing may exceed the ceiling, since sshd cannot adopt such an id.
	for _, f := range []struct {
		env string
		val uint
	}{
		{EnvAdminUID, l.AdminUID},
		{EnvAliasUID, l.AliasUID},
		{EnvAdminGroupGID, l.AdminGroupGID},
		{EnvSharedGroupGID, l.SharedGroupGID},
		{EnvUIDBase, l.UIDBase},
		{EnvGIDBase, l.GIDBase},
	} {
		if f.val > l.MaxID {
			return fmt.Errorf("%s=%d exceeds %s=%d", f.env, f.val, EnvMaxID, l.MaxID)
		}
	}

	// System accounts live below 1000 on Debian and adduser starts there.
	// nsswitch consults "files" before "http", so an overlap would let a
	// local account silently shadow a proxpass one.
	const firstNonSystemID = 1000
	for _, f := range []struct {
		env string
		val uint
	}{
		{EnvAdminUID, l.AdminUID},
		{EnvAliasUID, l.AliasUID},
		{EnvAdminGroupGID, l.AdminGroupGID},
		{EnvSharedGroupGID, l.SharedGroupGID},
		{EnvUIDBase, l.UIDBase},
		{EnvGIDBase, l.GIDBase},
	} {
		if f.val < firstNonSystemID {
			return fmt.Errorf(
				"%s=%d is in the system range; use %d or above to avoid colliding with a local account",
				f.env, f.val, firstNonSystemID)
		}
	}

	// Neither fixed uid may fall inside the range derived from client ids,
	// or a client would resolve to the same uid as the admin or an alias.
	if l.AdminUID >= l.UIDBase {
		return fmt.Errorf("%s=%d must be below %s=%d",
			EnvAdminUID, l.AdminUID, EnvUIDBase, l.UIDBase)
	}
	if l.AliasUID >= l.UIDBase {
		return fmt.Errorf("%s=%d must be below %s=%d",
			EnvAliasUID, l.AliasUID, EnvUIDBase, l.UIDBase)
	}
	// An alias is reachable with ANY valid key, including a client's, so it
	// must not share the administrator's uid: that would make an alias
	// session indistinguishable from the admin's to anything that
	// identifies a process by its owner.
	if l.AliasUID == l.AdminUID {
		return fmt.Errorf(
			"%s and %s must differ: an alias is reachable with any valid key, "+
				"so it must not share the administrator's uid",
			EnvAliasUID, EnvAdminUID)
	}
	// The fixed gids must not collide with the derived group range.
	if l.AdminGroupGID >= l.GIDBase || l.SharedGroupGID >= l.GIDBase {
		return fmt.Errorf("%s=%d and %s=%d must both be below %s=%d",
			EnvAdminGroupGID, l.AdminGroupGID,
			EnvSharedGroupGID, l.SharedGroupGID,
			EnvGIDBase, l.GIDBase)
	}
	if l.AdminGroupGID == l.SharedGroupGID {
		return fmt.Errorf(
			"%s and %s must differ: clients would otherwise share the admin's write access to the database",
			EnvAdminGroupGID, EnvSharedGroupGID)
	}
	// Leave room for a useful number of clients and groups.
	const minRoom = 100
	if l.UIDBase+minRoom > l.MaxID {
		return fmt.Errorf("%s=%d leaves room for fewer than %d clients below %s=%d",
			EnvUIDBase, l.UIDBase, minRoom, EnvMaxID, l.MaxID)
	}
	if l.GIDBase+minRoom > l.MaxID {
		return fmt.Errorf("%s=%d leaves room for fewer than %d groups below %s=%d",
			EnvGIDBase, l.GIDBase, minRoom, EnvMaxID, l.MaxID)
	}
	return nil
}

// InRange reports whether id can be served under this layout.
func (l IDLayout) InRange(id uint) bool { return id <= l.MaxID }

// UIDFor returns the uid for a client row id.
func (l IDLayout) UIDFor(rowID int64) uint {
	//nolint:gosec // row ids are small positive sqlite rowids
	return uint(rowID) + l.UIDBase
}

// GIDFor returns the gid for a group row id.
func (l IDLayout) GIDFor(rowID int64) uint {
	//nolint:gosec // row ids are small positive sqlite rowids
	return uint(rowID) + l.GIDBase
}
