package session

import (
	"context"
	"fmt"
	"os"
	"strings"

	"proxpass/internal/api"
	"proxpass/internal/db"

	gossh "golang.org/x/crypto/ssh"
)

// ErrNoAuthInfo reports that sshd did not tell the session which key
// authenticated it.
//
// This means ExposeAuthInfo is off, so the only thing identifying the
// session is the login name -- which is not an identity, because any unused
// name is served as an alias. Resolution refuses rather than guessing.
var ErrNoAuthInfo = fmt.Errorf(
	"%s is not set: sshd must be configured with `ExposeAuthInfo yes'", AuthInfoEnv)

// ErrUnknownKey reports that the authenticating key belongs to no client and
// is not an admin key.
//
// Reaching this means the key passed sshd's check but has since been removed
// or rewritten, so the session has no identity to act as and must stop.
var ErrUnknownKey = fmt.Errorf("the authenticating key matches no client or admin key")

// ErrDuplicateKey reports that one key is registered to more than one
// identity, so it does not name a single one.
//
// Refusing is the only safe answer: picking either would silently grant one
// client's access to another, and which one it picked would depend on row
// order.
var ErrDuplicateKey = fmt.Errorf("the authenticating key is registered to more than one identity")

// ResolveIdentityByKey determines who is connecting from the key sshd
// authenticated, ignoring the login name entirely.
//
// The login name cannot carry identity here: the directory serves any unused
// name so that sshd gets far enough to ask for a key at all, which means the
// name is chosen by the caller and proves nothing. The key is the only thing
// the client had to possess, so it -- and only it -- decides who they are.
//
// This applies to administrators too. An admin key grants admin whatever
// name it arrives under, and a client key grants that client; neither can be
// reached by typing the other's name.
//
// It fails closed. An unknown key, a key registered twice, or a missing
// SSH_USER_AUTH all return an error rather than a weaker identity, because
// every fallback available here (treat as admin, treat as the named client)
// would grant more than the key proves.
func ResolveIdentityByKey(
	ctx context.Context,
	repo db.Repository,
	loginName string,
	authInfoPath string,
	flagAdminKey string,
) (*Identity, error) {
	// The name does not identify anyone, but it is still echoed into a
	// passwd entry and an authorized_keys lookup, so one proxpass would
	// never serve must not be acted on either. See api.ValidLoginName.
	if !api.ValidLoginName(strings.TrimSpace(loginName)) {
		return nil, fmt.Errorf("invalid login name %q", loginName)
	}
	if authInfoPath == "" {
		return nil, ErrNoAuthInfo
	}
	presented, err := authKeys(authInfoPath)
	if err != nil {
		return nil, err
	}
	if len(presented) == 0 {
		// Authenticated by something other than a public key, or the file
		// held nothing parseable. Either way there is no key to identify.
		return nil, ErrUnknownKey
	}

	clients, err := repo.ListClients(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing clients: %w", err)
	}
	// Defense in depth: "admin" is reserved and cli.ValidateClientName
	// refuses to create a client with that name. One existing anyway (from
	// a database predating that check) is a misconfiguration that makes
	// two identities answer to one name, so refuse the whole login rather
	// than pick one.
	for _, c := range clients {
		if c.Name == AdminUser {
			return nil, fmt.Errorf(
				"a client named %q exists and shadows the administrator login; rename or remove it",
				AdminUser)
		}
	}
	adminKeys, err := repo.ListAdminKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing admin keys: %w", err)
	}
	if flagAdminKey != "" {
		adminKeys = append(adminKeys, flagAdminKey)
	}

	// Collect every identity the presented keys match, so that a key shared
	// between two of them is reported rather than resolved arbitrarily.
	var matches []*Identity
	for _, pub := range presented {
		for _, k := range adminKeys {
			if stored := parseStoredKey(k); stored != nil && sameKey(pub, stored) {
				matches = appendIdentity(matches, &Identity{
					User: loginName, DisplayName: AdminUser, IsAdmin: true,
				})
			}
		}
		for _, c := range clients {
			for _, k := range c.PublicKeys {
				stored := parseStoredKey(k)
				if stored == nil || !sameKey(pub, stored) {
					continue
				}
				matches = appendIdentity(matches, &Identity{
					User: loginName, DisplayName: c.Name, ClientID: c.ID,
				})
			}
		}
	}

	switch len(matches) {
	case 0:
		// Name the key so the operator can tell which one was refused
		// without having to reproduce the login. A public key and its
		// fingerprint are not secrets.
		return nil, fmt.Errorf("%w (%s)",
			ErrUnknownKey, keyFingerprints(presented))
	case 1:
		return matches[0], nil
	default:
		return nil, fmt.Errorf("%w (%s)",
			ErrDuplicateKey, keyFingerprints(presented))
	}
}

// keyFingerprints renders the presented keys for a log or error message.
func keyFingerprints(keys []gossh.PublicKey) string {
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, gossh.FingerprintSHA256(k))
	}
	return strings.Join(parts, ", ")
}

// appendIdentity adds id unless an equivalent one is already present.
//
// A key listed twice for the same client, or an admin key that also appears
// in --admin-key and the database, is not a conflict: it still names one
// identity. Only genuinely different identities make a key ambiguous.
func appendIdentity(list []*Identity, id *Identity) []*Identity {
	for _, existing := range list {
		if existing.IsAdmin == id.IsAdmin && existing.ClientID == id.ClientID {
			return list
		}
	}
	return append(list, id)
}

// AuthInfoPath returns the path sshd exposed for this session, if any.
func AuthInfoPath() string { return os.Getenv(AuthInfoEnv) }
