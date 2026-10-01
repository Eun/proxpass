package session

import (
	"context"
	"fmt"
	"io"
	"strings"

	"proxpass/internal/api"
	"proxpass/internal/db"
)

// WriteAuthorizedKeys prints the authorized_keys lines for user to w.
//
// sshd runs this through AuthorizedKeysCommand during authentication, so it
// must be fast, must write nothing but key lines to stdout, and must exit
// zero even when the user is unknown: any other output would be parsed as a
// key, and a non-zero exit is logged as an error on every failed probe.
//
// flagAdminKey, when non-empty, is an additional admin key supplied at
// startup; it is offered for the reserved admin user only.
func WriteAuthorizedKeys(
	ctx context.Context,
	w io.Writer,
	repo db.Repository,
	user string,
	flagAdminKey string,
) error {
	user = strings.TrimSpace(user)
	if user == "" {
		return nil
	}

	// Refuse a name proxpass would never serve as a login.
	//
	// In the current deployment sshd cannot actually reach this with a bad
	// name: it resolves the login through NSS first, and nss_http builds its
	// lookup URL by unescaped concatenation, so "alice?x" is looked up as
	// "alice" and sshd adopts that truncated name for everything afterwards
	// -- including the argument it passes here. Verified by logging the
	// AuthorizedKeysCommand argv in the image: `ssh 'a?b@host'` invokes it
	// with "a". The truncation is at least CONSISTENT, so it is a confusing
	// alias rather than a mismatch: "alice?x" lands on the real client
	// "alice" and is offered only that client's keys, not an admin key.
	//
	// The check is kept as a cheap invariant for the paths that do pass a
	// name straight through -- a hand-run `proxpass authorized-keys`, and a
	// future nss_http that escapes the name properly, where the full string
	// would arrive here for the first time.
	if !api.ValidLoginName(user) {
		return nil
	}

	client, err := repo.GetClientByName(ctx, user)
	if err == nil && client != nil && user != AdminUser {
		// A client: only its own keys, never an admin key.
		writeKeys(w, client.PublicKeys)
		return nil
	}

	// Not a client, so this is the administrator under some login name.
	// proxpass used to authenticate purely by key and ignore the name, so
	// "ssh tobias@host" worked with an admin key; the directory serves any
	// unused name as an admin alias to keep that working. Authorization
	// still comes from the admin key list alone.
	writeKeys(w, []string{flagAdminKey})
	keys, err := repo.ListAdminKeys(ctx)
	if err != nil {
		return fmt.Errorf("listing admin keys: %w", err)
	}
	writeKeys(w, keys)
	return nil
}

// writeKeys prints one key per line, skipping blanks.
//
// A stored value containing a line break would become several
// authorized_keys entries, so anything multi-line is dropped rather than
// emitted. cli.ValidatePublicKey rejects such values at the point of entry;
// this is the second line of defense for rows written before that check
// existed, or by anything that bypasses the CLI.
func writeKeys(w io.Writer, keys []string) {
	for _, k := range keys {
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		if strings.ContainsAny(k, "\n\r") {
			continue
		}
		fmt.Fprintln(w, k)
	}
}
