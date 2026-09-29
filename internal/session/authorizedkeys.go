package session

import (
	"context"
	"fmt"
	"io"
	"strings"

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

	if user == AdminUser {
		if key := strings.TrimSpace(flagAdminKey); key != "" {
			fmt.Fprintln(w, key)
		}
		keys, err := repo.ListAdminKeys(ctx)
		if err != nil {
			return fmt.Errorf("listing admin keys: %w", err)
		}
		writeKeys(w, keys)
		return nil
	}

	client, err := repo.GetClientByName(ctx, user)
	if err != nil || client == nil {
		// An unknown user is not an error: sshd asks about every login name
		// it is offered, including ones that do not exist.
		return nil
	}
	writeKeys(w, client.PublicKeys)
	return nil
}

// writeKeys prints one key per line, skipping blanks.
func writeKeys(w io.Writer, keys []string) {
	for _, k := range keys {
		if k = strings.TrimSpace(k); k != "" {
			fmt.Fprintln(w, k)
		}
	}
}
