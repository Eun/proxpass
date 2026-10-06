package session

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"proxpass/internal/api"
	"proxpass/internal/db"
	"proxpass/internal/models"
)

// WriteAuthorizedKeys prints the authorized_keys lines for user to w.
//
// sshd runs this through AuthorizedKeysCommand during authentication, so it
// must be fast, must write nothing but key lines to stdout, and must exit
// zero even when the user is unknown: any other output would be parsed as a
// key, and a non-zero exit is logged as an error on every failed probe.
//
// flagAdminKey, when non-empty, is an additional admin key supplied at
// startup. Like every other key it is offered for any servable name that is
// not a client's own, because the name does not decide who the caller is --
// the key does, at the session. See ResolveIdentityByKey.
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

	// The login name does not select WHICH keys are acceptable, because it
	// does not select who the caller is: the session resolves that from the
	// key that actually authenticated (see ResolveIdentityByKey). So every
	// key that could identify somebody is offered for every servable name,
	// and sshd's job here is only "is this key known to proxpass at all".
	//
	// Filtering by name instead would make the name a second, weaker
	// credential: "ssh alice@host" would accept only alice's keys, so the
	// administrator could not log in under that name even though their key
	// is strictly more privileged. It would also reintroduce the escalation
	// this design removes, by letting the offered set imply an identity.
	//
	// This is safe ONLY in combination with key-based resolution. Were the
	// session to fall back to trusting the name, offering client keys here
	// would let any client authenticate under an unused name and be treated
	// as the administrator. The two must change together, which is why the
	// session refuses to start at all when ExposeAuthInfo is off.
	//
	// Each line also carries a freshly minted API token for the identity
	// that key belongs to. sshd applies the options of the MATCHING key
	// only, so the session is handed exactly one token: the one for whoever
	// actually authenticated. That is why minting happens per line here and
	// not once per invocation -- this command cannot know which of the keys
	// it is about to print will be the one accepted.
	minter := newTokenMinter(ctx, repo)

	adminIdentity := &models.SessionIdentity{
		LoginName:    user,
		IdentityName: AdminUser,
		IsAdmin:      true,
	}
	minter.writeKeys(w, []string{flagAdminKey}, adminIdentity)

	keys, err := repo.ListAdminKeys(ctx)
	if err != nil {
		return fmt.Errorf("listing admin keys: %w", err)
	}
	minter.writeKeys(w, keys, adminIdentity)

	clients, err := repo.ListClients(ctx)
	if err != nil {
		return fmt.Errorf("listing clients: %w", err)
	}
	for _, c := range clients {
		minter.writeKeys(w, c.PublicKeys, &models.SessionIdentity{
			LoginName:    user,
			IdentityName: c.Name,
			ClientID:     c.ID,
		})
	}
	return minter.err
}

// tokenMinter writes key lines, giving each one an API token for the
// identity that key identifies.
//
// It accumulates the first error instead of returning one per call so that
// the caller can keep printing keys. A mint failure must not cost somebody
// their login: without a token the session simply falls back to resolving
// its own identity, which is exactly what it did before tokens existed.
type tokenMinter struct {
	ctx  context.Context //nolint:containedctx // carried so writeKeys can stay a plain writer
	repo db.Repository
	err  error
}

func newTokenMinter(ctx context.Context, repo db.Repository) *tokenMinter {
	return &tokenMinter{ctx: ctx, repo: repo}
}

// writeKeys prints one key per line, skipping blanks.
//
// A stored value containing a line break would become several
// authorized_keys entries, so anything multi-line is dropped rather than
// emitted. cli.ValidatePublicKey rejects such values at the point of entry;
// this is the second line of defense for rows written before that check
// existed, or by anything that bypasses the CLI.
func (m *tokenMinter) writeKeys(w io.Writer, keys []string, identity *models.SessionIdentity) {
	for _, k := range keys {
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		if strings.ContainsAny(k, "\n\r") {
			continue
		}
		fmt.Fprintln(w, m.lineFor(k, identity))
	}
}

// lineFor returns the authorized_keys line for one key: the key itself,
// preceded by an environment= option carrying this identity's token.
//
// On any failure it returns the bare key. sshd parses this stdout as keys,
// so there is nowhere to report a problem to, and a login that works without
// a token is far better than one that is refused: the session keeps its
// existing behavior. The error is recorded for the caller's return value,
// which reaches the sshd log via the command's exit status.
func (m *tokenMinter) lineFor(key string, identity *models.SessionIdentity) string {
	token, hash, err := NewToken()
	if err != nil {
		m.record(err)
		return key
	}
	if !ValidTokenValue(token) {
		m.record(errors.New("generated token is not option-safe"))
		return key
	}

	now := time.Now()
	if err := m.repo.MintSessionToken(
		m.ctx, hash, identity, now, now.Add(TokenTTL)); err != nil {
		m.record(err)
		return key
	}
	return fmt.Sprintf("environment=%q %s", TokenEnv+"="+token, key)
}

func (m *tokenMinter) record(err error) {
	if m.err == nil {
		m.err = err
	}
}
