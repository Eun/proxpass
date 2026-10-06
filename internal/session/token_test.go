package session_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"proxpass/internal/db"
	"proxpass/internal/session"
)

// parseKeyLine splits an authorized_keys line into its option prefix and the
// key itself, the way sshd does.
func parseKeyLine(t *testing.T, line string) (options, key string) {
	t.Helper()
	// Every line proxpass emits is either `<key>` or
	// `environment="..." <key>`; the key always starts with its type.
	i := strings.Index(line, "ssh-")
	if i < 0 {
		t.Fatalf("no key found in line %q", line)
	}
	return strings.TrimSpace(line[:i]), strings.TrimSpace(line[i:])
}

// tokenIn returns the token an authorized_keys line carries.
func tokenIn(t *testing.T, line string) string {
	t.Helper()
	options, _ := parseKeyLine(t, line)
	prefix := `environment="` + session.TokenEnv + "="
	if !strings.HasPrefix(options, prefix) {
		t.Fatalf("line %q carries no %s option", line, session.TokenEnv)
	}
	return strings.TrimSuffix(strings.TrimPrefix(options, prefix), `"`)
}

// The whole design rests on this: each key line carries a token minted for
// the identity THAT key belongs to, because sshd applies the options of the
// matching key only. One token for the whole invocation would hand a client
// the administrator's.
func TestEachKeyGetsItsOwnToken(t *testing.T) {
	const (
		adminKey  = "ssh-ed25519 AAAAadmin admin"
		clientKey = "ssh-ed25519 AAAAalice alice"
	)
	repo := newRepo(t)
	addClient(t, repo, clientKey)

	var out bytes.Buffer
	if err := session.WriteAuthorizedKeys(
		t.Context(), &out, repo, userAlias, adminKey); err != nil {
		t.Fatalf("WriteAuthorizedKeys: %v", err)
	}

	lines := nonEmptyLines(out.String())
	if len(lines) != 2 {
		t.Fatalf("got %d lines, want 2: %q", len(lines), out.String())
	}

	tokens := map[string]string{}
	for _, line := range lines {
		_, key := parseKeyLine(t, line)
		tokens[key] = tokenIn(t, line)
	}
	if tokens[adminKey] == "" || tokens[clientKey] == "" {
		t.Fatalf("a key is missing its token: %#v", tokens)
	}
	if tokens[adminKey] == tokens[clientKey] {
		t.Fatal("the admin and client keys share a token, so the client " +
			"would redeem the administrator's identity")
	}

	// And each token must redeem as the identity of its own key.
	admin, err := repo.RedeemSessionToken(
		t.Context(), session.HashToken(tokens[adminKey]), time.Now())
	if err != nil {
		t.Fatalf("redeem admin token: %v", err)
	}
	if !admin.IsAdmin {
		t.Errorf("the admin key's token redeemed as non-admin: %+v", admin)
	}

	client, err := repo.RedeemSessionToken(
		t.Context(), session.HashToken(tokens[clientKey]), time.Now())
	if err != nil {
		t.Fatalf("redeem client token: %v", err)
	}
	if client.IsAdmin {
		t.Errorf("the client key's token redeemed as ADMIN: %+v", client)
	}
	if client.ClientID == 0 {
		t.Errorf("the client token carries no client id: %+v", client)
	}
}

// The login name must not change who a token says you are: it is an alias
// anybody can pick, which is the reason this whole mechanism exists.
func TestTokenIdentityComesFromTheKeyNotTheName(t *testing.T) {
	const clientKey = "ssh-ed25519 AAAAalice alice"
	repo := newRepo(t)
	addClient(t, repo, clientKey)

	// Log in under a name that is not this client's own.
	var out bytes.Buffer
	if err := session.WriteAuthorizedKeys(
		t.Context(), &out, repo, userAlias, ""); err != nil {
		t.Fatalf("WriteAuthorizedKeys: %v", err)
	}
	lines := nonEmptyLines(out.String())
	if len(lines) != 1 {
		t.Fatalf("got %d lines, want 1: %q", len(lines), out.String())
	}

	identity, err := repo.RedeemSessionToken(
		t.Context(), session.HashToken(tokenIn(t, lines[0])), time.Now())
	if err != nil {
		t.Fatalf("redeem: %v", err)
	}
	if identity.IsAdmin {
		t.Fatal("a client that logged in under an unused name was " +
			"issued an administrator token")
	}
	if identity.LoginName != userAlias {
		t.Errorf("User = %q, want the login name %q for the audit log",
			identity.LoginName, userAlias)
	}
	if identity.IdentityName != userAlice {
		t.Errorf("IdentityName = %q, want the client's own name %q",
			identity.IdentityName, userAlice)
	}
}

// Single use is what makes the token survivable in an environment that other
// processes of the same uid can read.
func TestATokenCannotBeRedeemedTwice(t *testing.T) {
	const clientKey = "ssh-ed25519 AAAAalice alice"
	repo := newRepo(t)
	addClient(t, repo, clientKey)

	var out bytes.Buffer
	if err := session.WriteAuthorizedKeys(
		t.Context(), &out, repo, userAlice, ""); err != nil {
		t.Fatalf("WriteAuthorizedKeys: %v", err)
	}
	token := tokenIn(t, nonEmptyLines(out.String())[0])

	if _, err := repo.RedeemSessionToken(
		t.Context(), session.HashToken(token), time.Now()); err != nil {
		t.Fatalf("first redemption failed: %v", err)
	}
	_, err := repo.RedeemSessionToken(
		t.Context(), session.HashToken(token), time.Now())
	if !errors.Is(err, db.ErrNoSuchToken) {
		t.Fatalf("second redemption returned %v, want ErrNoSuchToken: a "+
			"replayed token must not work", err)
	}
}

// A token is a credential, so the database must hold only its hash: the file
// is world-readable in the shipped image.
func TestTheTokenItselfIsNeverStored(t *testing.T) {
	const clientKey = "ssh-ed25519 AAAAalice alice"
	repo := newRepo(t)
	addClient(t, repo, clientKey)

	var out bytes.Buffer
	if err := session.WriteAuthorizedKeys(
		t.Context(), &out, repo, userAlice, ""); err != nil {
		t.Fatalf("WriteAuthorizedKeys: %v", err)
	}
	token := tokenIn(t, nonEmptyLines(out.String())[0])

	// Redeeming by the raw token must fail; only the hash works.
	if _, err := repo.RedeemSessionToken(t.Context(), token, time.Now()); !errors.Is(err, db.ErrNoSuchToken) {
		t.Fatalf("the raw token was accepted as a stored hash (err=%v), so "+
			"the token is on disk in usable form", err)
	}
}

// A token that outlived its window must be refused even though it was never
// used, and the row must not keep it redeemable afterwards.
func TestAnExpiredTokenIsRefused(t *testing.T) {
	const clientKey = "ssh-ed25519 AAAAalice alice"
	repo := newRepo(t)
	addClient(t, repo, clientKey)

	var out bytes.Buffer
	if err := session.WriteAuthorizedKeys(
		t.Context(), &out, repo, userAlice, ""); err != nil {
		t.Fatalf("WriteAuthorizedKeys: %v", err)
	}
	token := tokenIn(t, nonEmptyLines(out.String())[0])

	later := time.Now().Add(session.TokenTTL).Add(time.Second)
	if _, err := repo.RedeemSessionToken(
		t.Context(), session.HashToken(token), later); !errors.Is(err, db.ErrNoSuchToken) {
		t.Fatalf("an expired token was redeemed (err=%v)", err)
	}
}

// The option is quoted, so a token containing a quote or a space would end
// it early and let the remainder be parsed as further sshd options.
func TestGeneratedTokensAreSafeInsideTheOption(t *testing.T) {
	for range 64 {
		token, _, err := session.NewToken()
		if err != nil {
			t.Fatalf("NewToken: %v", err)
		}
		if !session.ValidTokenValue(token) {
			t.Fatalf("NewToken produced an option-unsafe value: %q", token)
		}
	}
}

func TestValidTokenValueRejectsOptionBreakers(t *testing.T) {
	for _, bad := range []string{
		"", `has"quote`, "has\\backslash", "has space",
		"has\ttab", "has\nnewline", "has\rcarriage",
	} {
		if session.ValidTokenValue(bad) {
			t.Errorf("ValidTokenValue(%q) = true, want false", bad)
		}
	}
}

// Two invocations must never produce the same token.
func TestTokensAreUnique(t *testing.T) {
	seen := map[string]bool{}
	for range 256 {
		token, hash, err := session.NewToken()
		if err != nil {
			t.Fatalf("NewToken: %v", err)
		}
		if seen[token] {
			t.Fatalf("NewToken repeated a token: %q", token)
		}
		seen[token] = true
		if hash != session.HashToken(token) {
			t.Fatalf("NewToken returned a hash that is not HashToken(token)")
		}
	}
}
