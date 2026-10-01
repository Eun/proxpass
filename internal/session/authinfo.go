package session

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	gossh "golang.org/x/crypto/ssh"
)

// AuthInfoEnv is the environment variable sshd sets when ExposeAuthInfo is
// enabled. It names a file describing how the session authenticated.
//
// Without it the session knows only the login name, which is not an
// identity here: any unused name is served as an alias, so the name alone
// cannot say who connected. The file names the actual key, which can.
const AuthInfoEnv = "SSH_USER_AUTH"

// authKeys returns the public keys sshd recorded for this session.
//
// The file holds one line per successful authentication step, as
// "<method> <rest>"; for publickey the rest is an authorized_keys-style
// entry. Other methods (none, password, keyboard-interactive) are ignored
// rather than rejected: proxpass disables them in sshd_config, and an
// unexpected one simply contributes no key, so the caller fails closed.
//
// A session can legitimately present more than one key, for example under
// `AuthenticationMethods publickey,publickey`, so every key is returned.
func authKeys(path string) ([]gossh.PublicKey, error) {
	// The path comes from sshd via the environment, not from the client.
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", AuthInfoEnv, err)
	}
	defer func() { _ = f.Close() }()

	var keys []gossh.PublicKey
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		method, rest, found := strings.Cut(line, " ")
		if !found || method != "publickey" {
			continue
		}
		// ParseAuthorizedKey wants a bare authorized_keys entry, which is
		// what follows the method name.
		pub, parseErr := parseAuthorizedKeyOnly(rest)
		if parseErr != nil {
			// A line proxpass cannot parse must not be treated as a match;
			// skipping it means the caller sees no identity and refuses.
			continue
		}
		keys = append(keys, pub)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("reading %s: %w", AuthInfoEnv, err)
	}
	return keys, nil
}

// sameKey reports whether two public keys are identical.
//
// The wire encoding is compared rather than the text form, so a differing
// comment, option field or amount of whitespace cannot make one key look
// like another -- or stop a key matching itself.
func sameKey(a, b gossh.PublicKey) bool {
	ab, bb := a.Marshal(), b.Marshal()
	if len(ab) != len(bb) {
		return false
	}
	for i := range ab {
		if ab[i] != bb[i] {
			return false
		}
	}
	return true
}

// parseStoredKey parses a key as stored in the database or supplied by
// --admin-key. Blank and malformed entries yield nil, so a bad row cannot
// match anything.
func parseStoredKey(raw string) gossh.PublicKey {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	pub, err := parseAuthorizedKeyOnly(raw)
	if err != nil {
		return nil
	}
	return pub
}

// parseAuthorizedKeyOnly parses an authorized_keys entry and keeps only the
// key, discarding the comment, options and trailing bytes that
// gossh.ParseAuthorizedKey also returns.
func parseAuthorizedKeyOnly(raw string) (gossh.PublicKey, error) {
	pub, _, _, _, err := gossh.ParseAuthorizedKey([]byte(raw)) //nolint:dogsled // the other three returns are genuinely unused
	return pub, err
}
